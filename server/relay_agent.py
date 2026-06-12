"""
Relay-клиент агента (WebSocket-мост).

Архитектура внутри агента:
  Relay → WS → RelayAgentBridge → TCP → localhost:TCP_PORT → ClientHandler

Агент продолжает слушать TCP на 127.0.0.1.
RelayAgentBridge устанавливает WS-соединение к relay и для каждого
входящего запроса открывает TCP-соединение к локальному серверу,
пересылает байты туда и обратно.

Три параллельных соединения: cmd, scr, file — как в прямом режиме.
"""

import json
import ssl
import asyncio
import socket
import struct
import base64
import time
from pathlib import Path

try:
    import websockets.client
    HAS_WS = True
except ImportError:
    HAS_WS = False


RECONNECT_DELAY = 5


async def _relay_session(relay_url: str, agent_id: str, conn_type: str,
                          agent_label: str, tcp_port: int, password: str,
                          use_ssl: bool):
    """
    Одна сессия: WebSocket к relay + TCP к локальному серверу.
    Все команды relay → TCP → агент → TCP → relay.
    """
    import struct

    ws_url  = f"{relay_url.rstrip('/')}/ws/agent/{agent_id}/{conn_type}"
    ssl_ctx = ssl.create_default_context()
    headers = {"X-Agent-Label": agent_label}

    # Для file-канала отключаем ping: во время передачи файла event loop
    # заблокирован в run_in_executor (sendall/recv), ping_timeout=10с истекает
    # раньше чем агент отвечает — WS падает и файл не доставляется.
    # cmd и scr держат соединение пингами; file-канал живёт пока жив TCP.
    _ping_interval = None if conn_type == "file" else 30
    _ping_timeout  = None if conn_type == "file" else 10

    async with websockets.client.connect(
        ws_url, ssl=ssl_ctx, extra_headers=headers,
        ping_interval=_ping_interval, ping_timeout=_ping_timeout, open_timeout=20,
        max_size=16 * 1024 * 1024,  # 16 МБ — запас для upload_bytes (base64) и будущих команд
    ) as ws:
        print(f"[relay/{conn_type}] ✓ подключено к relay")

        # Открываем TCP к локальному серверу
        if use_ssl:
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.connect(("127.0.0.1", tcp_port))
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            tcp = ctx.wrap_socket(raw, server_hostname="localhost")
        else:
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp.connect(("127.0.0.1", tcp_port))

        tcp.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        tcp.settimeout(0)  # неблокирующий режим

        # Аутентифицируемся на локальном TCP-сервере
        from common.protocol import send_msg, recv_msg, MsgType
        from common.crypto import hash_password
        tcp.setblocking(True)
        tcp.settimeout(10)
        send_msg(tcp, MsgType.AUTH, {"password": password})
        auth_resp = recv_msg(tcp)
        if auth_resp.get("type") != MsgType.AUTH_OK:
            tcp.close()
            raise ConnectionError("Локальная аутентификация провалена")
        tcp.settimeout(120)
        print(f"[relay/{conn_type}] ✓ TCP-сервер аутентифицирован")

        loop = asyncio.get_event_loop()

        async def from_relay():
            """relay → TCP → relay: получаем JSON-команду, пишем в TCP, читаем ответ."""
            async for raw_msg in ws:
                try:
                    envelope  = json.loads(raw_msg)
                    req_id    = envelope["req_id"]
                    payload_b = envelope["payload"].encode()

                    # Пишем в TCP с 4-байтным заголовком длины
                    header = struct.pack(">I", len(payload_b))
                    await loop.run_in_executor(None, tcp.sendall, header + payload_b)

                    # Читаем ответ из TCP
                    response_b = await loop.run_in_executor(None, _read_tcp_msg, tcp)

                    # Для scr-соединения — отдаём бинарный фрейм если это скриншот.
                    # Формат бинарного фрейма:
                    #   4 байта (big-endian): ширина
                    #   4 байта (big-endian): высота
                    #   1 байт: формат (0=jpeg, 1=webp)
                    #   остаток: сырые байты изображения
                    # Это убирает base64 overhead (~33% меньше трафика).
                    if conn_type == "scr":
                        try:
                            resp_obj = json.loads(response_b)
                            p = resp_obj.get("payload", {})
                            if p.get("data") and p.get("width"):
                                img_bytes = base64.b64decode(p["data"])
                                fmt_byte  = 1 if p.get("fmt") == "webp" else 0
                                w = int(p["width"]); h = int(p["height"])
                                # Бинарный фрейм: [req_id 16 байт utf8][W:4][H:4][fmt:1][img]
                                req_id_b = req_id.encode().ljust(16, b'\x00')[:16]
                                binary_frame = req_id_b + struct.pack(">IIB", w, h, fmt_byte) + img_bytes
                                await ws.send(binary_frame)
                                continue
                        except Exception:
                            pass

                    # Обычный текстовый ответ для cmd/file
                    await ws.send(json.dumps({
                        "req_id":   req_id,
                        "response": response_b.decode(),
                    }))
                except Exception as e:
                    print(f"[relay/{conn_type}] ошибка обработки: {e}")
                    try:
                        await ws.send(json.dumps({
                            "req_id":  envelope.get("req_id","?"),
                            "response": json.dumps({"type":"error","payload":{"reason":str(e)}}),
                        }))
                    except Exception:
                        pass

        await from_relay()
        tcp.close()


def _read_tcp_msg(sock) -> bytes:
    """Читает одно сообщение из TCP (4-байтный заголовок + тело)."""
    import struct
    raw_len = _recv_exact(sock, 4)
    n       = struct.unpack(">I", raw_len)[0]
    return _recv_exact(sock, n)


def _recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        c = sock.recv(n - len(buf))
        if not c:
            raise ConnectionError("TCP connection closed")
        buf += c
    return buf


async def _conn_loop(relay_url, agent_id, conn_type, agent_label,
                     tcp_port, password, use_ssl):
    """Цикл переподключения для одного типа соединения."""
    while True:
        try:
            await _relay_session(relay_url, agent_id, conn_type,
                                 agent_label, tcp_port, password, use_ssl)
        except Exception as e:
            print(f"[relay/{conn_type}] ошибка: {e}, "
                  f"переподключение через {RECONNECT_DELAY}с...")
            await asyncio.sleep(RECONNECT_DELAY)


def start_relay_client(relay_url: str, agent_id: str, agent_label: str,
                        tcp_port: int, password: str, use_ssl: bool):
    """
    Запускает три WebSocket-соединения к relay в отдельном потоке.
    Блокирует поток до остановки.
    """
    if not HAS_WS:
        raise ImportError(
            "websockets не установлен: pip install websockets"
        )

    print(f"[relay] Подключаемся к {relay_url}")
    print(f"[relay] ID агента: {agent_id}  |  Имя: {agent_label}")

    async def main():
        await asyncio.gather(
            _conn_loop(relay_url, agent_id, "cmd",  agent_label, tcp_port, password, use_ssl),
            _conn_loop(relay_url, agent_id, "scr",  agent_label, tcp_port, password, use_ssl),
            _conn_loop(relay_url, agent_id, "file", agent_label, tcp_port, password, use_ssl),
        )

    asyncio.run(main())
