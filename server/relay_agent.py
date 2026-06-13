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


# Базовая задержка переподключения и максимум, между ними — exponential backoff.
RECONNECT_BASE  = 2
RECONNECT_MAX   = 60
# Application-level ping для file-канала: heartbeat поверх протокола,
# чтобы NAT не дропнул соединение при долгих передачах.
FILE_HEARTBEAT_SEC = 25


async def _relay_session(relay_url: str, agent_id: str, conn_type: str,
                          agent_label: str, tcp_port: int, password: str,
                          use_ssl: bool):
    """
    Одна сессия: WebSocket к relay + TCP к локальному серверу.
    Все команды relay → TCP → агент → TCP → relay.
    """
    ws_url  = f"{relay_url.rstrip('/')}/ws/agent/{agent_id}/{conn_type}"
    ssl_ctx = ssl.create_default_context()
    headers = {"X-Agent-Label": agent_label}

    # Для file-канала отключаем встроенный ping, потому что recv() агента
    # может блокироваться надолго при больших чанках. Heartbeat реализуем
    # application-level через периодический PING в отдельной задаче.
    _ping_interval = None if conn_type == "file" else 30
    _ping_timeout  = None if conn_type == "file" else 10

    async with websockets.client.connect(
        ws_url, ssl=ssl_ctx, extra_headers=headers,
        ping_interval=_ping_interval, ping_timeout=_ping_timeout, open_timeout=20,
        max_size=16 * 1024 * 1024,
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
        # Сразу blocking + большой таймаут для рабочего режима. Промежуточные
        # переключения (settimeout(0), затем 10, затем 120) убраны — они
        # ничего не давали и сбивали с толку.
        tcp.setblocking(True)
        tcp.settimeout(120)

        # Аутентификация: выполняем блокирующие send_msg/recv_msg в executor,
        # чтобы не блокировать event loop на время handshake.
        from common.protocol import send_msg, recv_msg, MsgType
        loop = asyncio.get_event_loop()

        def _auth_sync():
            tcp.settimeout(10)
            send_msg(tcp, MsgType.AUTH, {"password": password})
            r = recv_msg(tcp)
            tcp.settimeout(120)
            return r

        auth_resp = await loop.run_in_executor(None, _auth_sync)
        if auth_resp.get("type") != MsgType.AUTH_OK:
            tcp.close()
            raise ConnectionError("Локальная аутентификация провалена")
        print(f"[relay/{conn_type}] ✓ TCP-сервер аутентифицирован")

        # Application-level heartbeat только для file-канала.
        heartbeat_task = None
        if conn_type == "file":
            async def _heartbeat():
                try:
                    while True:
                        await asyncio.sleep(FILE_HEARTBEAT_SEC)
                        try:
                            await ws.ping()
                        except Exception:
                            return
                except asyncio.CancelledError:
                    return
            heartbeat_task = asyncio.create_task(_heartbeat())

        try:
            await _from_relay(ws, tcp, conn_type, loop)
        finally:
            if heartbeat_task:
                heartbeat_task.cancel()
                try:
                    await heartbeat_task
                except Exception:
                    pass
            try: tcp.close()
            except Exception: pass


async def _from_relay(ws, tcp, conn_type, loop):
    """
    relay → TCP → relay: получаем JSON-команду, пишем в TCP, читаем ответ.
    Поведение при ошибках:
      - Ошибка обработки одного сообщения НЕ закрывает канал. Попытка отправить
        error-ответ обёрнута в try/except — если ws.send упал, продолжаем
        читать следующее сообщение.
      - Исключение само по себе из ws.send в внутреннем catch'е перехвачено,
        чтобы не пробросилось в async for и не убило весь канал.
    """
    envelope = None
    async for raw_msg in ws:
        try:
            envelope  = json.loads(raw_msg)
            req_id    = envelope["req_id"]
            payload_b = envelope["payload"].encode()

            header = struct.pack(">I", len(payload_b))
            await loop.run_in_executor(None, tcp.sendall, header + payload_b)

            response_b = await loop.run_in_executor(None, _read_tcp_msg, tcp)

            if conn_type == "scr":
                try:
                    resp_obj = json.loads(response_b)
                    p = resp_obj.get("payload", {})
                    if p.get("data") and p.get("width"):
                        img_bytes = base64.b64decode(p["data"])
                        fmt_byte  = 1 if p.get("fmt") == "webp" else 0
                        w = int(p["width"]); h = int(p["height"])
                        req_id_b = req_id.encode().ljust(16, b'\x00')[:16]
                        binary_frame = req_id_b + struct.pack(">IIB", w, h, fmt_byte) + img_bytes
                        await ws.send(binary_frame)
                        continue
                except Exception:
                    pass

            await ws.send(json.dumps({
                "req_id":   req_id,
                "response": response_b.decode(),
            }))
        except Exception as e:
            print(f"[relay/{conn_type}] ошибка обработки: {e}")
            try:
                rid = envelope.get("req_id", "?") if envelope else "?"
                await ws.send(json.dumps({
                    "req_id":  rid,
                    "response": json.dumps({"type": "error", "payload": {"reason": str(e)}}),
                }))
            except Exception as send_err:
                # Если не можем сообщить об ошибке — продолжаем читать
                # следующее сообщение. async for закроется только при
                # фактическом отключении WS, а не при единичной ошибке.
                print(f"[relay/{conn_type}] failed to send error response: {send_err}")


def _read_tcp_msg(sock) -> bytes:
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
    """
    Цикл переподключения одного типа соединения с exponential backoff:
    1с → 2с → 4с → … → 60с. При успешном подключении счётчик сбрасывается.
    Это снимает нагрузку с relay при network storm — все агенты не
    будут одновременно долбить каждые 5с.
    """
    attempt = 0
    while True:
        try:
            await _relay_session(relay_url, agent_id, conn_type,
                                 agent_label, tcp_port, password, use_ssl)
            attempt = 0  # успешный сеанс — сбрасываем backoff
        except Exception as e:
            delay = min(RECONNECT_BASE * (2 ** attempt), RECONNECT_MAX)
            # Небольшой jitter (±20%) разносит переподключение нескольких
            # агентов во времени.
            import random
            jitter = delay * (0.8 + 0.4 * random.random())
            attempt = min(attempt + 1, 10)
            print(f"[relay/{conn_type}] ошибка: {e}, "
                  f"переподключение через {jitter:.1f}с...")
            await asyncio.sleep(jitter)


def start_relay_client(relay_url: str, agent_id: str, agent_label: str,
                        tcp_port: int, password: str, use_ssl: bool):
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
