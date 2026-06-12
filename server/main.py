"""
Сервер удалённого доступа.

Запуск через relay (два серых IP):
    python -m server.main --port 9999 --password МойПароль12 --relay https://your-relay.onrender.com --agent-id MyPC
"""

import ssl, socket, argparse, sys, threading, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from common.crypto import hash_password, generate_self_signed_cert
from server.handler import ClientHandler


def start_tcp(host, port, password_hash, use_ssl):
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw.bind((host, port))
    raw.listen(20)

    if use_ssl:
        cert, key = generate_self_signed_cert()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        srv = ctx.wrap_socket(raw, server_side=True)
        print(f"[TCP]  SSL-сервер на {host}:{port}")
    else:
        srv = raw
        print(f"[TCP]  Сервер без SSL на {host}:{port}")

    print("[TCP]  Ожидание подключений...")
    while True:
        try:
            conn, addr = srv.accept()
            ClientHandler(conn, addr, password_hash).start()
        except KeyboardInterrupt:
            break
        except ssl.SSLError as e:
            if e.reason not in ("HTTP_REQUEST", "UNKNOWN_PROTOCOL"):
                print(f"[TCP]  SSL error: {e.reason}")
        except Exception as e:
            print(f"[TCP]  accept error: {e}")
    srv.close()


def main():
    p = argparse.ArgumentParser(description="Remote Access Server (Agent)")
    p.add_argument("--host",     default="0.0.0.0")
    p.add_argument("--port",     type=int, default=9999)
    p.add_argument("--password", required=True)

    # ── Render Relay ───────────────────────────────────────────────────
    p.add_argument("--relay", default=None, metavar="URL",
                   help="URL relay-сервера (https://your-relay.onrender.com).")
    p.add_argument("--agent-id", default=None, metavar="ID",
                   help="Уникальный ID агента на relay (по умолчанию — hostname).")
    p.add_argument("--agent-label", default=None, metavar="LABEL",
                   help="Человекочитаемое имя агента (по умолчанию = agent-id).")

    args = p.parse_args()

    if len(args.password) < 12:
        print("❌  ОШИБКА: пароль должен быть не менее 12 символов")
        sys.exit(1)

    if not args.relay:
        print("❌  Укажите --relay URL")
        sys.exit(1)

    import socket as _socket
    agent_id    = args.agent_id or _socket.gethostname()
    agent_label = args.agent_label or agent_id

    print(f"[relay] Режим: агент подключается к {args.relay}")
    print(f"[relay] ID: {agent_id}  Имя: {agent_label}")

    # TCP слушает только на localhost без SSL
    tcp_thread = threading.Thread(
        target=start_tcp,
        args=("127.0.0.1", args.port, hash_password(args.password), False),
        daemon=True,
    )
    tcp_thread.start()
    time.sleep(1)

    relay_url = args.relay.rstrip("/")
    relay_ws  = relay_url.replace("https://", "wss://").replace("http://", "ws://")

    try:
        from server.relay_agent import start_relay_client
        start_relay_client(
            relay_url   = relay_ws,
            agent_id    = agent_id,
            agent_label = agent_label,
            tcp_port    = args.port,
            password    = args.password,
            use_ssl     = False,
        )
    except ImportError:
        print("❌  websockets не установлен: pip install websockets")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[relay] Остановка.")


if __name__ == "__main__":
    main()
