"""
WebSocket endpoint для агентов.
Агент подключается сюда, регистрируется, затем получает команды и отправляет ответы.

Известное ограничение: flask_sock игнорирует timeout=N в ws.receive() — он
форсирует свой собственный (или ждёт навсегда). Поэтому handshake защищаем
отдельным потоком-сторожем, а основной recv-цикл оставляем без timeout
(агенты сами шлют ping каждые 30 секунд — мёртвое соединение распознаётся
обрывом TCP).
"""

import json
import threading
import time
from relay.registry import registry


def _watchdog(ws, deadline, fired):
    """Закрывает ws если handshake не пришёл за deadline секунд."""
    time.sleep(deadline)
    if not fired.is_set():
        try:
            ws.close()
        except Exception:
            pass


def handle_agent_ws(ws, password_hash: str):
    from common.crypto import check_password

    # ── Handshake с watchdog'ом (flask_sock игнорирует receive(timeout=…)) ── #
    handshake_done = threading.Event()
    threading.Thread(target=_watchdog, args=(ws, 15, handshake_done), daemon=True).start()

    try:
        raw = ws.receive()  # timeout-параметр здесь бесполезен, см. модульный docstring
        if raw is None:
            return
        msg = json.loads(raw)
    except Exception:
        try: ws.send(json.dumps({"type": "auth_fail", "reason": "invalid handshake"}))
        except Exception: pass
        return
    finally:
        handshake_done.set()

    if msg.get("type") != "register":
        ws.send(json.dumps({"type": "auth_fail", "reason": "expected register"}))
        return

    agent_id = msg.get("agent_id", "").strip()
    password  = msg.get("password", "")

    if not agent_id:
        ws.send(json.dumps({"type": "auth_fail", "reason": "empty agent_id"}))
        return

    if not check_password(password, password_hash):
        ws.send(json.dumps({"type": "auth_fail", "reason": "wrong password"}))
        return

    entry = registry.register(agent_id, ws)
    entry.info = msg.get("info", {})

    ws.send(json.dumps({"type": "registered", "agent_id": agent_id}))
    print(f"[relay] Agent connected: {agent_id}")

    try:
        while True:
            raw = ws.receive()
            if raw is None:
                break
            try:
                resp = json.loads(raw)
            except Exception:
                continue

            req_id = resp.get("req_id")
            if req_id:
                registry.deliver(agent_id, req_id, resp)
            elif resp.get("type") == "ping":
                try: ws.send(json.dumps({"type": "pong"}))
                except Exception: break

    except Exception:
        pass
    finally:
        registry.unregister(agent_id)
        print(f"[relay] Agent disconnected: {agent_id}")
