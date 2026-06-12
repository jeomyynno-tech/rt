"""
WebSocket endpoint для агентов.
Агент подключается сюда, регистрируется, затем получает команды и отправляет ответы.
"""

import json
from relay.registry import registry


def handle_agent_ws(ws, password_hash: str):
    """
    Обрабатывает WebSocket-соединение одного агента.
    Вызывается flask_sock в отдельном потоке на каждое подключение.
    """
    from common.crypto import check_password

    # ── Аутентификация ────────────────────────────────────────────────── #
    try:
        raw = ws.receive(timeout=15)
        if raw is None:
            return
        msg = json.loads(raw)
    except Exception:
        ws.send(json.dumps({"type": "auth_fail", "reason": "invalid handshake"}))
        return

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

    # ── Регистрация ───────────────────────────────────────────────────── #
    entry = registry.register(agent_id, ws)
    entry.info = msg.get("info", {})   # hostname, OS и т.д.

    ws.send(json.dumps({"type": "registered", "agent_id": agent_id}))
    print(f"[relay] Agent connected: {agent_id}")

    # ── Цикл приёма ответов от агента ────────────────────────────────── #
    try:
        while True:
            raw = ws.receive(timeout=300)   # 5 минут тишины = отключение
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
                ws.send(json.dumps({"type": "pong"}))

    except Exception:
        pass
    finally:
        registry.unregister(agent_id)
        print(f"[relay] Agent disconnected: {agent_id}")
