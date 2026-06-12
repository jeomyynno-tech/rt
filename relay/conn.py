"""
RelayAgentConn — замена AgentConn для relay-режима.
Вместо TCP-сокета использует AgentRegistry для маршрутизации команд.

flask.session['agent_id'] определяет с каким агентом работает оператор.
"""

from flask import session
from relay.registry import registry


class RelayAgentConn:
    """
    Интерфейс совместим с AgentConn из server/web.py.
    Метод call(method, *args, **kwargs) — единственный публичный метод.
    """

    def __init__(self, label: str = "conn", timeout: float = 120.0):
        self.label   = label
        self.timeout = timeout

    def call(self, method: str, *args, **kwargs) -> dict:
        agent_id = session.get("agent_id")
        if not agent_id:
            return {"type": "error", "payload": {"reason": "No agent selected"}}

        # Конвертируем positional args в payload (зеркало AgentConn.call)
        payload = _args_to_payload(method, args, kwargs)
        resp    = registry.call(agent_id, method, payload, timeout=self.timeout)
        return resp

    def invalidate(self):
        """No-op в relay-режиме — соединение управляется агентом."""
        pass


def _args_to_payload(method: str, args: tuple, kwargs: dict) -> dict:
    """
    Преобразует positional-аргументы в payload-словарь.
    Зеркалит логику AgentConn из server/web.py.
    """
    import inspect
    from client.agent import RemoteAgent

    fn = getattr(RemoteAgent, method, None)
    if fn is None:
        return {"_args": list(args), **kwargs}

    try:
        sig    = inspect.signature(fn)
        params = [p for p in sig.parameters if p != "self"]
        payload = dict(zip(params, args))
        payload.update(kwargs)
        return payload
    except Exception:
        return {"_args": list(args), **kwargs}
