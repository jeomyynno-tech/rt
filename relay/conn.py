"""
RelayAgentConn — замена AgentConn для relay-режима.
Вместо TCP-сокета использует AgentRegistry для маршрутизации команд.

Особенность: Flask session.get('agent_id') недоступен в фоновых потоках,
куда мы выносим upload/download (т.к. там нет request context). Поэтому
конструктор принимает agent_id явно. В обработчике вью читаем agent_id
из сессии и передаём его в RelayAgentConn(agent_id=…), который затем
живёт в потоке без зависимости от Flask context.
"""

from flask import session, has_request_context
from relay.registry import registry


class RelayAgentConn:
    def __init__(self, label: str = "conn", timeout: float = 120.0,
                 agent_id: str = None):
        self.label   = label
        self.timeout = timeout
        # Приоритет: явный agent_id → сессия (если есть контекст) → None.
        # None → call() вернёт ошибку "No agent selected".
        if agent_id:
            self._agent_id = agent_id
        elif has_request_context():
            self._agent_id = session.get("agent_id")
        else:
            self._agent_id = None

    def call(self, method: str, *args, **kwargs) -> dict:
        agent_id = self._agent_id
        if not agent_id:
            return {"type": "error", "payload": {"reason": "No agent selected"}}

        payload = _args_to_payload(method, args, kwargs)
        return registry.call(agent_id, method, payload, timeout=self.timeout)

    def invalidate(self):
        pass


def _args_to_payload(method: str, args: tuple, kwargs: dict) -> dict:
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
