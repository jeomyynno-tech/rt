"""
AgentRegistry — потокобезопасный реестр подключённых агентов.

Каждый агент после подключения по WebSocket регистрируется здесь.
Flask-роуты используют registry.call(agent_id, ...) для отправки команд.
"""

import json
import threading
import uuid
from dataclasses import dataclass, field


@dataclass
class AgentEntry:
    agent_id:   str
    ws          = None          # flask_sock WS-объект
    lock:       threading.Lock  = field(default_factory=threading.Lock)
    pending:    dict            = field(default_factory=dict)  # req_id → {event, result}
    info:       dict            = field(default_factory=dict)  # произвольная мета


class AgentRegistry:
    def __init__(self):
        self._agents: dict[str, AgentEntry] = {}
        self._lock = threading.Lock()

    # ── Регистрация / разрегистрация ─────────────────────────────────── #
    def register(self, agent_id: str, ws) -> AgentEntry:
        entry = AgentEntry(agent_id=agent_id)
        entry.ws = ws
        with self._lock:
            self._agents[agent_id] = entry
        return entry

    def unregister(self, agent_id: str):
        with self._lock:
            self._agents.pop(agent_id, None)

    def get(self, agent_id: str) -> AgentEntry | None:
        with self._lock:
            return self._agents.get(agent_id)

    def list_agents(self) -> list[dict]:
        with self._lock:
            return [{"agent_id": e.agent_id, **e.info}
                    for e in self._agents.values()]

    # ── Отправка команды и ожидание ответа ───────────────────────────── #
    def call(self, agent_id: str, msg_type: str, payload: dict,
             timeout: float = 120.0) -> dict:
        """
        Отправляет команду агенту и блокирует поток до получения ответа.
        Возвращает {'type': ..., 'payload': ...} или {'type': 'error', ...}.
        """
        entry = self.get(agent_id)
        if entry is None:
            return {"type": "error", "payload": {"reason": f"Agent '{agent_id}' not connected"}}

        req_id = str(uuid.uuid4())
        event  = threading.Event()
        slot   = {"result": None}

        with entry.lock:
            entry.pending[req_id] = {"event": event, "slot": slot}

        try:
            msg = json.dumps({
                "req_id":  req_id,
                "type":    msg_type,
                "payload": payload,
            })
            # Отправляем в WS-поток агента
            # send() flask_sock вызывается из другого потока — нужна блокировка
            with entry.lock:
                try:
                    entry.ws.send(msg)
                except Exception as e:
                    entry.pending.pop(req_id, None)
                    return {"type": "error", "payload": {"reason": f"Send failed: {e}"}}

            # Ждём ответ
            if not event.wait(timeout=timeout):
                with entry.lock:
                    entry.pending.pop(req_id, None)
                return {"type": "error", "payload": {"reason": "Agent timeout"}}

            return slot["result"] or {"type": "error", "payload": {"reason": "No response"}}

        except Exception as e:
            with entry.lock:
                entry.pending.pop(req_id, None)
            return {"type": "error", "payload": {"reason": str(e)}}

    def deliver(self, agent_id: str, req_id: str, response: dict):
        """Вызывается WS-потоком агента когда пришёл ответ."""
        entry = self.get(agent_id)
        if not entry:
            return
        with entry.lock:
            pending = entry.pending.get(req_id)
        if pending:
            pending["slot"]["result"] = response
            pending["event"].set()


# Singleton
registry = AgentRegistry()
