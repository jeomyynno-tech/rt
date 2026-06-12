"""
Relay-сервер. Деплоится на Render.com.

Архитектура:
  Агент → WebSocket /ws/agent/{id}/{type} → Relay
  Оператор → HTTPS (Flask веб-интерфейс) → Relay → Агент

Env-переменные (задать в Render Dashboard):
  OPERATOR_PASSWORD  — пароль входа в веб-интерфейс (обязательно)
  SECRET_KEY         — генерируется автоматически
"""

import os, sys, json, base64, io, asyncio, secrets, time, threading
from pathlib import Path
from functools import wraps
from typing import Dict, Optional

# Render запускает из корня репо — добавляем корень в path
sys.path.insert(0, str(Path(__file__).parent.parent))

# ── FastAPI (WebSocket + proxy) ───────────────────────────────────────
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import JSONResponse
from starlette.middleware.sessions import SessionMiddleware

OPERATOR_PASSWORD = os.environ.get("OPERATOR_PASSWORD", "")
RELAY_AGENT_TOKEN = os.environ.get("RELAY_AGENT_TOKEN") or OPERATOR_PASSWORD
SECRET_KEY        = os.environ.get("SECRET_KEY", secrets.token_hex(32))
PORT              = int(os.environ.get("PORT", 8000))

if not OPERATOR_PASSWORD:
    raise RuntimeError("OPERATOR_PASSWORD must be set")
if not RELAY_AGENT_TOKEN:
    raise RuntimeError("RELAY_AGENT_TOKEN or OPERATOR_PASSWORD must be set")

app = FastAPI(title="Remote Access Relay")
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY,
                   max_age=86400, https_only=True, same_site="lax")

# ── Agent registry ────────────────────────────────────────────────────
class AgentRegistry:
    def __init__(self):
        self._agents: Dict[str, dict] = {}
        self._lock = asyncio.Lock()

    async def register(self, agent_id: str, conn_type: str, ws: WebSocket, label: str = ""):
        old_ws = None
        async with self._lock:
            if agent_id not in self._agents:
                self._agents[agent_id] = {"cmd": None, "scr": None, "file": None,
                                           "connected_at": time.time(), "label": label or agent_id}
            old_ws = self._agents[agent_id].get(conn_type)
            self._agents[agent_id][conn_type] = ws
            self._agents[agent_id]["label"] = label or agent_id
        # Закрываем старое соединение ВНЕ лока — закрытие может занять время
        if old_ws is not None and old_ws is not ws:
            print(f"[relay] evicting stale {agent_id}/{conn_type} (reconnect)")
            try:
                await old_ws.close(code=4001)
            except Exception:
                pass

    async def unregister(self, agent_id: str, conn_type: str, ws: WebSocket = None):
        async with self._lock:
            if agent_id in self._agents:
                # Если передан ws — разрегистрируем только если это тот же объект.
                # Иначе новое соединение уже заняло слот и трогать его нельзя.
                current = self._agents[agent_id].get(conn_type)
                if ws is not None and current is not ws:
                    print(f"[relay] unregister skipped {agent_id}/{conn_type}: ws={id(ws)} replaced by ws={id(current)}")
                    return
                self._agents[agent_id][conn_type] = None
                if all(self._agents[agent_id].get(k) is None for k in ("cmd", "scr", "file")):
                    del self._agents[agent_id]

    def list_agents(self) -> list:
        return [{"id": aid, "label": info["label"],
                 "online_sec": int(time.time() - info["connected_at"]),
                 "connections": {k: info[k] is not None for k in ("cmd", "scr", "file")}}
                for aid, info in self._agents.items()]

    def get_ws(self, agent_id: str, conn_type: str) -> Optional[WebSocket]:
        info = self._agents.get(agent_id)
        return info.get(conn_type) if info else None


registry = AgentRegistry()

# _pending хранит Future по req_id.
# _pending_meta хранит (agent_id, conn_type) для каждого req_id —
# чтобы при дисконнекте агента отменить все его зависшие запросы.
_pending: Dict[str, asyncio.Future] = {}
_pending_meta: Dict[str, tuple] = {}   # req_id -> (agent_id, conn_type)


def _cancel_pending_for(agent_id: str, conn_type: str):
    """Отменить все зависшие Future для данного агента/типа соединения."""
    stale = [rid for rid, (aid, ct) in list(_pending_meta.items())
             if aid == agent_id and ct == conn_type]
    for rid in stale:
        fut = _pending.pop(rid, None)
        _pending_meta.pop(rid, None)
        if fut and not fut.done():
            fut.set_exception(ConnectionError(
                f"Agent '{agent_id}' disconnected ({conn_type})"
            ))


# ── Health ────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    agents = registry.list_agents()
    return {"status": "ok", "agents": len(agents), "agent_list": agents}


@app.get("/debug/agents")
async def debug_agents():
    """Показывает всех подключённых агентов. Убрать в production."""
    return {"agents": registry.list_agents(), "pending": len(_pending)}


# ── Agent WebSocket endpoint ──────────────────────────────────────────
@app.websocket("/ws/agent/{agent_id}/{conn_type}")
async def ws_agent(websocket: WebSocket, agent_id: str, conn_type: str):
    if conn_type not in ("cmd", "scr", "file"):
        await websocket.close(code=4000); return
    label = websocket.headers.get("X-Agent-Label", agent_id)
    await websocket.accept()
    ws_id = id(websocket)
    print(f"[relay] accepting: {agent_id}/{conn_type} ws={ws_id}")
    await registry.register(agent_id, conn_type, websocket, label)
    print(f"[relay] connected: {agent_id}/{conn_type} ws={ws_id}")
    try:
        while True:
            # Принимаем любой тип сообщения — текст или бинарный
            msg = await websocket.receive()
            if msg["type"] == "websocket.disconnect":
                print(f"[relay] got disconnect frame: {agent_id}/{conn_type} ws={ws_id}")
                break
            if "text" in msg:
                raw = msg["text"]
            elif "bytes" in msg:
                # Бинарный фрейм от агента: [req_id 16 байт][W:4][H:4][fmt:1][img]
                raw_bytes = msg["bytes"]
                if len(raw_bytes) > 16:
                    req_id_b = raw_bytes[:16].rstrip(b'\x00').decode('utf-8', errors='replace')
                    frame_data = raw_bytes[16:]   # [W:4][H:4][fmt:1][img]
                    if req_id_b in _pending:
                        fut = _pending.pop(req_id_b)
                        _pending_meta.pop(req_id_b, None)
                        if not fut.done():
                            fut.set_result(frame_data)
                continue
            else:
                continue

            try:
                parsed = json.loads(raw)
                req_id = parsed.get("req_id")
                if req_id and req_id in _pending:
                    fut = _pending.pop(req_id)
                    _pending_meta.pop(req_id, None)
                    if not fut.done():
                        fut.set_result(parsed.get("response", "{}"))
            except Exception as e:
                print(f"[relay] parse error {agent_id}: {e}")
    except Exception as ws_exc:
        print(f"[relay] ws error: {agent_id}/{conn_type} ws={ws_id}: {ws_exc}")
    finally:
        # Отменяем все зависшие запросы этого соединения,
        # чтобы при повторном подключении агента не было утечки Future-объектов.
        _cancel_pending_for(agent_id, conn_type)
        await registry.unregister(agent_id, conn_type, websocket)
        print(f"[relay] disconnected: {agent_id}/{conn_type} ws={ws_id}")


# ── Proxy: Flask → Agent ──────────────────────────────────────────────
@app.post("/api/relay/{agent_id}/{conn_type}")
async def api_relay(agent_id: str, conn_type: str, request: Request):
    ws = registry.get_ws(agent_id, conn_type)
    if ws is None:
        return JSONResponse({"error": f"Agent '{agent_id}' not connected ({conn_type})"}, status_code=503)
    body   = await request.body()
    req_id = secrets.token_hex(8)
    loop   = asyncio.get_event_loop()
    fut    = loop.create_future()
    _pending[req_id] = fut
    _pending_meta[req_id] = (agent_id, conn_type)
    envelope = json.dumps({"req_id": req_id, "payload": body.decode()})
    try:
        await ws.send_text(envelope)
        response = await asyncio.wait_for(fut, timeout=120)
        return JSONResponse(json.loads(response))
    except asyncio.TimeoutError:
        _pending.pop(req_id, None)
        _pending_meta.pop(req_id, None)
        return JSONResponse({"error": "Agent timeout"}, status_code=504)
    except Exception as e:
        _pending.pop(req_id, None)
        _pending_meta.pop(req_id, None)
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/api/agents-list")
async def api_agents_list():
    return JSONResponse({"agents": registry.list_agents()})


@app.websocket("/ws/stream/{agent_id}")
async def ws_stream(websocket: WebSocket, agent_id: str):
    await websocket.accept()
    print(f"[relay] stream WS: {agent_id}")
    quality  = 60
    capturer = "dxcam"
    fps      = 8
    closed   = False

    async def _recv_settings():
        nonlocal quality, capturer, fps, closed
        while not closed:
            try:
                msg = await asyncio.wait_for(websocket.receive_text(), timeout=0.1)
                data = json.loads(msg)
                quality  = max(1, min(100, int(data.get("quality", quality))))
                capturer = data.get("capturer", capturer)
                fps      = max(1, min(60, int(data.get("fps", fps))))
            except asyncio.TimeoutError:
                pass
            except Exception:
                break

    asyncio.create_task(_recv_settings())

    try:
        while not closed:
            frame_started = time.perf_counter()
            scr_ws = registry.get_ws(agent_id, "scr")
            if scr_ws is None:
                try: await websocket.send_text(json.dumps({"error": "agent not connected"}))
                except Exception: break
                await asyncio.sleep(1)
                continue

            req_id = secrets.token_hex(8)
            fut    = _main_loop.create_future()
            _pending[req_id] = fut
            _pending_meta[req_id] = (agent_id, "scr")

            payload = json.dumps({
                "type": "screenshot",
                "payload": {"quality": quality, "fmt": "webp", "capturer": capturer}
            })
            try:
                await scr_ws.send_text(json.dumps({"req_id": req_id, "payload": payload}))
                response = await asyncio.wait_for(fut, timeout=5)

                if closed: break

                if isinstance(response, (bytes, bytearray)):
                    # Бинарный фрейм от агента — пересылаем напрямую
                    await websocket.send_bytes(bytes(response))
                else:
                    # JSON fallback
                    resp_obj = json.loads(response)
                    p = resp_obj.get("payload", resp_obj)
                    if p.get("data"):
                        import base64 as _b64, struct as _st
                        img_bytes = _b64.b64decode(p["data"])
                        fmt_byte  = 1 if p.get("fmt") == "webp" else 0
                        w = int(p.get("width", 1920))
                        h = int(p.get("height", 1080))
                        binary = _st.pack(">IIB", w, h, fmt_byte) + img_bytes
                        await websocket.send_bytes(binary)

                elapsed = time.perf_counter() - frame_started
                await asyncio.sleep(max(0, (1 / fps) - elapsed))

            except asyncio.TimeoutError:
                _pending.pop(req_id, None)
            except Exception as e:
                _pending.pop(req_id, None)
                break

    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"[relay] stream WS error: {e}")
    finally:
        closed = True
        print(f"[relay] stream WS closed: {agent_id}")


# ── Flask (веб-интерфейс оператора) ──────────────────────────────────
from flask import (Flask, render_template, request as freq, jsonify as fjsonify,
                   session, redirect, url_for, send_file, abort)
from jinja2 import Environment, FileSystemLoader
from starlette.middleware.wsgi import WSGIMiddleware

TEMPLATES_DIR = Path(__file__).parent.parent / "templates"

flask_app = Flask(__name__, template_folder=str(TEMPLATES_DIR))

# Ключ сессии — тот же что у FastAPI
flask_app.secret_key = SECRET_KEY
flask_app.config.update({
    "MAX_CONTENT_LENGTH":         2 * 1024 * 1024 * 1024,
    "SESSION_COOKIE_HTTPONLY":    True,
    "SESSION_COOKIE_SAMESITE":    "Lax",
    "SESSION_COOKIE_SECURE":      True,
    "PERMANENT_SESSION_LIFETIME": 86400,
})

SESSION_VERSION = 1
_progress: dict = {}
import uuid as _uuid

# ── Rate limiter ──────────────────────────────────────────────────────
from collections import defaultdict

class _RL:
    def __init__(self, max_a=5, win=300):
        self.max_a = max_a; self.win = win
        self._a = defaultdict(list); self._lock = threading.Lock()
    def is_blocked(self, ip):
        with self._lock:
            now = time.time()
            self._a[ip] = [t for t in self._a[ip] if now-t < self.win]
            if len(self._a[ip]) >= self.max_a:
                return True, int(self.win-(now-self._a[ip][0]))+1
            return False, 0
    def record(self, ip):
        with self._lock: self._a[ip].append(time.time())
    def clear(self, ip):
        with self._lock: self._a.pop(ip, None)
    def remaining(self, ip):
        return max(0, self.max_a - len(self._a.get(ip, [])))

_rl = _RL()

# ── Relay conn: прямой вызов без HTTP ────────────────────────────────
# Flask запущен внутри uvicorn через WSGIMiddleware.
# HTTP-запрос из Flask к тому же uvicorn вызывает дедлок:
# uvicorn ждёт Flask → Flask ждёт uvicorn → никто не отвечает.
# Решение: Flask вызывает relay-логику напрямую через asyncio,
# минуя HTTP-стек.


# Глобальный event loop — устанавливается когда uvicorn стартует
_main_loop: asyncio.AbstractEventLoop = None

@app.on_event("startup")
async def _capture_loop():
    global _main_loop
    _main_loop = asyncio.get_event_loop()


def _relay_call_sync(agent_id: str, conn_type: str, body: str, timeout: int = 120) -> dict:
    import concurrent.futures

    if _main_loop is None:
        print(f"[relay] ERROR: _main_loop is None! startup event не сработал?")
        return {"error": "Relay not ready - loop not initialized"}

    print(f"[relay] call: agent={agent_id} conn={conn_type} body={body[:80]}")

    async def _send():
        ws = registry.get_ws(agent_id, conn_type)
        if ws is None:
            print(f"[relay] ERROR: no WS for {agent_id}/{conn_type}, registry={registry.list_agents()}")
            return {"error": f"Agent '{agent_id}' not connected ({conn_type})"}
        req_id   = secrets.token_hex(8)
        fut      = _main_loop.create_future()
        _pending[req_id] = fut
        _pending_meta[req_id] = (agent_id, conn_type)
        envelope = json.dumps({"req_id": req_id, "payload": body})
        try:
            await ws.send_text(envelope)
            response = await asyncio.wait_for(fut, timeout=timeout)
            # Бинарный ответ (скриншот WebP/JPEG) — возвращаем как есть
            if isinstance(response, (bytes, bytearray)):
                return response
            print(f"[relay] response: {str(response)[:80]}")
            return json.loads(response)
        except asyncio.TimeoutError:
            _pending.pop(req_id, None)
            _pending_meta.pop(req_id, None)
            return {"error": "Agent timeout"}
        except Exception as e:
            _pending.pop(req_id, None)
            _pending_meta.pop(req_id, None)
            return {"error": str(e)}

    fut = asyncio.run_coroutine_threadsafe(_send(), _main_loop)
    try:
        return fut.result(timeout=timeout + 5)
    except concurrent.futures.TimeoutError:
        return {"error": "Relay call timeout"}
    except Exception as e:
        return {"error": str(e)}


class _Conn:
    def __init__(self, aid, ctype, timeout=120):
        self.aid = aid; self.ctype = ctype; self.timeout = timeout

    def _call_type(self, msg_type: str, payload: dict):
        body = json.dumps({"type": msg_type, "payload": payload})
        return _relay_call_sync(self.aid, self.ctype, body, self.timeout)

    def _download_file_via_chunks(self, path: str, progress_cb=None, cancelled_fn=None) -> bytes:
        """
        Поддерживает оба варианта ответа:
        - file_data (малые файлы)
        - dchunk_* (большие файлы)
        cancelled_fn() — функция без аргументов, возвращает True если передача отменена.
        """
        first = self._call_type("file_download", {"path": path})
        if isinstance(first, dict) and first.get("type") == "error":
            raise RuntimeError(first.get("payload", {}).get("reason", "download failed"))

        if isinstance(first, dict) and first.get("type") == "file_data":
            data_b64 = first.get("payload", {}).get("data", "")
            data = base64.b64decode(data_b64) if data_b64 else b""
            if progress_cb:
                try: progress_cb(len(data), len(data))
                except Exception: pass
            return data

        if not (isinstance(first, dict) and first.get("type") == "dchunk_begin"):
            raise RuntimeError(f"unexpected response: {first}")

        total = int(first.get("payload", {}).get("total_size", 0) or 0)
        n     = int(first.get("payload", {}).get("total_chunks", 0) or 0)
        print(f"[relay] dchunk begin: path={path} total={total} chunks={n}")

        # Проверяем отмену сразу после начала — до отправки первого ACK
        if cancelled_fn and cancelled_fn():
            print(f"[relay] dchunk cancelled before start, sending dchunk_cancel to agent path={path}")
            self._call_type("dchunk_cancel", {"reason": "cancelled_by_operator"})
            raise InterruptedError("download cancelled by operator")

        resp = self._call_type("dchunk_ack", {"index": -1})  # ACK begin -> ждём chunk #0
        buf  = bytearray()
        for i in range(n):
            # Проверяем отмену ПЕРЕД обработкой чанка — отправляем cancel агенту
            if cancelled_fn and cancelled_fn():
                print(f"[relay] dchunk cancelled at chunk={i+1}/{n}, sending dchunk_cancel to agent path={path}")
                self._call_type("dchunk_cancel", {"reason": "cancelled_by_operator"})
                raise InterruptedError("download cancelled by operator")

            if not (isinstance(resp, dict) and resp.get("type") == "dchunk_data"):
                raise RuntimeError(f"unexpected chunk response #{i}: {resp}")
            chunk_b64 = resp.get("payload", {}).get("data", "")
            chunk     = base64.b64decode(chunk_b64) if chunk_b64 else b""
            buf += chunk
            if progress_cb:
                try: progress_cb(len(buf), total)
                except Exception: pass
            if i == 0 or i == n - 1 or i % 20 == 0:
                print(f"[relay] dchunk data: path={path} chunk={i+1}/{n} size={len(chunk)}")
            resp = self._call_type("dchunk_ack", {"index": i})

        if not (isinstance(resp, dict) and resp.get("type") == "dchunk_end"):
            raise RuntimeError(f"expected dchunk_end, got: {resp}")
        print(f"[relay] dchunk end: path={path} received={len(buf)}")
        return bytes(buf)

    def _download_zip_via_chunks(self, paths: list, progress_cb=None, cancelled_fn=None) -> bytes:
        """
        FILE_ZIP_STREAM на агенте использует следующий протокол:
          агент → FILE_DATA {total_size, total_chunks}   (мета, без поля data)
          агент → CHUNK_DATA {index, data} × N            (чанки, ждут CHUNK_ACK)
          агент → OK {total_size}                         (финал)

        При отмене (cancelled_fn() == True) шлём агенту DCHUNK_CANCEL вместо
        очередного CHUNK_ACK — агент выходит из цикла по этому типу сообщения.
        """
        print(f"[relay] zip stream start: paths={paths}")
        meta = self._call_type("file_zip_stream", {"paths": paths})
        print(f"[relay] zip stream meta response: type={meta.get('type') if isinstance(meta, dict) else type(meta)}")

        if isinstance(meta, dict) and meta.get("type") == "error":
            reason = meta.get("payload", {}).get("reason", "zip stream failed")
            print(f"[relay] zip stream error from agent: {reason}")
            raise RuntimeError(reason)

        if not (isinstance(meta, dict) and meta.get("type") == "file_data"):
            print(f"[relay] zip stream unexpected first message: {meta}")
            raise RuntimeError(f"expected file_data meta, got: {meta}")

        total = int(meta.get("payload", {}).get("total_size", 0) or 0)
        n     = int(meta.get("payload", {}).get("total_chunks", 0) or 0)
        print(f"[relay] zip stream begin: total={total} bytes, chunks={n}")

        # Проверяем отмену до первого ACK
        if cancelled_fn and cancelled_fn():
            print(f"[relay] zip stream cancelled before start, sending dchunk_cancel")
            self._call_type("dchunk_cancel", {"reason": "cancelled_by_operator"})
            raise InterruptedError("zip download cancelled by operator")

        buf = bytearray()
        for i in range(n):
            # Проверяем отмену ПЕРЕД отправкой ACK.
            # Если отменено — шлём DCHUNK_CANCEL вместо CHUNK_ACK, агент выходит из цикла.
            if cancelled_fn and cancelled_fn():
                print(f"[relay] zip stream cancelled at chunk={i+1}/{n}, sending dchunk_cancel instead of chunk_ack")
                self._call_type("dchunk_cancel", {"reason": "cancelled_by_operator"})
                raise InterruptedError("zip download cancelled by operator")

            # ACK предыдущего чанка (для i=0: index=-1 — сигнал "готов к первому").
            # Этот вызов блокирующий — пока агент не пришлёт chunk_data, поток висит.
            resp = self._call_type("chunk_ack", {"index": i - 1})
            resp_type = resp.get("type") if isinstance(resp, dict) else type(resp)
            if i == 0 or i == n - 1 or i % 20 == 0:
                print(f"[relay] zip stream chunk response #{i}: type={resp_type}")

            if not (isinstance(resp, dict) and resp.get("type") == "chunk_data"):
                print(f"[relay] zip stream unexpected chunk response #{i}: {resp}")
                raise RuntimeError(f"unexpected zip chunk response #{i}: {resp}")

            chunk_b64 = resp.get("payload", {}).get("data", "")
            chunk     = base64.b64decode(chunk_b64) if chunk_b64 else b""
            buf += chunk

            # Проверяем отмену СРАЗУ ПОСЛЕ получения чанка, до progress_cb.
            # Это позволяет отреагировать как только блокирующий _call_type вернулся.
            if cancelled_fn and cancelled_fn():
                print(f"[relay] zip stream cancelled after chunk={i+1}/{n}, sending dchunk_cancel")
                self._call_type("dchunk_cancel", {"reason": "cancelled_by_operator"})
                raise InterruptedError("zip download cancelled by operator")

            if progress_cb:
                try: progress_cb(len(buf), total)
                except InterruptedError: raise
                except Exception: pass
            if i == 0 or i == n - 1 or i % 20 == 0:
                print(f"[relay] zip stream chunk={i+1}/{n} size={len(chunk)} total_so_far={len(buf)}")

        # Финальный ACK последнего чанка — агент отвечает OK
        final = self._call_type("chunk_ack", {"index": n - 1})
        print(f"[relay] zip stream final response: type={final.get('type') if isinstance(final, dict) else type(final)}")
        if not (isinstance(final, dict) and final.get("type") == "ok"):
            print(f"[relay] zip stream unexpected final: {final}")
            raise RuntimeError(f"expected ok, got: {final}")

        print(f"[relay] zip stream done: received={len(buf)} bytes")
        return bytes(buf)

    def _upload_file_via_chunks(self, remote_path: str, data: bytes, progress_cb=None, cancelled_fn=None):
        """
        Чанковая загрузка файла на агента через relay.
        Протокол агента (handler._chunk_begin / _chunk_data / _chunk_end):
          relay → CHUNK_BEGIN {path, total_chunks, total_size}
          агент → CHUNK_ACK  {index: -1}           (ready)
          loop:
            relay → CHUNK_DATA {index, data}
            агент → CHUNK_ACK  {index}
          relay → CHUNK_END {}
          агент → CHUNK_OK  {path, size}

        При отмене (cancelled_fn() == True) шлём CHUNK_CANCEL — агент закрывает
        и удаляет частичный файл, освобождая блокировку (WinError 32).
        """
        from common.protocol import CHUNK_SIZE
        total  = len(data)
        chunks = [data[i:i+CHUNK_SIZE] for i in range(0, max(total, 1), CHUNK_SIZE)]
        n      = len(chunks)
        print(f"[relay] upload chunks start: path={remote_path} total={total} chunks={n}")

        # Проверяем отмену до chunk_begin — файл ещё не открыт на агенте
        if cancelled_fn and cancelled_fn():
            print(f"[relay] upload cancelled before chunk_begin, skipping")
            raise InterruptedError("upload cancelled before start")

        # CHUNK_BEGIN → ждём CHUNK_ACK {index:-1}
        resp = self._call_type("chunk_begin", {"path": remote_path, "total_chunks": n, "total_size": total})
        print(f"[relay] upload chunk_begin response: type={resp.get('type') if isinstance(resp, dict) else type(resp)}")
        if isinstance(resp, dict) and resp.get("type") == "error":
            raise RuntimeError(resp.get("payload", {}).get("reason", "chunk_begin failed"))
        if not (isinstance(resp, dict) and resp.get("type") == "chunk_ack"):
            raise RuntimeError(f"expected chunk_ack after chunk_begin, got: {resp}")

        sent = 0
        for i, chunk in enumerate(chunks):
            # Проверяем отмену ПЕРЕД отправкой чанка
            if cancelled_fn and cancelled_fn():
                print(f"[relay] upload cancelled at chunk={i+1}/{n}, sending chunk_cancel")
                self._call_type("chunk_cancel", {})
                raise InterruptedError("upload cancelled by operator")

            chunk_b64 = base64.b64encode(chunk).decode()
            resp = self._call_type("chunk_data", {"index": i, "data": chunk_b64})
            if isinstance(resp, dict) and resp.get("type") == "error":
                raise RuntimeError(resp.get("payload", {}).get("reason", f"chunk_data #{i} failed"))
            if not (isinstance(resp, dict) and resp.get("type") == "chunk_ack"):
                raise RuntimeError(f"expected chunk_ack for chunk #{i}, got: {resp}")

            sent += len(chunk)

            # Проверяем отмену ПОСЛЕ получения ACK — как только блокировка снята
            if cancelled_fn and cancelled_fn():
                print(f"[relay] upload cancelled after chunk={i+1}/{n}, sending chunk_cancel")
                self._call_type("chunk_cancel", {})
                raise InterruptedError("upload cancelled by operator")

            if progress_cb:
                try: progress_cb(sent, total)
                except InterruptedError: raise
                except Exception: pass
            if i == 0 or i == n - 1 or i % 20 == 0:
                print(f"[relay] upload chunk={i+1}/{n} size={len(chunk)} sent={sent}")

        # CHUNK_END → ждём CHUNK_OK
        final = self._call_type("chunk_end", {})
        print(f"[relay] upload chunk_end response: type={final.get('type') if isinstance(final, dict) else type(final)}")
        if isinstance(final, dict) and final.get("type") == "error":
            raise RuntimeError(final.get("payload", {}).get("reason", "chunk_end failed"))
        print(f"[relay] upload done: path={remote_path} sent={sent} bytes")
        return final

    def call(self, method, *args, **kwargs):
        if method == "download_bytes_with_progress":
            return self._download_file_via_chunks(
                args[0] if args else "",
                kwargs.get("progress_cb") or (args[1] if len(args) > 1 else None),
                kwargs.get("cancelled_fn") or (args[2] if len(args) > 2 else None),
            )
        if method == "download_zip":
            return self._download_zip_via_chunks(
                args[0] if args else [],
                kwargs.get("progress_cb") or (args[1] if len(args) > 1 else None),
                kwargs.get("cancelled_fn") or (args[2] if len(args) > 2 else None),
            )
        if method == "upload_bytes_chunked":
            return self._upload_file_via_chunks(
                args[0] if args else "",
                args[1] if len(args) > 1 else b"",
                kwargs.get("progress_cb") or (args[2] if len(args) > 2 else None),
                kwargs.get("cancelled_fn") or (args[3] if len(args) > 3 else None),
            )
        payload = _build_payload(method, args, kwargs)
        body    = json.dumps({"type": payload[0], "payload": payload[1]})
        return _relay_call_sync(self.aid, self.ctype, body, self.timeout)

    def invalidate(self): pass


def _build_payload(method, args, kwargs):
    from common.protocol import MsgType
    # Используем lambda чтобы вычислять payload только для нужного метода.
    # Иначе base64.b64encode(args[1]) вычисляется для ВСЕХ записей сразу.
    m = {
        "ping":         lambda: (MsgType.PING, {}),
        "sys_info":     lambda: (MsgType.SYS_INFO, {}),
        "execute":      lambda: (MsgType.CMD, {"command": args[0] if args else "", "cwd": args[1] if len(args)>1 else ""}),
        "file_list":    lambda: (MsgType.FILE_LIST, {"path": args[0] if args else ""}),
        "upload_bytes": lambda: (MsgType.FILE_UPLOAD, {"path": args[0], "data": base64.b64encode(args[1]).decode()} if len(args)>=2 else {}),
        "download_bytes_with_progress": lambda: (MsgType.FILE_DOWNLOAD, {"path": args[0] if args else ""}),
        "download_zip": lambda: (MsgType.FILE_ZIP_STREAM, {"paths": args[0] if args else []}),
        "file_delete":  lambda: (MsgType.FILE_DELETE, {"path": args[0] if args else ""}),
        "file_mkdir":   lambda: (MsgType.FILE_MKDIR, {"path": args[0] if args else ""}),
        "file_rename":  lambda: (MsgType.FILE_RENAME, {"src": args[0], "dst": args[1]} if len(args)>=2 else {}),
        "file_zip":     lambda: (MsgType.FILE_ZIP, {"paths": args[0], "dest": args[1]} if len(args)>=2 else {}),
        "screenshot":   lambda: (MsgType.SCREENSHOT, {"quality": kwargs.get("quality", args[0] if args else 70), "fmt": kwargs.get("fmt", "webp"), "capturer": kwargs.get("capturer", "dxcam")}),
        "proc_list":    lambda: (MsgType.PROC_LIST, {}),
        "proc_kill":    lambda: (MsgType.PROC_KILL, {"pid": args[0] if args else 0}),
        "mouse_move":   lambda: (MsgType.MOUSE_MOVE, {"x": args[0], "y": args[1], "duration": 0} if len(args)>=2 else {}),
        "mouse_click":  lambda: (MsgType.MOUSE_CLICK, {"x": args[0], "y": args[1], "button": args[2] if len(args)>2 else "left", "clicks": args[3] if len(args)>3 else 1} if len(args)>=2 else {}),
        "mouse_scroll": lambda: (MsgType.MOUSE_SCROLL, {"amount": args[0] if args else 3}),
        "mouse_drag":   lambda: (MsgType.MOUSE_DRAG, {"x2": args[0], "y2": args[1]} if len(args)>=2 else {}),
        "key_press":    lambda: (MsgType.KEY_PRESS, {"key": args[0] if args else ""}),
        "key_hotkey":   lambda: (MsgType.KEY_HOTKEY, {"keys": args[0] if args else []}),
        "key_type":     lambda: (MsgType.KEY_TYPE, {"text": args[0] if args else ""}),
        "clipboard_get":lambda: (MsgType.CLIPBOARD_GET, {}),
        "clipboard_set":lambda: (MsgType.CLIPBOARD_SET, {"text": args[0] if args else ""}),
    }
    fn = m.get(method)
    if fn:
        t, p = fn()
    else:
        t, p = method, {}
    val = t.value if hasattr(t, 'value') else str(t)
    return val, p


def _conns(aid):
    return (_Conn(aid,"cmd"), _Conn(aid,"scr"), _Conn(aid,"file",timeout=600))


# ── Flask auth ────────────────────────────────────────────────────────
def _require(fn):
    @wraps(fn)
    def w(*a, **kw):
        if not session.get("auth") or session.get("v") != SESSION_VERSION:
            return fjsonify({"error": "unauthorized"}), 401
        if time.time() - session.get("created", 0) > 86400:
            session.clear()
            return fjsonify({"error": "session expired"}), 401
        return fn(*a, **kw)
    return w

def _aid():
    """agent_id из заголовка X-Agent-Id или query-param."""
    aid = freq.headers.get("X-Agent-Id", "").strip()
    if not aid:
        aid = freq.args.get("agent_id", "").strip()
    if not aid and freq.is_json:
        try: aid = (freq.get_json(silent=True) or {}).get("agent_id", "")
        except Exception: pass
    if not aid:
        print(f"[relay] WARNING: X-Agent-Id missing. URL={freq.path} method={freq.method}")
    return aid or ""

@flask_app.route("/")
def index():
    if not session.get("auth"): return redirect(url_for("login"))
    return render_template("index.html")

@flask_app.route("/login", methods=["GET","POST"])
def login():
    ip = freq.remote_addr or "unknown"
    if freq.method == "POST":
        blocked, wait = _rl.is_blocked(ip)
        if blocked:
            return render_template("login.html", error=f"Слишком много попыток. Подождите {(wait+59)//60} мин.")
        if freq.form.get("password","") == OPERATOR_PASSWORD:
            session.clear()
            session.update({"auth":True,"v":SESSION_VERSION,"created":int(time.time())})
            session.permanent = True
            _rl.clear(ip)
            return redirect(url_for("index"))
        _rl.record(ip)
        return render_template("login.html", error=f"Неверный пароль. Осталось попыток: {_rl.remaining(ip)}")
    return render_template("login.html", error=None)

@flask_app.route("/logout")
def logout():
    session.clear(); return redirect(url_for("login"))

@flask_app.route("/api/agents")
@_require
def api_agents():
    # Читаем registry напрямую — без HTTP запроса к FastAPI
    # (HTTP через WSGIMiddleware → Flask не знает /api/agents-list → пустой ответ)
    return fjsonify({"agents": registry.list_agents()})

@flask_app.route("/api/ping")
@_require
def api_ping():
    aid = _aid()
    if not aid: return fjsonify({"error":"no agent_id"}), 400
    try: cmd,_,_ = _conns(aid); cmd.call("ping"); return fjsonify({"ok":True})
    except Exception as e: return fjsonify({"ok":False,"error":str(e)}), 500

@flask_app.route("/api/sysinfo")
@_require
def api_sysinfo():
    aid = _aid()
    if not aid: return fjsonify({"error":"no agent_id"}), 400
    try: cmd,_,_ = _conns(aid); return fjsonify(cmd.call("sys_info").get("payload",{}))
    except Exception as e: return fjsonify({"error":str(e)}), 500

@flask_app.route("/api/cmd", methods=["POST"])
@_require
def api_cmd():
    aid = _aid()
    if not aid: return fjsonify({"error":"no agent_id"}), 400
    try:
        d = freq.json or {}; cmd,_,_ = _conns(aid)
        return fjsonify(cmd.call("execute", d.get("command",""), d.get("cwd","")).get("payload",{}))
    except Exception as e: return fjsonify({"error":str(e)}), 500

@flask_app.route("/api/path/parent")
@_require
def api_path_parent():
    from common.protocol import MsgType
    path = freq.args.get("path","")
    # простой path_parent без импорта server.web
    path = path.rstrip("/\\")
    if not path: return fjsonify({"parent": None})
    if "\\" in path or (len(path)>=2 and path[1]==":"):
        parts = [p for p in path.replace("/","\\").split("\\") if p]
        if len(parts)<=1: return fjsonify({"parent": (parts[0]+"\\") if parts else None})
        result = "\\".join(parts[:-1])
        if len(result)==2 and result[1]==":": result += "\\"
        return fjsonify({"parent": result})
    parts = [p for p in path.split("/") if p]
    return fjsonify({"parent": ("/"+"/".join(parts[:-1])) if len(parts)>1 else "/"})

@flask_app.route("/api/files")
@_require
def api_files():
    aid = _aid()
    if not aid: return fjsonify({"error":"no agent_id"}), 400
    try: cmd,_,_ = _conns(aid); return fjsonify(cmd.call("file_list", freq.args.get("path","")).get("payload",{}))
    except Exception as e: return fjsonify({"error":str(e)}), 500

@flask_app.route("/api/screenshot")
@_require
def api_screenshot():
    aid = _aid()
    if not aid: return fjsonify({"error":"no agent_id"}), 400
    try:
        import struct as _st, base64 as _b64
        _,scr,_ = _conns(aid)
        resp = scr.call("screenshot", quality=int(freq.args.get("quality",60)),
                        capturer=freq.args.get("capturer","dxcam"))
        # Бинарный ответ: [W:4][H:4][fmt:1][img bytes]
        if isinstance(resp, (bytes, bytearray)):
            if len(resp) >= 9:
                w   = _st.unpack_from(">I", resp, 0)[0]
                h   = _st.unpack_from(">I", resp, 4)[0]
                fmt = resp[8]
                img = resp[9:]
                return fjsonify({
                    "data":  _b64.b64encode(img).decode(),
                    "width": w, "height": h,
                    "fmt":   "webp" if fmt == 1 else "jpeg",
                })
            return fjsonify({"error": "bad binary frame"}), 500
        # JSON-ответ (старый агент)
        p = resp.get("payload", {}) if isinstance(resp, dict) else {}
        if "data" in p:
            return fjsonify({"data": p["data"], "width": p["width"], "height": p["height"]})
        return fjsonify({"error": p.get("reason", "failed")}), 500
    except Exception as e: return fjsonify({"error": str(e)}), 500

@flask_app.route("/api/processes")
@_require
def api_processes():
    aid = _aid()
    if not aid: return fjsonify({"error":"no agent_id"}), 400
    try: cmd,_,_ = _conns(aid); return fjsonify(cmd.call("proc_list").get("payload",{}))
    except Exception as e: return fjsonify({"error":str(e)}), 500

@flask_app.route("/api/processes/kill", methods=["POST"])
@_require
def api_proc_kill():
    aid = _aid()
    if not aid: return fjsonify({"error":"no agent_id"}), 400
    try: cmd,_,_ = _conns(aid); cmd.call("proc_kill", int((freq.json or {}).get("pid",0))); return fjsonify({"ok":True})
    except Exception as e: return fjsonify({"error":str(e)}), 500

@flask_app.route("/api/mouse/move", methods=["POST"])
@_require
def api_mouse_move():
    aid = _aid()
    if not aid: return fjsonify({"error":"no agent_id"}), 400
    try: d=freq.json or {}; cmd,_,_=_conns(aid); cmd.call("mouse_move",int(d["x"]),int(d["y"])); return fjsonify({"ok":True})
    except Exception as e: return fjsonify({"error":str(e)}), 500

@flask_app.route("/api/mouse/click", methods=["POST"])
@_require
def api_mouse_click():
    aid = _aid()
    if not aid: return fjsonify({"error":"no agent_id"}), 400
    try:
        d = freq.json or {}
        x = int(d["x"]) if d.get("x") is not None else None
        y = int(d["y"]) if d.get("y") is not None else None
        cmd,_,_ = _conns(aid)
        resp = cmd.call("mouse_click", x, y, d.get("button","left"), int(d.get("clicks",1)))
        if isinstance(resp, dict) and resp.get("type") == "error":
            return fjsonify({"error": resp.get("payload",{}).get("reason","click failed")}), 500
        return fjsonify({"ok": True})
    except Exception as e:
        import traceback
        print(f"[relay] mouse_click ERROR: {e}\n{traceback.format_exc()}\nbody={freq.data}")
        return fjsonify({"error": str(e)}), 500

@flask_app.route("/api/mouse/scroll", methods=["POST"])
@_require
def api_mouse_scroll():
    aid = _aid()
    if not aid: return fjsonify({"error":"no agent_id"}), 400
    try: cmd,_,_=_conns(aid); cmd.call("mouse_scroll",int((freq.json or {}).get("amount",3))); return fjsonify({"ok":True})
    except Exception as e: return fjsonify({"error":str(e)}), 500

@flask_app.route("/api/mouse/drag", methods=["POST"])
@_require
def api_mouse_drag():
    aid = _aid()
    if not aid: return fjsonify({"error":"no agent_id"}), 400
    try: d=freq.json or {}; cmd,_,_=_conns(aid); cmd.call("mouse_drag",int(d["x2"]),int(d["y2"])); return fjsonify({"ok":True})
    except Exception as e: return fjsonify({"error":str(e)}), 500

@flask_app.route("/api/keyboard/press", methods=["POST"])
@_require
def api_key_press():
    aid = _aid()
    if not aid: return fjsonify({"error":"no agent_id"}), 400
    try: cmd,_,_=_conns(aid); cmd.call("key_press",(freq.json or {}).get("key","")); return fjsonify({"ok":True})
    except Exception as e: return fjsonify({"error":str(e)}), 500

@flask_app.route("/api/keyboard/hotkey", methods=["POST"])
@_require
def api_key_hotkey():
    aid = _aid()
    if not aid: return fjsonify({"error":"no agent_id"}), 400
    try: cmd,_,_=_conns(aid); cmd.call("key_hotkey",(freq.json or {}).get("keys",[])); return fjsonify({"ok":True})
    except Exception as e: return fjsonify({"error":str(e)}), 500

@flask_app.route("/api/keyboard/type", methods=["POST"])
@_require
def api_key_type():
    aid = _aid()
    if not aid: return fjsonify({"error":"no agent_id"}), 400
    try: cmd,_,_=_conns(aid); cmd.call("key_type",(freq.json or {}).get("text","")); return fjsonify({"ok":True})
    except Exception as e: return fjsonify({"error":str(e)}), 500

@flask_app.route("/api/clipboard", methods=["GET"])
@_require
def api_clipboard_get():
    aid = _aid()
    if not aid: return fjsonify({"error":"no agent_id"}), 400
    try: cmd,_,_=_conns(aid); return fjsonify(cmd.call("clipboard_get").get("payload",{}))
    except Exception as e: return fjsonify({"error":str(e)}), 500

@flask_app.route("/api/clipboard", methods=["POST"])
@_require
def api_clipboard_set():
    aid = _aid()
    if not aid: return fjsonify({"error":"no agent_id"}), 400
    try: cmd,_,_=_conns(aid); cmd.call("clipboard_set",(freq.json or {}).get("text","")); return fjsonify({"ok":True})
    except Exception as e: return fjsonify({"error":str(e)}), 500

@flask_app.route("/api/files/delete", methods=["POST"])
@_require
def api_files_delete():
    aid = _aid()
    if not aid: return fjsonify({"error":"no agent_id"}), 400
    try:
        cmd,_,_=_conns(aid); resp=cmd.call("file_delete",(freq.json or {}).get("path",""))
        if resp.get("type")=="error": return fjsonify({"error":resp.get("payload",{}).get("reason","error")}), 500
        return fjsonify({"ok":True})
    except Exception as e: return fjsonify({"error":str(e)}), 500

@flask_app.route("/api/files/mkdir", methods=["POST"])
@_require
def api_files_mkdir():
    aid = _aid()
    if not aid: return fjsonify({"error":"no agent_id"}), 400
    try: cmd,_,_=_conns(aid); cmd.call("file_mkdir",(freq.json or {}).get("path","")); return fjsonify({"ok":True})
    except Exception as e: return fjsonify({"error":str(e)}), 500

@flask_app.route("/api/files/rename", methods=["POST"])
@_require
def api_files_rename():
    aid = _aid()
    if not aid: return fjsonify({"error":"no agent_id"}), 400
    try:
        d=freq.json or {}; cmd,_,_=_conns(aid)
        cmd.call("file_rename",d.get("src",""),d.get("dst",""))
        return fjsonify({"ok":True})
    except Exception as e: return fjsonify({"error":str(e)}), 500

@flask_app.route("/api/files/zip", methods=["POST"])
@_require
def api_files_zip():
    aid = _aid()
    if not aid: return fjsonify({"error":"no agent_id"}), 400
    try:
        d=freq.json or {}; cmd,_,_=_conns(aid)
        resp=cmd.call("file_zip",d.get("paths",[]),d.get("dest",""))
        if resp.get("type")=="error": return fjsonify({"error":resp.get("payload",{}).get("reason")}), 500
        return fjsonify({"ok":True})
    except Exception as e: return fjsonify({"error":str(e)}), 500

@flask_app.route("/api/files/upload", methods=["POST"])
@_require
def api_files_upload():
    """
    Возвращает {upload_id} НЕМЕДЛЕННО — до чтения файла.
    Это позволяет клиенту зарегистрировать uid для отмены ещё до того,
    как f.read() заблокирует поток (для больших файлов это секунды).
    Чтение файла и передача агенту происходят внутри фонового потока.
    """
    aid = _aid()
    if not aid: return fjsonify({"error":"no agent_id"}), 400
    try:
        f = freq.files.get("file")
        if not f: return fjsonify({"error":"no file"}), 400
        remote_path = freq.form.get("path","")
        if not remote_path: return fjsonify({"error":"no path"}), 400

        uid = str(_uuid.uuid4())
        # Регистрируем uid немедленно — клиент может отменить ещё до f.read()
        _progress[uid] = {"sent":0,"total":0,"done":False,"error":None,"cancelled":False,
                           "reading":True}
        print(f"[relay/upload] registered uid={uid} path={remote_path}")

        # Читаем файл в памяти внутри фонового потока — не блокируем ответ
        file_storage = f  # werkzeug FileStorage, читается один раз

        def _run():
            SMALL = 2 * 1024 * 1024  # base64-overhead ×4/3 → макс ~2.7 МБ в WS-фрейме
            try:
                # Отмена до чтения файла — выходим сразу
                if _progress.get(uid, {}).get("cancelled"):
                    print(f"[relay/upload] cancelled before read uid={uid}")
                    _progress[uid]["done"] = True
                    return

                print(f"[relay/upload] reading file uid={uid}")
                data = file_storage.read()
                _progress[uid]["total"] = len(data)
                _progress[uid]["reading"] = False
                print(f"[relay/upload] read done uid={uid} size={len(data)}")

                # Повторная проверка отмены после чтения
                if _progress.get(uid, {}).get("cancelled"):
                    print(f"[relay/upload] cancelled after read uid={uid}")
                    return

                _,_,file_c = _conns(aid)

                if len(data) <= SMALL:
                    print(f"[relay/upload] small file, single call uid={uid}")
                    resp = file_c.call("upload_bytes", remote_path, data)
                    print(f"[relay/upload] small call resp: {str(resp)[:120]}")
                    if not isinstance(resp, dict):
                        _progress[uid]["error"] = f"unexpected response: {type(resp).__name__}"
                    elif resp.get("type") == "error":
                        # Ошибка от агента: {type:error, payload:{reason:...}}
                        _progress[uid]["error"] = resp.get("payload", {}).get("reason", "agent error")
                    elif "error" in resp:
                        # Ошибка relay (таймаут, обрыв WS): {error:"..."}
                        err = resp["error"]
                        print(f"[relay/upload] small relay error uid={uid}: {err}")
                        _progress[uid]["error"] = err
                    else:
                        _progress[uid].update({"sent": len(data), "done": True})
                        print(f"[relay/upload] small done uid={uid}")
                else:
                    print(f"[relay/upload] large file, chunked upload uid={uid}")
                    if _progress.get(uid, {}).get("cancelled"):
                        print(f"[relay/upload] cancelled before chunk_begin uid={uid}")
                        return
                    def cb(sent, total):
                        if _progress.get(uid, {}).get("cancelled"):
                            raise InterruptedError("cancelled")
                        _progress[uid]["sent"] = sent
                    def is_cancelled():
                        return bool(_progress.get(uid, {}).get("cancelled"))
                    resp = file_c.call("upload_bytes_chunked", remote_path, data,
                                       progress_cb=cb, cancelled_fn=is_cancelled)
                    if _progress.get(uid, {}).get("cancelled"):
                        print(f"[relay/upload] cancelled uid={uid}")
                        return
                    print(f"[relay/upload] large call resp: {str(resp)[:120]}")
                    if not isinstance(resp, dict):
                        _progress[uid]["error"] = f"unexpected response: {type(resp).__name__}"
                    elif resp.get("type") == "error":
                        _progress[uid]["error"] = resp.get("payload", {}).get("reason", "agent error")
                    elif "error" in resp:
                        err = resp["error"]
                        print(f"[relay/upload] large relay error uid={uid}: {err}")
                        _progress[uid]["error"] = err
                    else:
                        _progress[uid].update({"sent": len(data), "done": True})
                        print(f"[relay/upload] large done uid={uid} size={len(data)}")
            except InterruptedError:
                print(f"[relay/upload] interrupted (cancelled) uid={uid}")
            except Exception as e:
                print(f"[relay/upload] error uid={uid} err={e}")
                # Сбрасываем reading чтобы клиент вышел из shimmer-анимации и увидел ошибку
                _progress[uid]["reading"] = False
                _progress[uid]["error"] = str(e)

        threading.Thread(target=_run, daemon=True).start()
        # Возвращаем uid немедленно — клиент начнёт polling и сможет отменить
        return fjsonify({"upload_id": uid, "done": False, "total": 0})
    except Exception as e: return fjsonify({"error":str(e)}), 500

@flask_app.route("/api/files/download")
@_require
def api_files_download():
    aid = _aid()
    if not aid: return fjsonify({"error":"no agent_id"}), 400
    try:
        remote_path = freq.args.get("path","")
        fname = remote_path.replace("\\","/").split("/")[-1] or "file"
        uid   = str(_uuid.uuid4())
        _progress[uid] = {"received":0,"total":0,"done":False,"error":None,"cancelled":False,"fname":fname}
        _,_,file_c = _conns(aid)
        def _run():
            try:
                def cb(recv,total):
                    if _progress.get(uid,{}).get("cancelled"): raise InterruptedError()
                    _progress[uid]["received"]=recv; _progress[uid]["total"]=total
                def is_cancelled():
                    return bool(_progress.get(uid, {}).get("cancelled"))
                print(f"[relay/download] start uid={uid} path={remote_path}")
                resp = file_c.call("download_bytes_with_progress", remote_path, cb, cancelled_fn=is_cancelled)
                if _progress.get(uid,{}).get("cancelled"):
                    print(f"[relay/download] cancelled uid={uid} path={remote_path}")
                    return
                data = resp if isinstance(resp, bytes) else resp.get("payload",{}).get("data","").encode()
                if isinstance(resp,dict) and "data" in resp.get("payload",{}):
                    data = base64.b64decode(resp["payload"]["data"])
                print(f"[relay/download] done uid={uid} path={remote_path} size={len(data)}")
                _progress[uid].update({"data":data,"received":len(data),"total":len(data),"done":True})
            except InterruptedError:
                print(f"[relay/download] interrupted (cancelled) uid={uid} path={remote_path}")
            except Exception as e:
                print(f"[relay/download] error uid={uid} path={remote_path} err={e}")
                _progress[uid]["error"]=str(e)
        threading.Thread(target=_run, daemon=True).start()
        return fjsonify({"download_id":uid})
    except Exception as e: return fjsonify({"error":str(e)}), 500

@flask_app.route("/api/files/zip-download", methods=["POST"])
@_require
def api_files_zip_download():
    aid = _aid()
    if not aid: return fjsonify({"error":"no agent_id"}), 400
    try:
        d=freq.json or {}; paths=d.get("paths",[]); name=d.get("name","archive.zip")
        uid=str(_uuid.uuid4())
        _progress[uid]={"received":0,"total":0,"done":False,"error":None,"cancelled":False,"fname":name}
        _,_,file_c=_conns(aid)
        def _run():
            try:
                def cb(recv,total):
                    if _progress.get(uid,{}).get("cancelled"): raise InterruptedError()
                    _progress[uid]["received"]=recv; _progress[uid]["total"]=total
                def is_cancelled_zip():
                    return bool(_progress.get(uid,{}).get("cancelled"))
                data = file_c.call("download_zip", paths, cb, cancelled_fn=is_cancelled_zip)
                if _progress.get(uid,{}).get("cancelled"):
                    print(f"[relay/zip-download] cancelled uid={uid}")
                    return
                if isinstance(data, dict): data = base64.b64decode(data.get("payload",{}).get("data",""))
                _progress[uid].update({"data":data,"received":len(data),"total":len(data),"done":True})
            except InterruptedError: pass
            except Exception as e: _progress[uid]["error"]=str(e)
        threading.Thread(target=_run, daemon=True).start()
        return fjsonify({"download_id":uid})
    except Exception as e: return fjsonify({"error":str(e)}), 500

@flask_app.route("/api/files/dl/<uid>")
@_require
def api_files_dl(uid):
    prog=_progress.get(uid)
    if not prog or not prog.get("done"): return fjsonify({"error":"not ready"}), 404
    data=prog.get("data",b""); fname=prog.get("fname","file")
    del _progress[uid]
    return send_file(io.BytesIO(data), as_attachment=True, download_name=fname)

@flask_app.route("/api/files/progress/<uid>")
@_require
def api_files_progress(uid):
    prog=_progress.get(uid)
    if not prog: return fjsonify({"error":"unknown id"}), 404
    return fjsonify({k:v for k,v in prog.items() if k!="data"})

@flask_app.route("/api/files/cancel", methods=["POST"])
@_require
def api_files_cancel():
    uid=(freq.json or {}).get("uid","")
    prog=_progress.get(uid)
    if prog: prog["cancelled"]=True
    return fjsonify({"ok":True})

# ── Монтируем Flask в FastAPI ─────────────────────────────────────────
app.mount("/", WSGIMiddleware(flask_app))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT)
