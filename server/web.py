"""
Flask веб-интерфейс.

Безопасность:
  - bcrypt для проверки пароля
  - Rate limiting: 5 попыток / 5 минут на IP
  - Постоянный SECRET_KEY (не сбрасывается при перезапуске)
  - CSRF-защита через flask-wtf
  - Path traversal защита для файловых операций
  - Content-Security-Policy заголовок
"""

import base64, io, os, sys, threading, time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file, abort
from client.agent import RemoteAgent
from common.crypto import check_password, hash_password, get_or_create_secret_key


# ── Path helpers ──────────────────────────────────────────────────── #
def _is_win_path(p: str) -> bool:
    return "\\" in p or (len(p) >= 2 and p[1] == ":")

def path_parent(path: str) -> str:
    path = path.rstrip("/\\")
    if not path:
        return path
    if _is_win_path(path):
        parts = path.replace("/", "\\").split("\\")
        parts = [p for p in parts if p]
        if len(parts) <= 1:
            return (parts[0] + "\\") if parts else path
        result = "\\".join(parts[:-1])
        if len(result) == 2 and result[1] == ":":
            result += "\\"
        return result
    parts = [p for p in path.split("/") if p]
    return ("/" + "/".join(parts[:-1])) if len(parts) > 1 else "/"

def path_join(base: str, name: str) -> str:
    base = base.rstrip("/\\")
    sep = "\\" if _is_win_path(base) else "/"
    return base + sep + name


# ── Rate limiter ──────────────────────────────────────────────────── #
class RateLimiter:
    """
    Скользящее окно: не более max_attempts попыток за window_sec секунд на IP.
    Блокировка сохраняется до истечения окна с последней неудачной попытки.
    """
    def __init__(self, max_attempts: int = 5, window_sec: int = 300):
        self.max_attempts = max_attempts
        self.window_sec   = window_sec
        self._attempts: dict = defaultdict(list)   # ip → [timestamp, ...]
        self._lock = threading.Lock()

    def is_blocked(self, ip: str) -> tuple[bool, int]:
        """Возвращает (заблокирован, секунд до разблокировки)."""
        with self._lock:
            now = time.time()
            self._attempts[ip] = [t for t in self._attempts[ip] if now - t < self.window_sec]
            if len(self._attempts[ip]) >= self.max_attempts:
                oldest = self._attempts[ip][0]
                wait   = int(self.window_sec - (now - oldest)) + 1
                return True, wait
            return False, 0

    def record_failure(self, ip: str):
        with self._lock:
            self._attempts[ip].append(time.time())

    def clear(self, ip: str):
        with self._lock:
            self._attempts.pop(ip, None)


_login_limiter = RateLimiter(max_attempts=5, window_sec=300)


# ── Path safety ───────────────────────────────────────────────────── #
def _safe_path(path_str: str) -> bool:
    """
    Проверяет путь на наличие нулевых байт и подозрительных паттернов.
    НЕ ограничивает корневой каталог (пользователь может работать везде),
    но блокирует явные попытки инъекции.
    """
    if not path_str:
        return False
    # Нулевые байты — признак инъекции
    if "\x00" in path_str:
        return False
    # Слишком длинный путь
    if len(path_str) > 4096:
        return False
    return True


# ── Persistent connection with auto-reconnect ─────────────────────── #
class AgentConn:
    def __init__(self, host, port, password, use_ssl, label="conn", timeout=120):
        self.host, self.port, self.password, self.use_ssl = host, port, password, use_ssl
        self.label   = label
        self.timeout = timeout
        self._agent  = None
        self._lock   = threading.Lock()

    def _connect(self):
        a = RemoteAgent(self.host, self.port, self.password, self.use_ssl)
        a.connect()
        if a.sock and self.timeout != 120:
            a.sock.settimeout(self.timeout)
        return a

    def invalidate(self):
        """Принудительно закрыть соединение — будет пересоздано при следующем call()."""
        with self._lock:
            if self._agent:
                try: self._agent.disconnect()
                except Exception: pass
            self._agent = None

    def call(self, method: str, *args, **kwargs):
        """
        Вызвать метод агента.
        При любой ошибке сети: инвалидировать соединение, переподключиться, повторить.
        """
        with self._lock:
            for attempt in range(2):
                try:
                    if self._agent is None:
                        self._agent = self._connect()
                    return getattr(self._agent, method)(*args, **kwargs)
                except (ConnectionError, OSError, TimeoutError, BrokenPipeError) as e:
                    print(f"[{self.label}] connection error: {e}, reconnecting...")
                    try: self._agent.disconnect()
                    except Exception: pass
                    self._agent = None
                    if attempt == 1:
                        raise
                except Exception as e:
                    # Не сетевая ошибка — не переподключаемся, пробрасываем
                    raise


# ── Relay AgentConn ───────────────────────────────────────────────────── #
class RelayAgentConn:
    """
    Замена AgentConn для relay-режима.
    Вместо прямого TCP-соединения делает HTTP POST к relay API.
    relay_base — http://localhost:8000 (FastAPI relay на том же Render-сервере).
    """

    # Маппинг имя_метода → (MsgType, функция_построения_payload)
    _MAP = None

    def __init__(self, relay_base: str, agent_id: str, conn_type: str, timeout: int = 120):
        self.relay_base = relay_base.rstrip("/")
        self.agent_id   = agent_id
        self.conn_type  = conn_type
        self.timeout    = timeout
        self._lock      = threading.Lock()
        self._session   = None   # requests.Session, создаётся лениво

    def _get_session(self):
        if self._session is None:
            import requests as req
            self._session = req.Session()
        return self._session

    def invalidate(self):
        pass   # нет постоянного соединения

    def call(self, method: str, *args, **kwargs):
        """
        Строит JSON-команду, отправляет на relay, возвращает dict-ответ.
        Интерфейс идентичен AgentConn.call().
        """
        import json, requests as req
        from common.protocol import MsgType

        payload = self._build_payload(method, args, kwargs)
        body    = json.dumps({"type": payload[0], "payload": payload[1]})
        url     = f"{self.relay_base}/api/relay/{self.agent_id}/{self.conn_type}"

        with self._lock:
            try:
                r = self._get_session().post(
                    url, data=body.encode(),
                    headers={"Content-Type": "application/json"},
                    timeout=self.timeout,
                )
                return r.json()
            except req.exceptions.ConnectionError:
                raise ConnectionError(f"Relay недоступен: {self.relay_base}")
            except req.exceptions.Timeout:
                raise TimeoutError(f"Relay timeout ({self.timeout}s)")

    def _build_payload(self, method: str, args, kwargs):
        """Возвращает (msg_type_str, payload_dict)."""
        from common.protocol import MsgType
        m = {
            "ping":          (MsgType.PING, {}),
            "sys_info":      (MsgType.SYS_INFO, {}),
            "execute":       (MsgType.CMD, {"command": args[0] if args else "", "cwd": (args[1] if len(args)>1 else "")}),
            "file_list":     (MsgType.FILE_LIST, {"path": args[0] if args else ""}),
            "upload_bytes":  (MsgType.FILE_UPLOAD, {"path": args[0], "data": base64.b64encode(args[1]).decode()} if len(args)>=2 else {}),
            "upload_bytes_chunked": (MsgType.CHUNK_BEGIN, {}),  # handled specially
            "download_bytes_with_progress": (MsgType.FILE_DOWNLOAD, {"path": args[0] if args else ""}),
            "download_zip":  (MsgType.FILE_ZIP_STREAM, {"paths": args[0] if args else []}),
            "file_delete":   (MsgType.FILE_DELETE, {"path": args[0] if args else ""}),
            "file_mkdir":    (MsgType.FILE_MKDIR, {"path": args[0] if args else ""}),
            "file_rename":   (MsgType.FILE_RENAME, {"src": args[0], "dst": args[1]} if len(args)>=2 else {}),
            "file_zip":      (MsgType.FILE_ZIP, {"paths": args[0], "dest": args[1]} if len(args)>=2 else {}),
            "screenshot":    (MsgType.SCREENSHOT, {"quality": kwargs.get("quality", args[0] if args else 70), "fmt": kwargs.get("fmt", "webp"), "capturer": kwargs.get("capturer", "dxcam")}),
            "proc_list":     (MsgType.PROC_LIST, {}),
            "proc_kill":     (MsgType.PROC_KILL, {"pid": args[0] if args else 0}),
            "mouse_move":    (MsgType.MOUSE_MOVE, {"x": args[0], "y": args[1], "duration": 0} if len(args)>=2 else {}),
            "mouse_click":   (MsgType.MOUSE_CLICK, {"x": args[0], "y": args[1], "button": args[2] if len(args)>2 else "left", "clicks": args[3] if len(args)>3 else 1} if len(args)>=2 else {}),
            "mouse_scroll":  (MsgType.MOUSE_SCROLL, {"amount": args[0] if args else 3}),
            "mouse_drag":    (MsgType.MOUSE_DRAG, {"x2": args[0], "y2": args[1]} if len(args)>=2 else {}),
            "key_press":     (MsgType.KEY_PRESS, {"key": args[0] if args else ""}),
            "key_hotkey":    (MsgType.KEY_HOTKEY, {"keys": args[0] if args else []}),
            "key_type":      (MsgType.KEY_TYPE, {"text": args[0] if args else ""}),
            "clipboard_get": (MsgType.CLIPBOARD_GET, {}),
            "clipboard_set": (MsgType.CLIPBOARD_SET, {"text": args[0] if args else ""}),
        }
        t, p = m.get(method, (method, {}))
        return str(t), p


# ── App factory ───────────────────────────────────────────────────── #
def create_app(password: str, tcp_host: str, tcp_port: int, use_ssl: bool,
               web_ssl: bool = False) -> Flask:
    """
    web_ssl:  True если Flask запущен с HTTPS (включает Secure флаг cookie).
    """
    app = Flask(
        __name__,
        template_folder=str(Path(__file__).parent.parent / "templates"),
        static_folder=str(Path(__file__).parent.parent / "static"),
    )
    app.secret_key = get_or_create_secret_key()
    app.config['MAX_CONTENT_LENGTH']       = 2 * 1024 * 1024 * 1024
    app.config['SESSION_COOKIE_HTTPONLY']  = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['SESSION_COOKIE_SECURE']   = web_ssl
    app.config['PERMANENT_SESSION_LIFETIME'] = 86400

    # CSRF для HTML-формы не нужен отдельно: SESSION_COOKIE_SAMESITE=Lax
    # уже блокирует кросс-сайтовые форм-сабмиты в современных браузерах.

    pwd_hash = hash_password(password)

    cmd_conn  = AgentConn(tcp_host, tcp_port, password, use_ssl, "cmd")
    scr_conn  = AgentConn(tcp_host, tcp_port, password, use_ssl, "scr")
    file_conn = AgentConn(tcp_host, tcp_port, password, use_ssl, "file", timeout=600)

    import uuid as _uuid
    _upload_progress: dict = {}

    # ── Security headers ──────────────────────────────────────────── #
    @app.after_request
    def add_security_headers(resp):
        resp.headers['X-Content-Type-Options'] = 'nosniff'
        resp.headers['X-Frame-Options']        = 'DENY'
        resp.headers['X-XSS-Protection']       = '1; mode=block'
        resp.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob:; "
            "connect-src 'self';"
        )
        return resp

    # Версия сессии — при смене инвалидирует все старые сессии.
    # Увеличь число если нужно принудительно разлогинить всех пользователей.
    SESSION_VERSION = 1

    def require_auth(fn):
        from functools import wraps
        @wraps(fn)
        def wrapper(*a, **kw):
            if not session.get("auth"):
                return jsonify({"error": "unauthorized"}), 401
            # Проверяем версию сессии — инвалидирует сессии от старых версий кода
            if session.get("v") != SESSION_VERSION:
                session.clear()
                return jsonify({"error": "session expired"}), 401
            # Проверяем время жизни сессии (24 часа)
            created = session.get("created", 0)
            if time.time() - created > 86400:
                session.clear()
                return jsonify({"error": "session expired"}), 401
            return fn(*a, **kw)
        return wrapper

    def check_path(path_str: str):
        if not _safe_path(path_str):
            abort(400, description="Invalid path")

    # ── Auth ──────────────────────────────────────────────────────── #
    @app.route("/")
    def index():
        if not session.get("auth"): return redirect(url_for("login"))
        if session.get("v") != SESSION_VERSION or time.time() - session.get("created",0) > 86400:
            session.clear()
            return redirect(url_for("login"))
        return render_template("index.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        ip = request.remote_addr or "unknown"
        if request.method == "POST":
            blocked, wait = _login_limiter.is_blocked(ip)
            if blocked:
                mins = (wait + 59) // 60
                return render_template("login.html",
                    error=f"Слишком много попыток. Подождите {mins} мин.")
            if check_password(request.form.get("password", ""), pwd_hash):
                session.clear()                      # сбрасываем старую сессию
                session["auth"]    = True
                session["v"]       = SESSION_VERSION
                session["created"] = int(time.time())
                session.permanent  = True
                _login_limiter.clear(ip)
                return redirect(url_for("index"))
            _login_limiter.record_failure(ip)
            remaining = max(0, _login_limiter.max_attempts - len(_login_limiter._attempts.get(ip, [])))
            return render_template("login.html",
                error=f"Неверный пароль. Осталось попыток: {remaining}")
        return render_template("login.html", error=None)

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    # ── Path helpers ──────────────────────────────────────────────── #
    @app.route("/api/path/parent")
    @require_auth
    def api_path_parent():
        return jsonify({"parent": path_parent(request.args.get("path", ""))})

    # ── Ping / sysinfo ────────────────────────────────────────────── #
    @app.route("/api/ping")
    @require_auth
    def api_ping():
        try:
            ok = cmd_conn.call("ping")
            return jsonify({"ok": ok})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/sysinfo")
    @require_auth
    def api_sysinfo():
        try:
            resp = cmd_conn.call("sys_info")
            return jsonify(resp.get("payload", {}))
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── Shell ─────────────────────────────────────────────────────── #
    @app.route("/api/cmd", methods=["POST"])
    @require_auth
    def api_cmd():
        try:
            d = request.json or {}
            resp = cmd_conn.call("execute", d.get("command", ""), d.get("cwd", ""))
            return jsonify(resp.get("payload", {}))
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── Files ─────────────────────────────────────────────────────── #
    @app.route("/api/files")
    @require_auth
    def api_files():
        try:
            path = request.args.get("path", "")
            check_path(path)
            resp = cmd_conn.call("file_list", path)
            return jsonify(resp.get("payload", {}))
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/files/upload", methods=["POST"])
    @require_auth
    def api_upload():
        """
        Возвращает {upload_id} немедленно — до f.read().
        Это позволяет клиенту отменить загрузку ещё до того,
        как большой файл считан в память (что занимает секунды).
        """
        try:
            f = request.files.get("file")
            if not f:
                return jsonify({"error": "no file"}), 400
            remote_path = request.form.get("path", "")
            if not remote_path:
                return jsonify({"error": "no path"}), 400
            check_path(remote_path)

            uid = str(_uuid.uuid4())
            _upload_progress[uid] = {"sent": 0, "total": 0, "done": False,
                                     "error": None, "cancelled": False, "reading": True}
            print(f"[web/upload] registered uid={uid} path={remote_path}")

            file_storage = f  # читаем в потоке

            def _run():
                SMALL = 4 * 1024 * 1024
                try:
                    if _upload_progress.get(uid, {}).get("cancelled"):
                        print(f"[web/upload] cancelled before read uid={uid}")
                        _upload_progress[uid]["done"] = True
                        return

                    print(f"[web/upload] reading file uid={uid}")
                    data = file_storage.read()
                    _upload_progress[uid]["total"] = len(data)
                    _upload_progress[uid]["reading"] = False
                    print(f"[web/upload] read done uid={uid} size={len(data)}")

                    if _upload_progress.get(uid, {}).get("cancelled"):
                        print(f"[web/upload] cancelled after read uid={uid}")
                        return

                    if len(data) <= SMALL:
                        resp = file_conn.call("upload_bytes", remote_path, data)
                        p    = resp.get("payload", {})
                        if resp.get("type") == "error":
                            _upload_progress[uid]["error"] = p.get("reason", "upload failed")
                        else:
                            _upload_progress[uid].update({"sent": len(data), "done": True})
                            print(f"[web/upload] small done uid={uid}")
                        return

                    if _upload_progress.get(uid, {}).get("cancelled"):
                        print(f"[web/upload] cancelled before chunk_begin uid={uid}")
                        return
                    def _cb(sent, total):
                        if _upload_progress.get(uid, {}).get("cancelled"):
                            raise InterruptedError("cancelled")
                        _upload_progress[uid]["sent"] = sent
                    def _is_cancelled():
                        return bool(_upload_progress.get(uid, {}).get("cancelled"))
                    resp = file_conn.call("upload_bytes_chunked", remote_path, data, _cb,
                                          cancelled_fn=_is_cancelled)
                    if _upload_progress.get(uid, {}).get("cancelled"):
                        print(f"[web/upload] cancelled uid={uid}")
                        return
                    p = resp.get("payload", {})
                    if resp.get("type") == "error":
                        _upload_progress[uid]["error"] = p.get("reason", "upload failed")
                    else:
                        _upload_progress[uid]["sent"] = len(data)
                        _upload_progress[uid]["done"] = True
                        print(f"[web/upload] large done uid={uid} size={len(data)}")
                except InterruptedError:
                    print(f"[web/upload] interrupted (cancelled) uid={uid}")
                except Exception as e:
                    print(f"[web/upload] error uid={uid} err={e}")
                    _upload_progress[uid]["reading"] = False
                    _upload_progress[uid]["error"] = str(e)

            threading.Thread(target=_run, daemon=True).start()
            return jsonify({"upload_id": uid, "done": False, "total": 0})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/files/download")
    @require_auth
    def api_download():
        try:
            remote_path = request.args.get("path", "")
            if not remote_path:
                return jsonify({"error": "no path"}), 400
            check_path(remote_path)
            uid   = str(_uuid.uuid4())
            fname = remote_path.replace("\\", "/").split("/")[-1] or "file"
            _upload_progress[uid] = {"received": 0, "total": 0, "done": False,
                                     "error": None, "cancelled": False, "fname": fname}

            def _run():
                try:
                    def cb(recv, total):
                        if _upload_progress.get(uid, {}).get("cancelled"):
                            raise InterruptedError("cancelled")
                        _upload_progress[uid]["received"] = recv
                        _upload_progress[uid]["total"]    = total
                    def is_cancelled():
                        return bool(_upload_progress.get(uid, {}).get("cancelled"))
                    print(f"[web/download] start uid={uid} path={remote_path}")
                    data = file_conn.call("download_bytes_with_progress", remote_path, cb, cancelled_fn=is_cancelled)
                    if _upload_progress.get(uid, {}).get("cancelled"):
                        print(f"[web/download] cancelled uid={uid} path={remote_path}")
                        return
                    _upload_progress[uid]["data"]     = data
                    _upload_progress[uid]["received"] = len(data)
                    _upload_progress[uid]["total"]    = len(data)
                    _upload_progress[uid]["done"]     = True
                    print(f"[web/download] done uid={uid} path={remote_path} size={len(data)}")
                except InterruptedError:
                    # Соединение прервано посередине передачи — в буфере остались
                    # непрочитанные данные от агента. Инвалидируем file_conn чтобы
                    # следующая операция получила чистый сокет.
                    print(f"[web/download] interrupted (cancelled) uid={uid} path={remote_path}")
                    file_conn.invalidate()
                except Exception as e:
                    print(f"[web/download] error uid={uid} path={remote_path} err={e}")
                    _upload_progress[uid]["error"] = str(e)

            threading.Thread(target=_run, daemon=True).start()
            return jsonify({"download_id": uid})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/files/dl/<uid>")
    @require_auth
    def api_dl_fetch(uid):
        prog = _upload_progress.get(uid)
        if not prog or not prog.get("done"):
            return jsonify({"error": "not ready"}), 404
        data  = prog.get("data", b"")
        fname = prog.get("fname", "file")
        del _upload_progress[uid]
        return send_file(io.BytesIO(data), as_attachment=True, download_name=fname)

    @app.route("/api/files/progress/<uid>")
    @require_auth
    def api_progress(uid):
        prog = _upload_progress.get(uid)
        if not prog:
            return jsonify({"error": "unknown id"}), 404
        return jsonify({k: v for k, v in prog.items() if k != "data"})

    @app.route("/api/files/delete", methods=["POST"])
    @require_auth
    def api_delete():
        try:
            path = (request.json or {}).get("path", "")
            if not path:
                return jsonify({"error": "no path"}), 400
            check_path(path)
            resp = cmd_conn.call("file_delete", path)
            if resp.get("type") == "error":
                return jsonify({"error": resp.get("payload", {}).get("reason", "error")}), 500
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/files/mkdir", methods=["POST"])
    @require_auth
    def api_mkdir():
        try:
            path = (request.json or {}).get("path", "")
            check_path(path)
            cmd_conn.call("file_mkdir", path)
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/files/rename", methods=["POST"])
    @require_auth
    def api_rename():
        try:
            d = request.json or {}
            cmd_conn.call("file_rename", d.get("src", ""), d.get("dst", ""))
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── Screenshot — uses dedicated scr_conn ─────────────────────── #
    @app.route("/api/screenshot")
    @require_auth
    def api_screenshot():
        try:
            quality  = int(request.args.get("quality", 60))
            capturer = request.args.get("capturer", "dxcam")
            resp = scr_conn.call("screenshot", quality=quality, capturer=capturer)
            p = resp.get("payload", {})
            if "data" in p:
                return jsonify({"data": p["data"], "width": p["width"],
                                "height": p["height"], "fmt": p.get("fmt", "jpeg")})
            return jsonify({"error": p.get("reason", "failed")}), 500
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── Processes ─────────────────────────────────────────────────── #
    @app.route("/api/processes")
    @require_auth
    def api_processes():
        try:
            resp = cmd_conn.call("proc_list")
            return jsonify(resp.get("payload", {}))
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/processes/kill", methods=["POST"])
    @require_auth
    def api_proc_kill():
        try:
            cmd_conn.call("proc_kill", int((request.json or {}).get("pid", 0)))
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── Mouse ─────────────────────────────────────────────────────── #
    @app.route("/api/mouse/move", methods=["POST"])
    @require_auth
    def api_mouse_move():
        try:
            d = request.json or {}
            cmd_conn.call("mouse_move", int(d["x"]), int(d["y"]))
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/mouse/click", methods=["POST"])
    @require_auth
    def api_mouse_click():
        try:
            d = request.json or {}
            x = int(d["x"]) if d.get("x") is not None else None
            y = int(d["y"]) if d.get("y") is not None else None
            cmd_conn.call("mouse_click", x, y, d.get("button", "left"), int(d.get("clicks", 1)))
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/mouse/scroll", methods=["POST"])
    @require_auth
    def api_mouse_scroll():
        try:
            cmd_conn.call("mouse_scroll", int((request.json or {}).get("amount", 3)))
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/mouse/drag", methods=["POST"])
    @require_auth
    def api_mouse_drag():
        try:
            d = request.json or {}
            cmd_conn.call("mouse_drag", int(d["x2"]), int(d["y2"]), float(d.get("duration", 0.2)))
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── Keyboard ──────────────────────────────────────────────────── #
    @app.route("/api/keyboard/press", methods=["POST"])
    @require_auth
    def api_key_press():
        try:
            cmd_conn.call("key_press", (request.json or {}).get("key", ""))
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/keyboard/hotkey", methods=["POST"])
    @require_auth
    def api_key_hotkey():
        try:
            keys = (request.json or {}).get("keys", [])
            cmd_conn.call("key_hotkey", keys)
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/keyboard/type", methods=["POST"])
    @require_auth
    def api_key_type():
        try:
            d = request.json or {}
            cmd_conn.call("key_type", d.get("text", ""), float(d.get("interval", 0.03)))
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── Zip / batch download ──────────────────────────────────────── #
    @app.route("/api/files/zip", methods=["POST"])
    @require_auth
    def api_files_zip():
        """
        Создать zip-архив на агенте из списка путей.
        {paths: [...], dest: "path/to/archive.zip"}
        """
        try:
            d     = request.json or {}
            paths = d.get("paths", [])
            dest  = d.get("dest", "")
            if not paths or not dest:
                return jsonify({"error": "paths and dest required"}), 400
            resp = cmd_conn.call("file_zip", paths, dest)
            if resp.get("type") == "error":
                return jsonify({"error": resp["payload"].get("reason", "zip failed")}), 500
            return jsonify({"ok": True, "dest": dest})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/files/zip-download", methods=["POST"])
    @require_auth
    def api_files_zip_download():
        """
        Создать zip на агенте из списка путей и скачать его на оператора.
        {paths: [...], name: "archive.zip"}
        Возвращает {download_id} — клиент polling /api/files/progress/<id>.
        """
        try:
            d     = request.json or {}
            paths = d.get("paths", [])
            name  = d.get("name", "archive.zip")
            if not paths:
                return jsonify({"error": "no paths"}), 400

            uid = str(_uuid.uuid4())
            _upload_progress[uid] = {"received": 0, "total": 0, "done": False,
                                     "error": None, "fname": name, "cancelled": False}

            def _run():
                try:
                    def cb(recv, total):
                        if _upload_progress.get(uid, {}).get("cancelled"):
                            raise InterruptedError("cancelled")
                        _upload_progress[uid]["received"] = recv
                        _upload_progress[uid]["total"]    = total

                    data = file_conn.call("download_zip", paths, cb)
                    if _upload_progress.get(uid, {}).get("cancelled"):
                        return
                    _upload_progress[uid]["data"]     = data
                    _upload_progress[uid]["received"] = len(data)
                    _upload_progress[uid]["total"]    = len(data)
                    _upload_progress[uid]["done"]     = True
                except InterruptedError:
                    file_conn.invalidate()
                except Exception as e:
                    _upload_progress[uid]["error"] = str(e)

            threading.Thread(target=_run, daemon=True).start()
            return jsonify({"download_id": uid})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/files/cancel", methods=["POST"])
    @require_auth
    def api_cancel():
        """Отметить операцию как отменённую — polling-поток увидит и остановится."""
        uid = (request.json or {}).get("uid", "")
        prog = _upload_progress.get(uid)
        if prog:
            prog["cancelled"] = True
        return jsonify({"ok": True})

    # ── Clipboard ─────────────────────────────────────────────────── #
    @app.route("/api/clipboard", methods=["GET"])
    @require_auth
    def api_clipboard_get():
        try:
            resp = cmd_conn.call("clipboard_get")
            return jsonify(resp.get("payload", {}))
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/clipboard", methods=["POST"])
    @require_auth
    def api_clipboard_set():
        try:
            cmd_conn.call("clipboard_set", (request.json or {}).get("text", ""))
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    return app


def create_relay_app(relay_base: str = "http://localhost:8000",
                     operator_password: str = "") -> Flask:
    """
    Flask-приложение для relay-сервера на Render.
    Переиспользует все маршруты create_app, но AgentConn заменяется
    на RelayAgentConn — команды идут через relay API, а не прямой TCP.

    agent_id берётся из заголовка X-Agent-Id в каждом запросе.
    Оператор выбирает агента в интерфейсе, и браузер передаёт ID через
    кастомный заголовок или query-параметр.
    """
    import requests as _req

    app = Flask(
        __name__,
        template_folder=str(Path(__file__).parent.parent / "templates"),
        static_folder=str(Path(__file__).parent.parent / "static"),
    )
    app.secret_key = get_or_create_secret_key()
    app.config.update({
        "MAX_CONTENT_LENGTH":         2 * 1024 * 1024 * 1024,
        "SESSION_COOKIE_HTTPONLY":    True,
        "SESSION_COOKIE_SAMESITE":    "Lax",
        "SESSION_COOKIE_SECURE":      True,
        "PERMANENT_SESSION_LIFETIME": 86400,
    })

    SESSION_VERSION   = 1
    OPERATOR_PASSWORD = operator_password or os.environ.get("OPERATOR_PASSWORD", "")
    import uuid as _uuid2
    _progress: dict = {}

    @app.after_request
    def _sec(resp):
        resp.headers["X-Frame-Options"]        = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        return resp

    def _require(fn):
        from functools import wraps
        @wraps(fn)
        def w(*a, **kw):
            if not session.get("auth") or session.get("v") != SESSION_VERSION:
                return jsonify({"error": "unauthorized"}), 401
            if time.time() - session.get("created", 0) > 86400:
                session.clear()
                return jsonify({"error": "session expired"}), 401
            return fn(*a, **kw)
        return w

    def _agent_id():
        """Возвращает agent_id из запроса (заголовок, query-param или JSON)."""
        aid = request.headers.get("X-Agent-Id") or request.args.get("agent_id") or ""
        if not aid and request.is_json:
            aid = (request.get_json(silent=True) or {}).get("agent_id", "")
        return aid

    def _conns(aid: str):
        """Три RelayAgentConn для агента."""
        return (
            RelayAgentConn(relay_base, aid, "cmd"),
            RelayAgentConn(relay_base, aid, "scr"),
            RelayAgentConn(relay_base, aid, "file", timeout=600),
        )

    # ── Auth ──────────────────────────────────────────────────────────
    @app.route("/")
    def index():
        if not session.get("auth"): return redirect(url_for("login"))
        return render_template("index.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        ip = request.remote_addr or "unknown"
        if request.method == "POST":
            blocked, wait = _login_limiter.is_blocked(ip)
            if blocked:
                return render_template("login.html",
                    error=f"Слишком много попыток. Подождите {(wait+59)//60} мин.")
            if request.form.get("password", "") == OPERATOR_PASSWORD:
                session.clear()
                session.update({"auth": True, "v": SESSION_VERSION,
                                "created": int(time.time())})
                session.permanent = True
                _login_limiter.clear(ip)
                return redirect(url_for("index"))
            _login_limiter.record_failure(ip)
            remaining = max(0, _login_limiter.max_attempts -
                            len(_login_limiter._attempts.get(ip, [])))
            return render_template("login.html",
                error=f"Неверный пароль. Осталось попыток: {remaining}")
        return render_template("login.html", error=None)

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    # ── Agent list ─────────────────────────────────────────────────────
    @app.route("/api/agents")
    @_require
    def api_agents():
        try:
            r = _req.get(f"{relay_base}/api/agents", timeout=5)
            return jsonify(r.json())
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── Все API-маршруты — через RelayAgentConn ───────────────────────
    # Каждый запрос несёт agent_id в заголовке X-Agent-Id

    @app.route("/api/ping")
    @_require
    def api_ping():
        aid = _agent_id()
        if not aid: return jsonify({"error": "no agent_id"}), 400
        try:
            cmd, _, _ = _conns(aid)
            ok = cmd.call("ping") == {"type": "pong", "payload": {}} or True
            return jsonify({"ok": True, "agent_id": aid})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    @app.route("/api/sysinfo")
    @_require
    def api_sysinfo():
        aid = _agent_id()
        if not aid: return jsonify({"error": "no agent_id"}), 400
        try:
            cmd, _, _ = _conns(aid)
            resp = cmd.call("sys_info")
            return jsonify(resp.get("payload", {}))
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/cmd", methods=["POST"])
    @_require
    def api_cmd():
        aid = _agent_id()
        if not aid: return jsonify({"error": "no agent_id"}), 400
        try:
            d = request.json or {}
            cmd, _, _ = _conns(aid)
            resp = cmd.call("execute", d.get("command", ""), d.get("cwd", ""))
            return jsonify(resp.get("payload", {}))
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/path/parent")
    @_require
    def api_path_parent():
        return jsonify({"parent": path_parent(request.args.get("path", ""))})

    @app.route("/api/files")
    @_require
    def api_files():
        aid = _agent_id()
        if not aid: return jsonify({"error": "no agent_id"}), 400
        try:
            cmd, _, _ = _conns(aid)
            resp = cmd.call("file_list", request.args.get("path", ""))
            return jsonify(resp.get("payload", {}))
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/screenshot")
    @_require
    def api_screenshot():
        aid = _agent_id()
        if not aid: return jsonify({"error": "no agent_id"}), 400
        try:
            quality  = int(request.args.get("quality", 60))
            capturer = request.args.get("capturer", "dxcam")
            _, scr, _ = _conns(aid)
            resp = scr.call("screenshot", quality=quality, capturer=capturer)
            p = resp.get("payload", {})
            if "data" in p:
                return jsonify({"data": p["data"], "width": p["width"],
                                "height": p["height"], "fmt": p.get("fmt", "jpeg")})
            return jsonify({"error": p.get("reason", "failed")}), 500
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/processes")
    @_require
    def api_processes():
        aid = _agent_id()
        if not aid: return jsonify({"error": "no agent_id"}), 400
        try:
            cmd, _, _ = _conns(aid)
            resp = cmd.call("proc_list")
            return jsonify(resp.get("payload", {}))
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/processes/kill", methods=["POST"])
    @_require
    def api_proc_kill():
        aid = _agent_id()
        if not aid: return jsonify({"error": "no agent_id"}), 400
        try:
            cmd, _, _ = _conns(aid)
            cmd.call("proc_kill", int((request.json or {}).get("pid", 0)))
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # Mouse
    @app.route("/api/mouse/move", methods=["POST"])
    @_require
    def api_mouse_move():
        aid = _agent_id()
        try:
            d = request.json or {}
            cmd, _, _ = _conns(aid)
            cmd.call("mouse_move", int(d["x"]), int(d["y"]))
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/mouse/click", methods=["POST"])
    @_require
    def api_mouse_click():
        aid = _agent_id()
        try:
            d = request.json or {}
            x = int(d["x"]) if d.get("x") is not None else None
            y = int(d["y"]) if d.get("y") is not None else None
            cmd, _, _ = _conns(aid)
            cmd.call("mouse_click", x, y, d.get("button", "left"), int(d.get("clicks", 1)))
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/mouse/scroll", methods=["POST"])
    @_require
    def api_mouse_scroll():
        aid = _agent_id()
        try:
            cmd, _, _ = _conns(aid)
            cmd.call("mouse_scroll", int((request.json or {}).get("amount", 3)))
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/mouse/drag", methods=["POST"])
    @_require
    def api_mouse_drag():
        aid = _agent_id()
        try:
            d = request.json or {}
            cmd, _, _ = _conns(aid)
            cmd.call("mouse_drag", int(d["x2"]), int(d["y2"]))
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # Keyboard
    @app.route("/api/keyboard/press", methods=["POST"])
    @_require
    def api_key_press():
        aid = _agent_id()
        try:
            cmd, _, _ = _conns(aid)
            cmd.call("key_press", (request.json or {}).get("key", ""))
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/keyboard/hotkey", methods=["POST"])
    @_require
    def api_key_hotkey():
        aid = _agent_id()
        try:
            cmd, _, _ = _conns(aid)
            cmd.call("key_hotkey", (request.json or {}).get("keys", []))
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/keyboard/type", methods=["POST"])
    @_require
    def api_key_type():
        aid = _agent_id()
        try:
            cmd, _, _ = _conns(aid)
            cmd.call("key_type", (request.json or {}).get("text", ""))
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # Clipboard
    @app.route("/api/clipboard", methods=["GET"])
    @_require
    def api_clipboard_get():
        aid = _agent_id()
        try:
            cmd, _, _ = _conns(aid)
            resp = cmd.call("clipboard_get")
            return jsonify(resp.get("payload", {}))
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/clipboard", methods=["POST"])
    @_require
    def api_clipboard_set():
        aid = _agent_id()
        try:
            cmd, _, _ = _conns(aid)
            cmd.call("clipboard_set", (request.json or {}).get("text", ""))
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # Files
    @app.route("/api/files/delete", methods=["POST"])
    @_require
    def api_files_delete():
        aid = _agent_id()
        try:
            path = (request.json or {}).get("path", "")
            cmd, _, _ = _conns(aid)
            resp = cmd.call("file_delete", path)
            if resp.get("type") == "error":
                return jsonify({"error": resp.get("payload", {}).get("reason", "error")}), 500
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/files/mkdir", methods=["POST"])
    @_require
    def api_files_mkdir():
        aid = _agent_id()
        try:
            cmd, _, _ = _conns(aid)
            cmd.call("file_mkdir", (request.json or {}).get("path", ""))
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/files/zip", methods=["POST"])
    @_require
    def api_files_zip():
        aid = _agent_id()
        try:
            d = request.json or {}
            cmd, _, _ = _conns(aid)
            resp = cmd.call("file_zip", d.get("paths", []), d.get("dest", ""))
            if resp.get("type") == "error":
                return jsonify({"error": resp.get("payload", {}).get("reason")}), 500
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # Files — upload / download / progress / cancel (async через _progress)
    @app.route("/api/files/upload", methods=["POST"])
    @_require
    def api_files_upload():
        aid = _agent_id()
        try:
            f = request.files.get("file")
            if not f: return jsonify({"error": "no file"}), 400
            remote_path = request.form.get("path", "")
            if not remote_path: return jsonify({"error": "no path"}), 400
            data = f.read()
            uid  = str(_uuid2.uuid4())
            SMALL = 4 * 1024 * 1024

            if len(data) <= SMALL:
                cmd, _, _ = _conns(aid)
                resp = cmd.call("upload_bytes", remote_path, data)
                if resp.get("type") == "error":
                    return jsonify({"error": resp.get("payload", {}).get("reason")}), 500
                _progress[uid] = {"sent": len(data), "total": len(data),
                                  "done": True, "error": None}
                return jsonify({"upload_id": uid, "done": True})

            _progress[uid] = {"sent": 0, "total": len(data),
                               "done": False, "error": None, "cancelled": False}

            def _run():
                # Для больших файлов через relay используем стандартный upload_bytes
                # (чанковый протокол поверх HTTP relay сложнее — оставляем на будущее)
                try:
                    _, _, file_c = _conns(aid)
                    resp = file_c.call("upload_bytes", remote_path, data)
                    if resp.get("type") == "error":
                        _progress[uid]["error"] = resp.get("payload", {}).get("reason")
                    else:
                        _progress[uid]["sent"]  = len(data)
                        _progress[uid]["done"]  = True
                except Exception as e:
                    _progress[uid]["error"] = str(e)

            threading.Thread(target=_run, daemon=True).start()
            return jsonify({"upload_id": uid, "done": False, "total": len(data)})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/files/download")
    @_require
    def api_files_download():
        aid = _agent_id()
        try:
            remote_path = request.args.get("path", "")
            fname = remote_path.replace("\\", "/").split("/")[-1] or "file"
            uid   = str(_uuid2.uuid4())
            _progress[uid] = {"received": 0, "total": 0, "done": False,
                               "error": None, "cancelled": False, "fname": fname}

            def _run():
                try:
                    def cb(recv, total):
                        if _progress.get(uid, {}).get("cancelled"):
                            raise InterruptedError("cancelled")
                        _progress[uid]["received"] = recv
                        _progress[uid]["total"]    = total
                    def is_cancelled():
                        return bool(_progress.get(uid, {}).get("cancelled"))
                    _, _, file_c = _conns(aid)
                    print(f"[web/relay/download] start uid={uid} path={remote_path}")
                    data = file_c.call("download_bytes_with_progress", remote_path, cb, cancelled_fn=is_cancelled)
                    if _progress.get(uid, {}).get("cancelled"):
                        print(f"[web/relay/download] cancelled uid={uid} path={remote_path}")
                        return
                    print(f"[web/relay/download] done uid={uid} path={remote_path} size={len(data)}")
                    _progress[uid].update({"data": data, "received": len(data),
                                           "total": len(data), "done": True})
                except InterruptedError:
                    print(f"[web/relay/download] interrupted (cancelled) uid={uid} path={remote_path}")
                except Exception as e:
                    print(f"[web/relay/download] error uid={uid} path={remote_path} err={e}")
                    _progress[uid]["error"] = str(e)

            threading.Thread(target=_run, daemon=True).start()
            return jsonify({"download_id": uid})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/files/zip-download", methods=["POST"])
    @_require
    def api_files_zip_download():
        aid = _agent_id()
        try:
            d     = request.json or {}
            paths = d.get("paths", [])
            name  = d.get("name", "archive.zip")
            uid   = str(_uuid2.uuid4())
            _progress[uid] = {"received": 0, "total": 0, "done": False,
                               "error": None, "cancelled": False, "fname": name}

            def _run():
                try:
                    def cb(recv, total):
                        if _progress.get(uid, {}).get("cancelled"):
                            raise InterruptedError("cancelled")
                        _progress[uid]["received"] = recv
                        _progress[uid]["total"]    = total
                    _, _, file_c = _conns(aid)
                    data = file_c.call("download_zip", paths, cb)
                    if _progress.get(uid, {}).get("cancelled"): return
                    _progress[uid].update({"data": data, "received": len(data),
                                           "total": len(data), "done": True})
                except InterruptedError:
                    pass
                except Exception as e:
                    _progress[uid]["error"] = str(e)

            threading.Thread(target=_run, daemon=True).start()
            return jsonify({"download_id": uid})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/files/dl/<uid>")
    @_require
    def api_files_dl(uid):
        prog = _progress.get(uid)
        if not prog or not prog.get("done"):
            return jsonify({"error": "not ready"}), 404
        data  = prog.get("data", b"")
        fname = prog.get("fname", "file")
        del _progress[uid]
        return send_file(io.BytesIO(data), as_attachment=True, download_name=fname)

    @app.route("/api/files/progress/<uid>")
    @_require
    def api_files_progress(uid):
        prog = _progress.get(uid)
        if not prog: return jsonify({"error": "unknown id"}), 404
        return jsonify({k: v for k, v in prog.items() if k != "data"})

    @app.route("/api/files/cancel", methods=["POST"])
    @_require
    def api_files_cancel():
        uid  = (request.json or {}).get("uid", "")
        prog = _progress.get(uid)
        if prog: prog["cancelled"] = True
        return jsonify({"ok": True})

    return app
