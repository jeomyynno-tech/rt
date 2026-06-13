"""
Flask веб-интерфейс (прямой режим: TCP к локальному агенту).

Безопасность:
  - bcrypt для проверки пароля
  - Rate limiting: 5 попыток / 5 минут на IP (общий RateLimiter из common.crypto)
  - Постоянный SECRET_KEY (env или certs/.session_key)
  - SameSite=Lax + Secure (под HTTPS)
  - Path validation (anti-injection)
  - Content-Security-Policy
"""

import base64, io, os, sys, threading, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file, abort
from client.agent import RemoteAgent
from common.crypto import check_password, hash_password, get_or_create_secret_key, RateLimiter


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


# Глобальный rate limiter Flask-логина.
_login_limiter = RateLimiter(max_attempts=5, window_sec=300)


# ── Path safety ───────────────────────────────────────────────────── #
def _safe_path(path_str: str) -> bool:
    if not path_str:
        return False
    if "\x00" in path_str:
        return False
    if len(path_str) > 4096:
        return False
    return True


# ── Progress store + TTL cleanup ─────────────────────────────────── #
# Записи могут остаться "висеть" если оператор закрыл вкладку до /api/files/dl.
# Чтобы не накапливать данные больших файлов в RAM, чистим записи старше TTL.
_PROGRESS_TTL_SEC = 10 * 60


def _start_progress_gc(store: dict, lock: threading.Lock):
    def _gc():
        while True:
            time.sleep(60)
            try:
                now = time.time()
                with lock:
                    stale = [uid for uid, p in store.items()
                             if (now - p.get("created_at", now) > _PROGRESS_TTL_SEC)
                             and (p.get("done") or p.get("error") or p.get("cancelled"))]
                    for uid in stale:
                        store.pop(uid, None)
                if stale:
                    print(f"[web/gc] purged {len(stale)} stale progress entries")
            except Exception as e:
                print(f"[web/gc] error: {e}")

    threading.Thread(target=_gc, daemon=True).start()


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
        with self._lock:
            if self._agent:
                try: self._agent.disconnect()
                except Exception: pass
            self._agent = None

    def call(self, method: str, *args, **kwargs):
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
                except Exception:
                    raise


# ── App factory ───────────────────────────────────────────────────── #
def create_app(password: str, tcp_host: str, tcp_port: int, use_ssl: bool,
               web_ssl: bool = False) -> Flask:
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

    pwd_hash = hash_password(password)

    cmd_conn  = AgentConn(tcp_host, tcp_port, password, use_ssl, "cmd")
    scr_conn  = AgentConn(tcp_host, tcp_port, password, use_ssl, "scr")
    file_conn = AgentConn(tcp_host, tcp_port, password, use_ssl, "file", timeout=600)

    import uuid as _uuid
    _upload_progress: dict = {}
    _progress_lock = threading.Lock()
    _start_progress_gc(_upload_progress, _progress_lock)

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

    SESSION_VERSION = 1

    def require_auth(fn):
        from functools import wraps
        @wraps(fn)
        def wrapper(*a, **kw):
            if not session.get("auth"):
                return jsonify({"error": "unauthorized"}), 401
            if session.get("v") != SESSION_VERSION:
                session.clear()
                return jsonify({"error": "session expired"}), 401
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
                session.clear()
                session["auth"]    = True
                session["v"]       = SESSION_VERSION
                session["created"] = int(time.time())
                session.permanent  = True
                # Не сбрасываем счётчик попыток — иначе атакующий,
                # знающий пароль, может авторизоваться и снять ограничения
                # с IP, после чего параллельно брутить с него другой пароль.
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
            return jsonify({"ok": bool(ok)})
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
                                     "error": None, "cancelled": False, "reading": True,
                                     "created_at": time.time()}
            print(f"[web/upload] registered uid={uid} path={remote_path}")

            file_storage = f

            def _run():
                SMALL = 4 * 1024 * 1024
                try:
                    if _upload_progress.get(uid, {}).get("cancelled"):
                        _upload_progress[uid]["done"] = True
                        return

                    data = file_storage.read()
                    _upload_progress[uid]["total"] = len(data)
                    _upload_progress[uid]["reading"] = False

                    if _upload_progress.get(uid, {}).get("cancelled"):
                        return

                    if len(data) <= SMALL:
                        resp = file_conn.call("upload_bytes", remote_path, data)
                        p    = resp.get("payload", {})
                        if resp.get("type") == "error":
                            _upload_progress[uid]["error"] = p.get("reason", "upload failed")
                        else:
                            _upload_progress[uid].update({"sent": len(data), "done": True})
                        return

                    if _upload_progress.get(uid, {}).get("cancelled"):
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
                        return
                    p = resp.get("payload", {}) if isinstance(resp, dict) else {}
                    if isinstance(resp, dict) and resp.get("type") == "error":
                        _upload_progress[uid]["error"] = p.get("reason", "upload failed")
                    else:
                        _upload_progress[uid]["sent"] = len(data)
                        _upload_progress[uid]["done"] = True
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
                                     "error": None, "cancelled": False, "fname": fname,
                                     "created_at": time.time()}

            def _run():
                try:
                    def cb(recv, total):
                        if _upload_progress.get(uid, {}).get("cancelled"):
                            raise InterruptedError("cancelled")
                        _upload_progress[uid]["received"] = recv
                        _upload_progress[uid]["total"]    = total
                    def is_cancelled():
                        return bool(_upload_progress.get(uid, {}).get("cancelled"))
                    data = file_conn.call("download_bytes_with_progress", remote_path, cb, cancelled_fn=is_cancelled)
                    if _upload_progress.get(uid, {}).get("cancelled"):
                        return
                    _upload_progress[uid]["data"]     = data
                    _upload_progress[uid]["received"] = len(data)
                    _upload_progress[uid]["total"]    = len(data)
                    _upload_progress[uid]["done"]     = True
                except InterruptedError:
                    # Не вызываем invalidate(): протокол гарантирует
                    # что после DCHUNK_CANCEL агент тихо выходит из цикла
                    # без send_msg(OK), поэтому сокет остаётся в чистом
                    # состоянии и пригоден для следующей операции.
                    print(f"[web/download] cancelled uid={uid}")
                except Exception as e:
                    print(f"[web/download] error uid={uid}: {e}")
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
            check_path(d.get("src", ""))
            check_path(d.get("dst", ""))
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
        try:
            d     = request.json or {}
            paths = d.get("paths", [])
            dest  = d.get("dest", "")
            if not paths or not dest:
                return jsonify({"error": "paths and dest required"}), 400
            for p in paths: check_path(p)
            check_path(dest)
            resp = cmd_conn.call("file_zip", paths, dest)
            if resp.get("type") == "error":
                return jsonify({"error": resp["payload"].get("reason", "zip failed")}), 500
            return jsonify({"ok": True, "dest": dest})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/files/zip-download", methods=["POST"])
    @require_auth
    def api_files_zip_download():
        try:
            d     = request.json or {}
            paths = d.get("paths", [])
            name  = d.get("name", "archive.zip")
            if not paths:
                return jsonify({"error": "no paths"}), 400
            for p in paths: check_path(p)

            uid = str(_uuid.uuid4())
            _upload_progress[uid] = {"received": 0, "total": 0, "done": False,
                                     "error": None, "fname": name, "cancelled": False,
                                     "created_at": time.time()}

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
                    print(f"[web/zip-download] cancelled uid={uid}")
                except Exception as e:
                    _upload_progress[uid]["error"] = str(e)

            threading.Thread(target=_run, daemon=True).start()
            return jsonify({"download_id": uid})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/files/cancel", methods=["POST"])
    @require_auth
    def api_cancel():
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
