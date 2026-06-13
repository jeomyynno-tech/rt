"""
Flask-приложение Relay для оператора.
Аналог server/web.py, но команды идут через RelayAgentConn → AgentRegistry → агент.
"""

import base64, io, os, sys, threading, time, uuid as _uuid_mod
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from flask import (Flask, render_template, request, jsonify,
                   session, redirect, url_for, send_file, abort)
from flask_sock import Sock
from common.crypto import (check_password, hash_password, get_or_create_secret_key,
                            RateLimiter)
from relay.registry import registry
from relay.conn import RelayAgentConn
from relay.agent_ws import handle_agent_ws


def _safe_path(p):
    if not p or not isinstance(p, str): return False
    if "\x00" in p or len(p) > 4096: return False
    return True


def create_relay_app(password: str) -> Flask:
    app = Flask(
        __name__,
        template_folder=str(Path(__file__).parent.parent / "templates"),
        static_folder=str(Path(__file__).parent.parent / "static"),
    )
    app.secret_key = get_or_create_secret_key()
    app.config['MAX_CONTENT_LENGTH']       = 2 * 1024 * 1024 * 1024
    app.config['SESSION_COOKIE_HTTPONLY']  = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['PERMANENT_SESSION_LIFETIME'] = 86400

    sock     = Sock(app)
    pwd_hash = hash_password(password)

    SESSION_VERSION = 1
    _login_limiter  = RateLimiter(max_attempts=5, window_sec=300)
    _transfer_progress: dict = {}
    _progress_lock = threading.Lock()

    PROGRESS_TTL_SEC = 10 * 60

    def _progress_gc():
        while True:
            time.sleep(60)
            try:
                now = time.time()
                with _progress_lock:
                    stale = [uid for uid, p in _transfer_progress.items()
                             if (now - p.get("created_at", now) > PROGRESS_TTL_SEC)
                             and (p.get("done") or p.get("error") or p.get("cancelled"))]
                    for uid in stale:
                        _transfer_progress.pop(uid, None)
            except Exception:
                pass
    threading.Thread(target=_progress_gc, daemon=True).start()

    # ── WebSocket endpoint для агентов ────────────────────────────────── #
    @sock.route('/ws/agent')
    def ws_agent(ws):
        handle_agent_ws(ws, pwd_hash)

    @app.after_request
    def security_headers(resp):
        resp.headers['X-Content-Type-Options'] = 'nosniff'
        resp.headers['X-Frame-Options']        = 'DENY'
        resp.headers['Content-Security-Policy'] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self';"
        )
        return resp

    def _is_auth():
        return (session.get("auth") and
                session.get("v") == SESSION_VERSION and
                time.time() - session.get("created", 0) < 86400)

    def require_auth(fn):
        from functools import wraps
        @wraps(fn)
        def wrapper(*a, **kw):
            if not _is_auth():
                return jsonify({"error": "unauthorized"}), 401
            return fn(*a, **kw)
        return wrapper

    def check_path(p):
        if not _safe_path(p): abort(400, description="Invalid path")

    @app.route("/")
    def index():
        if not _is_auth(): return redirect(url_for("login"))
        return render_template("index.html")

    @app.route("/login", methods=["GET","POST"])
    def login():
        ip = request.remote_addr or "unknown"
        if request.method == "POST":
            blocked, wait = _login_limiter.is_blocked(ip)
            if blocked:
                return render_template("login.html",
                    error=f"Слишком много попыток. Подождите {(wait+59)//60} мин.")
            if check_password(request.form.get("password",""), pwd_hash):
                session.clear()
                session["auth"]    = True
                session["v"]       = SESSION_VERSION
                session["created"] = int(time.time())
                session.permanent  = True
                # Намеренно не сбрасываем счётчик: иначе атакующий со
                # знанием одного пароля мог бы обнулять блокировку IP.
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

    @app.route("/api/agents")
    @require_auth
    def api_agents():
        agents = registry.list_agents()
        current = session.get("agent_id")
        return jsonify({"agents": agents, "current": current})

    @app.route("/api/agents/select", methods=["POST"])
    @require_auth
    def api_agents_select():
        agent_id = (request.json or {}).get("agent_id","")
        if not agent_id:
            return jsonify({"error": "no agent_id"}), 400
        if not registry.get(agent_id):
            return jsonify({"error": f"Agent '{agent_id}' not connected"}), 404
        session["agent_id"] = agent_id
        return jsonify({"ok": True, "agent_id": agent_id})

    def _conn(label="cmd", timeout=120, agent_id=None):
        """
        AgentConn-замена. При вызове из вью-функции agent_id может быть None —
        тогда RelayAgentConn возьмёт его из session. Для фоновых потоков
        (без request context) ОБЯЗАТЕЛЬНО передавайте agent_id явно.
        """
        return RelayAgentConn(label=label, timeout=timeout, agent_id=agent_id)

    @app.route("/api/path/parent")
    @require_auth
    def api_path_parent():
        from server.web import path_parent
        return jsonify({"parent": path_parent(request.args.get("path",""))})

    @app.route("/api/ping")
    @require_auth
    def api_ping():
        try:
            r = _conn().call("ping")
            return jsonify({"ok": r.get("type") == "pong"})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)})

    @app.route("/api/sysinfo")
    @require_auth
    def api_sysinfo():
        try:
            r = _conn().call("sys_info")
            return jsonify(r.get("payload", {}))
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/cmd", methods=["POST"])
    @require_auth
    def api_cmd():
        try:
            d = request.json or {}
            r = _conn().call("execute", d.get("command",""), d.get("cwd",""))
            return jsonify(r.get("payload", {}))
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/files")
    @require_auth
    def api_files():
        try:
            path = request.args.get("path","")
            if path: check_path(path)
            r = _conn().call("file_list", path)
            return jsonify(r.get("payload", {}))
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/files/upload", methods=["POST"])
    @require_auth
    def api_upload():
        SMALL = 4 * 1024 * 1024
        try:
            f = request.files.get("file")
            if not f: return jsonify({"error": "no file"}), 400
            remote_path = request.form.get("path","")
            if not remote_path: return jsonify({"error": "no path"}), 400
            check_path(remote_path)
            data = f.read()
            uid  = str(_uuid_mod.uuid4())

            if len(data) <= SMALL:
                r = _conn().call("upload_bytes", remote_path, data)
                if r.get("type") == "error":
                    return jsonify({"error": r["payload"].get("reason","upload failed")}), 500
                _transfer_progress[uid] = {"sent": len(data), "total": len(data),
                                           "done": True, "error": None,
                                           "created_at": time.time()}
                return jsonify({"upload_id": uid, "done": True})

            _transfer_progress[uid] = {"sent": 0, "total": len(data), "done": False,
                                       "error": None, "cancelled": False,
                                       "created_at": time.time()}
            # Захватываем agent_id СЕЙЧАС, пока есть request context. В _run()
            # context уже отсутствует — session.get там вернёт None.
            agent_id = session.get("agent_id")

            def _run():
                try:
                    def cb(sent, total):
                        if _transfer_progress.get(uid,{}).get("cancelled"):
                            raise InterruptedError("cancelled")
                        _transfer_progress[uid]["sent"] = sent
                    def is_cancelled():
                        return bool(_transfer_progress.get(uid,{}).get("cancelled"))

                    # Передаём agent_id явно — в потоке нет Flask context.
                    conn = RelayAgentConn(timeout=600, agent_id=agent_id)
                    r = conn.call("upload_bytes_chunked", remote_path, data,
                                  progress_cb=cb, cancelled_fn=is_cancelled)
                    if _transfer_progress.get(uid,{}).get("cancelled"):
                        return
                    if isinstance(r, dict) and r.get("type") == "error":
                        _transfer_progress[uid]["error"] = r["payload"].get("reason","failed")
                    else:
                        _transfer_progress[uid]["sent"] = len(data)
                        _transfer_progress[uid]["done"] = True
                except InterruptedError:
                    pass
                except Exception as e:
                    _transfer_progress[uid]["error"] = str(e)

            threading.Thread(target=_run, daemon=True).start()
            return jsonify({"upload_id": uid, "done": False, "total": len(data)})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/files/download")
    @require_auth
    def api_download():
        try:
            remote_path = request.args.get("path","")
            if not remote_path: return jsonify({"error": "no path"}), 400
            check_path(remote_path)
            uid   = str(_uuid_mod.uuid4())
            fname = remote_path.replace("\\","/").split("/")[-1] or "file"
            _transfer_progress[uid] = {"received": 0, "total": 0, "done": False,
                                       "error": None, "cancelled": False, "fname": fname,
                                       "created_at": time.time()}
            agent_id = session.get("agent_id")
            def _run():
                try:
                    def cb(recv, total):
                        if _transfer_progress.get(uid,{}).get("cancelled"):
                            raise InterruptedError("cancelled")
                        _transfer_progress[uid]["received"] = recv
                        _transfer_progress[uid]["total"]    = total
                    conn = RelayAgentConn(label="file", timeout=600, agent_id=agent_id)
                    r = conn.call("download_bytes_with_progress", remote_path, cb)
                    if isinstance(r, bytes):
                        _transfer_progress[uid].update({
                            "data": r, "received": len(r), "total": len(r), "done": True
                        })
                        return
                    data = r.get("payload", {}).get("data") if isinstance(r, dict) else None
                    if data:
                        decoded = base64.b64decode(data)
                        _transfer_progress[uid].update({
                            "data": decoded, "received": len(decoded), "total": len(decoded), "done": True
                        })
                    else:
                        _transfer_progress[uid]["error"] = (r.get("payload",{}).get("reason","no data")
                                                            if isinstance(r, dict) else "no data")
                except InterruptedError:
                    pass
                except Exception as e:
                    _transfer_progress[uid]["error"] = str(e)
            threading.Thread(target=_run, daemon=True).start()
            return jsonify({"download_id": uid})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/files/dl/<uid>")
    @require_auth
    def api_dl_fetch(uid):
        prog = _transfer_progress.get(uid)
        if not prog or not prog.get("done"): return jsonify({"error": "not ready"}), 404
        data  = prog.get("data", b"")
        fname = prog.get("fname","file")
        del _transfer_progress[uid]
        return send_file(io.BytesIO(data), as_attachment=True, download_name=fname)

    @app.route("/api/files/progress/<uid>")
    @require_auth
    def api_progress(uid):
        prog = _transfer_progress.get(uid)
        if not prog: return jsonify({"error": "unknown id"}), 404
        return jsonify({k:v for k,v in prog.items() if k != "data"})

    @app.route("/api/files/cancel", methods=["POST"])
    @require_auth
    def api_cancel():
        uid = (request.json or {}).get("uid","")
        prog = _transfer_progress.get(uid)
        if prog: prog["cancelled"] = True
        return jsonify({"ok": True})

    @app.route("/api/files/delete", methods=["POST"])
    @require_auth
    def api_delete():
        try:
            path = (request.json or {}).get("path","")
            check_path(path)
            r = _conn().call("file_delete", path)
            if r.get("type") == "error":
                return jsonify({"error": r["payload"].get("reason","error")}), 500
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/files/mkdir", methods=["POST"])
    @require_auth
    def api_mkdir():
        try:
            path = (request.json or {}).get("path","")
            check_path(path)
            _conn().call("file_mkdir", path)
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/files/rename", methods=["POST"])
    @require_auth
    def api_rename():
        try:
            d = request.json or {}
            check_path(d.get("src","")); check_path(d.get("dst",""))
            _conn().call("file_rename", d.get("src",""), d.get("dst",""))
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/files/zip", methods=["POST"])
    @require_auth
    def api_zip():
        try:
            d = request.json or {}
            r = _conn().call("file_zip", d.get("paths",[]), d.get("dest",""))
            if r.get("type") == "error":
                return jsonify({"error": r["payload"].get("reason","zip failed")}), 500
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/files/zip-download", methods=["POST"])
    @require_auth
    def api_zip_download():
        try:
            d     = request.json or {}
            paths = d.get("paths",[])
            name  = d.get("name","archive.zip")
            uid   = str(_uuid_mod.uuid4())
            _transfer_progress[uid] = {"received": 0, "total": 0, "done": False,
                                       "error": None, "fname": name, "cancelled": False,
                                       "created_at": time.time()}
            agent_id = session.get("agent_id")
            def _run():
                try:
                    def cb(recv, total):
                        if _transfer_progress.get(uid,{}).get("cancelled"):
                            raise InterruptedError("cancelled")
                        _transfer_progress[uid]["received"] = recv
                        _transfer_progress[uid]["total"]    = total
                    conn = RelayAgentConn(label="file", timeout=600, agent_id=agent_id)
                    r = conn.call("download_zip", paths, cb)
                    if isinstance(r, bytes):
                        _transfer_progress[uid].update({
                            "data": r, "received": len(r), "total": len(r), "done": True
                        })
                        return
                    data = r.get("payload",{}).get("data") if isinstance(r, dict) else None
                    if data:
                        decoded = base64.b64decode(data)
                        _transfer_progress[uid].update({
                            "data": decoded, "received": len(decoded), "total": len(decoded), "done": True
                        })
                    else:
                        _transfer_progress[uid]["error"] = (r.get("payload",{}).get("reason","failed")
                                                            if isinstance(r, dict) else "failed")
                except InterruptedError:
                    pass
                except Exception as e:
                    _transfer_progress[uid]["error"] = str(e)
            threading.Thread(target=_run, daemon=True).start()
            return jsonify({"download_id": uid})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/screenshot")
    @require_auth
    def api_screenshot():
        try:
            quality = int(request.args.get("quality", 60))
            r = _conn("scr").call("screenshot", quality=quality)
            p = r.get("payload", {})
            if "data" in p:
                return jsonify({"data": p["data"], "width": p["width"], "height": p["height"]})
            return jsonify({"error": p.get("reason","failed")}), 500
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/processes")
    @require_auth
    def api_processes():
        try:
            r = _conn().call("proc_list")
            return jsonify(r.get("payload", {}))
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/processes/kill", methods=["POST"])
    @require_auth
    def api_proc_kill():
        try:
            _conn().call("proc_kill", int((request.json or {}).get("pid",0)))
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/mouse/move", methods=["POST"])
    @require_auth
    def api_mouse_move():
        try:
            d = request.json or {}
            _conn().call("mouse_move", int(d["x"]), int(d["y"]))
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
            _conn().call("mouse_click", x, y, d.get("button","left"), int(d.get("clicks",1)))
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/mouse/scroll", methods=["POST"])
    @require_auth
    def api_mouse_scroll():
        try:
            _conn().call("mouse_scroll", int((request.json or {}).get("amount",3)))
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/mouse/drag", methods=["POST"])
    @require_auth
    def api_mouse_drag():
        try:
            d = request.json or {}
            _conn().call("mouse_drag", int(d["x2"]), int(d["y2"]), float(d.get("duration",0.2)))
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/keyboard/press", methods=["POST"])
    @require_auth
    def api_key_press():
        try:
            _conn().call("key_press", (request.json or {}).get("key",""))
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/keyboard/hotkey", methods=["POST"])
    @require_auth
    def api_key_hotkey():
        try:
            _conn().call("key_hotkey", (request.json or {}).get("keys",[]))
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/keyboard/type", methods=["POST"])
    @require_auth
    def api_key_type():
        try:
            d = request.json or {}
            _conn().call("key_type", d.get("text",""), float(d.get("interval",0.03)))
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/clipboard", methods=["GET"])
    @require_auth
    def api_clipboard_get():
        try:
            r = _conn().call("clipboard_get")
            return jsonify(r.get("payload", {}))
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/clipboard", methods=["POST"])
    @require_auth
    def api_clipboard_set():
        try:
            _conn().call("clipboard_set", (request.json or {}).get("text",""))
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    return app
