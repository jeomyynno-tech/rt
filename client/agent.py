"""
RemoteAgent — API-клиент к серверу.
"""
import ssl, socket, base64, threading
from pathlib import Path
from common.protocol import send_msg, recv_msg, MsgType, CHUNK_SIZE


class RemoteAgent:
    def __init__(self, host, port, password, use_ssl=True):
        self.host, self.port, self.password, self.use_ssl = host, port, password, use_ssl
        self.sock = None
        self._lock = threading.Lock()

    # ── Connect ──────────────────────────────────────────────────────── #
    def connect(self):
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(10)

        if self.use_ssl:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            self.sock = ctx.wrap_socket(raw, server_hostname=self.host)
        else:
            self.sock = raw

        self.sock.connect((self.host, self.port))
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock.settimeout(120)
        send_msg(self.sock, MsgType.AUTH, {"password": self.password})
        resp = recv_msg(self.sock)
        if resp["type"] != MsgType.AUTH_OK:
            raise PermissionError(resp["payload"].get("reason", "Auth failed"))
        return True

    def disconnect(self):
        try:
            if self.sock: self.sock.close()
        except Exception: pass
        self.sock = None

    def is_connected(self):
        return self.sock is not None

    def _call(self, msg_type, payload=None):
        with self._lock:
            send_msg(self.sock, msg_type, payload or {})
            return recv_msg(self.sock)

    # ── Basic ─────────────────────────────────────────────────────────── #
    def ping(self):
        return self._call(MsgType.PING)["type"] == MsgType.PONG

    def sys_info(self):
        return self._call(MsgType.SYS_INFO)

    # ── Shell ─────────────────────────────────────────────────────────── #
    def execute(self, command, cwd=""):
        return self._call(MsgType.CMD, {"command": command, "cwd": cwd})

    # ── Files ─────────────────────────────────────────────────────────── #
    def file_list(self, path):
        return self._call(MsgType.FILE_LIST, {"path": path})

    def upload_bytes(self, remote_path, data: bytes):
        """Маленький файл (<4MB) одним сообщением."""
        return self._call(MsgType.FILE_UPLOAD, {
            "path": remote_path,
            "data": base64.b64encode(data).decode(),
        })

    def upload_bytes_chunked(self, remote_path, data: bytes, progress_cb=None, cancelled_fn=None):
        """
        Большой файл чанками по CHUNK_SIZE.
        progress_cb(sent, total) вызывается после каждого ACK.
        cancelled_fn() — функция без аргументов, возвращает True если отменено.
        При отмене отправляет CHUNK_CANCEL агенту — тот закрывает и удаляет
        частичный файл, освобождая блокировку (WinError 32).
        """
        total  = len(data)
        chunks = [data[i:i+CHUNK_SIZE] for i in range(0, max(total, 1), CHUNK_SIZE)]
        with self._lock:
            # Проверяем отмену до открытия файла на агенте
            if cancelled_fn and cancelled_fn():
                print(f"[client/upload] cancelled before chunk_begin path={remote_path}")
                raise InterruptedError("upload cancelled before start")

            send_msg(self.sock, MsgType.CHUNK_BEGIN, {
                "path": remote_path, "total_chunks": len(chunks), "total_size": total
            })
            ack = recv_msg(self.sock)
            if ack.get("type") == MsgType.ERROR:
                return ack
            sent = 0
            for i, chunk in enumerate(chunks):
                # Проверяем отмену ПЕРЕД отправкой чанка
                if cancelled_fn and cancelled_fn():
                    print(f"[client/upload] cancelled at chunk={i+1}/{len(chunks)}, sending chunk_cancel path={remote_path}")
                    send_msg(self.sock, MsgType.CHUNK_CANCEL, {})
                    raise InterruptedError("upload cancelled by operator")

                send_msg(self.sock, MsgType.CHUNK_DATA, {
                    "index": i, "data": base64.b64encode(chunk).decode()
                })
                ack = recv_msg(self.sock)
                if ack.get("type") == MsgType.ERROR:
                    return ack
                sent += len(chunk)

                # Проверяем отмену ПОСЛЕ получения ACK
                if cancelled_fn and cancelled_fn():
                    print(f"[client/upload] cancelled after chunk={i+1}/{len(chunks)}, sending chunk_cancel path={remote_path}")
                    send_msg(self.sock, MsgType.CHUNK_CANCEL, {})
                    raise InterruptedError("upload cancelled by operator")

                if progress_cb:
                    try: progress_cb(sent, total)
                    except InterruptedError: raise
                    except Exception: pass
                if i == 0 or i == len(chunks) - 1 or i % 20 == 0:
                    print(f"[client/upload] chunk={i+1}/{len(chunks)} size={len(chunk)} sent={sent}")
            send_msg(self.sock, MsgType.CHUNK_END, {})
            return recv_msg(self.sock)

    def upload(self, local_path, remote_path):
        return self.upload_bytes(remote_path, Path(local_path).read_bytes())

    def download_bytes(self, remote_path):
        """
        Скачать файл с агента.
        Сервер сам решает: FILE_DATA (малый) или чанки (большой).
        Возвращает bytes.
        """
        with self._lock:
            send_msg(self.sock, MsgType.FILE_DOWNLOAD, {"path": remote_path})
            msg = recv_msg(self.sock)
            t   = msg.get("type")

            if t == MsgType.ERROR:
                raise RuntimeError(msg["payload"].get("reason", "download failed"))

            if t == MsgType.FILE_DATA:
                return base64.b64decode(msg["payload"]["data"])

            if t == MsgType.DCHUNK_BEGIN:
                total = msg["payload"].get("total_size", 0)
                n     = msg["payload"].get("total_chunks", 0)
                send_msg(self.sock, MsgType.DCHUNK_ACK, {"index": -1})
                buf = bytearray()
                for i in range(n):
                    chunk_msg = recv_msg(self.sock)
                    if chunk_msg.get("type") == MsgType.ERROR:
                        raise RuntimeError(chunk_msg["payload"].get("reason", "chunk error"))
                    buf += base64.b64decode(chunk_msg["payload"]["data"])
                    send_msg(self.sock, MsgType.DCHUNK_ACK, {"index": i})
                recv_msg(self.sock)  # DCHUNK_END
                return bytes(buf)

            raise RuntimeError(f"unexpected response: {t}")

    def download_bytes_with_progress(self, remote_path, progress_cb=None, cancelled_fn=None) -> bytes:
        """download_bytes с вызовами progress_cb(received, total).
        cancelled_fn() — функция без аргументов, возвращает True если передача отменена.
        При отмене отправляет DCHUNK_CANCEL агенту и бросает InterruptedError.
        """
        with self._lock:
            send_msg(self.sock, MsgType.FILE_DOWNLOAD, {"path": remote_path})
            msg = recv_msg(self.sock)
            t   = msg.get("type")

            if t == MsgType.ERROR:
                raise RuntimeError(msg["payload"].get("reason", "download failed"))

            if t == MsgType.FILE_DATA:
                data = base64.b64decode(msg["payload"]["data"])
                if progress_cb: progress_cb(len(data), len(data))
                return data

            if t == MsgType.DCHUNK_BEGIN:
                total = msg["payload"].get("total_size", 0)
                n     = msg["payload"].get("total_chunks", 0)
                print(f"[client/dchunk] begin path={remote_path} total={total} chunks={n}")

                # Проверяем отмену до отправки первого ACK
                if cancelled_fn and cancelled_fn():
                    print(f"[client/dchunk] cancelled before start, sending dchunk_cancel path={remote_path}")
                    send_msg(self.sock, MsgType.DCHUNK_CANCEL, {"reason": "cancelled_by_operator"})
                    raise InterruptedError("download cancelled by operator")

                send_msg(self.sock, MsgType.DCHUNK_ACK, {"index": -1})
                buf = bytearray()
                for i in range(n):
                    # Проверяем отмену ПЕРЕД ACK следующего чанка
                    if cancelled_fn and cancelled_fn():
                        print(f"[client/dchunk] cancelled at chunk={i+1}/{n}, sending dchunk_cancel path={remote_path}")
                        send_msg(self.sock, MsgType.DCHUNK_CANCEL, {"reason": "cancelled_by_operator"})
                        raise InterruptedError("download cancelled by operator")

                    chunk_msg = recv_msg(self.sock)
                    if chunk_msg.get("type") == MsgType.ERROR:
                        raise RuntimeError(chunk_msg["payload"].get("reason", "chunk error"))
                    chunk = base64.b64decode(chunk_msg["payload"]["data"])
                    buf += chunk
                    if progress_cb:
                        try: progress_cb(len(buf), total)
                        except Exception: pass
                    if i == 0 or i == n - 1 or i % 20 == 0:
                        print(f"[client/dchunk] chunk={i+1}/{n} size={len(chunk)}")
                    send_msg(self.sock, MsgType.DCHUNK_ACK, {"index": i})

                recv_msg(self.sock)  # DCHUNK_END
                print(f"[client/dchunk] end path={remote_path} received={len(buf)}")
                return bytes(buf)

            raise RuntimeError(f"unexpected response: {t}")

    def download(self, remote_path, local_path):
        data = self.download_bytes(remote_path)
        Path(local_path).write_bytes(data)
        return data

    def file_delete(self, path):
        return self._call(MsgType.FILE_DELETE, {"path": path})

    def file_mkdir(self, path):
        return self._call(MsgType.FILE_MKDIR, {"path": path})

    def file_rename(self, src, dst):
        return self._call(MsgType.FILE_RENAME, {"src": src, "dst": dst})

    def file_zip(self, paths: list, dest: str):
        """Создать zip-архив на агенте и сохранить там."""
        return self._call(MsgType.FILE_ZIP, {"paths": paths, "dest": dest})

    def download_zip(self, paths: list, progress_cb=None) -> bytes:
        """Запаковать выбранные файлы на агенте, получить zip чанками."""
        with self._lock:
            send_msg(self.sock, MsgType.FILE_ZIP_STREAM, {"paths": paths})
            meta = recv_msg(self.sock)
            if meta.get("type") == MsgType.ERROR:
                raise RuntimeError(meta["payload"].get("reason", "zip failed"))
            total = meta["payload"]["total_size"]
            n     = meta["payload"]["total_chunks"]
            buf   = bytearray()
            for i in range(n):
                chunk_msg = recv_msg(self.sock)
                if chunk_msg.get("type") == MsgType.ERROR:
                    raise RuntimeError(chunk_msg["payload"].get("reason", "zip stream error"))
                buf  += base64.b64decode(chunk_msg["payload"]["data"])
                if progress_cb:
                    try: progress_cb(len(buf), total)
                    except Exception: pass
                send_msg(self.sock, MsgType.CHUNK_ACK, {"index": i})
            recv_msg(self.sock)  # OK
            return bytes(buf)

    # ── Screen ────────────────────────────────────────────────────────── #
    def screenshot(self, quality=70):
        return self._call(MsgType.SCREENSHOT, {"quality": quality})

    # ── Processes ─────────────────────────────────────────────────────── #
    def proc_list(self):  return self._call(MsgType.PROC_LIST)
    def proc_kill(self, pid): return self._call(MsgType.PROC_KILL, {"pid": pid})

    # ── Mouse ─────────────────────────────────────────────────────────── #
    def mouse_move(self, x, y, duration=0):
        return self._call(MsgType.MOUSE_MOVE, {"x":x,"y":y,"duration":duration})
    def mouse_click(self, x=None, y=None, button="left", clicks=1):
        return self._call(MsgType.MOUSE_CLICK, {"x":x,"y":y,"button":button,"clicks":clicks})
    def mouse_scroll(self, amount=3, x=None, y=None):
        return self._call(MsgType.MOUSE_SCROLL, {"amount":amount,"x":x,"y":y})
    def mouse_drag(self, x2, y2, duration=0.3, button="left"):
        return self._call(MsgType.MOUSE_DRAG, {"x2":x2,"y2":y2,"duration":duration,"button":button})

    # ── Keyboard ──────────────────────────────────────────────────────── #
    def key_press(self, key):   return self._call(MsgType.KEY_PRESS, {"key": key})
    def key_hotkey(self, keys): return self._call(MsgType.KEY_HOTKEY, {"keys": keys})
    def key_type(self, text, interval=0.03):
        return self._call(MsgType.KEY_TYPE, {"text": text, "interval": interval})

    # ── Clipboard ─────────────────────────────────────────────────────── #
    def clipboard_get(self): return self._call(MsgType.CLIPBOARD_GET)
    def clipboard_set(self, text): return self._call(MsgType.CLIPBOARD_SET, {"text": text})
