"""
RemoteAgent — API-клиент к серверу.
"""
import ssl, socket, base64, threading, os
from pathlib import Path
from common.protocol import send_msg, recv_msg, MsgType, CHUNK_SIZE


class RemoteAgent:
    def __init__(self, host, port, password, use_ssl=True, ca_cert: str = None):
        """
        ca_cert: путь к CA-сертификату агента. Если задан — TLS-handshake
        проверяет, что сервер предъявил сертификат, подписанный этим CA
        (certificate pinning). Защищает от MITM на пути клиент → агент.
        Если None — режим небезопасной верификации (только для localhost!).
        """
        self.host, self.port, self.password, self.use_ssl = host, port, password, use_ssl
        self.ca_cert = ca_cert
        self.sock = None
        self._lock = threading.Lock()

    # ── Connect ──────────────────────────────────────────────────────── #
    def connect(self):
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(10)

        if self.use_ssl:
            if self.ca_cert and os.path.exists(self.ca_cert):
                # Безопасный режим: pinning по CA. MITM невозможен без
                # приватного ключа агента.
                ctx = ssl.create_default_context(cafile=self.ca_cert)
                # Самоподписанные сертификаты обычно не валидны по hostname.
                # check_hostname=False допустимо т.к. мы pinим CA.
                ctx.check_hostname = False
                self.sock = ctx.wrap_socket(raw, server_hostname=self.host)
            else:
                # Небезопасный fallback — только для localhost-трафика,
                # где MITM не имеет смысла. Для удалённых подключений
                # ОБЯЗАТЕЛЬНО передавайте ca_cert.
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
            if cancelled_fn and cancelled_fn():
                raise InterruptedError("upload cancelled before start")

            send_msg(self.sock, MsgType.CHUNK_BEGIN, {
                "path": remote_path, "total_chunks": len(chunks), "total_size": total
            })
            ack = recv_msg(self.sock)
            if ack.get("type") == MsgType.ERROR:
                return ack
            sent = 0
            for i, chunk in enumerate(chunks):
                if cancelled_fn and cancelled_fn():
                    send_msg(self.sock, MsgType.CHUNK_CANCEL, {})
                    raise InterruptedError("upload cancelled by operator")

                send_msg(self.sock, MsgType.CHUNK_DATA, {
                    "index": i, "data": base64.b64encode(chunk).decode()
                })
                ack = recv_msg(self.sock)
                if ack.get("type") == MsgType.ERROR:
                    return ack
                sent += len(chunk)

                if cancelled_fn and cancelled_fn():
                    send_msg(self.sock, MsgType.CHUNK_CANCEL, {})
                    raise InterruptedError("upload cancelled by operator")

                if progress_cb:
                    try: progress_cb(sent, total)
                    except InterruptedError: raise
                    except Exception: pass
            send_msg(self.sock, MsgType.CHUNK_END, {})
            return recv_msg(self.sock)

    def upload(self, local_path, remote_path):
        return self.upload_bytes(remote_path, Path(local_path).read_bytes())

    def download_bytes(self, remote_path, sink_path: str = None) -> bytes:
        """
        Скачать файл с агента.

        sink_path: если задан — чанки потоково пишутся в указанный файл,
        в памяти держится только текущий чанк. Возвращает None.
        Без sink_path возвращает bytes (старое поведение для совместимости —
        не использовать для файлов > 100 MB).
        """
        with self._lock:
            send_msg(self.sock, MsgType.FILE_DOWNLOAD, {"path": remote_path})
            msg = recv_msg(self.sock)
            t   = msg.get("type")

            if t == MsgType.ERROR:
                raise RuntimeError(msg["payload"].get("reason", "download failed"))

            if t == MsgType.FILE_DATA:
                data = base64.b64decode(msg["payload"]["data"])
                if sink_path:
                    with open(sink_path, "wb") as f: f.write(data)
                    return None
                return data

            if t == MsgType.DCHUNK_BEGIN:
                n = msg["payload"].get("total_chunks", 0)
                # Контракт: ACK с index=-1 — сигнал агенту "готов принять
                # первый чанк". Любое другое отрицательное значение
                # агент игнорирует.
                send_msg(self.sock, MsgType.DCHUNK_ACK, {"index": -1})
                fh = open(sink_path, "wb") if sink_path else None
                buf = None if sink_path else bytearray()
                try:
                    for i in range(n):
                        chunk_msg = recv_msg(self.sock)
                        if chunk_msg.get("type") == MsgType.ERROR:
                            raise RuntimeError(chunk_msg["payload"].get("reason", "chunk error"))
                        chunk = base64.b64decode(chunk_msg["payload"]["data"])
                        if fh:
                            fh.write(chunk)
                        else:
                            # extend быстрее чем +=, не создаёт промежуточный bytes
                            buf.extend(chunk)
                        send_msg(self.sock, MsgType.DCHUNK_ACK, {"index": i})
                    recv_msg(self.sock)  # DCHUNK_END
                finally:
                    if fh:
                        try: fh.close()
                        except Exception: pass
                return None if sink_path else bytes(buf)

            raise RuntimeError(f"unexpected response: {t}")

    def download_bytes_with_progress(self, remote_path, progress_cb=None,
                                      cancelled_fn=None, sink_path: str = None):
        """
        Скачивание с прогрессом и поддержкой отмены.

        sink_path: если задан — чанки пишутся в файл, в памяти только текущий
        чанк. Без него возвращает bytes (для маленьких файлов).
        cancelled_fn() — функция без аргументов, True если передача отменена.
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
                if sink_path:
                    with open(sink_path, "wb") as f: f.write(data)
                if progress_cb: progress_cb(len(data), len(data))
                return None if sink_path else data

            if t == MsgType.DCHUNK_BEGIN:
                total = msg["payload"].get("total_size", 0)
                n     = msg["payload"].get("total_chunks", 0)

                if cancelled_fn and cancelled_fn():
                    send_msg(self.sock, MsgType.DCHUNK_CANCEL, {"reason": "cancelled_by_operator"})
                    raise InterruptedError("download cancelled by operator")

                # ACK index=-1 — сигнал агенту "готов к первому чанку".
                # (Этот контракт описан в protocol.py)
                send_msg(self.sock, MsgType.DCHUNK_ACK, {"index": -1})

                fh = open(sink_path, "wb") if sink_path else None
                buf = None if sink_path else bytearray()
                received = 0
                try:
                    for i in range(n):
                        if cancelled_fn and cancelled_fn():
                            send_msg(self.sock, MsgType.DCHUNK_CANCEL, {"reason": "cancelled_by_operator"})
                            raise InterruptedError("download cancelled by operator")

                        chunk_msg = recv_msg(self.sock)
                        if chunk_msg.get("type") == MsgType.ERROR:
                            raise RuntimeError(chunk_msg["payload"].get("reason", "chunk error"))
                        chunk = base64.b64decode(chunk_msg["payload"]["data"])
                        if fh:
                            fh.write(chunk)
                        else:
                            buf.extend(chunk)
                        received += len(chunk)
                        if progress_cb:
                            # InterruptedError из cb (если он бросает) ДОЛЖЕН
                            # пробрасываться, иначе отмена не сработает.
                            try: progress_cb(received, total)
                            except InterruptedError: raise
                            except Exception: pass
                        send_msg(self.sock, MsgType.DCHUNK_ACK, {"index": i})

                    recv_msg(self.sock)  # DCHUNK_END
                finally:
                    if fh:
                        try: fh.close()
                        except Exception: pass
                return None if sink_path else bytes(buf)

            raise RuntimeError(f"unexpected response: {t}")

    def download(self, remote_path, local_path):
        # Стримим напрямую в файл — для больших файлов не съедаем 2x размер RAM.
        self.download_bytes(remote_path, sink_path=local_path)
        return None

    def file_delete(self, path):
        return self._call(MsgType.FILE_DELETE, {"path": path})

    def file_mkdir(self, path):
        return self._call(MsgType.FILE_MKDIR, {"path": path})

    def file_rename(self, src, dst):
        return self._call(MsgType.FILE_RENAME, {"src": src, "dst": dst})

    def file_zip(self, paths: list, dest: str):
        return self._call(MsgType.FILE_ZIP, {"paths": paths, "dest": dest})

    def download_zip(self, paths: list, progress_cb=None, sink_path: str = None):
        """
        Запаковать выбранные файлы на агенте, получить zip чанками.
        sink_path: если задан — пишем в файл стримом.
        """
        with self._lock:
            send_msg(self.sock, MsgType.FILE_ZIP_STREAM, {"paths": paths})
            meta = recv_msg(self.sock)
            if meta.get("type") == MsgType.ERROR:
                raise RuntimeError(meta["payload"].get("reason", "zip failed"))
            total = meta["payload"]["total_size"]
            n     = meta["payload"]["total_chunks"]
            fh = open(sink_path, "wb") if sink_path else None
            buf = None if sink_path else bytearray()
            received = 0
            try:
                for i in range(n):
                    chunk_msg = recv_msg(self.sock)
                    if chunk_msg.get("type") == MsgType.ERROR:
                        raise RuntimeError(chunk_msg["payload"].get("reason", "zip stream error"))
                    chunk = base64.b64decode(chunk_msg["payload"]["data"])
                    if fh:
                        fh.write(chunk)
                    else:
                        buf.extend(chunk)
                    received += len(chunk)
                    if progress_cb:
                        try: progress_cb(received, total)
                        except InterruptedError: raise
                        except Exception: pass
                    send_msg(self.sock, MsgType.CHUNK_ACK, {"index": i})
                recv_msg(self.sock)  # OK
            finally:
                if fh:
                    try: fh.close()
                    except Exception: pass
            return None if sink_path else bytes(buf)

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
