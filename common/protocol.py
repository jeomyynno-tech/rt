import json, struct, socket
from enum import Enum

class MsgType(str, Enum):
    AUTH="auth"; AUTH_OK="auth_ok"; AUTH_FAIL="auth_fail"
    PING="ping"; PONG="pong"; ERROR="error"; OK="ok"
    CMD="cmd"; CMD_RESULT="cmd_result"
    FILE_UPLOAD="file_upload"; FILE_DOWNLOAD="file_download"
    FILE_LIST="file_list"; FILE_DATA="file_data"; FILE_OK="file_ok"
    FILE_DELETE="file_delete"; FILE_MKDIR="file_mkdir"; FILE_RENAME="file_rename"
    FILE_ZIP="file_zip"
    FILE_ZIP_STREAM="file_zip_stream"
    CHUNK_BEGIN="chunk_begin"; CHUNK_DATA="chunk_data"
    CHUNK_ACK="chunk_ack"; CHUNK_END="chunk_end"; CHUNK_OK="chunk_ok"
    CHUNK_CANCEL="chunk_cancel"
    DCHUNK_BEGIN="dchunk_begin"; DCHUNK_DATA="dchunk_data"
    DCHUNK_ACK="dchunk_ack"; DCHUNK_END="dchunk_end"
    DCHUNK_CANCEL="dchunk_cancel"
    SCREENSHOT="screenshot"; SCREENSHOT_DATA="screenshot_data"
    STREAM_START="stream_start"; STREAM_STOP="stream_stop"; STREAM_FRAME="stream_frame"
    PROC_LIST="proc_list"; PROC_DATA="proc_data"; PROC_KILL="proc_kill"; PROC_OK="proc_ok"
    MOUSE_MOVE="mouse_move"; MOUSE_CLICK="mouse_click"
    MOUSE_SCROLL="mouse_scroll"; MOUSE_DRAG="mouse_drag"
    KEY_PRESS="key_press"; KEY_HOTKEY="key_hotkey"; KEY_TYPE="key_type"
    CLIPBOARD_GET="clipboard_get"; CLIPBOARD_SET="clipboard_set"; CLIPBOARD_DATA="clipboard_data"
    SYS_INFO="sys_info"; SYS_DATA="sys_data"

CHUNK_SIZE = 512 * 1024   # 512 KB

# Лимит размера одного сообщения. Защита от DoS/OOM: злоумышленник
# не сможет заставить _exact выделить 4 ГБ буфер заголовком n=2^31.
# 32 МБ покрывает все легитимные кейсы (CHUNK_SIZE=512KB + base64 overhead).
MAX_MSG_SIZE = 32 * 1024 * 1024

# Сериализационный лок на сокет: исключает interleaving header/body
# двух одновременных send_msg() из разных потоков. Без него можно
# получить header msg1 + body msg2 на другой стороне.
_send_locks: "dict" = {}
import threading as _threading
_send_locks_guard = _threading.Lock()


def _lock_for(sock):
    with _send_locks_guard:
        key = id(sock)
        lk = _send_locks.get(key)
        if lk is None:
            lk = _threading.Lock()
            _send_locks[key] = lk
        return lk


def send_msg(sock, msg_type, payload):
    data = json.dumps({"type": msg_type, "payload": payload}).encode()
    if len(data) > MAX_MSG_SIZE:
        raise ValueError(f"message too large: {len(data)} > {MAX_MSG_SIZE}")
    frame = struct.pack(">I", len(data)) + data
    lk = _lock_for(sock)
    with lk:
        try:
            sock.sendall(frame)
        except Exception:
            # При обрыве посередине header+body буфер ОС мог отправить
            # часть данных. Закрываем сокет — приёмная сторона увидит EOF
            # и выйдет из _exact(), не дожидаясь "хвоста" не пришедшего тела.
            try: sock.close()
            except Exception: pass
            raise


def recv_msg(sock):
    raw = _exact(sock, 4)
    n   = struct.unpack(">I", raw)[0]
    if n > MAX_MSG_SIZE:
        raise ValueError(f"incoming message too large: {n} > {MAX_MSG_SIZE}")
    return json.loads(_exact(sock, n).decode())

def _exact(sock, n):
    buf = b""
    while len(buf) < n:
        c = sock.recv(n - len(buf))
        if not c: raise ConnectionError("Connection closed")
        buf += c
    return buf
