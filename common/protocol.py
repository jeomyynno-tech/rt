import json, struct, socket
from enum import Enum

class MsgType(str, Enum):
    AUTH="auth"; AUTH_OK="auth_ok"; AUTH_FAIL="auth_fail"
    PING="ping"; PONG="pong"; ERROR="error"; OK="ok"
    CMD="cmd"; CMD_RESULT="cmd_result"
    FILE_UPLOAD="file_upload"; FILE_DOWNLOAD="file_download"
    FILE_LIST="file_list"; FILE_DATA="file_data"; FILE_OK="file_ok"
    FILE_DELETE="file_delete"; FILE_MKDIR="file_mkdir"; FILE_RENAME="file_rename"
    FILE_ZIP="file_zip"              # создать zip на агенте, сохранить там
    FILE_ZIP_STREAM="file_zip_stream"  # создать zip и отдать чанками оператору
    CHUNK_BEGIN="chunk_begin"; CHUNK_DATA="chunk_data"
    CHUNK_ACK="chunk_ack"; CHUNK_END="chunk_end"; CHUNK_OK="chunk_ok"
    CHUNK_CANCEL="chunk_cancel"  # оператор отменяет загрузку файла на агент
    DCHUNK_BEGIN="dchunk_begin"; DCHUNK_DATA="dchunk_data"
    DCHUNK_ACK="dchunk_ack"; DCHUNK_END="dchunk_end"
    DCHUNK_CANCEL="dchunk_cancel"  # оператор отменяет скачивание
    SCREENSHOT="screenshot"; SCREENSHOT_DATA="screenshot_data"
    STREAM_START="stream_start"; STREAM_STOP="stream_stop"; STREAM_FRAME="stream_frame"
    PROC_LIST="proc_list"; PROC_DATA="proc_data"; PROC_KILL="proc_kill"; PROC_OK="proc_ok"
    MOUSE_MOVE="mouse_move"; MOUSE_CLICK="mouse_click"
    MOUSE_SCROLL="mouse_scroll"; MOUSE_DRAG="mouse_drag"
    KEY_PRESS="key_press"; KEY_HOTKEY="key_hotkey"; KEY_TYPE="key_type"
    CLIPBOARD_GET="clipboard_get"; CLIPBOARD_SET="clipboard_set"; CLIPBOARD_DATA="clipboard_data"
    SYS_INFO="sys_info"; SYS_DATA="sys_data"

CHUNK_SIZE = 512 * 1024   # 512 KB

def send_msg(sock, msg_type, payload):
    data   = json.dumps({"type": msg_type, "payload": payload}).encode()
    sock.sendall(struct.pack(">I", len(data)) + data)

def recv_msg(sock):
    raw = _exact(sock, 4)
    n   = struct.unpack(">I", raw)[0]
    return json.loads(_exact(sock, n).decode())

def _exact(sock, n):
    buf = b""
    while len(buf) < n:
        c = sock.recv(n - len(buf))
        if not c: raise ConnectionError("Connection closed")
        buf += c
    return buf
