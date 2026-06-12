"""
Обработчик одного клиентского подключения.
"""

import os, base64, threading, socket, platform
from pathlib import Path
from common.protocol import send_msg, recv_msg, MsgType, CHUNK_SIZE
from common.crypto import check_password

IS_WIN = platform.system() == "Windows"


# ── TCP_NODELAY helper ───────────────────────────────────────────────── #
def set_nodelay(sock):
    """Отключить алгоритм Nagle — маленькие пакеты уходят немедленно."""
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass


# ── Клавиатура через pynput ──────────────────────────────────────────── #
# pynput использует низкоуровневые OS API (SendInput на Windows),
# поэтому работают системные комбинации: Alt+F4, Win, Ctrl+Alt+Del и т.д.
# pyautogui использует устаревший PostMessage — системные клавиши игнорируются.

# ── Клавиатура ──────────────────────────────────────────────────────── #
# Windows: ctypes SendInput — единственный надёжный способ для системных
# комбинаций (Alt+F4, Win+D, Ctrl+Alt+Del).
# pynput.Controller внутри тоже вызывает SendInput, но неправильно выставляет
# флаг KEYEVENTF_EXTENDEDKEY для расширенных клавиш (Alt, Ctrl, Win, F-keys).

# Таблица виртуальных кодов Windows
_VK: dict = {
    "enter": 0x0D, "return": 0x0D,
    "escape": 0x1B, "esc": 0x1B,
    "tab": 0x09,
    "backspace": 0x08,
    "delete": 0x2E, "del": 0x2E,
    "space": 0x20,
    "up": 0x26, "down": 0x28, "left": 0x25, "right": 0x27,
    "home": 0x24, "end": 0x23,
    "pageup": 0x21, "pagedown": 0x22,
    "shift": 0x10, "shift_l": 0xA0, "shift_r": 0xA1,
    "ctrl": 0x11, "ctrl_l": 0xA2, "ctrl_r": 0xA3,
    "alt": 0x12, "alt_l": 0xA4, "alt_r": 0xA5,
    "win": 0x5B, "super": 0x5B, "cmd": 0x5B,
    "f1": 0x70, "f2": 0x71, "f3": 0x72, "f4": 0x73,
    "f5": 0x74, "f6": 0x75, "f7": 0x76, "f8": 0x77,
    "f9": 0x78, "f10": 0x79, "f11": 0x7A, "f12": 0x7B,
    "insert": 0x2D, "printscreen": 0x2C,
    "caps_lock": 0x14, "num_lock": 0x90, "scroll_lock": 0x91,
    "media_play_pause": 0xB3,
    "media_volume_up": 0xAF, "media_volume_down": 0xAE, "media_volume_mute": 0xAD,
}
# Клавиши, требующие флага EXTENDEDKEY.
# Generic Ctrl (0x11) и generic Alt (0x12) НЕ расширенные — только правые варианты.
# Навигационные (стрелки, Home, End, PgUp, PgDn, Ins, Del) — расширенные.
_VK_EXTENDED = {
    0x21, 0x22, 0x23, 0x24,   # PageUp, PageDown, End, Home
    0x25, 0x26, 0x27, 0x28,   # Left, Up, Right, Down
    0x2D, 0x2E,               # Insert, Delete
    0xA2, 0xA3,               # Ctrl_L, Ctrl_R
    0xA4, 0xA5,               # Alt_L, Alt_R
    0x5B, 0x5C,               # Win_L, Win_R
}


def _vk(name: str) -> int:
    """Строка → виртуальный код клавиши."""
    k = name.lower().strip()
    if k in _VK:
        return _VK[k]
    if len(name) == 1:
        import ctypes
        return ctypes.windll.user32.VkKeyScanW(ord(name)) & 0xFF
    return 0


def _send_input_win(keys: list):
    """
    Нажать и отпустить набор клавиш через SendInput.
    Структуры определены точно по Windows SDK:
      - union содержит MOUSEINPUT чтобы sizeof(INPUT) был правильным
        (28 байт на 32-bit, 40 байт на 64-bit)
      - dwExtraInfo = c_void_p (ULONG_PTR: 4 байта на 32-bit, 8 на 64-bit)
    Без этого SendInput получает неверный cbSize и молча игнорирует ввод.
    """
    import ctypes, ctypes.wintypes as wt, time

    KEYEVENTF_KEYUP       = 0x0002
    KEYEVENTF_EXTENDEDKEY = 0x0001
    INPUT_KEYBOARD        = 1

    class KEYBDINPUT(ctypes.Structure):
        _fields_ = [
            ("wVk",          wt.WORD),
            ("wScan",        wt.WORD),
            ("dwFlags",      wt.DWORD),
            ("time",         wt.DWORD),
            ("dwExtraInfo",  ctypes.c_void_p),   # ULONG_PTR — pointer-sized
        ]

    class MOUSEINPUT(ctypes.Structure):
        _fields_ = [
            ("dx",           wt.LONG),
            ("dy",           wt.LONG),
            ("mouseData",    wt.DWORD),
            ("dwFlags",      wt.DWORD),
            ("time",         wt.DWORD),
            ("dwExtraInfo",  ctypes.c_void_p),
        ]

    class HARDWAREINPUT(ctypes.Structure):
        _fields_ = [
            ("uMsg",    wt.DWORD),
            ("wParamL", wt.WORD),
            ("wParamH", wt.WORD),
        ]

    class _INP(ctypes.Union):
        _fields_ = [
            ("ki", KEYBDINPUT),
            ("mi", MOUSEINPUT),     # нужен чтобы union имел правильный размер
            ("hi", HARDWAREINPUT),
        ]

    class INPUT(ctypes.Structure):
        _anonymous_ = ("_inp",)
        _fields_    = [
            ("type", wt.DWORD),
            ("_inp", _INP),
        ]

    user32    = ctypes.windll.user32
    sz        = ctypes.sizeof(INPUT)
    vks       = [_vk(k) for k in keys]

    def make(vk, flags):
        inp         = INPUT()
        inp.type    = INPUT_KEYBOARD
        inp.ki.wVk  = vk
        inp.ki.dwFlags = flags
        return inp

    # Press в прямом порядке
    for vk in vks:
        flags = KEYEVENTF_EXTENDEDKEY if vk in _VK_EXTENDED else 0
        ret = user32.SendInput(1, ctypes.byref(make(vk, flags)), sz)
        if ret == 0:
            print(f"[kb] SendInput press vk=0x{vk:02X} FAILED err={ctypes.GetLastError()}")
        time.sleep(0.02)

    time.sleep(0.05)

    # Release в обратном порядке
    for vk in reversed(vks):
        flags = (KEYEVENTF_EXTENDEDKEY if vk in _VK_EXTENDED else 0) | KEYEVENTF_KEYUP
        user32.SendInput(1, ctypes.byref(make(vk, flags)), sz)
        time.sleep(0.02)


def _kb_tap(key_name: str):
    if IS_WIN:
        _send_input_win([key_name])
    else:
        import time
        from pynput.keyboard import Controller, KeyCode
        kb = Controller()
        k  = _pynput_key(key_name)
        kb.press(k); time.sleep(0.02); kb.release(k)


def _kb_hotkey(keys: list):
    if IS_WIN:
        _send_input_win(keys)
    else:
        import time
        from pynput.keyboard import Controller
        kb     = Controller()
        mapped = [_pynput_key(k) for k in keys]
        for k in mapped:
            kb.press(k); time.sleep(0.02)
        time.sleep(0.05)
        for k in reversed(mapped):
            kb.release(k); time.sleep(0.02)


def _kb_type(text: str):
    from pynput.keyboard import Controller
    Controller().type(text)


def _pynput_key(name: str):
    """Только для не-Windows fallback."""
    from pynput.keyboard import Key, KeyCode
    _MAP = {
        "enter":Key.enter,"escape":Key.esc,"esc":Key.esc,"tab":Key.tab,
        "backspace":Key.backspace,"delete":Key.delete,"space":Key.space,
        "up":Key.up,"down":Key.down,"left":Key.left,"right":Key.right,
        "home":Key.home,"end":Key.end,"pageup":Key.page_up,"pagedown":Key.page_down,
        "shift":Key.shift,"ctrl":Key.ctrl,"alt":Key.alt,
        "win":Key.cmd,"super":Key.cmd,"cmd":Key.cmd,
        "f1":Key.f1,"f2":Key.f2,"f3":Key.f3,"f4":Key.f4,
        "f5":Key.f5,"f6":Key.f6,"f7":Key.f7,"f8":Key.f8,
        "f9":Key.f9,"f10":Key.f10,"f11":Key.f11,"f12":Key.f12,
    }
    k = name.lower().strip()
    if k in _MAP: return _MAP[k]
    return KeyCode.from_char(name[0]) if name else Key.space


# ── Быстрый скролл через win32api (без GIL-блокировки pyautogui) ───── #
def _fast_scroll(amount: int):
    """amount > 0 = вверх, < 0 = вниз"""
    if IS_WIN:
        try:
            import win32api, win32con
            # MOUSEEVENTF_WHEEL: +120 = один клик вверх
            win32api.mouse_event(win32con.MOUSEEVENTF_WHEEL, 0, 0, amount * 120, 0)
            return
        except ImportError:
            pass
    # Fallback: pyautogui
    import pyautogui
    pyautogui.scroll(amount)


# ── Захват экрана ───────────────────────────────────────────────────── #
class _Capturer:
    """
    Захват экрана без мерцания курсора.

    Windows: dxcam (DXGI Desktop Duplication API).
      Читает кадр прямо с GPU-фреймбуфера — дисплейный буфер не блокируется,
      курсор агента не затрагивается вообще. Курсор рисуем сами через
      win32api поверх кадра.

    Linux/macOS: mss с постоянным контекстом (без пересоздания DC).
    """
    _lock    = threading.Lock()
    # Windows
    _dxcam   = None          # dxcam.DXCamera instance
    _use_dxcam = False
    _dxcam_tried = False
    # Linux/macOS fallback
    _sct     = None

    @classmethod
    def _init_win(cls):
        """Инициализация dxcam один раз."""
        if cls._dxcam_tried:
            return
        cls._dxcam_tried = True
        try:
            import dxcam
            cls._dxcam = dxcam.create(output_color="RGB")
            cls._use_dxcam = True
        except Exception as e:
            print(f"[capturer] dxcam недоступен ({e}), fallback → mss")
            cls._use_dxcam = False

    @classmethod
    def _grab_dxcam(cls):
        """Захват через DXGI. Возвращает numpy RGB-массив."""
        frame = cls._dxcam.grab()
        # grab() возвращает None если кадр не изменился — повторяем
        if frame is None:
            # Принудительный захват через get_latest_frame
            cls._dxcam.start(target_fps=60, video_mode=True)
            frame = cls._dxcam.get_latest_frame()
            cls._dxcam.stop()
        return frame  # shape: (H, W, 3), dtype uint8, RGB

    @classmethod
    def _grab_mss(cls):
        """Fallback захват через mss."""
        from PIL import Image
        if cls._sct is None:
            import mss
            cls._sct = mss.mss()
        mon = cls._sct.monitors[1]
        raw = cls._sct.grab(mon)
        return Image.frombytes("RGB", raw.size, raw.bgra, "raw", "BGRX")

    @classmethod
    def grab(cls, quality: int, fmt: str = "webp", capturer: str = "dxcam") -> tuple:
        """
        Захватывает экран и сжимает.
        capturer: "dxcam" (только Windows, без артефактов цвета) или "mss" (кросс-платформа).
        fmt: "webp" (лучшее сжатие) или "jpeg" (совместимость).
        Возвращает (bytes, width, height, fmt_used).
        """
        import io
        from PIL import Image

        with cls._lock:
            if IS_WIN:
                cls._init_win()
                # Выбираем захватчик: dxcam если доступен и запрошен, иначе mss
                use_dxcam = cls._use_dxcam and capturer == "dxcam"
                if use_dxcam:
                    try:
                        arr = cls._grab_dxcam()
                        img = Image.fromarray(arr, "RGB")
                    except Exception:
                        cls._use_dxcam = False
                        cls._dxcam = None
                        img = cls._grab_mss()
                else:
                    img = cls._grab_mss()
            else:
                img = cls._grab_mss()

        if IS_WIN:
            img = _draw_cursor_win(img)

        buf = io.BytesIO()
        # WebP: лучше сжатие при том же визуальном качестве
        # При quality=60 WebP ≈ JPEG quality=80 по размеру
        try:
            if fmt == "webp":
                img.save(buf, format="WEBP", quality=quality, method=0)  # method=0 — быстрее
                return buf.getvalue(), img.width, img.height, "webp"
        except Exception:
            pass
        # Fallback на JPEG
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=quality, optimize=False)
        return buf.getvalue(), img.width, img.height, "jpeg"


def _draw_cursor_win(img):
    """
    Рисует аппаратный курсор Windows поверх PIL-изображения.
    Использует ctypes напрямую — не зависит от pywin32.
    """
    import ctypes
    import ctypes.wintypes as wt
    from PIL import Image as PILImage

    # ── 1. Позиция и handle курсора ────────────────────────────────── #
    class CURSORINFO(ctypes.Structure):
        _fields_ = [("cbSize", wt.DWORD), ("flags", wt.DWORD),
                    ("hCursor", wt.HANDLE), ("ptScreenPos", wt.POINT)]

    ci = CURSORINFO()
    ci.cbSize = ctypes.sizeof(CURSORINFO)
    if not ctypes.windll.user32.GetCursorInfo(ctypes.byref(ci)):
        return img
    if not (ci.flags & 0x1):   # CURSOR_SHOWING = 1
        return img
    cx, cy = ci.ptScreenPos.x, ci.ptScreenPos.y

    # ── 2. Рендер курсора в HBITMAP через DrawIconEx ────────────────── #
    SIZE = 32
    user32  = ctypes.windll.user32
    gdi32   = ctypes.windll.gdi32

    hdc_screen = user32.GetDC(None)
    hdc_mem    = gdi32.CreateCompatibleDC(hdc_screen)

    class BITMAPINFOHEADER(ctypes.Structure):
        _fields_ = [("biSize",wt.DWORD),("biWidth",wt.LONG),("biHeight",wt.LONG),
                    ("biPlanes",wt.WORD),("biBitCount",wt.WORD),("biCompression",wt.DWORD),
                    ("biSizeImage",wt.DWORD),("biXPelsPerMeter",wt.LONG),
                    ("biYPelsPerMeter",wt.LONG),("biClrUsed",wt.DWORD),("biClrImportant",wt.DWORD)]

    bih = BITMAPINFOHEADER()
    bih.biSize = ctypes.sizeof(BITMAPINFOHEADER)
    bih.biWidth = SIZE; bih.biHeight = -SIZE   # top-down
    bih.biPlanes = 1; bih.biBitCount = 32; bih.biCompression = 0

    bits = ctypes.create_string_buffer(SIZE * SIZE * 4)
    hbmp = gdi32.CreateDIBSection(hdc_mem, ctypes.byref(bih), 0,
                                   ctypes.byref(ctypes.c_void_p()), None, 0)
    old  = gdi32.SelectObject(hdc_mem, hbmp)

    # Заливка прозрачным (ARGB = 0)
    gdi32.PatBlt(hdc_mem, 0, 0, SIZE, SIZE, 0x000042)  # BLACKNESS

    DI_NORMAL = 3
    user32.DrawIconEx(hdc_mem, 0, 0, ci.hCursor, SIZE, SIZE, 0, None, DI_NORMAL)

    # Читаем пиксели
    gdi32.GetDIBits(hdc_mem, hbmp, 0, SIZE, bits, ctypes.byref(bih), 0)

    gdi32.SelectObject(hdc_mem, old)
    gdi32.DeleteObject(hbmp)
    gdi32.DeleteDC(hdc_mem)
    user32.ReleaseDC(None, hdc_screen)

    # ── 3. Накладываем на кадр ──────────────────────────────────────── #
    try:
        # bits = BGRA, top-down
        cur_img = PILImage.frombuffer("RGBA", (SIZE, SIZE),
                                      bytes(bits), "raw", "BGRA", 0, 1)
        # Используем alpha-канал как маску
        r2, g2, b2, a2 = cur_img.split()
        # Для курсоров без альфа (старый стиль) — делаем всё непрозрачное видимым
        # Если альфа везде 0, значит DrawIconEx не поддержал ARGB — fallback
        if max(a2.getdata()) == 0:
            # XOR-маска: всё ненулевое = видимый пиксель
            rgb = cur_img.convert("RGB")
            mask_data = [255 if (r+g+b) > 0 else 0
                         for r,g,b in rgb.getdata()]
            from PIL import Image as _I
            mask = _I.new("L", (SIZE, SIZE))
            mask.putdata(mask_data)
            cur_img.putalpha(mask)

        base = img.convert("RGBA")
        base.paste(cur_img, (cx, cy), cur_img)
        img = base.convert("RGB")
    except Exception:
        pass

    return img


class ClientHandler(threading.Thread):
    def __init__(self, conn: socket.socket, addr: tuple, password_hash: str):
        super().__init__(daemon=True)
        self.conn          = conn
        self.addr          = addr
        self.password_hash = password_hash
        self._streaming    = False
        self._skip_auth    = False   # True в relay-режиме — агент уже аутентифицирован

    def run(self):
        print(f"[server] Подключение: {self.addr}")
        set_nodelay(self.conn)
        try:
            if not self._skip_auth and not self._authenticate():
                return
            while True:
                msg = recv_msg(self.conn)
                self._dispatch(msg)
        except ConnectionError:
            print(f"[server] Отключение: {self.addr}")
        except Exception as e:
            print(f"[server] Ошибка ({self.addr}): {e}")
        finally:
            self._streaming = False
            self.conn.close()

    def _authenticate(self):
        msg = recv_msg(self.conn)
        if msg["type"] != MsgType.AUTH:
            send_msg(self.conn, MsgType.AUTH_FAIL, {"reason": "expected auth"})
            return False
        if check_password(msg["payload"].get("password", ""), self.password_hash):
            send_msg(self.conn, MsgType.AUTH_OK, {"message": "Welcome!"})
            print(f"[server] Auth OK: {self.addr}")
            return True
        send_msg(self.conn, MsgType.AUTH_FAIL, {"reason": "wrong password"})
        return False

    def _dispatch(self, msg):
        t = msg["type"]
        p = msg.get("payload", {})
        m = {
            MsgType.PING:          lambda: send_msg(self.conn, MsgType.PONG, {}),
            MsgType.CMD:           lambda: self._cmd(p),
            MsgType.FILE_UPLOAD:   lambda: self._file_upload(p),
            MsgType.FILE_DOWNLOAD: lambda: self._file_download(p),
            MsgType.FILE_LIST:     lambda: self._file_list(p),
            MsgType.FILE_DELETE:   lambda: self._file_delete(p),
            MsgType.FILE_MKDIR:    lambda: self._file_mkdir(p),
            MsgType.FILE_RENAME:   lambda: self._file_rename(p),
            MsgType.FILE_ZIP:      lambda: self._file_zip(p),
            MsgType.FILE_ZIP_STREAM: lambda: self._file_zip_stream(p),
            MsgType.CHUNK_BEGIN:   lambda: self._chunk_begin(p),
            MsgType.CHUNK_DATA:    lambda: self._chunk_data(p),
            MsgType.CHUNK_END:     lambda: self._chunk_end(),
            MsgType.CHUNK_CANCEL:  lambda: self._chunk_cancel(),
            MsgType.SCREENSHOT:    lambda: self._screenshot(p),
            MsgType.STREAM_START:  lambda: self._stream_start(p),
            MsgType.STREAM_STOP:   lambda: self._stream_stop(),
            MsgType.PROC_LIST:     lambda: self._proc_list(),
            MsgType.PROC_KILL:     lambda: self._proc_kill(p),
            MsgType.MOUSE_MOVE:    lambda: self._mouse_move(p),
            MsgType.MOUSE_CLICK:   lambda: self._mouse_click(p),
            MsgType.MOUSE_SCROLL:  lambda: self._mouse_scroll(p),
            MsgType.MOUSE_DRAG:    lambda: self._mouse_drag(p),
            MsgType.KEY_PRESS:     lambda: self._key_press(p),
            MsgType.KEY_HOTKEY:    lambda: self._key_hotkey(p),
            MsgType.KEY_TYPE:      lambda: self._key_type(p),
            MsgType.CLIPBOARD_GET: lambda: self._clipboard_get(),
            MsgType.CLIPBOARD_SET: lambda: self._clipboard_set(p),
            MsgType.SYS_INFO:      lambda: self._sys_info(),
        }
        fn = m.get(t)
        if fn:
            fn()
        else:
            send_msg(self.conn, MsgType.ERROR, {"reason": f"unknown: {t}"})

    # ── Shell ─────────────────────────────────────────────────────────── #
    def _cmd(self, p):
        import subprocess
        try:
            # Windows cmd.exe выводит текст в кодировке системной codepage (CP866 для ru_RU).
            # text=False + ручное декодирование с errors='replace' предотвращает кракозябры.
            r = subprocess.run(
                p.get("command",""), shell=True, capture_output=True,
                text=False, timeout=60, cwd=p.get("cwd") or os.path.expanduser("~")
            )
            enc = "cp866" if IS_WIN else "utf-8"
            stdout = r.stdout.decode(enc, errors="replace") if r.stdout else ""
            stderr = r.stderr.decode(enc, errors="replace") if r.stderr else ""
            send_msg(self.conn, MsgType.CMD_RESULT, {
                "stdout": stdout, "stderr": stderr, "returncode": r.returncode,
            })
        except subprocess.TimeoutExpired:
            send_msg(self.conn, MsgType.ERROR, {"reason": "Timeout"})
        except Exception as e:
            send_msg(self.conn, MsgType.ERROR, {"reason": str(e)})

    # ── Files ──────────────────────────────────────────────────────────── #
    def _file_list(self, p):
        path = p.get("path") or os.path.expanduser("~")
        try:
            pp = Path(path)
            parent = str(pp.parent) if pp.parent != pp else None
            entries = []
            for e in sorted(pp.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
                try:
                    st = e.stat()
                    entries.append({"name": e.name, "type": "dir" if e.is_dir() else "file",
                                    "size": st.st_size, "mtime": int(st.st_mtime)})
                except PermissionError:
                    pass
            send_msg(self.conn, MsgType.FILE_DATA, {"path": str(pp), "entries": entries, "parent": parent})
        except Exception as e:
            send_msg(self.conn, MsgType.ERROR, {"reason": str(e)})

    def _file_upload(self, p):
        """Маленькие файлы (<4MB) — одним сообщением."""
        try:
            path = p["path"]; data = base64.b64decode(p["data"])
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            Path(path).write_bytes(data)
            send_msg(self.conn, MsgType.FILE_OK, {"path": path, "size": len(data)})
        except Exception as e:
            send_msg(self.conn, MsgType.ERROR, {"reason": str(e)})

    # ── Chunked upload (большие файлы) ─────────────────────────────────── #
    def _chunk_begin(self, p):
        """Начало чанковой загрузки. Открываем файл для записи."""
        try:
            path = p["path"]
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            self._chunk_path   = path
            self._chunk_fh     = open(path, "wb")
            self._chunk_total  = p.get("total_chunks", 0)
            self._chunk_idx    = 0
            self._chunk_bytes  = 0
            send_msg(self.conn, MsgType.CHUNK_ACK, {"index": -1})  # ready
        except Exception as e:
            send_msg(self.conn, MsgType.ERROR, {"reason": str(e)})

    def _chunk_data(self, p):
        """Один чанк данных. Пишем в файл и шлём ACK."""
        try:
            data = base64.b64decode(p["data"])
            self._chunk_fh.write(data)
            self._chunk_bytes += len(data)
            self._chunk_idx   += 1
            send_msg(self.conn, MsgType.CHUNK_ACK, {"index": p["index"]})
        except Exception as e:
            try: self._chunk_fh.close()
            except Exception: pass
            send_msg(self.conn, MsgType.ERROR, {"reason": str(e)})

    def _chunk_end(self):
        """Финализация: закрываем файл и сообщаем успех."""
        try:
            self._chunk_fh.close()
            send_msg(self.conn, MsgType.CHUNK_OK, {
                "path": self._chunk_path, "size": self._chunk_bytes
            })
        except Exception as e:
            send_msg(self.conn, MsgType.ERROR, {"reason": str(e)})

    def _chunk_cancel(self):
        """
        Оператор отменил загрузку — закрываем и удаляем частичный файл.
        После этого агент готов к новым командам на том же соединении.
        """
        path = getattr(self, "_chunk_path", None)
        fh   = getattr(self, "_chunk_fh",   None)
        try:
            if fh:
                fh.close()
                print(f"[handler/chunk_cancel] file handle closed: {path}")
        except Exception as e:
            print(f"[handler/chunk_cancel] close error: {e}")
        finally:
            self._chunk_fh = None
        if path:
            try:
                Path(path).unlink(missing_ok=True)
                print(f"[handler/chunk_cancel] partial file deleted: {path}")
            except Exception as e:
                print(f"[handler/chunk_cancel] delete error (file may still be locked): {e}")
        self._chunk_path  = None
        self._chunk_total = 0
        self._chunk_idx   = 0
        self._chunk_bytes = 0
        # Не отправляем ответ — relay не ждёт его при отмене

    # ── Zip ────────────────────────────────────────────────────────────── #
    def _file_zip(self, p):
        """Создать zip-архив на агенте из списка путей, сохранить в dest."""
        import zipfile
        try:
            paths = p.get("paths", [])
            dest  = p.get("dest", "")
            if not paths or not dest:
                send_msg(self.conn, MsgType.ERROR, {"reason": "paths and dest required"})
                return
            Path(dest).parent.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
                for fp in paths:
                    path = Path(fp)
                    if path.is_file():
                        zf.write(path, path.name)
                    elif path.is_dir():
                        for sub in path.rglob("*"):
                            if sub.is_file():
                                zf.write(sub, sub.relative_to(path.parent))
            send_msg(self.conn, MsgType.OK, {"dest": dest, "size": Path(dest).stat().st_size})
        except Exception as e:
            send_msg(self.conn, MsgType.ERROR, {"reason": str(e)})

    def _file_zip_stream(self, p):
        """Создать zip в памяти и отдать чанками оператору."""
        import zipfile, io
        try:
            paths = p.get("paths", [])
            if not paths:
                send_msg(self.conn, MsgType.ERROR, {"reason": "no paths"})
                return
            # Собираем zip в памяти
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                for fp in paths:
                    path = Path(fp)
                    if path.is_file():
                        zf.write(path, path.name)
                    elif path.is_dir():
                        for sub in path.rglob("*"):
                            if sub.is_file():
                                zf.write(sub, sub.relative_to(path.parent))
            data   = buf.getvalue()
            total  = len(data)
            chunks = [data[i:i+CHUNK_SIZE] for i in range(0, max(total,1), CHUNK_SIZE)]
            n      = len(chunks)

            # Мета-сообщение
            send_msg(self.conn, MsgType.FILE_DATA,
                     {"total_size": total, "total_chunks": n})

            for i, chunk in enumerate(chunks):
                send_msg(self.conn, MsgType.CHUNK_DATA,
                         {"index": i, "data": base64.b64encode(chunk).decode()})
                # Ждём ACK от клиента (или отмену)
                ack = recv_msg(self.conn)
                ack_type = ack.get("type")
                if ack_type == MsgType.ERROR:
                    print(f"[handler/zip_stream] error ack at chunk={i}, aborting")
                    return
                if ack_type == MsgType.DCHUNK_CANCEL:
                    print(f"[handler/zip_stream] cancel received at chunk={i}, aborting")
                    return

            send_msg(self.conn, MsgType.OK, {"total_size": total})
        except Exception as e:
            send_msg(self.conn, MsgType.ERROR, {"reason": str(e)})

    def _file_download(self, p):
        """Маленькие файлы (<4MB) — одним сообщением."""
        try:
            path = p["path"]
            data = Path(path).read_bytes()
            print(f"[file/download] path={path} size={len(data)}")
            if len(data) > 4 * 1024 * 1024:
                # Слишком большой — перенаправляем на чанковую отдачу
                print(f"[file/download] switching to dchunk path={path}")
                self._dchunk_send(path)
                return
            send_msg(self.conn, MsgType.FILE_DATA, {
                "path": path, "data": base64.b64encode(data).decode(), "size": len(data)
            })
            print(f"[file/download] sent single payload path={path} size={len(data)}")
        except Exception as e:
            print(f"[file/download] error: {e}")
            send_msg(self.conn, MsgType.ERROR, {"reason": str(e)})

    def _dchunk_send(self, path: str):
        """Чанковая отдача файла агентом → оператору."""
        from common.protocol import CHUNK_SIZE
        try:
            dchunk_begin  = getattr(MsgType, "DCHUNK_BEGIN",  "dchunk_begin")
            dchunk_data   = getattr(MsgType, "DCHUNK_DATA",   "dchunk_data")
            dchunk_end    = getattr(MsgType, "DCHUNK_END",    "dchunk_end")
            dchunk_cancel = getattr(MsgType, "DCHUNK_CANCEL", "dchunk_cancel")
            data   = Path(path).read_bytes()
            total  = len(data)
            chunks = [data[i:i+CHUNK_SIZE] for i in range(0, max(total, 1), CHUNK_SIZE)]
            print(f"[file/dchunk] begin path={path} total={total} chunks={len(chunks)} chunk_size={CHUNK_SIZE}")
            send_msg(self.conn, MsgType.DCHUNK_BEGIN, {
                "path": path, "total_size": total, "total_chunks": len(chunks)
            })
            # Ждём ACK на BEGIN
            ack = recv_msg(self.conn)
            print(f"[file/dchunk] ack begin type={ack.get('type')}")
            if ack.get("type") in (MsgType.ERROR, dchunk_cancel):
                send_msg(self.conn, MsgType.OK, {
                    "cancelled": True,
                    "path": path,
                    "stage": "begin_ack",
                })
                print(f"[file/dchunk] cancelled after begin ack: type={ack.get('type')} response sent")
                return

            for i, chunk in enumerate(chunks):
                send_msg(self.conn, dchunk_data, {
                    "index": i, "data": base64.b64encode(chunk).decode()
                })
                ack = recv_msg(self.conn)
                ack_type = ack.get("type")
                if i == 0 or i == len(chunks) - 1 or i % 20 == 0:
                    print(f"[file/dchunk] chunk={i+1}/{len(chunks)} size={len(chunk)} ack={ack_type}")
                if ack_type in (MsgType.ERROR, dchunk_cancel):
                    send_msg(self.conn, MsgType.OK, {
                        "cancelled": True,
                        "path": path,
                        "stage": "chunk_ack",
                        "chunk_index": i,
                    })
                    print(f"[file/dchunk] cancelled at chunk={i+1}/{len(chunks)} ack={ack_type} response sent")
                    return

            send_msg(self.conn, MsgType.DCHUNK_END, {"path": path, "size": total})
            print(f"[file/dchunk] normal-end path={path} size={total} response sent")
        except Exception as e:
            print(f"[file/dchunk] error: {e}")
            send_msg(self.conn, MsgType.ERROR, {"reason": str(e)})

    def _file_delete(self, p):
        import shutil
        try:
            t = Path(p["path"])
            shutil.rmtree(t) if t.is_dir() else t.unlink()
            send_msg(self.conn, MsgType.OK, {})
        except Exception as e:
            send_msg(self.conn, MsgType.ERROR, {"reason": str(e)})

    def _file_mkdir(self, p):
        try:
            Path(p["path"]).mkdir(parents=True, exist_ok=True)
            send_msg(self.conn, MsgType.OK, {})
        except Exception as e:
            send_msg(self.conn, MsgType.ERROR, {"reason": str(e)})

    def _file_rename(self, p):
        try:
            Path(p["src"]).rename(p["dst"])
            send_msg(self.conn, MsgType.OK, {})
        except Exception as e:
            send_msg(self.conn, MsgType.ERROR, {"reason": str(e)})

    # ── Screen ─────────────────────────────────────────────────────────── #
    def _screenshot(self, p):
        try:
            fmt      = p.get("fmt", "webp")
            capturer = p.get("capturer", "dxcam")
            data, w, h, fmt_used = _Capturer.grab(p.get("quality", 65), fmt, capturer)
            send_msg(self.conn, MsgType.SCREENSHOT_DATA, {
                "data": base64.b64encode(data).decode(),
                "width": w, "height": h, "fmt": fmt_used,
            })
        except Exception as e:
            send_msg(self.conn, MsgType.ERROR, {"reason": str(e)})

    def _stream_start(self, p):
        if self._streaming:
            return
        self._streaming = True
        quality  = p.get("quality", 50)
        fmt      = p.get("fmt", "webp")
        capturer = p.get("capturer", "dxcam")

        def loop():
            import time
            while self._streaming:
                t0 = time.perf_counter()
                try:
                    data, w, h, fmt_used = _Capturer.grab(quality, fmt, capturer)
                    send_msg(self.conn, MsgType.STREAM_FRAME, {
                        "data": base64.b64encode(data).decode(),
                        "width": w, "height": h, "fmt": fmt_used,
                    })
                except Exception:
                    self._streaming = False
                    break
                elapsed = time.perf_counter() - t0
                time.sleep(max(0, 0.033 - elapsed))

        threading.Thread(target=loop, daemon=True).start()

    def _stream_stop(self):
        self._streaming = False
        send_msg(self.conn, MsgType.OK, {})

    # ── Processes ──────────────────────────────────────────────────────── #
    def _proc_list(self):
        try:
            import psutil
            procs = []
            for pr in psutil.process_iter(["pid","name","username","cpu_percent","memory_info","status"]):
                try:
                    i = pr.info
                    procs.append({"pid": i["pid"], "name": i["name"], "user": i["username"],
                                  "cpu": i["cpu_percent"],
                                  "mem_mb": round(i["memory_info"].rss / 1048576, 1),
                                  "status": i["status"]})
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            send_msg(self.conn, MsgType.PROC_DATA, {"processes": procs})
        except Exception as e:
            send_msg(self.conn, MsgType.ERROR, {"reason": str(e)})

    def _proc_kill(self, p):
        try:
            import psutil
            psutil.Process(int(p["pid"])).terminate()
            send_msg(self.conn, MsgType.PROC_OK, {"pid": p["pid"], "action": "terminated"})
        except Exception as e:
            send_msg(self.conn, MsgType.ERROR, {"reason": str(e)})

    # ── Mouse ──────────────────────────────────────────────────────────── #
    def _mouse_move(self, p):
        try:
            import pyautogui
            pyautogui.FAILSAFE = False
            pyautogui.moveTo(p["x"], p["y"], duration=0)
            send_msg(self.conn, MsgType.OK, {})
        except Exception as e:
            send_msg(self.conn, MsgType.ERROR, {"reason": str(e)})

    def _mouse_click(self, p):
        try:
            import pyautogui
            pyautogui.FAILSAFE = False
            x, y = p.get("x"), p.get("y")
            if x is not None:
                pyautogui.click(x, y, clicks=p.get("clicks", 1), button=p.get("button", "left"))
            else:
                pyautogui.click(clicks=p.get("clicks", 1), button=p.get("button", "left"))
            send_msg(self.conn, MsgType.OK, {})
        except Exception as e:
            send_msg(self.conn, MsgType.ERROR, {"reason": str(e)})

    def _mouse_scroll(self, p):
        """Fast scroll: win32api on Windows, pyautogui fallback elsewhere."""
        try:
            amount = int(p.get("amount", 3))
            _fast_scroll(amount)
            # No send_msg — fire-and-forget from client side, skip TCP reply
            # But protocol requires a response, so send OK
            send_msg(self.conn, MsgType.OK, {})
        except Exception as e:
            send_msg(self.conn, MsgType.ERROR, {"reason": str(e)})

    def _mouse_drag(self, p):
        try:
            import pyautogui
            pyautogui.dragTo(p["x2"], p["y2"], duration=p.get("duration",0.2), button=p.get("button","left"))
            send_msg(self.conn, MsgType.OK, {})
        except Exception as e:
            send_msg(self.conn, MsgType.ERROR, {"reason": str(e)})

    # ── Keyboard ───────────────────────────────────────────────────────── #
    def _key_press(self, p):
        try:
            _kb_tap(p.get("key", ""))
            send_msg(self.conn, MsgType.OK, {})
        except Exception as e:
            send_msg(self.conn, MsgType.ERROR, {"reason": str(e)})

    def _key_hotkey(self, p):
        try:
            _kb_hotkey(p.get("keys", []))
            send_msg(self.conn, MsgType.OK, {})
        except Exception as e:
            send_msg(self.conn, MsgType.ERROR, {"reason": str(e)})

    def _key_type(self, p):
        try:
            _kb_type(p.get("text", ""))
            send_msg(self.conn, MsgType.OK, {})
        except Exception as e:
            send_msg(self.conn, MsgType.ERROR, {"reason": str(e)})

    # ── Clipboard ──────────────────────────────────────────────────────── #
    def _clipboard_get(self):
        try:
            import pyperclip
            send_msg(self.conn, MsgType.CLIPBOARD_DATA, {"text": pyperclip.paste()})
        except Exception as e:
            send_msg(self.conn, MsgType.ERROR, {"reason": str(e)})

    def _clipboard_set(self, p):
        try:
            import pyperclip
            pyperclip.copy(p.get("text",""))
            send_msg(self.conn, MsgType.OK, {})
        except Exception as e:
            send_msg(self.conn, MsgType.ERROR, {"reason": str(e)})

    # ── Sys info ───────────────────────────────────────────────────────── #
    def _sys_info(self):
        try:
            import psutil
            cpu  = psutil.cpu_percent(interval=0.5)
            mem  = psutil.virtual_memory()
            disk = psutil.disk_usage("/")
            send_msg(self.conn, MsgType.SYS_DATA, {
                "os": platform.system(), "os_version": platform.version(),
                "hostname": platform.node(), "arch": platform.machine(),
                "cpu_count": psutil.cpu_count(), "cpu_percent": cpu,
                "mem_total_gb": round(mem.total/1073741824,2),
                "mem_used_gb":  round(mem.used/1073741824,2),
                "mem_percent":  mem.percent,
                "disk_total_gb": round(disk.total/1073741824,2),
                "disk_used_gb":  round(disk.used/1073741824,2),
                "disk_percent":  disk.percent,
            })
        except Exception as e:
            send_msg(self.conn, MsgType.ERROR, {"reason": str(e)})
