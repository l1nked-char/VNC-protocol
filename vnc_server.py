"""
VNC-подобный сервер удалённого рабочего стола
Запускается на машине, которой нужно управлять.
Порт: 5900

Протокол (упрощённый RFB):
  1. Обмен версиями       -> "RFB 003.008\n"
  2. Согласование безопасности -> тип 1 (None) или 2 (VNC auth)
  3. Аутентификация       -> DES challenge/response (при наличии пароля)
  4. ClientInit / ServerInit  -> обмен разрешением экрана
  5. Основной обмен       -> кадры (сервер) + команды управления (клиент)

Использование:
  python vnc_server.py [--host 0.0.0.0] [--port 5900] [--password PASS]
                       [--fps 20] [--quality 50]
"""

import socket
import struct
import threading
import time
import io
import logging
import sys
import argparse
import os
import subprocess
import glob

IS_LINUX   = sys.platform.startswith("linux")
IS_WINDOWS = sys.platform == "win32"

# ─── Зависимости ─────────────────────────────────────────────────────────────
try:
    from PIL import Image
except ImportError:
    sys.exit("Установите Pillow:  pip install Pillow")

# ─── Логирование ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SERVER] %(levelname)-7s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("vnc.server")

# ─── Константы протокола ─────────────────────────────────────────────────────
VERSION        = b"RFB 003.008\n"
SECURITY_NONE  = 1
SECURITY_VNC   = 2

MSG_FRAME      = 0   # Server → Client: кадр экрана

CMD_MOUSE_MOVE   = 1  # Client → Server
CMD_MOUSE_CLICK  = 2
CMD_MOUSE_SCROLL = 3
CMD_KEY_EVENT    = 4

BUTTON_MAP = {0: "left", 1: "middle", 2: "right"}


# ─── DES для VNC-аутентификации ──────────────────────────────────────────────
def _mirror_bits(b: int) -> int:
    result = 0
    for i in range(8):
        if b & (1 << i):
            result |= 1 << (7 - i)
    return result


def vnc_des_encrypt(password: str, challenge: bytes) -> bytes:
    key_raw = password.encode("latin-1")[:8].ljust(8, b"\x00")
    key = bytes(_mirror_bits(b) for b in key_raw)
    try:
        from Crypto.Cipher import DES
        return DES.new(key, DES.MODE_ECB).encrypt(challenge)
    except ImportError:
        log.warning("pycryptodome не найден — используется XOR-заглушка вместо DES")
        return bytes(challenge[i] ^ key[i % 8] for i in range(16))


# ══════════════════════════════════════════════════════════════════════════════
#  LINUX-БЛОК: X11-окружение, захват экрана, управление вводом через Xlib
# ══════════════════════════════════════════════════════════════════════════════

# Глобальные объекты X11 (заполняются в _linux_init)
_xlib_display  = None   # Xlib.display.Display
_xlib_root     = None   # корневое окно
_xlib_screen   = None   # экран

# Метод захвата, выбранный при инициализации
_GRAB_METHOD: str = "unset"

# Бэкенд ввода (мышь + клавиатура)
_INPUT_BACKEND: str = "unset"

# Потоко-локальные объекты mss для Linux/X11.
# На Linux экземпляр mss нельзя безопасно создавать в одном потоке
# и использовать в другом: внутри у него thread-local состояние X11.
# Поэтому храним отдельный mss на каждый поток.
_MSS_TLS = threading.local()
_MSS_MONITOR = None
_MSS_MONITORS = []
_GRAB_LOCK = threading.Lock()


def _linux_find_xauthority() -> str | None:
    """
    Ищет файл .Xauthority в стандартных местах.
    Возвращает путь к файлу или None.
    """
    uid  = os.getuid()
    home = os.path.expanduser("~")

    candidates: list[str] = [
        # Стандартный файл пользователя
        os.path.join(home, ".Xauthority"),
        # GDM (GNOME Display Manager)
        f"/run/user/{uid}/gdm/Xauthority",
        f"/run/user/{uid}/.Xauthority",
        # KDE / SDDM
        f"/run/sddm/xauth_{os.environ.get('DISPLAY', ':0').replace(':', '')}",
    ]
    # LightDM
    candidates += glob.glob("/var/run/lightdm/*/authority")
    candidates += glob.glob("/var/run/lightdm/*/.Xauthority")
    # Временные файлы авторизации
    candidates += glob.glob("/tmp/xauth_*")
    candidates += glob.glob("/tmp/.gdm*")

    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


def _linux_setup_env() -> None:
    """
    Настраивает переменные окружения DISPLAY и XAUTHORITY.
    Должна вызываться ДО импорта python-xlib и mss.
    """
    # 1. DISPLAY
    if not os.environ.get("DISPLAY"):
        # Спрашиваем у loginctl / who, какой дисплей активен
        try:
            out = subprocess.check_output(
                ["loginctl", "show-session", "--property=Display", "--value"],
                stderr=subprocess.DEVNULL, timeout=3,
            ).decode().strip()
            if out:
                os.environ["DISPLAY"] = out
                log.info(f"DISPLAY определён через loginctl: {out}")
        except Exception:
            pass

    if not os.environ.get("DISPLAY"):
        os.environ["DISPLAY"] = ":0"
        log.info("DISPLAY не задан — использую :0 (по умолчанию)")

    # 2. XAUTHORITY
    if not os.environ.get("XAUTHORITY"):
        path = _linux_find_xauthority()
        if path:
            os.environ["XAUTHORITY"] = path
            log.info(f"XAUTHORITY → {path}")
        else:
            log.warning(
                "Файл .Xauthority не найден автоматически.\n"
                "Если ошибка сохраняется, выполните одно из:\n"
                "  export XAUTHORITY=$(ls /run/user/$(id -u)/gdm/Xauthority 2>/dev/null | head -1)\n"
                "  xhost +local:    # разрешить локальные подключения без авторизации\n"
                "  xhost +SI:localuser:$(whoami)"
            )


def _linux_init_xlib() -> bool:
    """
    Подключается к X11 через python-xlib.
    Возвращает True при успехе.
    Xlib используется для:
      • определения разрешения экрана
      • имитации ввода (XTEST extension)
      • поиска keysym-кодов
    """
    global _xlib_display, _xlib_root, _xlib_screen
    try:
        from Xlib import display as xdisplay
        from Xlib.ext import xtest as xtest_ext  # noqa: F401 (проверяем наличие)

        d = xdisplay.Display()
        if not d.query_extension("XTEST"):
            log.warning("X11 XTEST extension недоступен — ввод через Xlib невозможен")
            return False

        _xlib_display = d
        _xlib_screen  = d.screen()
        _xlib_root    = _xlib_screen.root
        log.info(
            f"python-xlib подключён: {d.get_display_name()}  "
            f"разрешение {_xlib_screen.width_in_pixels}×{_xlib_screen.height_in_pixels}"
        )
        return True
    except ImportError:
        log.info("python-xlib не установлен (pip install python-xlib) — используем pyautogui")
        return False
    except Exception as e:
        log.warning(f"python-xlib: не удалось подключиться к дисплею: {e}")
        return False


# ── Таблица keysym-имён → X11-keysym-коды ────────────────────────────────────
# Используется при вводе клавиш через Xlib.ext.xtest
_XLIB_KEYSYM_TABLE: dict[str, int] = {}


def _build_xlib_keysym_table() -> None:
    """Загружает стандартную таблицу keysym из Xlib.keysymdef."""
    global _XLIB_KEYSYM_TABLE
    try:
        from Xlib import keysymdef
        # keysymdef содержит подмодули: latin1, miscellany, xkb_keys и т.д.
        import importlib, pkgutil
        for finder, modname, _ in pkgutil.iter_modules(keysymdef.__path__):
            try:
                mod = importlib.import_module(f"Xlib.keysymdef.{modname}")
                for name, val in vars(mod).items():
                    if isinstance(val, int):
                        # Убираем префикс "XK_"
                        clean = name[3:] if name.startswith("XK_") else name
                        _XLIB_KEYSYM_TABLE[clean.lower()] = val
            except Exception:
                pass
        log.debug(f"Таблица keysym загружена: {len(_XLIB_KEYSYM_TABLE)} записей")
    except Exception as e:
        log.debug(f"Не удалось загрузить таблицу keysym: {e}")


# Маппинг имён pyautogui-клавиш → X11-keysym имена
_PYAUTOGUI_TO_XSYM: dict[str, str] = {
    "enter":       "Return",
    "backspace":   "BackSpace",
    "tab":         "Tab",
    "escape":      "Escape",
    "delete":      "Delete",
    "insert":      "Insert",
    "home":        "Home",
    "end":         "End",
    "pageup":      "Prior",
    "pagedown":    "Next",
    "up":          "Up",
    "down":        "Down",
    "left":        "Left",
    "right":       "Right",
    "f1":  "F1",  "f2":  "F2",  "f3":  "F3",  "f4":  "F4",
    "f5":  "F5",  "f6":  "F6",  "f7":  "F7",  "f8":  "F8",
    "f9":  "F9",  "f10": "F10", "f11": "F11", "f12": "F12",
    "shiftleft":   "Shift_L",   "shiftright":  "Shift_R",
    "ctrlleft":    "Control_L", "ctrlright":   "Control_R",
    "altleft":     "Alt_L",     "altright":    "Alt_R",
    "winleft":     "Super_L",   "winright":    "Super_R",
    "capslock":    "Caps_Lock", "numlock":     "Num_Lock",
    "scrolllock":  "Scroll_Lock",
    "printscreen": "Print",     "pause":       "Pause",
    "space":       "space",
    "-": "minus",   "=": "equal",   "[": "bracketleft",
    "]": "bracketright", "\\": "backslash", ";": "semicolon",
    "'": "apostrophe",   "`": "grave",      ",": "comma",
    ".": "period",       "/": "slash",
    "num0": "KP_0", "num1": "KP_1", "num2": "KP_2", "num3": "KP_3",
    "num4": "KP_4", "num5": "KP_5", "num6": "KP_6", "num7": "KP_7",
    "num8": "KP_8", "num9": "KP_9",
}


def _xlib_send_mouse_move(x: int, y: int) -> None:
    """Перемещает мышь через XTEST."""
    from Xlib.ext import xtest
    from Xlib import X
    xtest.fake_input(_xlib_display, X.MotionNotify, x=int(x), y=int(y))
    _xlib_display.sync()


def _xlib_send_mouse_button(btn_code: int, pressed: bool, x: int, y: int) -> None:
    """
    Нажимает или отпускает кнопку мыши через XTEST.
    btn_code: 1=левая, 2=средняя, 3=правая, 4=колесо вверх, 5=колесо вниз
    """
    from Xlib.ext import xtest
    from Xlib import X
    _xlib_send_mouse_move(x, y)
    event_type = X.ButtonPress if pressed else X.ButtonRelease
    xtest.fake_input(_xlib_display, event_type, detail=int(btn_code))
    _xlib_display.sync()


def _xlib_send_scroll(x: int, y: int, dy: int) -> None:
    """Прокрутка через имитацию нажатия кнопок 4 (вверх) и 5 (вниз)."""
    btn = 4 if dy > 0 else 5
    for _ in range(abs(dy)):
        _xlib_send_mouse_button(btn, True,  x, y)
        _xlib_send_mouse_button(btn, False, x, y)


def _xlib_send_key(key_name: str, pressed: bool) -> None:
    """
    Нажимает или отпускает клавишу через XTEST.
    key_name — имя клавиши в формате pyautogui (например 'enter', 'a', 'ctrlleft').
    """
    from Xlib import X
    from Xlib.ext import xtest

    # Переводим имя pyautogui → keysym-имя для Xlib
    xsym_name = _PYAUTOGUI_TO_XSYM.get(key_name.lower(), key_name)

    # Ищем keysym-код в таблице (ключ в нижнем регистре)
    keysym = _XLIB_KEYSYM_TABLE.get(xsym_name.lower())

    # Если не нашли — пробуем строчную букву напрямую
    if keysym is None and len(xsym_name) == 1:
        keysym = ord(xsym_name)

    if keysym is None:
        log.warning(f"Xlib: неизвестный keysym для клавиши [{key_name!r}]")
        return

    keycode = _xlib_display.keysym_to_keycode(keysym)
    if keycode == 0:
        log.warning(f"Xlib: нет keycode для keysym={keysym} (клавиша [{key_name!r}])")
        return

    event_type = X.KeyPress if pressed else X.KeyRelease
    xtest.fake_input(_xlib_display, event_type, detail=int(keycode))
    _xlib_display.sync()


# ── Инициализация бэкендов ────────────────────────────────────────────────────

def _init_input_backend() -> None:
    """Выбирает бэкенд управления мышью/клавиатурой."""
    global _INPUT_BACKEND

    if IS_LINUX and _xlib_display is not None:
        _INPUT_BACKEND = "xlib"
        _build_xlib_keysym_table()
        log.info("Бэкенд ввода: python-xlib (XTEST)")
        return

    # Fallback: pyautogui (работает на Windows и Linux с pyautogui>=0.9.54)
    try:
        import pyautogui
        pyautogui.FAILSAFE = False
        pyautogui.PAUSE    = 0
        _INPUT_BACKEND = "pyautogui"
        log.info("Бэкенд ввода: pyautogui")
    except ImportError:
        log.error("Ни один бэкенд ввода не доступен!\n"
                  "  pip install pyautogui\n"
                  "  pip install python-xlib   (Linux)")
        _INPUT_BACKEND = "none"


def _init_grab_backend() -> None:
    """
    Выбирает бэкенд захвата экрана.

    Linux:
      только mss через один заранее созданный экземпляр.
      Дополнительные fallback-ветки специально удалены.

    Важно: не делаем тестовый grab() прямо здесь.
    На некоторых Linux-конфигурациях XGetImage() падает для "общего"
    виртуального монитора monitors[0], но отдельные мониторы при этом
    работают нормально. Поэтому рабочий monitor выбираем лениво.

    Windows:
      оставляем прежний захват через Pillow ImageGrab.
    """
    global _GRAB_METHOD, _MSS_MONITOR, _MSS_MONITORS

    if IS_LINUX:
        session_type = (os.environ.get("XDG_SESSION_TYPE") or "").strip().lower()
        if session_type == "wayland":
            raise RuntimeError(
                "Текущая сессия Wayland. Для Linux в этом сервере оставлен только mss, "
                "а mss на Linux использует Xlib/XGetImage и в Wayland/XWayland часто не может "
                "захватить экран. Переключите графическую сессию на Xorg/X11."
            )

        try:
            import mss
        except ImportError as e:
            raise RuntimeError("Для Linux требуется mss: pip install mss") from e

        probe = None
        try:
            probe = mss.mss()
            _MSS_MONITORS = [dict(mon) for mon in probe.monitors]
            _MSS_MONITOR = None
        except Exception:
            _MSS_MONITOR = None
            _MSS_MONITORS = []
            raise
        finally:
            try:
                if probe is not None:
                    probe.close()
            except Exception:
                pass

        _GRAB_METHOD = "mss"
        log.info(
            "Бэкенд захвата экрана: mss (Linux/X11, monitors=%d)",
            len(_MSS_MONITORS),
        )
        return

    if IS_WINDOWS:
        try:
            from PIL import ImageGrab
            img = ImageGrab.grab()
            img.close()
        except Exception as e:
            raise RuntimeError(f"PIL ImageGrab недоступен: {e}") from e

        _GRAB_METHOD = "pil"
        log.info("Бэкенд захвата экрана: PIL ImageGrab")
        return

    raise RuntimeError("Поддерживаются только Linux и Windows")


def _get_thread_mss():
    """
    Возвращает экземпляр mss, привязанный к текущему потоку.
    Для Linux это обязательно: объект mss нельзя безопасно шарить
    между потоками из-за внутреннего thread-local состояния.
    """
    inst = getattr(_MSS_TLS, "instance", None)
    if inst is None:
        import mss
        inst = mss.mss()
        _MSS_TLS.instance = inst
    return inst


def _close_thread_mss() -> None:
    """Закрывает mss текущего потока, если он был создан."""
    inst = getattr(_MSS_TLS, "instance", None)
    if inst is not None:
        try:
            inst.close()
        except Exception:
            pass
        try:
            delattr(_MSS_TLS, "instance")
        except Exception:
            _MSS_TLS.instance = None


def _linux_monitor_candidates() -> list[dict]:
    """
    Возвращает список кандидатов для mss.grab().

    Порядок важен:
      1. Уже найденный рабочий монитор.
      2. Отдельные физические мониторы (1..N).
      3. Общий виртуальный монитор (0).
      4. Геометрия Xlib-экрана как ручной fallback.
    """
    seen: set[tuple[int, int, int, int]] = set()
    result: list[dict] = []

    def add(mon: dict | None) -> None:
        if not mon:
            return
        key = (
            int(mon.get("left", 0)),
            int(mon.get("top", 0)),
            int(mon.get("width", 0)),
            int(mon.get("height", 0)),
        )
        if key[2] <= 0 or key[3] <= 0 or key in seen:
            return
        seen.add(key)
        result.append({
            "left": key[0],
            "top": key[1],
            "width": key[2],
            "height": key[3],
        })

    add(_MSS_MONITOR)

    if _MSS_MONITORS:
        for mon in _MSS_MONITORS[1:]:
            add(mon)
        add(_MSS_MONITORS[0])

    if _xlib_screen is not None:
        add({
            "left": 0,
            "top": 0,
            "width": int(_xlib_screen.width_in_pixels),
            "height": int(_xlib_screen.height_in_pixels),
        })

    return result


# ── Захват экрана ─────────────────────────────────────────────────────────────

def grab_screen() -> Image.Image:
    """
    Потокобезопасный снимок экрана.

    Linux:
      используется один общий экземпляр mss, созданный при инициализации.
      Рабочий monitor подбирается лениво и запоминается.

    Windows:
      оставляем Pillow ImageGrab.
    """
    global _MSS_MONITOR

    if _GRAB_METHOD == "mss":
        sct = _get_thread_mss()
        candidates = _linux_monitor_candidates()
        errors: list[str] = []

        for mon in candidates:
            try:
                raw = sct.grab(mon)
                with _GRAB_LOCK:
                    _MSS_MONITOR = dict(mon)
                return Image.frombytes("RGB", raw.size, raw.bgra, "raw", "BGRX")
            except Exception as e:
                errors.append(f"{mon} -> {e}")

        raise RuntimeError(
            "mss не смог захватить экран ни по одному кандидату: " + " | ".join(errors)
        )

    if _GRAB_METHOD == "pil":
        from PIL import ImageGrab
        return ImageGrab.grab()

    raise RuntimeError(f"Бэкенд захвата не инициализирован (grab_method={_GRAB_METHOD!r})")

# ── Универсальные функции ввода ───────────────────────────────────────────────

def input_mouse_move(x: int, y: int) -> None:
    if _INPUT_BACKEND == "xlib":
        _xlib_send_mouse_move(x, y)
    else:
        import pyautogui
        pyautogui.moveTo(x, y, _pause=False)


def input_mouse_button(btn: int, pressed: bool, x: int, y: int) -> None:
    if _INPUT_BACKEND == "xlib":
        _xlib_send_mouse_button(btn + 1, pressed, x, y)  # Xlib: кнопки с 1
    else:
        import pyautogui
        button = BUTTON_MAP.get(btn, "left")
        if pressed:
            pyautogui.mouseDown(x=x, y=y, button=button, _pause=False)
        else:
            pyautogui.mouseUp(x=x, y=y, button=button, _pause=False)


def input_mouse_scroll(x: int, y: int, dy: int) -> None:
    if _INPUT_BACKEND == "xlib":
        _xlib_send_scroll(x, y, dy)
    else:
        import pyautogui
        pyautogui.scroll(int(dy), x=x, y=y, _pause=False)


def input_key(key_name: str, pressed: bool) -> None:
    if _INPUT_BACKEND == "xlib":
        _xlib_send_key(key_name, pressed)
    else:
        import pyautogui
        if pressed:
            pyautogui.keyDown(key_name)
        else:
            pyautogui.keyUp(key_name)


# ── Точка инициализации всех бэкендов ─────────────────────────────────────────

def init_platform() -> None:
    """
    Вызывается один раз перед запуском сервера.
    Настраивает X11-окружение (Linux) и выбирает бэкенды.
    """
    if IS_LINUX:
        log.info("─── Инициализация Linux/X11 ───")
        _linux_setup_env()
        _linux_init_xlib()
    elif IS_WINDOWS:
        log.info("─── Платформа: Windows ───")
    else:
        raise RuntimeError("Поддерживаются только Linux и Windows")

    _init_input_backend()
    _init_grab_backend()

    log.info(
        f"Бэкенды: захват=[{_GRAB_METHOD}]  ввод=[{_INPUT_BACKEND}]"
    )


# ─── Сессия клиента ──────────────────────────────────────────────────────────
class ClientSession:
    """Обрабатывает одно клиентское подключение в отдельных потоках."""

    def __init__(self, sock: socket.socket, addr, password: str,
                 fps: int, quality: int):
        self.sock     = sock
        self.addr     = addr
        self.password = password
        self.interval = 1.0 / max(1, fps)
        self.quality  = max(1, min(95, quality))
        self.alive    = False
        self._lock    = threading.Lock()   # для потокобезопасной отправки

    # ── Сетевые примитивы ──────────────────────────────────────────────────
    def _send(self, data: bytes) -> None:
        with self._lock:
            self.sock.sendall(data)

    def _recv(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("Соединение закрыто")
            buf += chunk
        return buf

    # ── Точка входа ────────────────────────────────────────────────────────
    def run(self) -> None:
        try:
            self._handshake()
            self.alive = True
            log.info(f"[{self.addr}] Сессия запущена (fps={int(1/self.interval)}, q={self.quality})")

            # Поток отправки кадров
            ft = threading.Thread(target=self._frame_loop, name="FrameSender", daemon=True)
            ft.start()

            # Основной поток: приём команд
            self._cmd_loop()

        except ConnectionError as e:
            log.info(f"[{self.addr}] Отключение: {e}")
        except Exception as e:
            log.exception(f"[{self.addr}] Ошибка сессии: {e}")
        finally:
            self.alive = False
            _close_thread_mss()
            try:
                self.sock.close()
            except Exception:
                pass
            log.info(f"[{self.addr}] Сессия завершена")

    # ── RFB-рукопожатие ────────────────────────────────────────────────────
    def _handshake(self) -> None:
        # 1. Обмен версиями
        self._send(VERSION)
        cv = self._recv(12)
        log.info(f"[{self.addr}] Версия клиента: {cv.strip().decode()}")

        # 2. Согласование безопасности
        if self.password:
            self._send(struct.pack("BB", 1, SECURITY_VNC))
        else:
            self._send(struct.pack("BB", 1, SECURITY_NONE))

        chosen = self._recv(1)[0]
        log.info(f"[{self.addr}] Выбран тип безопасности: {chosen}")

        # 3. Аутентификация
        if chosen == SECURITY_VNC:
            if not self.password:
                raise ValueError("Клиент запросил VNC-аутентификацию, но пароль не задан")
            challenge = os.urandom(16)
            self._send(challenge)
            response  = self._recv(16)
            expected  = vnc_des_encrypt(self.password, challenge)
            if response == expected:
                self._send(struct.pack(">I", 0))  # успех
                log.info(f"[{self.addr}] Аутентификация прошла успешно")
            else:
                self._send(struct.pack(">I", 1))  # ошибка
                raise PermissionError("Неверный пароль")
        elif chosen == SECURITY_NONE:
            self._send(struct.pack(">I", 0))  # успех без проверки
        else:
            raise ValueError(f"Неизвестный тип безопасности: {chosen}")

        # 4. ClientInit
        self._recv(1)  # shared-flag (игнорируем)

        # 5. ServerInit
        screen = grab_screen()
        w, h   = screen.size

        # PixelFormat: 32bpp, RGB, big-endian=False, true-colour=True
        pixel_format = struct.pack(
            ">BBBB HHH BBB 3x",
            32, 24, 0, 1,       # bpp, depth, big-endian, true-colour
            255, 255, 255,      # r/g/b-max
            16, 8, 0,           # r/g/b-shift
        )
        name = b"PythonVNC"
        server_init = (
            struct.pack(">HH", w, h)
            + pixel_format
            + struct.pack(">I", len(name))
            + name
        )
        self._send(server_init)
        self.server_w, self.server_h = w, h
        log.info(f"[{self.addr}] ServerInit отправлен: {w}×{h}")

    # ── Поток отправки кадров ───────────────────────────────────────────────
    def _frame_loop(self) -> None:
        log.debug(f"[{self.addr}] Поток кадров запущен")
        frames_sent  = 0
        fps_ts       = time.time()

        while self.alive:
            t0 = time.time()
            try:
                img  = grab_screen()
                buf  = io.BytesIO()
                img.save(buf, "JPEG", quality=self.quality, optimize=False)
                data = buf.getvalue()
                self._send(struct.pack(">BI", MSG_FRAME, len(data)) + data)
                frames_sent += 1
            except Exception as e:
                log.error(f"[{self.addr}] Ошибка отправки кадра: {e}")
                self.alive = False
                break

            # Лог FPS раз в 5 секунд
            if time.time() - fps_ts >= 5:
                fps = frames_sent / (time.time() - fps_ts)
                log.info(f"[{self.addr}] Реальный FPS: {fps:.1f}")
                frames_sent = 0
                fps_ts = time.time()

            elapsed = time.time() - t0
            sleep_t = self.interval - elapsed
            if sleep_t > 0:
                time.sleep(sleep_t)

        _close_thread_mss()
        log.debug(f"[{self.addr}] Поток кадров остановлен")

    # ── Цикл приёма команд ──────────────────────────────────────────────────
    def _cmd_loop(self) -> None:
        log.debug(f"[{self.addr}] Цикл команд запущен")
        while self.alive:
            cmd = self._recv(1)[0]

            # Перемещение мыши
            if cmd == CMD_MOUSE_MOVE:
                x, y = struct.unpack(">HH", self._recv(4))
                input_mouse_move(x, y)
                log.debug(f"[{self.addr}] MOUSE_MOVE ({x}, {y})")

            # Нажатие/отпускание кнопки мыши
            elif cmd == CMD_MOUSE_CLICK:
                btn, pressed, x, y = struct.unpack(">BBHH", self._recv(6))
                input_mouse_button(btn, bool(pressed), x, y)
                action = "↓" if pressed else "↑"
                log.info(f"[{self.addr}] MOUSE_CLICK {action} btn={btn} ({x},{y})")

            # Прокрутка колёсика
            elif cmd == CMD_MOUSE_SCROLL:
                x, y, dy = struct.unpack(">HHh", self._recv(6))
                input_mouse_scroll(x, y, int(dy))
                log.info(f"[{self.addr}] MOUSE_SCROLL ({x},{y}) dy={dy}")

            # Клавиатурное событие
            elif cmd == CMD_KEY_EVENT:
                pressed, klen = struct.unpack(">BH", self._recv(3))
                key = self._recv(klen).decode("utf-8", errors="replace")
                try:
                    input_key(key, bool(pressed))
                    action = "↓" if pressed else "↑"
                    log.info(f"[{self.addr}] KEY {action} [{key}]")
                except Exception as e:
                    log.warning(f"[{self.addr}] Ошибка ввода клавиши [{key}]: {e}")

            else:
                log.warning(f"[{self.addr}] Неизвестный тип команды: {cmd}")

        log.debug(f"[{self.addr}] Цикл команд остановлен")


# ─── Главный сервер ──────────────────────────────────────────────────────────
class VNCServer:
    def __init__(self, host="0.0.0.0", port=5900, password="",
                 fps=20, quality=50):
        self.host     = host
        self.port     = port
        self.password = password
        self.fps      = fps
        self.quality  = quality

    def run(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen(5)
        auth_info = f"пароль={'***' if self.password else 'нет'}"
        log.info(f"VNC-сервер запущен: {self.host}:{self.port}  ({auth_info})")
        log.info(f"Параметры: FPS={self.fps}, качество JPEG={self.quality}%")

        try:
            while True:
                sock, addr = srv.accept()
                log.info(f"Новое подключение: {addr}")
                session = ClientSession(
                    sock, addr, self.password, self.fps, self.quality
                )
                t = threading.Thread(
                    target=session.run,
                    name=f"Client-{addr}",
                    daemon=True,
                )
                t.start()
        except KeyboardInterrupt:
            log.info("Сервер остановлен по Ctrl+C")
        finally:
            srv.close()


# ─── Точка входа ─────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="VNC-подобный сервер удалённого управления"
    )
    parser.add_argument("--host",     default="0.0.0.0",  help="IP-адрес прослушивания")
    parser.add_argument("--port",     default=5900, type=int, help="Порт (по умолчанию 5900)")
    parser.add_argument("--password", default="",          help="Пароль (пусто = без аутентификации)")
    parser.add_argument("--fps",      default=20,  type=int, help="Кадров в секунду (по умолчанию 20)")
    parser.add_argument("--quality",  default=50,  type=int, help="Качество JPEG 1-95 (по умолчанию 50)")
    args = parser.parse_args()

    # Инициализация платформы (X11 на Linux, выбор бэкендов захвата и ввода)
    init_platform()

    server = VNCServer(
        host=args.host,
        port=args.port,
        password=args.password,
        fps=args.fps,
        quality=args.quality,
    )
    server.run()


if __name__ == "__main__":
    main()
