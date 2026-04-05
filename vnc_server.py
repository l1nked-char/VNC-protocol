from __future__ import annotations

import argparse
import glob
import hashlib
import io
import importlib
import logging
import os
import pkgutil
import socket
import struct
import subprocess
import sys
import threading
import time

IS_LINUX = sys.platform.startswith("linux")
IS_WINDOWS = sys.platform == "win32"

try:
    from PIL import Image
except ImportError:
    sys.exit("Установите Pillow:  pip install Pillow")

from vnc_shared import (
    BUTTON_MAP,
    CMD_KEY_EVENT,
    CMD_MOUSE_CLICK,
    CMD_MOUSE_MOVE,
    CMD_MOUSE_SCROLL,
    MSG_FRAME,
    MSG_FRAME_DELTA,
    PYAUTOGUI_TO_XSYM,
    SECURITY_NONE,
    SECURITY_VNC,
    TILE_SIZE,
    VERSION,
    vnc_des_encrypt,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SERVER] %(levelname)-7s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("vnc.server")

_xlib_display = None
_xlib_root = None
_xlib_screen = None
_XLIB_KEYSYM_TABLE: dict[str, int] = {}

_GRAB_METHOD = "unset"
_INPUT_BACKEND = "unset"

_MSS_TLS = threading.local()
_MSS_MONITOR: dict | None = None
_MSS_MONITORS: list[dict] = []
_GRAB_LOCK = threading.Lock()


def _linux_find_xauthority() -> str | None:
    """Ищет XAUTHORITY в типовых местах Linux-системы."""
    uid = os.getuid()
    home = os.path.expanduser("~")

    candidates: list[str] = [
        os.path.join(home, ".Xauthority"),
        f"/run/user/{uid}/gdm/Xauthority",
        f"/run/user/{uid}/.Xauthority",
        f"/run/sddm/xauth_{os.environ.get('DISPLAY', ':0').replace(':', '')}",
    ]
    candidates.extend(glob.glob("/var/run/lightdm/*/authority"))
    candidates.extend(glob.glob("/var/run/lightdm/*/.Xauthority"))
    candidates.extend(glob.glob("/tmp/xauth_*"))
    candidates.extend(glob.glob("/tmp/.gdm*"))

    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


def _linux_setup_env() -> None:
    """Настраивает DISPLAY и XAUTHORITY перед инициализацией X11-бэкендов."""
    if not os.environ.get("DISPLAY"):
        try:
            output = subprocess.check_output(
                ["loginctl", "show-session", "--property=Display", "--value"],
                stderr=subprocess.DEVNULL,
                timeout=3,
            ).decode().strip()
            if output:
                os.environ["DISPLAY"] = output
                log.info("DISPLAY определён через loginctl: %s", output)
        except Exception:
            pass

    if not os.environ.get("DISPLAY"):
        os.environ["DISPLAY"] = ":0"
        log.info("DISPLAY не задан — использую :0")

    if not os.environ.get("XAUTHORITY"):
        path = _linux_find_xauthority()
        if path:
            os.environ["XAUTHORITY"] = path
            log.info("XAUTHORITY → %s", path)
        else:
            log.warning("Файл .Xauthority не найден автоматически")


def _linux_init_xlib() -> bool:
    """Подключается к X11 и проверяет наличие расширения XTEST."""
    global _xlib_display, _xlib_root, _xlib_screen
    try:
        from Xlib import display as xdisplay
        from Xlib.ext import xtest

        _ = xtest
        display = xdisplay.Display()
        if not display.query_extension("XTEST"):
            log.warning("X11 XTEST extension недоступен")
            return False

        _xlib_display = display
        _xlib_screen = display.screen()
        _xlib_root = _xlib_screen.root
        log.info(
            "python-xlib подключён: %s  разрешение %s×%s",
            display.get_display_name(),
            _xlib_screen.width_in_pixels,
            _xlib_screen.height_in_pixels,
        )
        return True
    except ImportError:
        log.info("python-xlib не установлен — используем pyautogui")
        return False
    except Exception as error:
        log.warning("python-xlib: не удалось подключиться к дисплею: %s", error)
        return False


def _build_xlib_keysym_table() -> None:
    """Загружает таблицу keysym-значений из python-xlib."""
    global _XLIB_KEYSYM_TABLE
    try:
        from Xlib import keysymdef

        for _, module_name, _ in pkgutil.iter_modules(keysymdef.__path__):
            try:
                module = importlib.import_module(f"Xlib.keysymdef.{module_name}")
                for name, value in vars(module).items():
                    if isinstance(value, int):
                        clean_name = name[3:] if name.startswith("XK_") else name
                        _XLIB_KEYSYM_TABLE[clean_name.lower()] = value
            except Exception:
                pass
        log.debug("Таблица keysym загружена: %s записей", len(_XLIB_KEYSYM_TABLE))
    except Exception as error:
        log.debug("Не удалось загрузить таблицу keysym: %s", error)


def _xlib_send_mouse_move(x: int, y: int) -> None:
    """Перемещает мышь через XTEST."""
    from Xlib import X
    from Xlib.ext import xtest

    xtest.fake_input(_xlib_display, X.MotionNotify, 0, 0, 0, int(x), int(y))
    _xlib_display.sync()


def _xlib_send_mouse_button(button_code: int, pressed: bool, x: int, y: int) -> None:
    """Нажимает или отпускает кнопку мыши через XTEST."""
    from Xlib import X
    from Xlib.ext import xtest

    _xlib_send_mouse_move(x, y)
    event_type = X.ButtonPress if pressed else X.ButtonRelease
    xtest.fake_input(_xlib_display, event_type, detail=int(button_code))
    _xlib_display.sync()


def _xlib_send_scroll(x: int, y: int, delta_y: int) -> None:
    """Прокручивает колесо мыши через имитацию кнопок 4 и 5."""
    button_code = 4 if delta_y > 0 else 5
    for _ in range(abs(delta_y)):
        _xlib_send_mouse_button(button_code, True, x, y)
        _xlib_send_mouse_button(button_code, False, x, y)


def _xlib_send_key(key_name: str, pressed: bool) -> None:
    """Нажимает или отпускает клавишу через XTEST."""
    from Xlib import X
    from Xlib.ext import xtest

    xlib_name = PYAUTOGUI_TO_XSYM.get(key_name.lower(), key_name)
    keysym = _XLIB_KEYSYM_TABLE.get(xlib_name.lower())

    if keysym is None and len(xlib_name) == 1:
        keysym = ord(xlib_name)
    if keysym is None:
        log.warning("Xlib: неизвестный keysym для клавиши %r", key_name)
        return

    keycode = _xlib_display.keysym_to_keycode(keysym)
    if keycode == 0:
        log.warning("Xlib: нет keycode для keysym=%s (%r)", keysym, key_name)
        return

    event_type = X.KeyPress if pressed else X.KeyRelease
    xtest.fake_input(_xlib_display, event_type, detail=int(keycode))
    _xlib_display.sync()


def _init_input_backend() -> None:
    """Выбирает бэкенд эмуляции мыши и клавиатуры."""
    global _INPUT_BACKEND

    if IS_LINUX and _xlib_display is not None:
        _INPUT_BACKEND = "xlib"
        _build_xlib_keysym_table()
        log.info("Бэкенд ввода: python-xlib (XTEST)")
        return

    try:
        import pyautogui

        pyautogui.FAILSAFE = False
        pyautogui.PAUSE = 0
        _INPUT_BACKEND = "pyautogui"
        log.info("Бэкенд ввода: pyautogui")
    except ImportError:
        log.error("Ни один бэкенд ввода не доступен")
        _INPUT_BACKEND = "none"


def _init_grab_backend() -> None:
    """Выбирает бэкенд захвата экрана для текущей платформы."""
    global _GRAB_METHOD, _MSS_MONITOR, _MSS_MONITORS

    if IS_LINUX:
        session_type = (os.environ.get("XDG_SESSION_TYPE") or "").strip().lower()
        if session_type == "wayland":
            raise RuntimeError(
                "Текущая сессия Wayland. Для Linux оставлен только mss/X11. "
                "Переключите графическую сессию на Xorg/X11."
            )

        try:
            import mss
        except ImportError as error:
            raise RuntimeError("Для Linux требуется mss: pip install mss") from error

        probe = None
        try:
            probe = mss.mss()
            _MSS_MONITORS = [dict(monitor) for monitor in probe.monitors]
            _MSS_MONITOR = None
        finally:
            if probe is not None:
                try:
                    probe.close()
                except Exception:
                    pass

        _GRAB_METHOD = "mss"
        log.info("Бэкенд захвата экрана: mss (monitors=%s)", len(_MSS_MONITORS))
        return

    if IS_WINDOWS:
        try:
            from PIL import ImageGrab

            image = ImageGrab.grab()
            image.close()
        except Exception as error:
            raise RuntimeError(f"PIL ImageGrab недоступен: {error}") from error

        _GRAB_METHOD = "pil"
        log.info("Бэкенд захвата экрана: PIL ImageGrab")
        return

    raise RuntimeError("Поддерживаются только Linux и Windows")


def _get_thread_mss():
    """Возвращает экземпляр mss, привязанный к текущему потоку."""
    instance = getattr(_MSS_TLS, "instance", None)
    if instance is None:
        import mss

        instance = mss.mss()
        _MSS_TLS.instance = instance
    return instance


def _close_thread_mss() -> None:
    """Закрывает mss текущего потока, если он был создан."""
    instance = getattr(_MSS_TLS, "instance", None)
    if instance is not None:
        try:
            instance.close()
        except Exception:
            pass
        try:
            delattr(_MSS_TLS, "instance")
        except Exception:
            _MSS_TLS.instance = None


def _linux_monitor_candidates() -> list[dict]:
    """Формирует список геометрий, которые можно попробовать для mss.grab."""
    seen: set[tuple[int, int, int, int]] = set()
    result: list[dict] = []

    def add(monitor: dict | None) -> None:
        if not monitor:
            return
        key = (
            int(monitor.get("left", 0)),
            int(monitor.get("top", 0)),
            int(monitor.get("width", 0)),
            int(monitor.get("height", 0)),
        )
        if key[2] <= 0 or key[3] <= 0 or key in seen:
            return
        seen.add(key)
        result.append({"left": key[0], "top": key[1], "width": key[2], "height": key[3]})

    add(_MSS_MONITOR)

    if _MSS_MONITORS:
        for monitor in _MSS_MONITORS[1:]:
            add(monitor)
        add(_MSS_MONITORS[0])

    if _xlib_screen is not None:
        add(
            {
                "left": 0,
                "top": 0,
                "width": int(_xlib_screen.width_in_pixels),
                "height": int(_xlib_screen.height_in_pixels),
            }
        )

    return result


def grab_screen() -> Image.Image:
    """Делает снимок экрана через выбранный бэкенд."""
    global _MSS_MONITOR

    if _GRAB_METHOD == "mss":
        sct = _get_thread_mss()
        errors: list[str] = []
        for monitor in _linux_monitor_candidates():
            try:
                raw = sct.grab(monitor)
                with _GRAB_LOCK:
                    _MSS_MONITOR = dict(monitor)
                return Image.frombytes("RGB", raw.size, raw.bgra, "raw", "BGRX")
            except Exception as error:
                errors.append(f"{monitor} -> {error}")
        raise RuntimeError("mss не смог захватить экран: " + " | ".join(errors))

    if _GRAB_METHOD == "pil":
        from PIL import ImageGrab

        return ImageGrab.grab()

    raise RuntimeError(f"Бэкенд захвата не инициализирован: {_GRAB_METHOD!r}")


def input_mouse_move(x: int, y: int) -> None:
    """Перемещает курсор мыши через выбранный бэкенд ввода."""
    if _INPUT_BACKEND == "xlib":
        _xlib_send_mouse_move(x, y)
        return

    import pyautogui

    pyautogui.moveTo(x, y, _pause=False)


def input_mouse_button(button: int, pressed: bool, x: int, y: int) -> None:
    """Нажимает или отпускает кнопку мыши через выбранный бэкенд ввода."""
    if _INPUT_BACKEND == "xlib":
        _xlib_send_mouse_button(button + 1, pressed, x, y)
        return

    import pyautogui

    button_name = BUTTON_MAP.get(button, "left")
    if pressed:
        pyautogui.mouseDown(x=x, y=y, button=button_name, _pause=False)
    else:
        pyautogui.mouseUp(x=x, y=y, button=button_name, _pause=False)


def input_mouse_scroll(x: int, y: int, delta_y: int) -> None:
    """Прокручивает колесо мыши через выбранный бэкенд ввода."""
    if _INPUT_BACKEND == "xlib":
        _xlib_send_scroll(x, y, delta_y)
        return

    import pyautogui

    pyautogui.scroll(int(delta_y), x=x, y=y, _pause=False)


def input_key(key_name: str, pressed: bool) -> None:
    """Нажимает или отпускает клавишу через выбранный бэкенд ввода."""
    if _INPUT_BACKEND == "xlib":
        _xlib_send_key(key_name, pressed)
        return

    import pyautogui

    if pressed:
        pyautogui.keyDown(key_name)
    else:
        pyautogui.keyUp(key_name)


def init_platform() -> None:
    """Инициализирует окружение X11 и выбирает бэкенды захвата и ввода."""
    if IS_LINUX:
        log.info("Инициализация Linux/X11")
        _linux_setup_env()
        _linux_init_xlib()
    elif IS_WINDOWS:
        log.info("Платформа: Windows")
    else:
        raise RuntimeError("Поддерживаются только Linux и Windows")

    _init_input_backend()
    _init_grab_backend()
    log.info("Бэкенды: захват=[%s] ввод=[%s]", _GRAB_METHOD, _INPUT_BACKEND)


class DeltaEncoder:
    """Кодирует экран как дельту: отправляет только изменившиеся тайлы.

    Алгоритм:
      1. Делим кадр на тайлы tile_size×tile_size пикселей.
      2. Для каждого тайла считаем MD5-хэш его сырых RGB-байт (без PIL-объекта).
      3. Сравниваем с хэшем из предыдущего кадра; изменившиеся кодируем в JPEG.
      4. Собираем пакет MSG_FRAME_DELTA: количество тайлов + координаты + JPEG.
      5. Каждые FULL_FRAME_EVERY кадров принудительно отправляем полный кадр
         (для восстановления после возможных потерь/рассинхронизации).
    """

    FULL_FRAME_EVERY = 300  # принудительный полный кадр раз в N кадров (~15 сек при 20 fps)

    def __init__(self, quality: int, tile_size: int = TILE_SIZE) -> None:
        self.quality = quality
        self.tile_size = tile_size
        # хэши тайлов предыдущего кадра: (tile_x, tile_y) -> md5-digest (bytes)
        self._tile_hashes: dict[tuple[int, int], bytes] = {}
        self._prev_size: tuple[int, int] = (0, 0)
        self._frame_count = 0

    def encode(self, image: "Image.Image") -> tuple[int, bytes]:
        """Возвращает (msg_type, payload).

        msg_type = MSG_FRAME       — полный кадр (JPEG)
        msg_type = MSG_FRAME_DELTA — только изменившиеся тайлы
        payload  = b""             — ничего не изменилось (не отправлять)
        """
        self._frame_count += 1
        w, h = image.size

        # Полный кадр: первый, при смене разрешения или раз в N кадров
        force_full = (
            (w, h) != self._prev_size
            or self._frame_count == 1
            or self._frame_count % self.FULL_FRAME_EVERY == 0
        )
        if force_full:
            self._prev_size = (w, h)
            self._tile_hashes.clear()
            # Заполняем хэши тайлов, чтобы следующий кадр мог вычислить дельту
            full_bytes = image.tobytes()
            stride = w * 3
            ts = self.tile_size
            for ty in range(0, h, ts):
                th = min(ts, h - ty)
                for tx in range(0, w, ts):
                    tw = min(ts, w - tx)
                    rows = [
                        full_bytes[(ty + row) * stride + tx * 3: (ty + row) * stride + (tx + tw) * 3]
                        for row in range(th)
                    ]
                    self._tile_hashes[(tx, ty)] = hashlib.md5(b"".join(rows)).digest()
            buf = io.BytesIO()
            image.save(buf, "JPEG", quality=self.quality, optimize=False)
            return MSG_FRAME, buf.getvalue()

        ts = self.tile_size

        full_bytes = image.tobytes()
        stride = w * 3

        changed: list[tuple[int, int, int, int, bytes]] = []  # (x, y, w, h, jpeg)

        for ty in range(0, h, ts):
            th = min(ts, h - ty)
            for tx in range(0, w, ts):
                tw = min(ts, w - tx)

                tile_rows = [
                    full_bytes[(ty + row) * stride + tx * 3: (ty + row) * stride + (tx + tw) * 3]
                    for row in range(th)
                ]
                tile_hash = hashlib.md5(b"".join(tile_rows)).digest()

                key = (tx, ty)
                if self._tile_hashes.get(key) == tile_hash:
                    continue

                self._tile_hashes[key] = tile_hash

                tile_img = image.crop((tx, ty, tx + tw, ty + th))
                buf = io.BytesIO()
                tile_img.save(buf, "JPEG", quality=self.quality, optimize=False)
                tile_img.close()
                changed.append((tx, ty, tw, th, buf.getvalue()))

        if not changed:
            return MSG_FRAME_DELTA, b""

        # Сборка пакета: num_tiles(2) + [x(2) y(2) w(2) h(2) data_len(4) data…] × N
        parts: list[bytes] = [struct.pack(">H", len(changed))]
        for tx, ty, tw, th, data in changed:
            parts.append(struct.pack(">HHHHI", tx, ty, tw, th, len(data)))
            parts.append(data)
        return MSG_FRAME_DELTA, b"".join(parts)


class ClientSession:
    """Обрабатывает одно клиентское подключение."""

    def __init__(self, sock: socket.socket, addr, password: str, fps: int, quality: int):
        self.sock = sock
        self.addr = addr
        self.password = password
        self.interval = 1.0 / max(1, fps)
        self.quality = max(1, min(95, quality))
        self.alive = False
        self.send_lock = threading.Lock()
        self.server_w = 1
        self.server_h = 1

    def _send(self, data: bytes) -> None:
        """Потокобезопасно отправляет данные клиенту."""
        with self.send_lock:
            self.sock.sendall(data)

    def _recv_exact(self, size: int) -> bytes:
        """Считывает из сокета ровно указанное число байт."""
        buffer = b""
        while len(buffer) < size:
            chunk = self.sock.recv(size - len(buffer))
            if not chunk:
                raise ConnectionError("Соединение закрыто")
            buffer += chunk
        return buffer

    def run(self) -> None:
        """Запускает рукопожатие, поток кадров и цикл команд клиента."""
        try:
            self._handshake()
            self.alive = True
            log.info("[%s] Сессия запущена (fps=%s, q=%s)", self.addr, int(1 / self.interval), self.quality)
            threading.Thread(target=self._frame_loop, name="FrameSender", daemon=True).start()
            self._cmd_loop()
        except ConnectionError as error:
            log.info("[%s] Отключение: %s", self.addr, error)
        except Exception as error:
            log.exception("[%s] Ошибка сессии: %s", self.addr, error)
        finally:
            self.alive = False
            _close_thread_mss()
            try:
                self.sock.close()
            except Exception:
                pass
            log.info("[%s] Сессия завершена", self.addr)

    def _handshake(self) -> None:
        """Выполняет RFB-рукопожатие и отправляет ServerInit."""
        self._send(VERSION)
        client_version = self._recv_exact(12)
        log.info("[%s] Версия клиента: %s", self.addr, client_version.strip().decode())

        if self.password:
            self._send(struct.pack("BB", 1, SECURITY_VNC))
        else:
            self._send(struct.pack("BB", 1, SECURITY_NONE))

        chosen_security = self._recv_exact(1)[0]
        log.info("[%s] Выбран тип безопасности: %s", self.addr, chosen_security)

        if chosen_security == SECURITY_VNC:
            if not self.password:
                raise ValueError("Клиент запросил VNC-аутентификацию, но пароль не задан")
            challenge = os.urandom(16)
            self._send(challenge)
            response = self._recv_exact(16)
            expected = vnc_des_encrypt(self.password, challenge)
            if response == expected:
                self._send(struct.pack(">I", 0))
                log.info("[%s] Аутентификация прошла успешно", self.addr)
            else:
                self._send(struct.pack(">I", 1))
                raise PermissionError("Неверный пароль")
        elif chosen_security == SECURITY_NONE:
            self._send(struct.pack(">I", 0))
        else:
            raise ValueError(f"Неизвестный тип безопасности: {chosen_security}")

        self._recv_exact(1)
        screen = grab_screen()
        width, height = screen.size
        screen.close()

        pixel_format = struct.pack(
            ">BBBB HHH BBB 3x",
            32,
            24,
            0,
            1,
            255,
            255,
            255,
            16,
            8,
            0,
        )
        name = b"PythonVNC"
        payload = struct.pack(">HH", width, height) + pixel_format + struct.pack(">I", len(name)) + name
        self._send(payload)
        self.server_w = width
        self.server_h = height
        log.info("[%s] ServerInit отправлен: %s×%s", self.addr, width, height)

    def _frame_loop(self) -> None:
        """Захватывает экран и отправляет клиенту полные кадры или дельты."""
        encoder = DeltaEncoder(self.quality)
        frames_sent = 0
        skipped = 0
        fps_started_at = time.time()

        while self.alive:
            started_at = time.time()
            image: "Image.Image | None" = None
            try:
                image = grab_screen()
                msg_type, payload = encoder.encode(image)

                if msg_type == MSG_FRAME_DELTA and not payload:
                    skipped += 1
                else:
                    self._send(struct.pack(">BI", msg_type, len(payload)) + payload)
                    frames_sent += 1

            except Exception as error:
                log.error("[%s] Ошибка отправки кадра: %s", self.addr, error)
                self.alive = False
                break
            finally:
                if image is not None:
                    image.close()

            elapsed = time.time() - fps_started_at
            if elapsed >= 5:
                fps = frames_sent / elapsed
                log.info(
                    "[%s] FPS: %.1f  отправлено=%d  пропущено (без изменений)=%d",
                    self.addr, fps, frames_sent, skipped,
                )
                frames_sent = 0
                skipped = 0
                fps_started_at = time.time()

            remaining = self.interval - (time.time() - started_at)
            if remaining > 0:
                time.sleep(remaining)

        _close_thread_mss()

        _close_thread_mss()

    def _cmd_loop(self) -> None:
        """Принимает и выполняет команды мыши и клавиатуры от клиента."""
        while self.alive:
            command = self._recv_exact(1)[0]

            if command == CMD_MOUSE_MOVE:
                x, y = struct.unpack(">HH", self._recv_exact(4))
                input_mouse_move(x, y)
                continue

            if command == CMD_MOUSE_CLICK:
                button, pressed, x, y = struct.unpack(">BBHH", self._recv_exact(6))
                input_mouse_button(button, bool(pressed), x, y)
                action = "↓" if pressed else "↑"
                log.info("[%s] MOUSE_CLICK %s btn=%s (%s,%s)", self.addr, action, button, x, y)
                continue

            if command == CMD_MOUSE_SCROLL:
                x, y, delta_y = struct.unpack(">HHh", self._recv_exact(6))
                input_mouse_scroll(x, y, int(delta_y))
                log.info("[%s] MOUSE_SCROLL (%s,%s) dy=%s", self.addr, x, y, delta_y)
                continue

            if command == CMD_KEY_EVENT:
                pressed, key_length = struct.unpack(">BH", self._recv_exact(3))
                key_name = self._recv_exact(key_length).decode("utf-8", errors="replace")
                try:
                    input_key(key_name, bool(pressed))
                    action = "↓" if pressed else "↑"
                    log.info("[%s] KEY %s [%s]", self.addr, action, key_name)
                except Exception as error:
                    log.warning("[%s] Ошибка ввода клавиши [%s]: %s", self.addr, key_name, error)
                continue

            log.warning("[%s] Неизвестный тип команды: %s", self.addr, command)


class VNCServer:
    """Принимает входящие подключения и создаёт клиентские сессии."""

    def __init__(self, host: str = "0.0.0.0", port: int = 5900, password: str = "", fps: int = 20, quality: int = 50):
        self.host = host
        self.port = port
        self.password = password
        self.fps = fps
        self.quality = quality

    def run(self) -> None:
        """Запускает основной цикл приёма TCP-подключений."""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        password_info = "***" if self.password else "нет"
        log.info("VNC-сервер запущен: %s:%s  (пароль=%s)", self.host, self.port, password_info)
        log.info("Параметры: FPS=%s, качество JPEG=%s%%", self.fps, self.quality)

        try:
            while True:
                sock, addr = server_socket.accept()
                log.info("Новое подключение: %s", addr)
                session = ClientSession(sock, addr, self.password, self.fps, self.quality)
                threading.Thread(target=session.run, name=f"Client-{addr}", daemon=True).start()
        except KeyboardInterrupt:
            log.info("Сервер остановлен по Ctrl+C")
        finally:
            server_socket.close()


def main() -> None:
    """Разбирает аргументы командной строки и запускает сервер."""
    parser = argparse.ArgumentParser(description="VNC-подобный сервер удалённого управления")
    parser.add_argument("--host", default="0.0.0.0", help="IP-адрес прослушивания")
    parser.add_argument("--port", default=5900, type=int, help="Порт")
    parser.add_argument("--password", default="", help="Пароль")
    parser.add_argument("--fps", default=20, type=int, help="Кадров в секунду")
    parser.add_argument("--quality", default=50, type=int, help="Качество JPEG 1-95")
    args = parser.parse_args()

    init_platform()
    VNCServer(
        host=args.host,
        port=args.port,
        password=args.password,
        fps=args.fps,
        quality=args.quality,
    ).run()

if __name__ == "__main__":
    main()