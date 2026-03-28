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

# ─── Зависимости ────────────────────────────────────────────────────────────
try:
    from PIL import ImageGrab, Image
except ImportError:
    sys.exit("Установите Pillow:  pip install Pillow")

try:
    import pyautogui
    pyautogui.FAILSAFE = False
    pyautogui.PAUSE = 0
except ImportError:
    sys.exit("Установите pyautogui:  pip install pyautogui")

# ─── Логирование ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SERVER] %(levelname)-7s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("vnc.server")

# ─── Константы протокола ─────────────────────────────────────────────────────
VERSION         = b"RFB 003.008\n"
SECURITY_NONE   = 1
SECURITY_VNC    = 2

# Типы сообщений Server → Client
MSG_FRAME       = 0   # кадр экрана

# Типы команд Client → Server
CMD_MOUSE_MOVE  = 1   # перемещение мыши
CMD_MOUSE_CLICK = 2   # нажатие/отпускание кнопки мыши
CMD_MOUSE_SCROLL= 3   # прокрутка колёсика
CMD_KEY_EVENT   = 4   # клавиша

BUTTON_MAP = {0: "left", 1: "middle", 2: "right"}


# ─── DES для VNC-аутентификации ──────────────────────────────────────────────
def _mirror_bits(b: int) -> int:
    """VNC-специфичное зеркалирование битов в каждом байте ключа DES."""
    result = 0
    for i in range(8):
        if b & (1 << i):
            result |= 1 << (7 - i)
    return result


def vnc_des_encrypt(password: str, challenge: bytes) -> bytes:
    """
    Шифрует 16-байтный challenge паролем по схеме VNC DES.
    Требует pycryptodome (pip install pycryptodome).
    Если библиотека отсутствует — используется заглушка XOR.
    """
    key_raw = password.encode("latin-1")[:8].ljust(8, b"\x00")
    key = bytes(_mirror_bits(b) for b in key_raw)
    try:
        from Crypto.Cipher import DES
        return DES.new(key, DES.MODE_ECB).encrypt(challenge)
    except ImportError:
        # Заглушка — не криптостойко, только для совместимости при тестировании
        log.warning("pycryptodome не найден — DES-аутентификация отключена (используется XOR)")
        return bytes(challenge[i] ^ key[i % 8] for i in range(16))


# ─── Захват экрана ───────────────────────────────────────────────────────────
def grab_screen() -> Image.Image:
    """Делает снимок экрана. На Linux требует python3-xlib или scrot."""
    try:
        return ImageGrab.grab()
    except Exception:
        # Fallback через scrot (Linux без X11 DISPLAY может дать OSError)
        import subprocess, tempfile
        tmp = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
        tmp.close()
        subprocess.run(["scrot", tmp.name], check=True, timeout=2)
        img = Image.open(tmp.name)
        os.unlink(tmp.name)
        return img


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

        log.debug(f"[{self.addr}] Поток кадров остановлен")

    # ── Цикл приёма команд ──────────────────────────────────────────────────
    def _cmd_loop(self) -> None:
        log.debug(f"[{self.addr}] Цикл команд запущен")
        while self.alive:
            cmd = self._recv(1)[0]

            # Перемещение мыши
            if cmd == CMD_MOUSE_MOVE:
                x, y = struct.unpack(">HH", self._recv(4))
                pyautogui.moveTo(x, y, _pause=False)
                log.debug(f"[{self.addr}] MOUSE_MOVE ({x}, {y})")

            # Нажатие/отпускание кнопки мыши
            elif cmd == CMD_MOUSE_CLICK:
                btn, pressed, x, y = struct.unpack(">BBHH", self._recv(6))
                button = BUTTON_MAP.get(btn, "left")
                if pressed:
                    pyautogui.mouseDown(x=x, y=y, button=button, _pause=False)
                else:
                    pyautogui.mouseUp(x=x, y=y, button=button, _pause=False)
                action = "↓" if pressed else "↑"
                log.info(f"[{self.addr}] MOUSE_CLICK {action} {button} ({x},{y})")

            # Прокрутка колёсика
            elif cmd == CMD_MOUSE_SCROLL:
                x, y, dy = struct.unpack(">HHh", self._recv(6))
                pyautogui.scroll(int(dy), x=x, y=y, _pause=False)
                log.info(f"[{self.addr}] MOUSE_SCROLL ({x},{y}) dy={dy}")

            # Клавиатурное событие
            elif cmd == CMD_KEY_EVENT:
                pressed, klen = struct.unpack(">BH", self._recv(3))
                key = self._recv(klen).decode("utf-8", errors="replace")
                try:
                    if pressed:
                        pyautogui.keyDown(key)
                    else:
                        pyautogui.keyUp(key)
                    action = "↓" if pressed else "↑"
                    log.info(f"[{self.addr}] KEY {action} [{key}]")
                except Exception as e:
                    log.warning(f"[{self.addr}] Неизвестная клавиша [{key}]: {e}")

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