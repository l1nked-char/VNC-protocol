"""
VNC-подобный клиент удалённого рабочего стола
Запускается на машине, с которой осуществляется управление.

Возможности:
  • Отображение трансляции экрана удалённой машины (JPEG-поток)
  • Передача движений мыши, нажатий кнопок, прокрутки
  • Передача нажатий и отпусканий клавиш
  • Масштабирование: окно можно свободно изменять, координаты пересчитываются
  • Строка статуса: IP, FPS, задержка кадра

Использование:
  python vnc_client.py [--host HOST] [--port 5900] [--password PASS]

Если HOST не указан — показывается диалог подключения.
"""

import socket
import struct
import threading
import io
import time
import logging
import sys
import argparse
import queue

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog

try:
    from PIL import Image, ImageTk
except ImportError:
    sys.exit("Установите Pillow:  pip install Pillow")

# ─── Логирование ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CLIENT] %(levelname)-7s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("vnc.client")

# ─── Константы протокола ─────────────────────────────────────────────────────
VERSION         = b"RFB 003.008\n"
SECURITY_NONE   = 1
SECURITY_VNC    = 2

MSG_FRAME       = 0

CMD_MOUSE_MOVE  = 1
CMD_MOUSE_CLICK = 2
CMD_MOUSE_SCROLL= 3
CMD_KEY_EVENT   = 4

# Маппинг кнопок мыши: tkinter номер → наш код
MOUSE_BUTTON_MAP = {1: 0, 2: 1, 3: 2}

# ─── Маппинг клавиш: tkinter keysym → pyautogui key name ─────────────────────
# Для одиночных символов маппинг не нужен — отправляем сам символ.
KEYSYM_MAP: dict[str, str] = {
    # Управление
    "Return":        "enter",
    "KP_Enter":      "enter",
    "BackSpace":     "backspace",
    "Tab":           "tab",
    "Escape":        "escape",
    "Delete":        "delete",
    "Insert":        "insert",
    "Home":          "home",
    "End":           "end",
    "Prior":         "pageup",
    "Next":          "pagedown",
    "Up":            "up",
    "Down":          "down",
    "Left":          "left",
    "Right":         "right",
    # Функциональные
    "F1": "f1",  "F2": "f2",  "F3": "f3",  "F4": "f4",
    "F5": "f5",  "F6": "f6",  "F7": "f7",  "F8": "f8",
    "F9": "f9",  "F10": "f10", "F11": "f11", "F12": "f12",
    # Модификаторы
    "Control_L":  "ctrlleft",  "Control_R": "ctrlright",
    "Alt_L":      "altleft",   "Alt_R":     "altright",
    "Shift_L":    "shiftleft", "Shift_R":   "shiftright",
    "Super_L":    "winleft",   "Super_R":   "winright",
    "Meta_L":     "winleft",   "Meta_R":    "winright",
    "Menu":       "apps",
    "Caps_Lock":  "capslock",
    "Num_Lock":   "numlock",
    "Scroll_Lock":"scrolllock",
    "Print":      "printscreen",
    "Pause":      "pause",
    # Numpad
    "KP_0": "num0", "KP_1": "num1", "KP_2": "num2", "KP_3": "num3",
    "KP_4": "num4", "KP_5": "num5", "KP_6": "num6", "KP_7": "num7",
    "KP_8": "num8", "KP_9": "num9",
    "KP_Decimal":  "decimal",  "KP_Add":     "add",
    "KP_Subtract": "subtract", "KP_Multiply":"multiply",
    "KP_Divide":   "divide",
    # Пробел и пунктуация
    "space":     "space",
    "minus":     "-",       "equal":      "=",
    "bracketleft": "[",     "bracketright":"]",
    "backslash": "\\",      "semicolon":  ";",
    "apostrophe":"'",       "grave":      "`",
    "comma":     ",",       "period":     ".",
    "slash":     "/",
}


def keysym_to_pyautogui(keysym: str) -> str | None:
    """
    Преобразует tkinter-keysym в имя клавиши pyautogui.
    Возвращает None, если клавишу нужно игнорировать.
    """
    if keysym in KEYSYM_MAP:
        return KEYSYM_MAP[keysym]
    # Одиночный печатаемый символ — отправляем напрямую
    if len(keysym) == 1:
        return keysym
    # Многосимвольные неизвестные keysym (напр. "??") — игнорируем
    return None


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
        return bytes(challenge[i] ^ key[i % 8] for i in range(16))


# ─── Диалог подключения ──────────────────────────────────────────────────────
class ConnectDialog(tk.Toplevel):
    """Диалог ввода параметров подключения."""

    def __init__(self, master):
        super().__init__(master)
        self.title("VNC — Подключение")
        self.resizable(False, False)
        self.result = None

        self.grab_set()

        pad = {"padx": 10, "pady": 6}

        tk.Label(self, text="Хост / IP сервера:").grid(row=0, column=0, sticky="e", **pad)
        self._host = tk.Entry(self, width=22)
        self._host.insert(0, "127.0.0.1")
        self._host.grid(row=0, column=1, **pad)

        tk.Label(self, text="Порт:").grid(row=1, column=0, sticky="e", **pad)
        self._port = tk.Entry(self, width=8)
        self._port.insert(0, "5900")
        self._port.grid(row=1, column=1, sticky="w", **pad)

        tk.Label(self, text="Пароль:").grid(row=2, column=0, sticky="e", **pad)
        self._pwd = tk.Entry(self, show="*", width=22)
        self._pwd.grid(row=2, column=1, **pad)

        btn_frame = tk.Frame(self)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=10)
        tk.Button(btn_frame, text="Подключиться", command=self._ok, width=16).pack(side="left", padx=5)
        tk.Button(btn_frame, text="Отмена", command=self._cancel, width=10).pack(side="left", padx=5)

        self._host.focus()
        self.bind("<Return>", lambda _: self._ok())
        self.bind("<Escape>", lambda _: self._cancel())

        # Центрирование
        self.update_idletasks()
        x = master.winfo_x() + (master.winfo_width()  - self.winfo_width())  // 2
        y = master.winfo_y() + (master.winfo_height() - self.winfo_height()) // 2
        self.geometry(f"+{x}+{y}")

    def _ok(self):
        try:
            port = int(self._port.get())
        except ValueError:
            messagebox.showerror("Ошибка", "Порт должен быть числом", parent=self)
            return
        host = self._host.get().strip()
        if not host:
            messagebox.showerror("Ошибка", "Введите хост или IP", parent=self)
            return
        self.result = (host, port, self._pwd.get())
        self.destroy()

    def _cancel(self):
        self.result = None
        self.destroy()


# ─── Основной клиент ─────────────────────────────────────────────────────────
class VNCClient:
    """
    Клиент VNC-подобного протокола.
    Управляет соединением, отображением и отправкой событий ввода.
    """

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("VNC Клиент")
        self.root.configure(bg="#1a1a2e")

        self.sock:       socket.socket | None = None
        self.alive:      bool = False
        self._send_lock: threading.Lock = threading.Lock()

        # Размеры удалённого экрана (заполняются из ServerInit)
        self.server_w: int = 1
        self.server_h: int = 1

        # Очередь декодированных кадров (frame_receiver → UI)
        self._frame_queue: queue.Queue[Image.Image] = queue.Queue(maxsize=2)

        # Статистика
        self._frames_shown: int = 0
        self._fps_ts: float = time.time()
        self._last_frame_ms: float = 0.0

        self._build_ui()

    # ─── Построение UI ────────────────────────────────────────────────────
    def _build_ui(self):
        # Панель инструментов
        toolbar = tk.Frame(self.root, bg="#16213e", height=36)
        toolbar.pack(fill=tk.X, side=tk.TOP)
        toolbar.pack_propagate(False)

        tk.Button(
            toolbar, text="⏻  Подключиться",
            command=self._ask_connect,
            bg="#0f3460", fg="white", relief=tk.FLAT,
            padx=12, cursor="hand2",
        ).pack(side=tk.LEFT, padx=4, pady=4)

        tk.Button(
            toolbar, text="✕  Отключиться",
            command=self._disconnect,
            bg="#533483", fg="white", relief=tk.FLAT,
            padx=12, cursor="hand2",
        ).pack(side=tk.LEFT, padx=4, pady=4)

        # Строка статуса
        self._status_var = tk.StringVar(value="Не подключено")
        tk.Label(
            toolbar, textvariable=self._status_var,
            bg="#16213e", fg="#a0c4ff", font=("Courier", 9),
        ).pack(side=tk.RIGHT, padx=12)

        # Canvas для отображения кадров
        self.canvas = tk.Canvas(
            self.root, bg="#000000",
            highlightthickness=0, cursor="none",
        )
        self.canvas.pack(fill=tk.BOTH, expand=True)
        self._photo: ImageTk.PhotoImage | None = None

        # Привязка событий
        self._bind_events()

        # Запуск цикла обновления дисплея (16 мс ≈ 60 FPS обновлений UI)
        self._schedule_display_refresh()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _bind_events(self):
        c = self.canvas
        c.bind("<Motion>",         self._on_mouse_move)
        c.bind("<ButtonPress>",    self._on_mouse_press)
        c.bind("<ButtonRelease>",  self._on_mouse_release)
        c.bind("<MouseWheel>",     self._on_scroll)       # Windows / macOS
        c.bind("<Button-4>",       self._on_scroll_up)    # Linux
        c.bind("<Button-5>",       self._on_scroll_down)  # Linux
        self.root.bind("<KeyPress>",   self._on_key_press)
        self.root.bind("<KeyRelease>", self._on_key_release)

    # ─── Подключение / отключение ─────────────────────────────────────────
    def _ask_connect(self):
        if self.alive:
            self._disconnect()
        dlg = ConnectDialog(self.root)
        self.root.wait_window(dlg)
        if dlg.result:
            host, port, password = dlg.result
            self._connect(host, port, password)

    def _connect(self, host: str, port: int, password: str):
        self._status_var.set(f"Подключение к {host}:{port} …")
        self.root.update_idletasks()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((host, port))
            s.settimeout(None)
            self.sock = s
            self._handshake(password)
            self.alive = True
            self.root.title(f"VNC Клиент — {host}:{port}")
            self._status_var.set(f"✔ Подключено к {host}:{port}  |  {self.server_w}×{self.server_h}")
            log.info(f"Подключено к {host}:{port}")
            # Запуск потока приёма кадров
            threading.Thread(
                target=self._frame_receiver,
                name="FrameReceiver",
                daemon=True,
            ).start()
        except Exception as e:
            messagebox.showerror("Ошибка подключения", str(e))
            log.error(f"Ошибка подключения: {e}")
            self._status_var.set("Ошибка подключения")
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def _disconnect(self):
        self.alive = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
        self._status_var.set("Отключено")
        self.root.title("VNC Клиент")
        self.canvas.delete("all")
        log.info("Отключено")

    def _on_close(self):
        self._disconnect()
        self.root.destroy()

    # ─── RFB-рукопожатие ──────────────────────────────────────────────────
    def _handshake(self, password: str):
        # 1. Версия
        sv = self._recv(12)
        log.info(f"Версия сервера: {sv.strip().decode()}")
        self._send_raw(VERSION)

        # 2. Типы безопасности
        n = self._recv(1)[0]
        types = list(self._recv(n))
        log.info(f"Типы безопасности: {types}")

        # Выбираем VNC-auth если есть пароль и тип доступен, иначе None
        if SECURITY_VNC in types and password:
            chosen = SECURITY_VNC
        else:
            chosen = SECURITY_NONE if SECURITY_NONE in types else types[0]
        self._send_raw(bytes([chosen]))

        # 3. Аутентификация
        if chosen == SECURITY_VNC:
            challenge = self._recv(16)
            response  = vnc_des_encrypt(password, challenge)
            self._send_raw(response)

        result = struct.unpack(">I", self._recv(4))[0]
        if result != 0:
            raise PermissionError("Аутентификация не прошла — неверный пароль?")
        log.info("Аутентификация успешна")

        # 4. ClientInit
        self._send_raw(b"\x01")

        # 5. ServerInit
        w, h = struct.unpack(">HH", self._recv(4))
        _pf  = self._recv(16)
        nlen = struct.unpack(">I", self._recv(4))[0]
        name = self._recv(nlen).decode("utf-8", errors="replace")
        log.info(f"Сервер: {name!r}, экран {w}×{h}")

        self.server_w, self.server_h = w, h
        # Устанавливаем начальный размер окна по размеру экрана (с ограничением)
        max_w = min(w, self.root.winfo_screenwidth()  - 40)
        max_h = min(h, self.root.winfo_screenheight() - 80)
        self.root.geometry(f"{max_w}x{max_h+36}")  # +36 для тулбара

    # ─── Сетевые примитивы ────────────────────────────────────────────────
    def _send_raw(self, data: bytes) -> None:
        if self.sock:
            self.sock.sendall(data)

    def send(self, data: bytes) -> None:
        """Потокобезопасная отправка."""
        with self._send_lock:
            try:
                self._send_raw(data)
            except Exception as e:
                log.error(f"Ошибка отправки: {e}")
                self.alive = False

    def _recv(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("Сервер закрыл соединение")
            buf += chunk
        return buf

    # ─── Поток приёма кадров ──────────────────────────────────────────────
    def _frame_receiver(self):
        log.debug("Поток приёма кадров запущен")
        while self.alive:
            try:
                t0     = time.perf_counter()
                header = self._recv(5)
                msg_type, data_len = struct.unpack(">BI", header)

                data   = self._recv(data_len)
                dt_ms  = (time.perf_counter() - t0) * 1000
                self._last_frame_ms = dt_ms

                if msg_type == MSG_FRAME:
                    img = Image.open(io.BytesIO(data))
                    img.load()
                    # Кладём в очередь; если переполнена — выбрасываем старый кадр
                    if self._frame_queue.full():
                        try:
                            self._frame_queue.get_nowait()
                        except queue.Empty:
                            pass
                    self._frame_queue.put_nowait(img)

            except ConnectionError as e:
                log.info(f"Соединение прервано: {e}")
                self.alive = False
                self.root.after(0, self._status_var.set, "Соединение прервано")
                break
            except Exception as e:
                if self.alive:
                    log.error(f"Ошибка приёма кадра: {e}")
                break

        log.debug("Поток приёма кадров остановлен")

    # ─── Отображение кадров в UI (главный поток) ──────────────────────────
    def _schedule_display_refresh(self):
        self._refresh_display()
        # Следующий вызов через 16 мс
        self.root.after(16, self._schedule_display_refresh)

    def _refresh_display(self):
        try:
            img = self._frame_queue.get_nowait()
        except queue.Empty:
            return

        # Масштабирование под текущий размер canvas
        cw = self.canvas.winfo_width()  or self.server_w
        ch = self.canvas.winfo_height() or self.server_h

        if cw != img.width or ch != img.height:
            img = img.resize((cw, ch), Image.BILINEAR)

        photo = ImageTk.PhotoImage(img)
        self.canvas.create_image(0, 0, anchor=tk.NW, image=photo)
        self._photo = photo   # предотвращаем сборку мусора

        # Счётчик FPS
        self._frames_shown += 1
        now = time.time()
        if now - self._fps_ts >= 2.0:
            fps = self._frames_shown / (now - self._fps_ts)
            self._status_var.set(
                f"✔ Подключено  |  {self.server_w}×{self.server_h}"
                f"  |  FPS: {fps:.1f}"
                f"  |  Кадр: {self._last_frame_ms:.0f} мс"
            )
            self._frames_shown = 0
            self._fps_ts = now

    # ─── Координаты ────────────────────────────────────────────────────────
    def _map_coords(self, ex: int, ey: int) -> tuple[int, int]:
        """Пересчитывает координаты canvas → удалённый экран."""
        cw = self.canvas.winfo_width()  or self.server_w
        ch = self.canvas.winfo_height() or self.server_h
        x = round(ex * self.server_w / cw)
        y = round(ey * self.server_h / ch)
        return (
            max(0, min(x, self.server_w - 1)),
            max(0, min(y, self.server_h - 1)),
        )

    # ─── Обработчики событий мыши ─────────────────────────────────────────
    def _on_mouse_move(self, e):
        if not self.alive:
            return
        x, y = self._map_coords(e.x, e.y)
        self.send(struct.pack(">BHH", CMD_MOUSE_MOVE, x, y))

    def _on_mouse_press(self, e):
        if not self.alive:
            return
        btn = MOUSE_BUTTON_MAP.get(e.num, 0)
        x, y = self._map_coords(e.x, e.y)
        self.send(struct.pack(">BBBHH", CMD_MOUSE_CLICK, btn, 1, x, y))

    def _on_mouse_release(self, e):
        if not self.alive:
            return
        btn = MOUSE_BUTTON_MAP.get(e.num, 0)
        x, y = self._map_coords(e.x, e.y)
        self.send(struct.pack(">BBBHH", CMD_MOUSE_CLICK, btn, 0, x, y))

    def _on_scroll(self, e):
        """Windows / macOS: e.delta = ±120 (или кратное)."""
        if not self.alive:
            return
        dy = 1 if e.delta > 0 else -1
        x, y = self._map_coords(e.x, e.y)
        self.send(struct.pack(">BHHh", CMD_MOUSE_SCROLL, x, y, dy))

    def _on_scroll_up(self, e):
        """Linux: Button-4."""
        if not self.alive:
            return
        x, y = self._map_coords(e.x, e.y)
        self.send(struct.pack(">BHHh", CMD_MOUSE_SCROLL, x, y, 1))

    def _on_scroll_down(self, e):
        """Linux: Button-5."""
        if not self.alive:
            return
        x, y = self._map_coords(e.x, e.y)
        self.send(struct.pack(">BHHh", CMD_MOUSE_SCROLL, x, y, -1))

    # ─── Обработчики событий клавиатуры ───────────────────────────────────
    def _send_key_event(self, keysym: str, pressed: bool):
        if not self.alive:
            return
        key = keysym_to_pyautogui(keysym)
        if key is None:
            log.debug(f"Игнорируем keysym: {keysym!r}")
            return
        key_bytes = key.encode("utf-8")
        self.send(
            struct.pack(">BBH", CMD_KEY_EVENT, int(pressed), len(key_bytes))
            + key_bytes
        )

    def _on_key_press(self, e):
        self._send_key_event(e.keysym, True)

    def _on_key_release(self, e):
        self._send_key_event(e.keysym, False)


# ─── Точка входа ─────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="VNC-подобный клиент удалённого управления"
    )
    parser.add_argument("--host",     default="",   help="IP-адрес сервера (пусто = диалог)")
    parser.add_argument("--port",     default=5900, type=int, help="Порт (по умолчанию 5900)")
    parser.add_argument("--password", default="",   help="Пароль")
    args = parser.parse_args()

    root = tk.Tk()
    root.minsize(400, 300)
    app  = VNCClient(root)

    # Если хост задан аргументом — подключаемся сразу
    if args.host:
        root.after(200, app._connect, args.host, args.port, args.password)
    else:
        root.after(200, app._ask_connect)

    root.mainloop()


if __name__ == "__main__":
    main()