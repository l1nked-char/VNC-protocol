from __future__ import annotations

import argparse
import io
import logging
import queue
import socket
import struct
import sys
import threading
import time
import tkinter as tk
from tkinter import messagebox

try:
    from PIL import Image, ImageTk
except ImportError:
    sys.exit("Установите Pillow:  pip install Pillow")

from vnc_shared import (
    CMD_KEY_EVENT,
    CMD_MOUSE_CLICK,
    CMD_MOUSE_MOVE,
    CMD_MOUSE_SCROLL,
    MSG_FRAME,
    MOUSE_BUTTON_MAP,
    SECURITY_NONE,
    SECURITY_VNC,
    VERSION,
    keysym_to_key_name,
    vnc_des_encrypt,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CLIENT] %(levelname)-7s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("vnc.client")


class ConnectDialog(tk.Toplevel):
    """Диалог ввода параметров подключения."""

    def __init__(self, master: tk.Misc):
        super().__init__(master)
        self.title("VNC — Подключение")
        self.resizable(False, False)
        self.result: tuple[str, int, str] | None = None

        self.grab_set()

        padding = {"padx": 10, "pady": 6}

        tk.Label(self, text="Хост / IP сервера:").grid(row=0, column=0, sticky="e", **padding)
        self.host_entry = tk.Entry(self, width=22)
        self.host_entry.insert(0, "127.0.0.1")
        self.host_entry.grid(row=0, column=1, **padding)

        tk.Label(self, text="Порт:").grid(row=1, column=0, sticky="e", **padding)
        self.port_entry = tk.Entry(self, width=8)
        self.port_entry.insert(0, "5900")
        self.port_entry.grid(row=1, column=1, sticky="w", **padding)

        tk.Label(self, text="Пароль:").grid(row=2, column=0, sticky="e", **padding)
        self.password_entry = tk.Entry(self, width=22, show="*")
        self.password_entry.grid(row=2, column=1, **padding)

        button_frame = tk.Frame(self)
        button_frame.grid(row=3, column=0, columnspan=2, pady=10)
        tk.Button(button_frame, text="Подключиться", command=self._accept, width=16).pack(side="left", padx=5)
        tk.Button(button_frame, text="Отмена", command=self._cancel, width=10).pack(side="left", padx=5)

        self.host_entry.focus()
        self.bind("<Return>", lambda _: self._accept())
        self.bind("<Escape>", lambda _: self._cancel())

        self.update_idletasks()
        master_x = master.winfo_x()
        master_y = master.winfo_y()
        offset_x = (master.winfo_width() - self.winfo_width()) // 2
        offset_y = (master.winfo_height() - self.winfo_height()) // 2
        self.geometry(f"+{master_x + offset_x}+{master_y + offset_y}")

    def _accept(self) -> None:
        """Проверяет введённые данные и сохраняет результат диалога."""
        try:
            port = int(self.port_entry.get())
        except ValueError:
            messagebox.showerror("Ошибка", "Порт должен быть числом", parent=self)
            return

        host = self.host_entry.get().strip()
        if not host:
            messagebox.showerror("Ошибка", "Введите хост или IP", parent=self)
            return

        self.result = (host, port, self.password_entry.get())
        self.destroy()

    def _cancel(self) -> None:
        """Закрывает диалог без результата."""
        self.result = None
        self.destroy()


class VNCClient:
    """Управляет подключением, отображением кадров и отправкой ввода."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("VNC Клиент")
        self.root.configure(bg="#1a1a2e")

        self.sock: socket.socket | None = None
        self.alive = False
        self.send_lock = threading.Lock()

        self.server_w = 1
        self.server_h = 1
        self.remote_host = ""
        self.remote_port = 0

        self.frame_queue: queue.Queue[Image.Image] = queue.Queue(maxsize=2)
        self.frames_shown = 0
        self.fps_started_at = time.time()
        self.last_frame_ms = 0.0

        self.image_item: int | None = None
        self.photo: ImageTk.PhotoImage | None = None

        self.cursor_visible = False
        self.cursor_canvas_x = 0
        self.cursor_canvas_y = 0
        self.cursor_items: list[int] = []

        self._build_ui()

    def _build_ui(self) -> None:
        """Создаёт окно клиента и привязывает обработчики событий."""
        toolbar = tk.Frame(self.root, bg="#16213e", height=36)
        toolbar.pack(fill=tk.X, side=tk.TOP)
        toolbar.pack_propagate(False)

        tk.Button(
            toolbar,
            text="⏻  Подключиться",
            command=self.ask_connect,
            bg="#0f3460",
            fg="white",
            relief=tk.FLAT,
            padx=12,
            cursor="hand2",
        ).pack(side=tk.LEFT, padx=4, pady=4)

        tk.Button(
            toolbar,
            text="✕  Отключиться",
            command=self.disconnect,
            bg="#533483",
            fg="white",
            relief=tk.FLAT,
            padx=12,
            cursor="hand2",
        ).pack(side=tk.LEFT, padx=4, pady=4)

        self.status_var = tk.StringVar(value="Не подключено")
        tk.Label(
            toolbar,
            textvariable=self.status_var,
            bg="#16213e",
            fg="#a0c4ff",
            font=("Courier", 9),
        ).pack(side=tk.RIGHT, padx=12)

        self.canvas = tk.Canvas(self.root, bg="#000000", highlightthickness=0, cursor="none")
        self.canvas.pack(fill=tk.BOTH, expand=True)
        self.image_item = self.canvas.create_image(0, 0, anchor=tk.NW)

        self.canvas.bind("<Motion>", self._on_mouse_move)
        self.canvas.bind("<ButtonPress>", self._on_mouse_press)
        self.canvas.bind("<ButtonRelease>", self._on_mouse_release)
        self.canvas.bind("<MouseWheel>", self._on_scroll)
        self.canvas.bind("<Button-4>", self._on_scroll_up)
        self.canvas.bind("<Button-5>", self._on_scroll_down)
        self.canvas.bind("<Enter>", self._on_pointer_enter)
        self.canvas.bind("<Leave>", self._on_pointer_leave)
        self.canvas.bind("<Configure>", self._on_canvas_configure)
        self.root.bind("<KeyPress>", self._on_key_press)
        self.root.bind("<KeyRelease>", self._on_key_release)

        self._schedule_display_refresh()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def ask_connect(self) -> None:
        """Показывает диалог подключения и запускает соединение."""
        if self.alive:
            self.disconnect()
        dialog = ConnectDialog(self.root)
        self.root.wait_window(dialog)
        if dialog.result:
            host, port, password = dialog.result
            self.connect(host, port, password)

    def connect(self, host: str, port: int, password: str) -> None:
        """Открывает TCP-соединение и выполняет RFB-рукопожатие."""
        self.status_var.set(f"Подключение к {host}:{port} …")
        self.root.update_idletasks()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((host, port))
            sock.settimeout(None)

            self.sock = sock
            self._handshake(password)
            self.alive = True
            self.remote_host = host
            self.remote_port = port
            self.root.title(f"VNC Клиент — {host}:{port}")
            self._set_connected_status()
            log.info("Подключено к %s:%s", host, port)

            threading.Thread(target=self._frame_receiver, name="FrameReceiver", daemon=True).start()
        except Exception as error:
            messagebox.showerror("Ошибка подключения", str(error))
            log.error("Ошибка подключения: %s", error)
            self.status_var.set("Ошибка подключения")
            if self.sock is not None:
                try:
                    self.sock.close()
                except Exception:
                    pass
            self.sock = None

    def disconnect(self) -> None:
        """Разрывает соединение и очищает экран клиента."""
        self.alive = False
        self.remote_host = ""
        self.remote_port = 0
        if self.sock is not None:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
        self.status_var.set("Отключено")
        self.root.title("VNC Клиент")
        if self.image_item is not None:
            self.canvas.itemconfigure(self.image_item, image="")
        self.photo = None
        self._hide_cursor()
        log.info("Отключено")

    def _on_close(self) -> None:
        """Закрывает соединение и завершает приложение."""
        self.disconnect()
        self.root.destroy()

    def _handshake(self, password: str) -> None:
        """Выполняет согласование версии, безопасности и параметров экрана."""
        server_version = self._recv_exact(12)
        log.info("Версия сервера: %s", server_version.strip().decode())
        self._send_raw(VERSION)

        security_count = self._recv_exact(1)[0]
        security_types = list(self._recv_exact(security_count))
        log.info("Типы безопасности: %s", security_types)

        if SECURITY_VNC in security_types and password:
            chosen_security = SECURITY_VNC
        else:
            chosen_security = SECURITY_NONE if SECURITY_NONE in security_types else security_types[0]
        self._send_raw(bytes([chosen_security]))

        if chosen_security == SECURITY_VNC:
            challenge = self._recv_exact(16)
            response = vnc_des_encrypt(password, challenge)
            self._send_raw(response)

        result = struct.unpack(">I", self._recv_exact(4))[0]
        if result != 0:
            raise PermissionError("Аутентификация не прошла — неверный пароль?")

        self._send_raw(b"\x01")

        width, height = struct.unpack(">HH", self._recv_exact(4))
        self._recv_exact(16)
        name_length = struct.unpack(">I", self._recv_exact(4))[0]
        server_name = self._recv_exact(name_length).decode("utf-8", errors="replace")
        log.info("Сервер: %r, экран %s×%s", server_name, width, height)

        self.server_w = width
        self.server_h = height
        max_width = min(width, self.root.winfo_screenwidth() - 40)
        max_height = min(height, self.root.winfo_screenheight() - 80)
        self.root.geometry(f"{max_width}x{max_height + 36}")

    def _send_raw(self, data: bytes) -> None:
        """Отправляет данные в сокет без дополнительной синхронизации."""
        if self.sock is not None:
            self.sock.sendall(data)

    def send_packet(self, data: bytes) -> None:
        """Потокобезопасно отправляет данные серверу."""
        with self.send_lock:
            try:
                self._send_raw(data)
            except Exception as error:
                log.error("Ошибка отправки: %s", error)
                self.alive = False

    def _recv_exact(self, size: int) -> bytes:
        """Считывает из сокета ровно указанное число байт."""
        if self.sock is None:
            raise ConnectionError("Сокет не инициализирован")
        buffer = b""
        while len(buffer) < size:
            chunk = self.sock.recv(size - len(buffer))
            if not chunk:
                raise ConnectionError("Сервер закрыл соединение")
            buffer += chunk
        return buffer

    def _frame_receiver(self) -> None:
        """Принимает JPEG-кадры в фоновом потоке и кладёт их в очередь."""
        while self.alive:
            try:
                started_at = time.perf_counter()
                msg_type, payload_size = struct.unpack(">BI", self._recv_exact(5))
                payload = self._recv_exact(payload_size)
                self.last_frame_ms = (time.perf_counter() - started_at) * 1000

                if msg_type != MSG_FRAME:
                    continue

                image = Image.open(io.BytesIO(payload))
                image.load()

                if self.frame_queue.full():
                    try:
                        dropped = self.frame_queue.get_nowait()
                        dropped.close()
                    except queue.Empty:
                        pass
                self.frame_queue.put_nowait(image)
            except ConnectionError as error:
                log.info("Соединение прервано: %s", error)
                self.alive = False
                self.root.after(0, self.status_var.set, "Соединение прервано")
                break
            except Exception as error:
                if self.alive:
                    log.error("Ошибка приёма кадра: %s", error)
                break

    def _schedule_display_refresh(self) -> None:
        """Планирует очередное обновление экрана клиента."""
        self._refresh_display()
        self.root.after(16, self._schedule_display_refresh)

    def _refresh_display(self) -> None:
        """Отрисовывает последний кадр и обновляет строку состояния."""
        try:
            image = self.frame_queue.get_nowait()
        except queue.Empty:
            self._redraw_cursor()
            return

        canvas_width = self.canvas.winfo_width() or self.server_w
        canvas_height = self.canvas.winfo_height() or self.server_h

        if canvas_width != image.width or canvas_height != image.height:
            resized = image.resize((canvas_width, canvas_height), Image.BILINEAR)
            image.close()
            image = resized

        self.photo = ImageTk.PhotoImage(image)
        image.close()

        if self.image_item is not None:
            self.canvas.itemconfigure(self.image_item, image=self.photo)

        self._redraw_cursor()

        self.frames_shown += 1
        now = time.time()
        if now - self.fps_started_at >= 2.0:
            fps = self.frames_shown / (now - self.fps_started_at)
            self._set_connected_status(fps)
            self.frames_shown = 0
            self.fps_started_at = now

    def _set_connected_status(self, fps: float | None = None) -> None:
        """Обновляет строку состояния для активного соединения."""
        parts = [f"✔ Подключено к {self.remote_host}:{self.remote_port}", f"{self.server_w}×{self.server_h}"]
        if fps is not None:
            parts.append(f"FPS: {fps:.1f}")
            parts.append(f"Кадр: {self.last_frame_ms:.0f} мс")
        self.status_var.set("  |  ".join(parts))

    def _map_coords(self, event_x: int, event_y: int) -> tuple[int, int]:
        """Пересчитывает координаты canvas в координаты удалённого экрана."""
        canvas_width = self.canvas.winfo_width() or self.server_w
        canvas_height = self.canvas.winfo_height() or self.server_h
        x = round(event_x * self.server_w / canvas_width)
        y = round(event_y * self.server_h / canvas_height)
        x = max(0, min(x, self.server_w - 1))
        y = max(0, min(y, self.server_h - 1))
        return x, y

    def _update_cursor_position(self, event_x: int, event_y: int) -> None:
        """Запоминает положение программного курсора внутри canvas."""
        canvas_width = max(1, self.canvas.winfo_width())
        canvas_height = max(1, self.canvas.winfo_height())
        self.cursor_canvas_x = max(0, min(event_x, canvas_width - 1))
        self.cursor_canvas_y = max(0, min(event_y, canvas_height - 1))
        self.cursor_visible = True
        self._redraw_cursor()

    def _hide_cursor(self) -> None:
        """Скрывает программный курсор в окне клиента."""
        self.cursor_visible = False
        for item_id in self.cursor_items:
            self.canvas.delete(item_id)
        self.cursor_items.clear()

    def _redraw_cursor(self) -> None:
        """Рисует поверх кадра программный курсор, независимый от ОС."""
        for item_id in self.cursor_items:
            self.canvas.delete(item_id)
        self.cursor_items.clear()

        if not self.cursor_visible:
            return

        x = self.cursor_canvas_x
        y = self.cursor_canvas_y
        points = [x, y, x, y + 18, x + 4, y + 14, x + 8, y + 22, x + 11, y + 20, x + 7, y + 12, x + 13, y + 12]
        cursor_id = self.canvas.create_polygon(points, fill="white", outline="black", width=1)
        self.cursor_items.append(cursor_id)
        self.canvas.tag_raise(cursor_id)

    def _on_pointer_enter(self, _: tk.Event) -> None:
        """Показывает программный курсор при входе мыши в область кадра."""
        self.cursor_visible = True
        self._redraw_cursor()

    def _on_pointer_leave(self, _: tk.Event) -> None:
        """Скрывает программный курсор при выходе мыши из области кадра."""
        self._hide_cursor()

    def _on_canvas_configure(self, _: tk.Event) -> None:
        """Перерисовывает курсор после изменения размера canvas."""
        self._redraw_cursor()

    def _on_mouse_move(self, event: tk.Event) -> None:
        """Отправляет серверу перемещение мыши и обновляет курсор клиента."""
        self._update_cursor_position(event.x, event.y)
        if not self.alive:
            return
        x, y = self._map_coords(event.x, event.y)
        self.send_packet(struct.pack(">BHH", CMD_MOUSE_MOVE, x, y))

    def _on_mouse_press(self, event: tk.Event) -> None:
        """Отправляет событие нажатия кнопки мыши."""
        self._update_cursor_position(event.x, event.y)
        if not self.alive:
            return
        button = MOUSE_BUTTON_MAP.get(event.num, 0)
        x, y = self._map_coords(event.x, event.y)
        self.send_packet(struct.pack(">BBBHH", CMD_MOUSE_CLICK, button, 1, x, y))

    def _on_mouse_release(self, event: tk.Event) -> None:
        """Отправляет событие отпускания кнопки мыши."""
        self._update_cursor_position(event.x, event.y)
        if not self.alive:
            return
        button = MOUSE_BUTTON_MAP.get(event.num, 0)
        x, y = self._map_coords(event.x, event.y)
        self.send_packet(struct.pack(">BBBHH", CMD_MOUSE_CLICK, button, 0, x, y))

    def _on_scroll(self, event: tk.Event) -> None:
        """Отправляет прокрутку колеса мыши для Windows и macOS."""
        self._update_cursor_position(event.x, event.y)
        if not self.alive:
            return
        delta = 1 if event.delta > 0 else -1
        x, y = self._map_coords(event.x, event.y)
        self.send_packet(struct.pack(">BHHh", CMD_MOUSE_SCROLL, x, y, delta))

    def _on_scroll_up(self, event: tk.Event) -> None:
        """Отправляет прокрутку вверх для Linux Button-4."""
        self._update_cursor_position(event.x, event.y)
        if not self.alive:
            return
        x, y = self._map_coords(event.x, event.y)
        self.send_packet(struct.pack(">BHHh", CMD_MOUSE_SCROLL, x, y, 1))

    def _on_scroll_down(self, event: tk.Event) -> None:
        """Отправляет прокрутку вниз для Linux Button-5."""
        self._update_cursor_position(event.x, event.y)
        if not self.alive:
            return
        x, y = self._map_coords(event.x, event.y)
        self.send_packet(struct.pack(">BHHh", CMD_MOUSE_SCROLL, x, y, -1))

    def _send_key_event(self, keysym: str, pressed: bool) -> None:
        """Преобразует keysym и отправляет событие клавиатуры серверу."""
        if not self.alive:
            return
        key_name = keysym_to_key_name(keysym)
        if key_name is None:
            log.debug("Игнорируем keysym: %r", keysym)
            return
        payload = key_name.encode("utf-8")
        self.send_packet(struct.pack(">BBH", CMD_KEY_EVENT, int(pressed), len(payload)) + payload)

    def _on_key_press(self, event: tk.Event) -> None:
        """Отправляет событие нажатия клавиши."""
        self._send_key_event(event.keysym, True)

    def _on_key_release(self, event: tk.Event) -> None:
        """Отправляет событие отпускания клавиши."""
        self._send_key_event(event.keysym, False)


def main() -> None:
    """Разбирает аргументы командной строки и запускает клиента."""
    parser = argparse.ArgumentParser(description="VNC-подобный клиент удалённого управления")
    parser.add_argument("--host", default="", help="IP-адрес сервера")
    parser.add_argument("--port", default=5900, type=int, help="Порт")
    parser.add_argument("--password", default="", help="Пароль")
    args = parser.parse_args()

    root = tk.Tk()
    root.minsize(400, 300)
    app = VNCClient(root)

    if args.host:
        root.after(200, app.connect, args.host, args.port, args.password)
    else:
        root.after(200, app.ask_connect)

    root.mainloop()


if __name__ == "__main__":
    main()
