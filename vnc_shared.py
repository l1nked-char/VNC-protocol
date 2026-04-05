from __future__ import annotations

VERSION = b"RFB 003.008\n"
SECURITY_NONE = 1
SECURITY_VNC = 2

MSG_FRAME = 0
MSG_FRAME_DELTA = 1  # только изменившиеся тайлы

TILE_SIZE = 64       # размер тайла в пикселях

CMD_MOUSE_MOVE = 1
CMD_MOUSE_CLICK = 2
CMD_MOUSE_SCROLL = 3
CMD_KEY_EVENT = 4

MOUSE_BUTTON_MAP = {1: 0, 2: 1, 3: 2}
BUTTON_MAP = {0: "left", 1: "middle", 2: "right"}

KEYSYM_MAP: dict[str, str] = {
    "Return": "enter",
    "KP_Enter": "enter",
    "BackSpace": "backspace",
    "Tab": "tab",
    "Escape": "escape",
    "Delete": "delete",
    "Insert": "insert",
    "Home": "home",
    "End": "end",
    "Prior": "pageup",
    "Next": "pagedown",
    "Up": "up",
    "Down": "down",
    "Left": "left",
    "Right": "right",
    "F1": "f1",
    "F2": "f2",
    "F3": "f3",
    "F4": "f4",
    "F5": "f5",
    "F6": "f6",
    "F7": "f7",
    "F8": "f8",
    "F9": "f9",
    "F10": "f10",
    "F11": "f11",
    "F12": "f12",
    "Control_L": "ctrlleft",
    "Control_R": "ctrlright",
    "Alt_L": "altleft",
    "Alt_R": "altright",
    "Shift_L": "shiftleft",
    "Shift_R": "shiftright",
    "Super_L": "winleft",
    "Super_R": "winright",
    "Meta_L": "winleft",
    "Meta_R": "winright",
    "Menu": "apps",
    "Caps_Lock": "capslock",
    "Num_Lock": "numlock",
    "Scroll_Lock": "scrolllock",
    "Print": "printscreen",
    "Pause": "pause",
    "KP_0": "num0",
    "KP_1": "num1",
    "KP_2": "num2",
    "KP_3": "num3",
    "KP_4": "num4",
    "KP_5": "num5",
    "KP_6": "num6",
    "KP_7": "num7",
    "KP_8": "num8",
    "KP_9": "num9",
    "KP_Decimal": "decimal",
    "KP_Add": "add",
    "KP_Subtract": "subtract",
    "KP_Multiply": "multiply",
    "KP_Divide": "divide",
    "space": "space",
    "minus": "-",
    "equal": "=",
    "bracketleft": "[",
    "bracketright": "]",
    "backslash": "\\",
    "semicolon": ";",
    "apostrophe": "'",
    "grave": "`",
    "comma": ",",
    "period": ".",
    "slash": "/",
    # ---------------------------------------------------------------------------
    # Сдвинутые (Shift) варианты символьных клавиш.
    # Когда Shift уже зажат на сервере (мы отправили Shift_L/Shift_R отдельным
    # событием), серверу достаточно получить БАЗОВУЮ клавишу, и ОС сама
    # произведёт нужный символ согласно своей раскладке.
    # ---------------------------------------------------------------------------
    # Ряд цифр (US: ! @ # $ % ^ & * ( ))
    "exclam": "1",
    "at": "2",
    "numbersign": "3",
    "dollar": "4",
    "percent": "5",
    "asciicircum": "6",
    "ampersand": "7",
    "asterisk": "8",
    "parenleft": "9",
    "parenright": "0",
    # Знаки препинания / прочее (US: _ + { } | : " ~ < > ?)
    "underscore": "-",
    "plus": "=",
    "braceleft": "[",
    "braceright": "]",
    "bar": "\\",
    "colon": ";",
    "quotedbl": "'",
    "asciitilde": "`",
    "less": ",",
    "greater": ".",
    "question": "/",
}

PYAUTOGUI_TO_XSYM: dict[str, str] = {
    "enter": "Return",
    "backspace": "BackSpace",
    "tab": "Tab",
    "escape": "Escape",
    "delete": "Delete",
    "insert": "Insert",
    "home": "Home",
    "end": "End",
    "pageup": "Prior",
    "pagedown": "Next",
    "up": "Up",
    "down": "Down",
    "left": "Left",
    "right": "Right",
    "f1": "F1",
    "f2": "F2",
    "f3": "F3",
    "f4": "F4",
    "f5": "F5",
    "f6": "F6",
    "f7": "F7",
    "f8": "F8",
    "f9": "F9",
    "f10": "F10",
    "f11": "F11",
    "f12": "F12",
    "shiftleft": "Shift_L",
    "shiftright": "Shift_R",
    "ctrlleft": "Control_L",
    "ctrlright": "Control_R",
    "altleft": "Alt_L",
    "altright": "Alt_R",
    "winleft": "Super_L",
    "winright": "Super_R",
    "capslock": "Caps_Lock",
    "numlock": "Num_Lock",
    "scrolllock": "Scroll_Lock",
    "printscreen": "Print",
    "pause": "Pause",
    "space": "space",
    "-": "minus",
    "=": "equal",
    "[": "bracketleft",
    "]": "bracketright",
    "\\": "backslash",
    ";": "semicolon",
    "'": "apostrophe",
    "`": "grave",
    ",": "comma",
    ".": "period",
    "/": "slash",
    "num0": "KP_0",
    "num1": "KP_1",
    "num2": "KP_2",
    "num3": "KP_3",
    "num4": "KP_4",
    "num5": "KP_5",
    "num6": "KP_6",
    "num7": "KP_7",
    "num8": "KP_8",
    "num9": "KP_9",
}


def keysym_to_key_name(keysym: str) -> str | None:
    """Преобразует tkinter keysym в имя клавиши, передаваемое серверу.

    Порядок поиска:
    1. Таблица KEYSYM_MAP (спецклавиши, сдвинутые символы и т.д.).
    2. Одиночный символ — возвращается как есть (напр. «a», «A», «2»).
    3. Unicode-keysym вида «U0041» (tkinter на некоторых платформах/раскладках).
    4. Иначе — None (событие будет проигнорировано).
    """
    if keysym in KEYSYM_MAP:
        return KEYSYM_MAP[keysym]
    if len(keysym) == 1:
        return keysym
    # Unicode-keysym: «U» + 4..6 шестнадцатеричных цифр
    if len(keysym) >= 5 and keysym[0] == "U":
        try:
            char = chr(int(keysym[1:], 16))
            if char.isprintable():
                return char
        except ValueError:
            pass
    return None


def mirror_bits(value: int) -> int:
    """Зеркально разворачивает порядок битов в одном байте."""
    result = 0
    for bit_index in range(8):
        if value & (1 << bit_index):
            result |= 1 << (7 - bit_index)
    return result


def vnc_des_encrypt(password: str, challenge: bytes) -> bytes:
    """Шифрует challenge по правилам VNC-аутентификации."""
    key_raw = password.encode("latin-1")[:8].ljust(8, b"\x00")
    key = bytes(mirror_bits(byte) for byte in key_raw)
    try:
        from Crypto.Cipher import DES

        return DES.new(key, DES.MODE_ECB).encrypt(challenge)
    except ImportError:
        return bytes(challenge[index] ^ key[index % 8] for index in range(16))