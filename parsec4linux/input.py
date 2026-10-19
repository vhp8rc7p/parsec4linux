"""Parsec client -> host input messages (150-105c).

Input messages share the 13-byte control header from `app.py` -- three big-endian
u32 fields then the type byte -- but occupy their own type range.

MEASURED, not guessed. 987 client->host messages captured by our own host from a real
Windows Parsec client (`/tmp/p4l.log`, 2026-10-19) split cleanly:

    types 0x00..0x09  ->  input          (only 0x01 and 0x03 appeared)
    types 0x0a..0x23  ->  control        (0x0a 0x0b 0x0d 0x11 0x15 0x18 0x23)

The SDK has exactly nine `ParsecMessageType` values (KEYBOARD=1, MOUSE_BUTTON=2,
MOUSE_WHEEL=3, MOUSE_MOTION=4, GAMEPAD_BUTTON=5, GAMEPAD_AXIS=6, GAMEPAD_UNPLUG=7,
RELEASE=8, GAMEPAD_STATE=9) and the two observed types fit `wire = SDK - 1`:

    0x01  mouse button   f0=1 (MOUSE_L), f1 toggled 1 then 0 in press/release pairs
    0x03  mouse motion   f0=0, f1=x, f2=y, both moving monotonically as the pointer did

so f0 of a motion message is the SDK's `relative` flag.

Keyboard (0x00) was predicted by the same arithmetic and then CONFIRMED on the wire:
typing "abc" produced codes 4, 5, 6 -- SDL scancodes for A, B, C -- each as a
pressed=1 / pressed=0 pair, with `mod` constant at 0x1000 (SDL's KMOD_NUM, num lock
on). The layout is {code, mod, pressed} and `mod` is an SDL keymod bitmask.

Wheel (0x02) is {x, y} = {field0, field1}, read from the Windows host's own injector
(0x18007E230, case 2): field1 goes to SendInput as MOUSEEVENTF_WHEEL and field0 as
MOUSEEVENTF_HWHEEL, both straight into `mouseData` -- so the units are Windows wheel
units, 120 per notch, positive = up / right. Confirmed on the wire: the first scroll
of a real session arrived as fields (0, -120, 0), one notch down.

Coordinate space: absolute motion arrives in **the size we advertise in the video
frame header**, which is the encode size. Measured in two configurations:

  header 1920x1080 (while encoding 1280x720 pixels)  -> x 23..1920,  y 0..1077
  header 1914x884  (native, no scaling)              -> x 203..1495, y 0..884

The first was long misread as "the client's own 1920x1080 screen", because the
advertised size and the client's screen were the same number; the second separates
them and follows the header. That is also the only size the client is ever told: its
config asks for `resolutionX/Y: 0` ("whatever the host has"), so the frame header is
its sole source of truth for how big we are.

So the client space is not a constant. The host sends `{"t": "space", ...}` to
`tools/inject_input.py` once the capture reports its size, and again whenever it
changes. `CLIENT_SPACE_DEFAULT` is only the value used before the first frame.
`tools/inject_input.py` rescales that onto the real desktop itself rather than letting
libinput do it, because the desktop is resizable and generally has a different aspect
ratio (seen: 1482x537, then 2554x1367), and an absolute device whose axis range does
not match the screen leaves the mapping up to the compositor.
"""
from __future__ import annotations

import struct

from . import app

# --- wire message types (app.py's header, type byte last) --------------------
TYPE_KEYBOARD = 0x00        # confirmed
TYPE_MOUSE_BUTTON = 0x01    # confirmed
TYPE_MOUSE_WHEEL = 0x02     # confirmed
TYPE_MOUSE_MOTION = 0x03    # confirmed
TYPE_GAMEPAD_BUTTON = 0x04  # inferred
TYPE_GAMEPAD_AXIS = 0x05    # inferred
TYPE_GAMEPAD_UNPLUG = 0x06  # inferred
TYPE_RELEASE = 0x07         # inferred
TYPE_GAMEPAD_STATE = 0x08   # inferred

INPUT_TYPE_MAX = 0x09       # 0x0a and up is control, see app.py

CONFIRMED = frozenset({TYPE_KEYBOARD, TYPE_MOUSE_BUTTON, TYPE_MOUSE_MOTION,
                       TYPE_MOUSE_WHEEL})

# SDL keymod bits, as they arrive in a keyboard message's `mod`.
KMOD_LSHIFT, KMOD_RSHIFT = 0x0001, 0x0002
KMOD_LCTRL, KMOD_RCTRL = 0x0040, 0x0080
KMOD_LALT, KMOD_RALT = 0x0100, 0x0200
KMOD_LGUI, KMOD_RGUI = 0x0400, 0x0800
KMOD_NUM, KMOD_CAPS = 0x1000, 0x2000

# Fallback only: absolute coordinates arrive in the size the video header advertises,
# so the real value is the encode size and is learned at runtime. This is what to
# assume before the first captured frame has reported one.
CLIENT_SPACE_DEFAULT = (1920, 1080)

# SDK ParsecMouseButton
MOUSE_L, MOUSE_MIDDLE, MOUSE_R, MOUSE_X1, MOUSE_X2 = 1, 2, 3, 4, 5

_NAMES = {
    TYPE_KEYBOARD: "keyboard",
    TYPE_MOUSE_BUTTON: "mouse_button",
    TYPE_MOUSE_WHEEL: "mouse_wheel",
    TYPE_MOUSE_MOTION: "mouse_motion",
    TYPE_GAMEPAD_BUTTON: "gamepad_button",
    TYPE_GAMEPAD_AXIS: "gamepad_axis",
    TYPE_GAMEPAD_UNPLUG: "gamepad_unplug",
    TYPE_RELEASE: "release",
    TYPE_GAMEPAD_STATE: "gamepad_state",
}


def is_input(msg_type: int) -> bool:
    """True for the input type range. Control messages start at 0x0a."""
    return 0 <= msg_type <= INPUT_TYPE_MAX


def name(msg_type: int) -> str:
    return _NAMES.get(msg_type, f"input_{msg_type:#04x}")


def _s32(v: int) -> int:
    return v - (1 << 32) if v >= (1 << 31) else v


def decode(data: bytes) -> dict | None:
    """Decode one client->host input message, or None if it is not one.

    Returns a dict with `kind`, the decoded fields, `confirmed` (whether the field
    layout was observed on the wire rather than inferred), and the raw fields so a
    caller can log something useful about a layout we got wrong.
    """
    hdr = app.parse(data)
    t = hdr["type"]
    if not is_input(t):
        return None

    ev: dict = {"type": t, "kind": name(t), "confirmed": t in CONFIRMED,
                "raw": (hdr["field0"], hdr["field1"], hdr["field2"])}
    f0, f1, f2 = hdr["field0"], hdr["field1"], hdr["field2"]

    if t == TYPE_MOUSE_MOTION:
        # f0 is the SDK `relative` flag; only f0 == 0 (absolute) has been observed.
        ev.update(relative=bool(f0), x=_s32(f1), y=_s32(f2))
    elif t == TYPE_MOUSE_BUTTON:
        ev.update(button=f0, pressed=bool(f1))
    elif t == TYPE_MOUSE_WHEEL:
        ev.update(x=_s32(f0), y=_s32(f1))
    elif t == TYPE_KEYBOARD:
        # SDK ParsecMessageKeyboard is {code, mod, pressed}.
        ev.update(code=f0, mod=f1, pressed=bool(f2))
    return ev


def build(msg_type: int, f0: int = 0, f1: int = 0, f2: int = 0) -> bytes:
    """Encode an input message -- used by the self-test and by parsec_client.py."""
    return app.build(msg_type, f0, f1, f2)


def mouse_motion(x: int, y: int, relative: bool = False) -> bytes:
    return build(TYPE_MOUSE_MOTION, 1 if relative else 0,
                 x & 0xFFFFFFFF, y & 0xFFFFFFFF)


def mouse_button(button: int, pressed: bool) -> bytes:
    return build(TYPE_MOUSE_BUTTON, button, 1 if pressed else 0, 0)


# --- Parsec keycode -> Linux input-event-codes ------------------------------
# ParsecKeycode mirrors SDL2's SDL_Scancode. Left column is the SDL scancode, right
# is the KEY_* value from linux/input-event-codes.h.
_SDL_TO_LINUX = {}

# A..Z: SDL 4..29 in alphabetical order; Linux codes are QWERTY-ordered, not alphabetical
for _i, _code in enumerate([
        30, 48, 46, 32, 18, 33, 34, 35, 23, 36, 37, 38, 50,   # A B C D E F G H I J K L M
        49, 24, 25, 16, 19, 31, 20, 22, 47, 17, 45, 21, 44]):  # N O P Q R S T U V W X Y Z
    _SDL_TO_LINUX[4 + _i] = _code

# 1..9 then 0: SDL 30..39 -> Linux KEY_1..KEY_9 (2..10) then KEY_0 (11)
for _i in range(9):
    _SDL_TO_LINUX[30 + _i] = 2 + _i
_SDL_TO_LINUX[39] = 11

_SDL_TO_LINUX.update({
    40: 28,   # RETURN       KEY_ENTER
    41: 1,    # ESCAPE       KEY_ESC
    42: 14,   # BACKSPACE
    43: 15,   # TAB
    44: 57,   # SPACE
    45: 12,   # MINUS
    46: 13,   # EQUALS       KEY_EQUAL
    47: 26,   # LEFTBRACKET  KEY_LEFTBRACE
    48: 27,   # RIGHTBRACKET KEY_RIGHTBRACE
    49: 43,   # BACKSLASH
    50: 43,   # NONUSHASH    same physical key on many layouts
    51: 39,   # SEMICOLON
    52: 40,   # APOSTROPHE
    53: 41,   # GRAVE
    54: 51,   # COMMA
    55: 52,   # PERIOD       KEY_DOT
    56: 53,   # SLASH
    57: 58,   # CAPSLOCK
    70: 99,   # PRINTSCREEN  KEY_SYSRQ
    71: 70,   # SCROLLLOCK
    72: 119,  # PAUSE
    73: 110,  # INSERT
    74: 102,  # HOME
    75: 104,  # PAGEUP
    76: 111,  # DELETE
    77: 107,  # END
    78: 109,  # PAGEDOWN
    79: 106,  # RIGHT
    80: 105,  # LEFT
    81: 108,  # DOWN
    82: 103,  # UP
    83: 69,   # NUMLOCKCLEAR KEY_NUMLOCK
    84: 98,   # KP_DIVIDE    KEY_KPSLASH
    85: 55,   # KP_MULTIPLY  KEY_KPASTERISK
    86: 74,   # KP_MINUS
    87: 78,   # KP_PLUS
    88: 96,   # KP_ENTER
    89: 79, 90: 80, 91: 81, 92: 75, 93: 76,   # KP_1..KP_5
    94: 77, 95: 71, 96: 72, 97: 73,           # KP_6..KP_9
    98: 82,   # KP_0
    99: 83,   # KP_PERIOD    KEY_KPDOT
    100: 86,  # NONUSBACKSLASH  KEY_102ND
    101: 127,  # APPLICATION  KEY_COMPOSE
    224: 29,  # LCTRL
    225: 42,  # LSHIFT
    226: 56,  # LALT
    227: 125,  # LGUI        KEY_LEFTMETA
    228: 97,  # RCTRL
    229: 54,  # RSHIFT
    230: 100,  # RALT
    231: 126,  # RGUI        KEY_RIGHTMETA
})

# F1..F12: SDL 58..69 -> Linux 59..68 for F1..F10, then 87, 88 for F11, F12
for _i in range(10):
    _SDL_TO_LINUX[58 + _i] = 59 + _i
_SDL_TO_LINUX[68] = 87
_SDL_TO_LINUX[69] = 88

# SDK ParsecMouseButton -> Linux BTN_*
MOUSE_TO_LINUX = {
    MOUSE_L: 0x110,       # BTN_LEFT
    MOUSE_MIDDLE: 0x112,  # BTN_MIDDLE
    MOUSE_R: 0x111,       # BTN_RIGHT
    MOUSE_X1: 0x113,      # BTN_SIDE
    MOUSE_X2: 0x114,      # BTN_EXTRA
}


def linux_keycode(parsec_code: int) -> int | None:
    """Linux KEY_* for a Parsec/SDL scancode, or None if unmapped."""
    return _SDL_TO_LINUX.get(parsec_code)


def linux_button(parsec_button: int) -> int | None:
    return MOUSE_TO_LINUX.get(parsec_button)


ALL_LINUX_KEYS = sorted(set(_SDL_TO_LINUX.values()))
ALL_LINUX_BUTTONS = sorted(MOUSE_TO_LINUX.values())


if __name__ == "__main__":
    # the type range split that the capture established
    assert is_input(0x00) and is_input(0x03) and is_input(0x09)
    assert not is_input(0x0a), "0x0a is control (seen in the capture)"
    assert not is_input(app.TYPE_CONFIG) and not is_input(app.TYPE_HEARTBEAT)

    # real bytes, straight out of /tmp/p4l.log
    m = decode(bytes.fromhex("000000000000052a000000f003"))
    assert m["kind"] == "mouse_motion" and m["confirmed"], m
    assert m["x"] == 1322 and m["y"] == 240 and not m["relative"], m

    b = decode(bytes.fromhex("00000001000000010000000001"))
    assert b["kind"] == "mouse_button" and b["confirmed"], b
    assert b["button"] == MOUSE_L and b["pressed"], b
    b = decode(bytes.fromhex("00000001000000000000000001"))
    assert b["button"] == MOUSE_L and not b["pressed"], b

    # control messages must not decode as input
    assert decode(bytes.fromhex("0000015a00000000000000000b")) is None
    assert decode(bytes.fromhex("00006fb8000000010000000015")) is None

    # keyboard, confirmed: typing "abc" gave SDL scancodes 4/5/6 with mod = KMOD_NUM
    for raw, want_code, want_key in (("00000004000010000000000100", 4, 30),
                                     ("00000005000010000000000100", 5, 48),
                                     ("00000006000010000000000100", 6, 46)):
        k = decode(bytes.fromhex(raw))
        assert k["kind"] == "keyboard" and k["confirmed"], k
        assert k["code"] == want_code and k["pressed"], k
        assert k["mod"] == KMOD_NUM, k
        assert linux_keycode(k["code"]) == want_key, (k, want_key)
    # and the matching release
    up = decode(bytes.fromhex("00000004000010000000000000"))
    assert up["code"] == 4 and not up["pressed"], up

    # the first real scroll: one notch down, in Windows wheel units
    w = decode(bytes.fromhex("00000000ffffff880000000002"))
    assert w["kind"] == "mouse_wheel" and w["confirmed"], w
    assert (w["x"], w["y"]) == (0, -120), w

    # round trip, and negative coordinates for relative mode
    assert decode(mouse_motion(1322, 240))["x"] == 1322
    r = decode(mouse_motion(-5, -3, relative=True))
    assert r["relative"] and r["x"] == -5 and r["y"] == -3, r
    assert decode(mouse_button(MOUSE_R, True))["button"] == MOUSE_R

    # keycode table sanity: SDL A/Z/1/0/Return/Space -> Linux
    assert linux_keycode(4) == 30, "A -> KEY_A"
    assert linux_keycode(29) == 44, "Z -> KEY_Z"
    assert linux_keycode(26) == 17, "W -> KEY_W"
    assert linux_keycode(30) == 2, "1 -> KEY_1"
    assert linux_keycode(39) == 11, "0 -> KEY_0"
    assert linux_keycode(40) == 28, "Return -> KEY_ENTER"
    assert linux_keycode(44) == 57, "Space -> KEY_SPACE"
    assert linux_keycode(58) == 59 and linux_keycode(67) == 68, "F1 -> KEY_F1, F10"
    assert linux_keycode(68) == 87 and linux_keycode(69) == 88, "F11/F12 are out of line"
    assert linux_keycode(225) == 42 and linux_keycode(224) == 29, "LShift/LCtrl"
    assert linux_keycode(999) is None
    # no two SDL letters collide
    letters = [linux_keycode(c) for c in range(4, 30)]
    assert len(set(letters)) == 26, "letter map must be a bijection"
    assert linux_button(MOUSE_L) == 0x110 and linux_button(MOUSE_R) == 0x111

    print(f"input.py self-test OK ({len(_SDL_TO_LINUX)} keycodes, "
          f"{len(MOUSE_TO_LINUX)} buttons; motion+button+keyboard+wheel confirmed on the wire)")
