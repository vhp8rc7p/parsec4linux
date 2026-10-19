#!/usr/bin/env python3
"""Inject Parsec client input into the Linux desktop via /dev/uinput.

Runs as a child process of the host and reads one JSON object per line from stdin,
mirroring how `capture_h264.py` is a child on the output side. Keeping it separate
means the host itself needs no privileges: only this process touches /dev/uinput.

    {"t": "motion", "x": 1322, "y": 240, "rel": false}
    {"t": "button", "b": 1, "p": true}
    {"t": "wheel",  "x": 0, "y": -1}
    {"t": "key",    "code": 26, "p": true}

Two devices are created, because libinput classifies a device by what it advertises
and a combined keyboard/pointer confuses that:

  "parsec4linux pointer"   ABS_X/ABS_Y + buttons + REL_WHEEL/REL_HWHEEL
  "parsec4linux keyboard"  every KEY_* code in input.py's table

The pointer is *absolute*, with its axes sized to the coordinate space the client
actually sends (1920x1080 by default -- measured, see input.py). That makes the
compositor responsible for mapping onto the real desktop, so it keeps working when
the desktop is resized and needs no resolution negotiation. This is the same shape
as VMware's own guest pointer, which is why it works under Wayland where XTEST does
not.

Needs write access to /dev/uinput:
    sudo setfacl -m u:$USER:rw /dev/uinput        # until reboot
or a udev rule for something permanent -- see README.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from parsec4linux import input as pinput  # noqa: E402

# linux/uinput.h
UI_DEV_CREATE = 0x5501
UI_DEV_DESTROY = 0x5502
UI_SET_EVBIT = 0x40045564
UI_SET_KEYBIT = 0x40045565
UI_SET_RELBIT = 0x40045566
UI_SET_ABSBIT = 0x40045567

# linux/input-event-codes.h
EV_SYN, EV_KEY, EV_REL, EV_ABS = 0x00, 0x01, 0x02, 0x03
SYN_REPORT = 0
REL_HWHEEL, REL_WHEEL = 0x06, 0x08
# 1/120-notch axes (kernel 5.0+). Same unit as Windows mouseData, which is what
# the client sends, so no conversion is needed -- only the notch count derived.
REL_WHEEL_HI_RES, REL_HWHEEL_HI_RES = 0x0b, 0x0c
WHEEL_DELTA = 120
ABS_X, ABS_Y = 0x00, 0x01
ABS_CNT = 64

# struct input_event { struct timeval time; __u16 type, code; __s32 value; }
_EVENT = struct.Struct("=qqHHi")
assert _EVENT.size == 24, _EVENT.size

# struct uinput_user_dev { char name[80]; struct input_id id; __u32 ff_effects_max;
#                          __s32 absmax/absmin/absfuzz/absflat[ABS_CNT]; }
_USER_DEV = struct.Struct("=80sHHHHI" + f"{4 * ABS_CNT}i")
assert _USER_DEV.size == 1116, _USER_DEV.size

BUS_USB = 0x03


class UinputDevice:
    """A uinput device built through the legacy uinput_user_dev write() path."""

    def __init__(self, name: str, keys=(), rels=(), abs_axes=()):
        self.name = name
        try:
            self.fd = os.open("/dev/uinput", os.O_WRONLY | os.O_NONBLOCK)
        except PermissionError:
            raise SystemExit(
                "inject: no write access to /dev/uinput.\n"
                "  grant it with:  sudo setfacl -m u:$USER:rw /dev/uinput\n"
                "  or install the udev rule described in the README.")
        except FileNotFoundError:
            raise SystemExit("inject: /dev/uinput missing -- modprobe uinput")

        if keys:
            fcntl.ioctl(self.fd, UI_SET_EVBIT, EV_KEY)
            for k in keys:
                fcntl.ioctl(self.fd, UI_SET_KEYBIT, k)
        if rels:
            fcntl.ioctl(self.fd, UI_SET_EVBIT, EV_REL)
            for r in rels:
                fcntl.ioctl(self.fd, UI_SET_RELBIT, r)
        if abs_axes:
            fcntl.ioctl(self.fd, UI_SET_EVBIT, EV_ABS)
            for axis, _lo, _hi in abs_axes:
                fcntl.ioctl(self.fd, UI_SET_ABSBIT, axis)
        fcntl.ioctl(self.fd, UI_SET_EVBIT, EV_SYN)

        absmin = [0] * ABS_CNT
        absmax = [0] * ABS_CNT
        for axis, lo, hi in abs_axes:
            absmin[axis], absmax[axis] = lo, hi
        os.write(self.fd, _USER_DEV.pack(
            name.encode()[:79], BUS_USB, 0x1234, 0x5678, 1, 0,
            *absmax, *absmin, *([0] * ABS_CNT), *([0] * ABS_CNT)))
        fcntl.ioctl(self.fd, UI_DEV_CREATE)

    def emit(self, etype: int, code: int, value: int) -> None:
        os.write(self.fd, _EVENT.pack(0, 0, etype, code, value))

    def sync(self) -> None:
        self.emit(EV_SYN, SYN_REPORT, 0)

    def close(self) -> None:
        try:
            fcntl.ioctl(self.fd, UI_DEV_DESTROY)
        except OSError:
            pass
        os.close(self.fd)


class InputSink:
    def __init__(self, space=pinput.CLIENT_SPACE_DEFAULT, relative=False,
                 desktop=None):
        self.space = space
        self.relative = relative
        # Declaring the absolute axes at the real desktop size makes the device-to-
        # screen mapping the identity, so libinput has no aspect-ratio decision to
        # make. Client coordinates are rescaled here instead. Without this the
        # injected cursor drifts away from the client's own cursor whenever the
        # desktop aspect differs from the client's (it generally does).
        self.desktop = desktop
        w, h = desktop or space
        if relative:
            self.pointer = UinputDevice(
                "parsec4linux pointer",
                keys=pinput.ALL_LINUX_BUTTONS,
                rels=(0, 1, REL_WHEEL, REL_HWHEEL,  # REL_X, REL_Y
                      REL_WHEEL_HI_RES, REL_HWHEEL_HI_RES))
            self._last = None
        else:
            self.pointer = UinputDevice(
                "parsec4linux pointer",
                keys=pinput.ALL_LINUX_BUTTONS,
                rels=(REL_WHEEL, REL_HWHEEL, REL_WHEEL_HI_RES, REL_HWHEEL_HI_RES),
                abs_axes=((ABS_X, 0, w - 1), (ABS_Y, 0, h - 1)))
        self.keyboard = UinputDevice("parsec4linux keyboard",
                                     keys=pinput.ALL_LINUX_KEYS)
        self.unmapped: set[int] = set()
        self._wheel_acc = [0, 0]  # partial notches, [horizontal, vertical]

    def motion(self, x: int, y: int, rel: bool = False) -> None:
        if rel or self.relative:
            if rel:
                dx, dy = x, y
            else:
                # absolute coordinates but a relative device: difference them
                if self._last is None:
                    self._last = (x, y)
                    return
                dx, dy = x - self._last[0], y - self._last[1]
                self._last = (x, y)
            if dx:
                self.pointer.emit(EV_REL, 0, dx)
            if dy:
                self.pointer.emit(EV_REL, 1, dy)
        else:
            sw, sh = self.space
            if self.desktop:
                dw, dh = self.desktop
                # Map the client's space onto the desktop. Scale by (size - 1) so the
                # extremes land exactly on the edges rather than one pixel short.
                x = round(x * (dw - 1) / max(1, sw - 1))
                y = round(y * (dh - 1) / max(1, sh - 1))
                w, h = dw, dh
            else:
                w, h = sw, sh
            self.pointer.emit(EV_ABS, ABS_X, max(0, min(w - 1, x)))
            self.pointer.emit(EV_ABS, ABS_Y, max(0, min(h - 1, y)))
        self.pointer.sync()

    def button(self, parsec_button: int, pressed: bool) -> None:
        code = pinput.linux_button(parsec_button)
        if code is None:
            self.unmapped.add(parsec_button)
            return
        self.pointer.emit(EV_KEY, code, 1 if pressed else 0)
        self.pointer.sync()

    def wheel(self, x: int, y: int) -> None:
        # Units are Windows mouseData: 120 per notch, smaller for smooth-scrolling
        # devices. The DLL's injector (0x18007E230, case 2) passes them straight to
        # SendInput: field1 as MOUSEEVENTF_WHEEL, field0 as MOUSEEVENTF_HWHEEL. Signs
        # agree with evdev (positive = up / right).
        #
        # Emit the hi-res axis with the value as-is -- libinput scrolls smoothly from
        # it -- and the legacy notch axis once a whole notch has accumulated, for
        # clients that only read REL_WHEEL. The kernel's own hi-res mice do the same.
        for value, hi, lo, idx in ((y, REL_WHEEL_HI_RES, REL_WHEEL, 1),
                                   (x, REL_HWHEEL_HI_RES, REL_HWHEEL, 0)):
            if not value:
                continue
            self.pointer.emit(EV_REL, hi, value)
            self._wheel_acc[idx] += value
            notches = int(self._wheel_acc[idx] / WHEEL_DELTA)  # toward zero
            if notches:
                self.pointer.emit(EV_REL, lo, notches)
                self._wheel_acc[idx] -= notches * WHEEL_DELTA
        if x or y:
            self.pointer.sync()

    def key(self, parsec_code: int, pressed: bool) -> None:
        code = pinput.linux_keycode(parsec_code)
        if code is None:
            if parsec_code not in self.unmapped:
                self.unmapped.add(parsec_code)
                print(f"inject: unmapped keycode {parsec_code}", file=sys.stderr,
                      flush=True)
            return
        self.keyboard.emit(EV_KEY, code, 1 if pressed else 0)
        self.keyboard.sync()

    def set_space(self, w: int, h: int) -> None:
        """Change the client coordinate space that incoming motion is scaled from.

        The host sends this once it knows the encode size, and again if it changes.
        Only the scaling changes; the uinput device keeps the axes it was created
        with, since they describe the desktop, not the client.
        """
        if (w, h) == tuple(self.space) or w <= 0 or h <= 0:
            return
        print(f"inject: client space {self.space[0]}x{self.space[1]} -> {w}x{h}",
              file=sys.stderr, flush=True)
        self.space = (w, h)

    def handle(self, ev: dict) -> None:
        t = ev.get("t")
        if t == "space":
            self.set_space(int(ev["w"]), int(ev["h"]))
        elif t == "motion":
            self.motion(int(ev["x"]), int(ev["y"]), bool(ev.get("rel")))
        elif t == "button":
            self.button(int(ev["b"]), bool(ev.get("p")))
        elif t == "wheel":
            self.wheel(int(ev.get("x", 0)), int(ev.get("y", 0)))
        elif t == "key":
            self.key(int(ev["code"]), bool(ev.get("p")))

    def close(self) -> None:
        self.pointer.close()
        self.keyboard.close()


def parse_space(s: str) -> tuple[int, int]:
    w, h = s.lower().split("x")
    return int(w), int(h)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--client-space", type=parse_space,
                   default=pinput.CLIENT_SPACE_DEFAULT,
                   help="coordinate space of absolute motion. Only the value used "
                        "until the host reports the real one, which is the size it "
                        "advertises in the video header (the encode size).")
    p.add_argument("--desktop", type=parse_space, default=None,
                   help="real desktop size, e.g. 2554x1367. Given, the absolute axes "
                        "are declared at this size and client coordinates are "
                        "rescaled here, so the compositor maps 1:1. Strongly "
                        "recommended: without it the cursor drifts when the desktop "
                        "aspect differs from the client's.")
    p.add_argument("--relative", action="store_true",
                   help="create a relative pointer and difference absolute "
                        "coordinates, for compositors that mishandle an "
                        "absolute pointer")
    p.add_argument("--selftest", action="store_true",
                   help="create the devices, draw a small square, exit")
    args = p.parse_args()

    sink = InputSink(args.client_space, relative=args.relative,
                     desktop=args.desktop)
    w, h = args.client_space
    dsc = f" -> desktop {args.desktop[0]}x{args.desktop[1]}" if args.desktop else \
          " (no --desktop: compositor decides the mapping)"
    print(f"inject: devices up, client space {w}x{h}{dsc}"
          f"{' (relative mode)' if args.relative else ''}",
          file=sys.stderr, flush=True)

    if args.selftest:
        import time
        time.sleep(0.5)  # let udev/libinput notice the device
        for x, y in ((w // 4, h // 4), (3 * w // 4, h // 4),
                     (3 * w // 4, 3 * h // 4), (w // 4, 3 * h // 4),
                     (w // 2, h // 2)):
            sink.motion(x, y)
            print(f"inject: moved to {x},{y}", file=sys.stderr, flush=True)
            time.sleep(0.4)
        sink.close()
        return

    n = 0
    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                sink.handle(json.loads(line))
            except Exception as e:
                print(f"inject: bad event {line[:80]!r}: {e}", file=sys.stderr,
                      flush=True)
                continue
            n += 1
            if n % 500 == 0:
                print(f"inject: {n} events", file=sys.stderr, flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        sink.close()
        print(f"inject: closed after {n} events", file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()
