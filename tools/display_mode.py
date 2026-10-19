#!/usr/bin/env python3
"""Change the desktop resolution when a Parsec client asks for one, and put it back.

The Windows host does this in `sub_1800AB550` -> `sub_180061A20`: when a guest's config
(control message 0x0b, `resolutionX`/`resolutionY`) names a size different from the
current one, it writes that size into the display's source mode and calls
SetDisplayConfig(..., SDC_APPLY | SDC_USE_SUPPLIED_DISPLAY_CONFIG | SDC_ALLOW_CHANGES),
letting Windows snap it to something the display supports. A request of 0 (or 0xFFFF)
means "the original resolution", which is how it restores.

On GNOME the equivalent is Mutter's org.gnome.Mutter.DisplayConfig. Mutter will not
snap for us, so the nearest advertised mode is chosen here. Changes are applied with
method 1 (temporary): nothing is written to monitors.xml, so a crash leaves the
user's saved layout untouched.

    display_mode.py get                    current size, as JSON
    display_mode.py set 1920x1080 [--fps 60]
    display_mode.py restore                back to the mode before the first `set`

Runs under the system python3 (needs gi), like capture_h264.py. Prints one JSON line.
Only the primary monitor is changed; other monitors keep their current modes.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import gi

gi.require_version("Gio", "2.0")
from gi.repository import Gio, GLib  # noqa: E402

BUS_NAME = "org.gnome.Mutter.DisplayConfig"
OBJ_PATH = "/org/gnome/Mutter/DisplayConfig"
METHOD_TEMPORARY = 1
STATE = os.path.join(os.environ.get("XDG_RUNTIME_DIR", "/tmp"),
                     "parsec4linux-display.json")


def _call(bus, method, params=None, sig=None):
    return bus.call_sync(BUS_NAME, OBJ_PATH, BUS_NAME, method,
                         params, GLib.VariantType(sig) if sig else None,
                         Gio.DBusCallFlags.NONE, -1, None).unpack()


def current_state(bus):
    """-> (serial, monitors, logical_monitors), monitors keyed by connector."""
    serial, monitors, logical, _props = _call(bus, "GetCurrentState")
    mons = {}
    for (conn, vendor, product, mserial), modes, _mprops in monitors:
        mons[conn] = {
            "modes": [{"id": m[0], "w": m[1], "h": m[2], "rate": m[3],
                       "scales": list(m[5]), "current": bool(m[6].get("is-current")),
                       "preferred": bool(m[6].get("is-preferred"))} for m in modes],
        }
    return serial, mons, logical


def _current_mode(mon):
    return next((m for m in mon["modes"] if m["current"]), None)


def _primary(logical):
    return next((lm for lm in logical if lm[4]), logical[0])


def pick_mode(modes, w, h, fps):
    """Exact size if offered (refresh nearest `fps`), else the nearest size.

    Distance is |dw| + |dh|: asking for 2560x1440 on a display that offers 2560x1600
    and 2048x1152 gets 2560x1600, the one that keeps the requested width.
    """
    exact = [m for m in modes if m["w"] == w and m["h"] == h]
    pool = exact or modes
    return min(pool, key=lambda m: (abs(m["w"] - w) + abs(m["h"] - h),
                                    abs(m["rate"] - fps)))


def apply(bus, serial, mons, logical, primary_mode_id, primary_scale=None):
    """Re-apply the whole layout with the primary monitor's mode replaced."""
    prim = _primary(logical)
    prim_conn = prim[5][0][0]
    out = []
    for x, y, scale, transform, is_primary, conns, _p in logical:
        monitors = []
        for conn, *_ in conns:
            if conn == prim_conn:
                mode_id = primary_mode_id
            else:
                cur = _current_mode(mons[conn])
                mode_id = cur["id"] if cur else mons[conn]["modes"][0]["id"]
            monitors.append((conn, mode_id, {}))
        if prim_conn in [c[0] for c in conns]:
            mode = next(m for m in mons[prim_conn]["modes"] if m["id"] == primary_mode_id)
            want = primary_scale if primary_scale is not None else scale
            # keep the user's scale if the new mode supports it, else fall back to 1x
            scale = min(mode["scales"], key=lambda s: abs(s - want))
            if abs(scale - want) > 0.01:
                scale = 1.0
        out.append((x, y, scale, transform, is_primary, monitors))
    params = GLib.Variant("(uua(iiduba(ssa{sv}))a{sv})",
                          (serial, METHOD_TEMPORARY, out, {}))
    _call(bus, "ApplyMonitorsConfig", params)


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("get")
    s = sub.add_parser("set")
    s.add_argument("size", help="WxH")
    s.add_argument("--fps", type=float, default=60.0)
    sub.add_parser("restore")
    args = p.parse_args()

    bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
    serial, mons, logical = current_state(bus)
    prim = _primary(logical)
    conn = prim[5][0][0]
    cur = _current_mode(mons[conn])

    if args.cmd == "get":
        print(json.dumps({"ok": True, "connector": conn, "mode": cur["id"],
                          "size": [cur["w"], cur["h"]], "scale": prim[2]}))
        return 0

    if args.cmd == "set":
        w, h = (int(v) for v in args.size.lower().split("x"))
        mode = pick_mode(mons[conn]["modes"], w, h, args.fps)
        # Remember the ORIGINAL mode once, so repeated requests during a session (or
        # across reconnects) still restore to what the desktop had before Parsec.
        if not os.path.exists(STATE):
            with open(STATE, "w") as f:
                json.dump({"connector": conn, "mode": cur["id"], "scale": prim[2]}, f)
        if mode["id"] != cur["id"]:
            apply(bus, serial, mons, logical, mode["id"])
        print(json.dumps({"ok": True, "requested": [w, h], "mode": mode["id"],
                          "size": [mode["w"], mode["h"]],
                          "changed": mode["id"] != cur["id"]}))
        return 0

    # restore
    try:
        with open(STATE) as f:
            saved = json.load(f)
    except FileNotFoundError:
        print(json.dumps({"ok": True, "changed": False, "size": [cur["w"], cur["h"]],
                          "note": "nothing to restore"}))
        return 0
    known = {m["id"]: m for m in mons[conn]["modes"]}
    mode = known.get(saved["mode"])
    if mode is None:
        # The original was a window-sized custom mode that no longer exists (the VM
        # window was resized meanwhile): fall back to the display's preferred mode.
        mode = next((m for m in mons[conn]["modes"] if m["preferred"]), cur)
    changed = mode["id"] != cur["id"]
    if changed:
        apply(bus, serial, mons, logical, mode["id"], saved.get("scale"))
    os.remove(STATE)
    print(json.dumps({"ok": True, "changed": changed, "mode": mode["id"],
                      "size": [mode["w"], mode["h"]]}))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except GLib.Error as e:
        print(json.dumps({"ok": False, "error": e.message}))
        sys.exit(1)
