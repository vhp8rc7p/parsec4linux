#!/usr/bin/env python3
"""Capture + H.264 encode, emitting one length-prefixed Annex-B frame per access unit.

Runs under the SYSTEM python3 (it needs the GStreamer gi bindings, which the p4l venv
does not have). kessel_probe.py spawns it and reads frames from its stdout, so the
encoder and the Parsec protocol stay in separate processes.

stdout framing:  [u32 little-endian length][Annex-B frame bytes] ...

Sources:
  videotestsrc  a moving test pattern. Needs no portal consent, so it is the right way
                to prove the live pipeline (continuous frames, P-frames, realistic
                multi-fragment sizes) before adding screen-capture permissions.
  pipewire      the real screen via xdg-desktop-portal ScreenCast. On GNOME/Wayland
                this needs an interactive "share your screen" approval on the VM's own
                display; pass --node to skip the portal if you already have a node id.

x264 is configured for streaming, matching what a Parsec client accepts:
  * tune=zerolatency, no B-frames (bframes=0) -> output order == capture order
  * key-int-max so IDRs recur
  * h264parse config-interval=-1 -> SPS/PPS repeat with every keyframe, so a client
    that joins late (or loses the first frames) can still start decoding
"""
import argparse
import os
import random
import struct
import sys

import gi

gi.require_version("Gst", "1.0")
from gi.repository import Gio, GLib, Gst  # noqa: E402

PORTAL_NAME = "org.freedesktop.portal.Desktop"
PORTAL_PATH = "/org/freedesktop/portal/desktop"
SCREENCAST = "org.freedesktop.portal.ScreenCast"
TOKEN_FILE = os.path.expanduser("~/.config/parsec4linux/portal_token")

# SelectSources options
SOURCE_MONITOR = 1
CURSOR_MODE_EMBEDDED = 2  # draw the cursor into the frames (simplest for a host)
PERSIST_PERSISTENT = 2    # returns a restore_token so later runs skip the dialog


class ScreenCastPortal:
    """xdg-desktop-portal ScreenCast handshake.

    The PipeWire stream only lives as long as this portal session, so the object must
    be kept alive for the whole capture. On GNOME the first Start() shows an
    interactive "share your screen" dialog on the user's own display; we request
    persist_mode=2 and cache the restore_token so subsequent runs are silent.
    """

    def __init__(self):
        self.bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
        self.proxy = Gio.DBusProxy.new_sync(
            self.bus, Gio.DBusProxyFlags.NONE, None,
            PORTAL_NAME, PORTAL_PATH, SCREENCAST, None)
        self.session = None
        self.node_id = None
        self._loop = GLib.MainLoop()
        self._result = None

    @staticmethod
    def _token():
        return f"p4l{random.randint(0, 1 << 30)}"

    def _await_response(self, request_path):
        """Block until the portal answers on `request_path`, returning its results."""
        self._result = None

        def on_response(_conn, _sender, _path, _iface, _signal, params):
            code, results = params.unpack()
            self._result = (code, results)
            self._loop.quit()

        sub = self.bus.signal_subscribe(
            PORTAL_NAME, "org.freedesktop.portal.Request", "Response",
            request_path, None, Gio.DBusSignalFlags.NONE, on_response)
        try:
            self._loop.run()
        finally:
            self.bus.signal_unsubscribe(sub)
        code, results = self._result
        if code != 0:
            raise RuntimeError(f"portal request {request_path} denied/cancelled (code {code})")
        return results

    def _load_token(self):
        try:
            with open(TOKEN_FILE) as f:
                return f.read().strip()
        except OSError:
            return None

    def _save_token(self, token):
        if not token:
            return
        os.makedirs(os.path.dirname(TOKEN_FILE), mode=0o700, exist_ok=True)
        fd = os.open(TOKEN_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(token)

    def start(self):
        req = self.proxy.call_sync(
            "CreateSession",
            GLib.Variant("(a{sv})", ({"handle_token": GLib.Variant("s", self._token()),
                                      "session_handle_token": GLib.Variant("s", self._token())},)),
            Gio.DBusCallFlags.NONE, -1, None).unpack()[0]
        self.session = self._await_response(req)["session_handle"]

        opts = {
            "handle_token": GLib.Variant("s", self._token()),
            "types": GLib.Variant("u", SOURCE_MONITOR),
            "multiple": GLib.Variant("b", False),
            "cursor_mode": GLib.Variant("u", CURSOR_MODE_EMBEDDED),
            "persist_mode": GLib.Variant("u", PERSIST_PERSISTENT),
        }
        saved = self._load_token()
        if saved:
            opts["restore_token"] = GLib.Variant("s", saved)
            print("portal: reusing saved restore_token", file=sys.stderr, flush=True)
        req = self.proxy.call_sync(
            "SelectSources", GLib.Variant("(oa{sv})", (self.session, opts)),
            Gio.DBusCallFlags.NONE, -1, None).unpack()[0]
        self._await_response(req)

        print("portal: calling Start (approve the dialog on the host's display if it appears)",
              file=sys.stderr, flush=True)
        req = self.proxy.call_sync(
            "Start",
            GLib.Variant("(osa{sv})",
                         (self.session, "",
                          {"handle_token": GLib.Variant("s", self._token())})),
            Gio.DBusCallFlags.NONE, -1, None).unpack()[0]
        results = self._await_response(req)
        self._save_token(results.get("restore_token"))

        streams = results.get("streams") or []
        if not streams:
            raise RuntimeError("portal returned no streams")
        self.node_id = streams[0][0]
        print(f"portal: node_id={self.node_id} props={streams[0][1]}",
              file=sys.stderr, flush=True)
        return self.node_id

    def open_pipewire_fd(self):
        """Dup'd PipeWire remote fd for pipewiresrc."""
        ret, fds = self.proxy.call_with_unix_fd_list_sync(
            "OpenPipeWireRemote",
            GLib.Variant("(oa{sv})", (self.session, {})),
            Gio.DBusCallFlags.NONE, -1, None, None)
        return fds.get(ret.unpack()[0])


def build_pipeline(args):
    if args.source == "videotestsrc":
        src = (f"videotestsrc pattern={args.pattern} is-live=true "
               f"! video/x-raw,width={args.width},height={args.height},"
               f"framerate={args.fps}/1")
    else:
        props = f" path={args.node}" if args.node else ""
        if args.fd is not None:
            props += f" fd={args.fd}"
        # A desktop can be an odd size (seen: 1482x537). x264 with I420 needs even
        # dimensions or it refuses to initialise, so always scale to the requested
        # (even) size rather than passing the raw desktop size through.
        src = (f"pipewiresrc{props} do-timestamp=true "
               f"! videorate ! video/x-raw,framerate={args.fps}/1 "
               f"! videoscale ! video/x-raw,width={args.width},height={args.height}")
    return Gst.parse_launch(
        f"{src} ! videoconvert ! video/x-raw,format=I420 "
        f"! x264enc tune=zerolatency speed-preset={args.preset} "
        f"  bitrate={args.bitrate} key-int-max={args.keyint or args.fps} bframes=0 "
        f"! h264parse config-interval=-1 "
        f"! video/x-h264,stream-format=byte-stream,alignment=au "
        f"! appsink name=out emit-signals=true max-buffers=2 drop=true sync=false"
    )


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--source", choices=("videotestsrc", "pipewire"), default="videotestsrc")
    p.add_argument("--node", help="PipeWire node id from the portal (skips the portal)")
    p.add_argument("--fd", type=int, default=None, help="PipeWire remote fd (internal)")
    p.add_argument("--pattern", default="smpte", help="videotestsrc pattern")
    p.add_argument("--width", type=int, default=1280)
    p.add_argument("--height", type=int, default=720)
    p.add_argument("--fps", type=int, default=30)
    p.add_argument("--keyint", type=int, default=0,
                   help="IDR interval in frames (default: fps, i.e. 1 s)")
    p.add_argument("--bitrate", type=int, default=4000, help="kbit/s")
    p.add_argument("--preset", default="ultrafast")
    args = p.parse_args()

    Gst.init(None)

    # Hold the portal session for the whole capture: the PipeWire stream dies with it.
    portal = None
    if args.source == "pipewire" and not args.node:
        portal = ScreenCastPortal()
        args.node = portal.start()
        args.fd = portal.open_pipewire_fd()
        print(f"portal: fd={args.fd}", file=sys.stderr, flush=True)

    pipeline = build_pipeline(args)
    out = pipeline.get_by_name("out")
    stdout = sys.stdout.buffer

    def on_sample(sink):
        sample = sink.emit("pull-sample")
        if sample is None:
            return Gst.FlowReturn.OK
        buf = sample.get_buffer()
        ok, info = buf.map(Gst.MapFlags.READ)
        if not ok:
            return Gst.FlowReturn.OK
        try:
            stdout.write(struct.pack("<I", info.size))
            stdout.write(info.data)
            stdout.flush()
        except BrokenPipeError:
            loop.quit()
        finally:
            buf.unmap(info)
        return Gst.FlowReturn.OK

    out.connect("new-sample", on_sample)

    loop = GLib.MainLoop()

    def on_message(_bus, msg):
        if msg.type == Gst.MessageType.ERROR:
            err, debug = msg.parse_error()
            print(f"gst error: {err} ({debug})", file=sys.stderr, flush=True)
            loop.quit()
        elif msg.type == Gst.MessageType.EOS:
            print("gst eos", file=sys.stderr, flush=True)
            loop.quit()

    bus = pipeline.get_bus()
    bus.add_signal_watch()
    bus.connect("message", on_message)

    if pipeline.set_state(Gst.State.PLAYING) == Gst.StateChangeReturn.FAILURE:
        print("failed to start pipeline", file=sys.stderr, flush=True)
        return 1
    print(f"capture: {args.source} {args.width}x{args.height}@{args.fps} "
          f"{args.bitrate}kbps", file=sys.stderr, flush=True)
    try:
        loop.run()
    except KeyboardInterrupt:
        pass
    finally:
        pipeline.set_state(Gst.State.NULL)
    return 0


if __name__ == "__main__":
    sys.exit(main())
