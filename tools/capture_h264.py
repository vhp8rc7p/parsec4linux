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
import collections
import os
import random
import struct
import sys
import time

import gi

gi.require_version("Gst", "1.0")
from gi.repository import Gio, GLib, Gst  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from parsec4linux.video import encode_size  # noqa: E402

PORTAL_NAME = "org.freedesktop.portal.Desktop"
PORTAL_PATH = "/org/freedesktop/portal/desktop"
SCREENCAST = "org.freedesktop.portal.ScreenCast"
TOKEN_FILE = os.path.expanduser("~/.config/parsec4linux/portal_token")

# SelectSources options
SOURCE_MONITOR = 1
CURSOR_MODE_HIDDEN = 1    # leave the cursor out; the client draws its own
CURSOR_MODE_EMBEDDED = 2  # draw the cursor into the frames (simplest for a host)
PERSIST_PERSISTENT = 2    # returns a restore_token so later runs skip the dialog


class ScreenCastPortal:
    """xdg-desktop-portal ScreenCast handshake.

    The PipeWire stream only lives as long as this portal session, so the object must
    be kept alive for the whole capture. On GNOME the first Start() shows an
    interactive "share your screen" dialog on the user's own display; we request
    persist_mode=2 and cache the restore_token so subsequent runs are silent.
    """

    def __init__(self, cursor_mode=CURSOR_MODE_EMBEDDED):
        self.cursor_mode = cursor_mode
        self.bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
        self.proxy = Gio.DBusProxy.new_sync(
            self.bus, Gio.DBusProxyFlags.NONE, None,
            PORTAL_NAME, PORTAL_PATH, SCREENCAST, None)
        self.session = None
        self.node_id = None
        self.size = None
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
            "cursor_mode": GLib.Variant("u", self.cursor_mode),
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
        props = streams[0][1] or {}
        # The portal hands us the monitor's real size here, which is how we learn what
        # to encode at. Probing it from a throwaway pipeline does not work: the
        # PipeWire fd is consumed by the first pipewiresrc that uses it.
        size = props.get("size")
        if size and len(size) == 2 and size[0] > 0 and size[1] > 0:
            self.size = (int(size[0]), int(size[1]))
        print(f"portal: node_id={self.node_id} props={props}",
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
               f"framerate={args.fps}/1 ! identity name=stamp")
    else:
        props = f" path={args.node}" if args.node else ""
        if args.fd is not None:
            props += f" fd={args.fd}"
        # A desktop can be an odd size (seen: 1482x537). x264 with I420 needs even
        # dimensions or it refuses to initialise, so always scale to the requested
        # (even) size rather than passing the raw desktop size through.
        # args.width/height are the chosen ENCODE size, already even and aspect-
        # preserving (see encode_size). When they equal the source there is no scaler
        # in the path; videoscale is a no-op passthrough on matching caps, and the
        # capsfilter is what keeps x264 on a stable size if the desktop is resized.
        # pixel-aspect-ratio=1/1 stops videoscale from "satisfying" a fixed size by
        # changing the PAR and letting the decoder stretch it back out.
        scale = (f"videoscale add-borders=true ! video/x-raw,"
                 f"width={args.width},height={args.height},pixel-aspect-ratio=1/1")
        # drop-only: videorate's default may *duplicate* buffers to reach the target
        # rate, which means holding the previous one to decide -- a frame of latency we
        # have no use for. We only want to cap the rate: PipeWire is damage-driven, so
        # an idle desktop should produce nothing rather than synthetic repeats.
        # identity name=stamp: a passthrough where each frame's arrival is clocked, for
        # the per-frame encode latency (see on_stamp). It sits AFTER videorate because
        # videorate rewrites timestamps, and the PTS is how the frame is found again at
        # the appsink.
        # keepalive-time: PipeWire only delivers on damage, and with --cursor hidden
        # moving the mouse is not damage, so a still desktop sent ONE frame and then
        # nothing -- a connecting client sat on "getting things ready" until something
        # repainted. Re-sending the last buffer when idle keeps a floor of frames; x264
        # turns an unchanged frame into a P-frame of a few hundred bytes.
        props += f" keepalive-time={args.keepalive_ms}"
        src = (f"pipewiresrc{props} do-timestamp=true "
               f"! videorate drop-only=true ! video/x-raw,framerate={args.fps}/1 "
               f"! identity name=stamp ! {scale}")
    return Gst.parse_launch(
        f"{src} ! videoconvert ! video/x-raw,format=I420 "
        f"! x264enc tune=zerolatency speed-preset={args.preset} "
        f"  sliced-threads={str(args.sliced_threads).lower()} threads={args.threads} "
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
    p.add_argument("--width", type=int, default=1280,
                   help="encode width; with pipewire this is only a fallback, since "
                        "the source's own size is used (see --native-off)")
    p.add_argument("--height", type=int, default=720, help="encode height; see --width")
    p.add_argument("--max-w", type=int, default=1920,
                   help="scale down past this width, preserving aspect (Parsec's own "
                        "host scales only above 1920x1080)")
    p.add_argument("--max-h", type=int, default=1080, help="see --max-w")
    p.add_argument("--native-off", action="store_true",
                   help="ignore the source size and encode at --width x --height, "
                        "distorting if the aspect differs (the old behaviour)")
    p.add_argument("--fps", type=int, default=30)
    p.add_argument("--cursor", choices=("embedded", "hidden"), default="embedded",
                   help="embedded draws the real cursor into the stream, so you see "
                        "two cursors (the client draws its own too) and can check "
                        "they line up; hidden leaves it out, like real Parsec, "
                        "leaving only the client's")
    p.add_argument("--keepalive-ms", type=int, default=100,
                   help="when the desktop is idle, repeat the last frame this often "
                        "(0 = only send on screen changes, which can leave a newly "
                        "connected client waiting for its first picture)")
    p.add_argument("--keyint", type=int, default=0,
                   help="IDR interval in frames (default: fps, i.e. 1 s)")
    p.add_argument("--bitrate", type=int, default=4000, help="kbit/s")
    p.add_argument("--preset", default="ultrafast")
    p.add_argument("--threads", type=int, default=0,
                   help="x264 threads (0 = one per core)")
    p.add_argument("--sliced-threads", dest="sliced_threads",
                   action=argparse.BooleanOptionalAction, default=True,
                   help="split each frame into slices across cores instead of encoding "
                        "several frames in parallel. ON by default, and tune=zerolatency "
                        "sets it too -- but x264enc applies the tune first and then "
                        "overwrites it from this property, so --no-sliced-threads really "
                        "does re-enable frame-based threading, which holds ~threads "
                        "frames (>100 ms at 30 fps) before the first one comes out. "
                        "It costs a little compression efficiency, not throughput: an "
                        "earlier benchmark found no frame-rate difference, which is the "
                        "wrong metric -- this is a latency control.")
    args = p.parse_args()

    Gst.init(None)

    # Hold the portal session for the whole capture: the PipeWire stream dies with it.
    portal = None
    if args.source == "pipewire" and not args.node:
        portal = ScreenCastPortal(
            CURSOR_MODE_HIDDEN if args.cursor == "hidden" else CURSOR_MODE_EMBEDDED)
        args.node = portal.start()
        args.fd = portal.open_pipewire_fd()
        print(f"portal: fd={args.fd}", file=sys.stderr, flush=True)

    # Native-resolution encoding: ask the source how big it actually is, then encode
    # at that size (even-rounded, capped) rather than at a size chosen on the command
    # line. --width/--height become the cap, not the target.
    if args.source == "pipewire" and not args.native_off:
        got = portal.size if portal else None
        if got:
            src_w, src_h = got
            args.width, args.height = encode_size(src_w, src_h, args.max_w, args.max_h)
            scaled = (src_w, src_h) != (args.width, args.height)
            print(f"capture: source {src_w}x{src_h} -> encode {args.width}x"
                  f"{args.height}"
                  f"{' (scaled to cap)' if scaled else ' (native, no scaling)'}",
                  file=sys.stderr, flush=True)
        else:
            print(f"capture: portal did not report a size; falling back to "
                  f"{args.width}x{args.height}", file=sys.stderr, flush=True)

    pipeline = build_pipeline(args)
    out = pipeline.get_by_name("out")
    stdout = sys.stdout.buffer

    # Per-frame capture -> encoded latency, the figure Parsec's host reports as
    # "Encode" in the client's HUD. Clock each raw frame as it leaves the `stamp`
    # passthrough and pair it with the next encoded frame at the appsink, in order.
    # Not by PTS: x264enc rewrites it (a 1000-hour min-pts offset, and snapped to its
    # frame grid), so nothing links an output to its input but sequence -- and with
    # bframes=0 and nothing in between that drops, it is exactly one out per one in.
    arrivals: collections.deque[int] = collections.deque(maxlen=64)

    def on_stamp(_pad, info):
        arrivals.append(time.monotonic_ns())
        return Gst.PadProbeReturn.OK

    pipeline.get_by_name("stamp").get_static_pad("src").add_probe(
        Gst.PadProbeType.BUFFER, on_stamp)

    def on_sample(sink):
        sample = sink.emit("pull-sample")
        if sample is None:
            return Gst.FlowReturn.OK
        buf = sample.get_buffer()
        ok, info = buf.map(Gst.MapFlags.READ)
        if not ok:
            return Gst.FlowReturn.OK
        try:
            # Record: [u32 le payload length][u16 le width][u16 le height]
            #         [u32 le encode latency, us; 0 = unknown][payload].
            # The dimensions travel with every frame because the host writes them
            # into the video header of every frame, and because a stream can change
            # size while running -- which is exactly why Parsec put width/height in
            # the per-frame header rather than in the handshake.
            enc_us = 0
            if arrivals:
                enc_us = (time.monotonic_ns() - arrivals.popleft()) // 1000
                if enc_us > 1_000_000:  # pairing lost (a drop somewhere): resync
                    arrivals.clear()
                    enc_us = 0
            w, h = args.width, args.height
            caps = sample.get_caps()
            if caps and caps.get_size():
                s = caps.get_structure(0)
                ok_w, cw = s.get_int("width")
                ok_h, ch = s.get_int("height")
                if ok_w and ok_h and cw > 0 and ch > 0:
                    w, h = cw, ch
            stdout.write(struct.pack("<IHHI", info.size, w, h, enc_us))
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
