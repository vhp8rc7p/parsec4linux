#!/usr/bin/env python3
"""Capture the desktop's audio output and encode it the way a Parsec host does.

What the Windows host does (host_audio_thread 0x1800AD180 -> 0x1800AA990 ->
audio_encode_init 0x18004BD20): capture 48 kHz interleaved int16 stereo in frames of
960 samples (20 ms; 240 in its low-latency mode), and encode each frame with
opus_encoder_create(48000, 2, OPUS_APPLICATION_AUDIO) at host_audio_bitrate. Every
encoded frame becomes one audio message (see parsec4linux/audio.py).

Here: PipeWire's pulse compatibility layer exposes the default output's monitor as
@DEFAULT_MONITOR@ -- what is being played, not a microphone -- and GStreamer's opusenc
emits exactly one Opus packet per buffer, so packet boundaries survive.

Writes to stdout one record per packet: [u32 le length][payload]. Runs under the
system python3 (needs gi), like capture_h264.py.
"""
from __future__ import annotations

import argparse
import struct
import sys
import time

import gi

gi.require_version("Gst", "1.0")
from gi.repository import GLib, Gst  # noqa: E402

RATE = 48000
CHANNELS = 2


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--device", default="@DEFAULT_MONITOR@",
                   help="pulse source to capture (default: whatever is playing)")
    p.add_argument("--bitrate", type=int, default=128,
                   help="Opus kbit/s (default 128, which matches the ~308-byte packets "
                        "a real Windows host sent)")
    p.add_argument("--frame-ms", type=int, default=20, choices=(5, 10, 20),
                   help="20 ms = the host's normal 960-sample frame; 5 = its low-latency "
                        "240-sample mode")
    args = p.parse_args()

    Gst.init(None)
    # latency-time: how often pulsesrc hands over audio. Keep it below one Opus frame
    # so it never adds a frame of delay of its own.
    # buffer-time: how much it can hold if this process is starved of CPU. It is
    # capacity, not delay -- audio is still handed over every latency-time -- so it
    # is sized for the worst stall (heavy encode while scrolling a playing video),
    # not for latency. At 40 ms that stall overran it: audible dropouts.
    pipeline = Gst.parse_launch(
        f"pulsesrc device={args.device} latency-time=5000 buffer-time=200000 "
        f"! audioconvert ! audioresample "
        f"! audio/x-raw,format=S16LE,rate={RATE},channels={CHANNELS},layout=interleaved "
        f"! opusenc bitrate={args.bitrate * 1000} frame-size={args.frame_ms} "
        f"  audio-type=generic "
        f"! appsink name=out emit-signals=true max-buffers=8 drop=true sync=false")
    out = pipeline.get_by_name("out")
    stdout = sys.stdout.buffer
    loop = GLib.MainLoop()
    frame_ns = args.frame_ms * 1_000_000
    gaps = {"n": 0, "lost_ms": 0.0, "prev": None, "reported": time.monotonic()}

    def note_gap(buf):
        """Count audio lost BEFORE encoding: a capture overrun shows up as a jump in
        timestamps (and the DISCONT flag). Reported every 5 s, only when non-zero, so
        a dropout can be pinned on capture rather than on the network."""
        pts = buf.pts
        if pts != Gst.CLOCK_TIME_NONE and gaps["prev"] is not None:
            lost = pts - gaps["prev"] - frame_ns
            if lost > frame_ns // 2 or buf.has_flags(Gst.BufferFlags.DISCONT):
                gaps["n"] += 1
                gaps["lost_ms"] += max(0, lost) / 1e6
        if pts != Gst.CLOCK_TIME_NONE:
            gaps["prev"] = pts
        now = time.monotonic()
        if now - gaps["reported"] >= 5.0:
            if gaps["n"]:
                print(f"audio: capture lost {gaps['lost_ms']:.0f} ms in {gaps['n']} "
                      f"gap(s) over the last 5 s", file=sys.stderr, flush=True)
            gaps.update(n=0, lost_ms=0.0, reported=now)

    def on_sample(sink):
        sample = sink.emit("pull-sample")
        if sample is None:
            return Gst.FlowReturn.OK
        buf = sample.get_buffer()
        note_gap(buf)
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

    def on_message(_bus, msg):
        if msg.type == Gst.MessageType.ERROR:
            err, debug = msg.parse_error()
            print(f"audio: gst error: {err} ({debug})", file=sys.stderr, flush=True)
            loop.quit()
        elif msg.type == Gst.MessageType.EOS:
            loop.quit()

    bus = pipeline.get_bus()
    bus.add_signal_watch()
    bus.connect("message", on_message)
    if pipeline.set_state(Gst.State.PLAYING) == Gst.StateChangeReturn.FAILURE:
        print("audio: failed to start pipeline", file=sys.stderr, flush=True)
        return 1
    print(f"audio: {args.device} -> Opus {RATE} Hz x{CHANNELS} {args.bitrate} kbit/s, "
          f"{args.frame_ms} ms frames", file=sys.stderr, flush=True)
    try:
        loop.run()
    except KeyboardInterrupt:
        pass
    finally:
        pipeline.set_state(Gst.State.NULL)
    return 0


if __name__ == "__main__":
    sys.exit(main())
