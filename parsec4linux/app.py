"""Parsec app-level control messages (150-105c) — the 13-byte header.

Reversed from the per-client dispatch `sub_1800A9E70`, whose send calls look like:

    v87[0] = htonl(field0); v87[1] = htonl(field1); v87[2] = htonl(field2);
    v88 = <type>;
    send(bud_ctx, /*channel=*/0, 0, 0, v87, 13, 0);

So a control message is `{3 x u32 be, u8 type}` with the **type byte last**, and the
three fields are type-specific. (The earlier guess that field0 was always the payload
length only fitted the config message by coincidence.) Control messages ride
**channel 0**; video rides channel 1 (see video.py).

Types observed host->client:
  0x1D  stream init   {stream_index, timestamp, 0}  — sent on the first frame after the
                      encoder comes up (the `encode_x`/`encode_y` path), so a client
                      probably needs it before it will accept video.
  0x10  blocked flag  {1, 0, 0} = blocked (host window occluded / not capturable),
                      {0, 0, 0} = unblocked. Not sent at all in normal operation.
  0x15  heartbeat     {1, encode_us, stream_index} — every 30 frames. Field1 is NOT an
                      uptime: the host sends lrint(encode_ms * 1000.0) (0x1800AA411,
                      constant 0x408F4000... = 1000.0) and the client stores
                      field1 / 1000 as that stream's encodeLatency (0x180048A40, case
                      21). It is what the HUD's "Encode" shows. {2, ..., 0} is the
                      audio stream's equivalent.
  0x22  frame stats   {0, stream_index, 0} + 16-byte payload: 4 x float32, big-endian
                      (the DLL htonl()s each float's bit pattern). Built in the
                      per-stream loop `sub_1800ABCA0`, once per encoded frame:
                        [0] total     ms, start of this loop iteration -> encoded
                        [1] capture   ms, capture call -> frame in hand
                        [2] encode    ms, frame captured -> encoded; the same value the
                                      host EWMAs into its own `encodeLatency` metric
                        [3] interval  ms since the previous encoded frame
                      The client pushes these into a per-stream history ring
                      (0x180048A40, case 34) -- the performance graphs -- not into
                      the HUD's number, which comes from the 0x15 heartbeat.
                      {1, 0, 0} + 12 bytes is the audio version. (Long misfiled
                      here as "cursor/stats".)

Types observed client->host (see re/NOTES.md): 0x0b config JSON, 0x23, 0x11, 0x0d, 0x03.
"""
from __future__ import annotations

import struct

HEADER_LEN = 13
CONTROL_CHANNEL = 0

TYPE_STREAM_INIT = 0x1D
TYPE_BLOCKED = 0x10
TYPE_HEARTBEAT = 0x15
TYPE_FRAME_STATS = 0x22
_STATS = struct.Struct("!ffff")

# client -> host, for decoding
TYPE_CONFIG = 0x0B
TYPE_CLIENT_23 = 0x23
TYPE_CLIENT_11 = 0x11
TYPE_CLIENT_0D = 0x0D
TYPE_CLIENT_03 = 0x03


def build(msg_type: int, field0: int = 0, field1: int = 0, field2: int = 0) -> bytes:
    """Build a 13-byte control header: three big-endian u32s then the type byte."""
    return struct.pack("!IIIB", field0 & 0xFFFFFFFF, field1 & 0xFFFFFFFF,
                       field2 & 0xFFFFFFFF, msg_type & 0xFF)


def parse(data: bytes) -> dict:
    """Decode a 13-byte control header (plus whatever payload follows)."""
    if len(data) < HEADER_LEN:
        raise ValueError(f"short control header: {len(data)} bytes")
    f0, f1, f2, t = struct.unpack_from("!IIIB", data, 0)
    return {"type": t, "field0": f0, "field1": f1, "field2": f2,
            "payload": data[HEADER_LEN:]}


def stream_init(stream_index: int, timestamp: int) -> bytes:
    """0x1D — tells the client a stream is starting. Sent before the first frame."""
    return build(TYPE_STREAM_INIT, stream_index, timestamp, 0)


def heartbeat(encode_us: int, stream_index: int) -> bytes:
    """0x15 — every 30 frames: the video encode time the client's HUD shows."""
    return build(TYPE_HEARTBEAT, 1, encode_us, stream_index)


def blocked(is_blocked: bool) -> bytes:
    """0x10 — host capture blocked / unblocked."""
    return build(TYPE_BLOCKED, 1 if is_blocked else 0, 0, 0)


def frame_stats(stream_index: int, total_ms: float, capture_ms: float,
                encode_ms: float, interval_ms: float) -> bytes:
    """0x22 — per-frame host timings, the source of the client HUD's "Encode"."""
    return (build(TYPE_FRAME_STATS, 0, stream_index, 0)
            + _STATS.pack(total_ms, capture_ms, encode_ms, interval_ms))


def parse_frame_stats(data: bytes) -> tuple[float, float, float, float]:
    """Inverse of frame_stats' payload: (total, capture, encode, interval) in ms."""
    return _STATS.unpack_from(data, HEADER_LEN)


if __name__ == "__main__":
    h = stream_init(0, 0x11223344)
    assert len(h) == HEADER_LEN
    got = parse(h)
    assert got["type"] == TYPE_STREAM_INIT, got
    assert got["field0"] == 0 and got["field1"] == 0x11223344, got
    # type byte really is last, and fields really are big-endian
    assert h == bytes.fromhex("00000000") + bytes.fromhex("11223344") + bytes.fromhex("00000000") + b"\x1d"
    assert parse(heartbeat(5000, 2))["field2"] == 2
    assert parse(blocked(True))["field0"] == 1
    assert parse(blocked(False))["field0"] == 0
    # the captured client config decodes as type 0x0b
    cap = bytes.fromhex("0000015a00000000000000000b")
    assert parse(cap)["type"] == TYPE_CONFIG, parse(cap)
    # 0x22: 13 + 16 bytes, stream index in field1, floats big-endian
    st = frame_stats(0, 9.5, 0.0, 8.25, 33.0)
    assert len(st) == HEADER_LEN + 16, len(st)
    assert parse(st)["type"] == TYPE_FRAME_STATS and parse(st)["field1"] == 0
    assert st[HEADER_LEN + 8:HEADER_LEN + 12] == struct.pack(">f", 8.25)
    assert parse_frame_stats(st) == (9.5, 0.0, 8.25, 33.0)
    print("app.py self-test OK (13-byte header, type last, big-endian fields, 0x22 stats)")
