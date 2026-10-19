"""Parsec video packet format (150-105c).

Reversed from `proto_video_write` (DLL 0x1800A5230), its caller 0x1800A9E70 (the
per-client frame dispatch) and the per-stream capture/encode thread 0x1800ABCA0.

A video packet is an ordinary BUD reliable message whose app-level header is 10 bytes
(control messages use a different 13-byte header -- see `app.py`):

    BUD 7-byte header        01 | 0x21 last / 0x01 more | channel | u32 be seq
    u32 be total length      first fragment only
    10-byte video header     <- this module
    payload                  the encoder's output, verbatim

    video header
      +0  u32  timestamp / frame counter
      +4  u16  width
      +6  u16  height
      +8  u8   frame kind   (client cfg field, else 1)
      +9  u8   flags        (qp & 7) | 0x08 | 0x10 | 0x20 | 0x60

Channel: `stream_index ? stream_index + 2 : 1`, so the primary stream is **channel 1**.
The host supports 5 streams (0x1800AF5B0 spawns 5 per-stream threads).

Payload: with `mediaContainer == 0` (what a real client requests) the encoded frame is
sent verbatim. Only `mediaContainer == 2` routes through a repacker
(`sub_18009CBF0`), which we do not implement.

BYTE ORDER CAVEAT: `proto_video_write` stores these fields with plain assignments and
no htonl/htons, unlike the control-message path which byte-swaps explicitly. So the
video header looks NATIVE (little-endian on x86) while control messages are big-endian.
That asymmetry is suspicious and is NOT yet confirmed against a live client -- if a
client rejects our frames, flipping `BIG_ENDIAN_HEADER` is the first thing to try.
"""
from __future__ import annotations

import struct

HEADER_LEN = 10
PRIMARY_CHANNEL = 1
MAX_STREAMS = 5

# See the caveat above: the DLL appears to write these natively.
BIG_ENDIAN_HEADER = False

# flags bits, from 0x1800A5230 / 0x1800A9E70
FLAG_MASK_QP = 0x07
FLAG_BIT_08 = 0x08
FLAG_BIT_10 = 0x10
FLAG_BIT_20 = 0x20
# 0x1800A9E70's stats path additionally ORs 0x60 into the same byte.
FLAG_BITS_60 = 0x60


# Parsec's own host encodes natively and scales only past this, preserving aspect
# (verified in the host pipeline at 0x1800AF5B0; its hard cap is 0x2000 x 0x10E0).
MAX_ENCODE_W, MAX_ENCODE_H = 1920, 1080
HARD_CAP_W, HARD_CAP_H = 0x2000, 0x10E0


def encode_size(src_w: int, src_h: int,
                max_w: int = MAX_ENCODE_W, max_h: int = MAX_ENCODE_H) -> tuple:
    """Encode size for a source of src_w x src_h, the way Parsec picks one.

    At or under the cap the native size is kept, so no scaler is needed at all. Over
    it, scale down preserving aspect to fit inside the cap. Either way round *down* to
    even, because H.264 with I420 chroma subsampling needs even width and height and
    x264 refuses to initialise otherwise (a 1482x537 desktop hit exactly this).

    Rounding down costs at most one row or column, which is invisible; rescaling to a
    fixed shape instead visibly squashes the picture, which is what we used to do.
    """
    if src_w <= 0 or src_h <= 0:
        raise ValueError(f"bad source size {src_w}x{src_h}")
    w, h = src_w, src_h
    if w > max_w or h > max_h:
        scale = min(max_w / w, max_h / h)
        w, h = int(w * scale), int(h * scale)
    w -= w % 2
    h -= h % 2
    return max(2, w), max(2, h)


def channel_for_stream(stream_index: int) -> int:
    """Video BUD channel for a stream: 0 -> 1, N -> N + 2."""
    if not 0 <= stream_index < MAX_STREAMS:
        raise ValueError(f"stream {stream_index} outside 0..{MAX_STREAMS - 1}")
    return stream_index + 2 if stream_index else PRIMARY_CHANNEL


def build_header(timestamp: int, width: int, height: int, kind: int = 1,
                 qp: int = 0, bit08: bool = False, bit10: bool = False,
                 bit20: bool = False) -> bytes:
    """Build the 10-byte video header that precedes an encoded frame."""
    flags = qp & FLAG_MASK_QP
    if bit08:
        flags |= FLAG_BIT_08
    if bit10:
        flags |= FLAG_BIT_10
    if bit20:
        flags |= FLAG_BIT_20
    fmt = "!IHHBB" if BIG_ENDIAN_HEADER else "<IHHBB"
    return struct.pack(fmt, timestamp & 0xFFFFFFFF, width, height, kind, flags)


def build_raw_header(timestamp: int, width: int, height: int, kind: int,
                     flags: int) -> bytes:
    """Build the 10-byte header from literal field values.

    Preferred over build_header() now that the real values are known from a live host:
    timestamp is a constant 1, kind is 0x02, and flags is 0x01/0x21/0x61 rather than
    anything derived from a qp.
    """
    fmt = "!IHHBB" if BIG_ENDIAN_HEADER else "<IHHBB"
    return struct.pack(fmt, timestamp & 0xFFFFFFFF, width, height,
                       kind & 0xFF, flags & 0xFF)


def parse_header(data: bytes) -> dict:
    """Inverse of build_header, for checking captures."""
    if len(data) < HEADER_LEN:
        raise ValueError(f"short video header: {len(data)} bytes")
    fmt = "!IHHBB" if BIG_ENDIAN_HEADER else "<IHHBB"
    ts, w, h, kind, flags = struct.unpack_from(fmt, data, 0)
    return {"timestamp": ts, "width": w, "height": h, "kind": kind, "flags": flags,
            "qp": flags & FLAG_MASK_QP}


def iter_nal_types(frame: bytes):
    """Yield H.264 nal_unit_type for each NAL in an Annex-B frame."""
    i, n = 0, len(frame)
    while i < n - 3:
        if frame[i] == 0 and frame[i + 1] == 0:
            if frame[i + 2] == 1:
                hdr = i + 3
            elif frame[i + 2] == 0 and i + 3 < n and frame[i + 3] == 1:
                hdr = i + 4
            else:
                i += 1
                continue
            if hdr < n:
                yield frame[hdr] & 0x1F
            i = hdr + 1
            continue
        i += 1


def is_keyframe(frame: bytes) -> bool:
    """True if the access unit contains an IDR slice (NAL type 5).

    The DLL passes the encoder's frame type in the header's `kind` byte, so I-frames
    and P-frames must not be labelled identically: a client that treats every frame as
    a GOP start cannot decode the P-frames and only refreshes on real IDRs.
    """
    return any(t == 5 for t in iter_nal_types(frame))


def build_packet(timestamp: int, width: int, height: int, frame: bytes, **kw) -> bytes:
    """The full app-level payload for one frame: 10-byte header + encoder output."""
    return build_header(timestamp, width, height, **kw) + frame


if __name__ == "__main__":
    h = build_header(0x11223344, 1920, 1080, kind=1, qp=5, bit10=True)
    assert len(h) == HEADER_LEN, len(h)
    got = parse_header(h)
    assert got["width"] == 1920 and got["height"] == 1080, got
    assert got["qp"] == 5 and got["flags"] & FLAG_BIT_10, got
    assert got["timestamp"] == 0x11223344, got

    assert channel_for_stream(0) == 1
    assert channel_for_stream(1) == 3
    assert channel_for_stream(4) == 6

    # keyframe detection: NAL type 5 = IDR, type 1 = non-IDR slice
    assert is_keyframe(bytes.fromhex("0000000165") + bytes(8))
    assert not is_keyframe(bytes.fromhex("0000000141") + bytes(8))
    # a real access unit: AUD(9) + SPS(7) + PPS(8) + IDR(5)
    au = (bytes.fromhex("0000000109") + bytes.fromhex("0000000167") +
          bytes.fromhex("0000000168") + bytes.fromhex("0000000165"))
    assert sorted(set(iter_nal_types(au))) == [5, 7, 8, 9], sorted(set(iter_nal_types(au)))
    assert is_keyframe(au)
    # 3-byte start codes too
    assert is_keyframe(bytes.fromhex("00000165"))

    # encode_size: native when it fits, aspect-preserving downscale when it doesn't,
    # always even.
    assert encode_size(1920, 1080) == (1920, 1080), "exactly at the cap: unchanged"
    assert encode_size(1280, 720) == (1280, 720), "under the cap: native"
    # the real desktops this ran on
    assert encode_size(1482, 537) == (1482, 536), "odd height rounds down, no scaling"
    w, h = encode_size(2554, 1367)
    assert (w, h) == (1920, 1026), (w, h)
    # aspect preserved to within the even-rounding
    assert abs((w / h) - (2554 / 1367)) < 0.01, (w / h, 2554 / 1367)
    assert w % 2 == 0 and h % 2 == 0, (w, h)
    # a 4K source is bounded by height here, not width
    assert encode_size(3840, 2160) == (1920, 1080)
    # odd in both axes
    assert encode_size(1483, 539) == (1482, 538)
    # a custom cap still rounds even
    assert encode_size(1000, 1000, 999, 999) == (998, 998)
    for bad in ((0, 100), (100, 0), (-1, 5)):
        try:
            encode_size(*bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"encode_size{bad} should reject")

    frame = bytes.fromhex("0000000165")  # a plausible H.264 start code + NAL
    pkt = build_packet(1, 640, 480, frame)
    assert pkt[HEADER_LEN:] == frame, "payload must be verbatim"
    assert len(pkt) == HEADER_LEN + len(frame)
    print("video.py self-test OK (10-byte header, channel map, verbatim payload)")
