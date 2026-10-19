"""Parsec audio messages (150-105c) — the 15-byte header on reliable channel 2.

Reversed from `proto_audio_write` (DLL 0x1800A5050), called from the host's audio
path 0x1800AA990 as (ctx, data, len, container, codec, _, channels, mask, _, frames):

    off 0   u32 le  channel mask      3 = front left | front right
        4   u32 le  frames            samples per channel in this packet: 960 (20 ms)
        8   u32 le  sample rate       48000, hard-coded
       12   u8      codec             1 = Opus, 2 = raw int16 PCM (client's rawAudio)
       13   u8      2                 constant
       14   u8      channels          2
       15   ...     one Opus packet, or interleaved int16 PCM

Host byte order, like the 10-byte video header (and unlike the 13-byte control header,
whose fields go through htonl). The header and payload are handed to the BUD send call
separately and arrive as one reliable message on app channel 2.

Matches the only real host audio seen so far: channel 2, codec byte 1, ~323-byte
messages = 15 + a ~308-byte packet, i.e. Opus at about 128 kbit/s per 20 ms frame.

The host also sends `0x15 {2, audio_encode_us, 0}` every 100 audio packets, which the
client shows as its audio encode time. We do not: we do not measure Opus encode time,
and sending something else there (an uptime, as a first draft did) displays nonsense.
"""
from __future__ import annotations

import struct

CHANNEL = 2
SAMPLE_RATE = 48000
FRAMES_20MS = 960
CODEC_OPUS = 1
CODEC_RAW = 2
CHANNEL_MASK_STEREO = 3

_HEADER = struct.Struct("<IIIBBB")
HEADER_LEN = _HEADER.size  # 15


def build_header(frames: int = FRAMES_20MS, codec: int = CODEC_OPUS,
                 channels: int = 2, channel_mask: int = CHANNEL_MASK_STEREO) -> bytes:
    return _HEADER.pack(channel_mask, frames, SAMPLE_RATE, codec, 2, channels)


def build_message(packet: bytes, frames: int = FRAMES_20MS,
                  codec: int = CODEC_OPUS) -> bytes:
    return build_header(frames, codec) + packet


def parse(data: bytes) -> dict:
    mask, frames, rate, codec, const, channels = _HEADER.unpack_from(data, 0)
    return {"channel_mask": mask, "frames": frames, "rate": rate, "codec": codec,
            "const": const, "channels": channels, "payload": data[HEADER_LEN:]}


if __name__ == "__main__":
    assert HEADER_LEN == 15
    h = build_header()
    assert h == bytes.fromhex("03000000" "c0030000" "80bb0000" "01" "02" "02"), h.hex()
    m = build_message(b"\xfc" * 308)
    assert len(m) == 323  # the size a real host's audio messages had
    got = parse(m)
    assert (got["rate"], got["frames"], got["codec"], got["channels"]) == \
        (48000, 960, CODEC_OPUS, 2), got
    print("audio.py self-test OK (15-byte LE header, 48 kHz, 960-frame Opus, 323 B)")
