"""BUD reliable-channel framing (Parsec 150-105c).

Reversed from the DLL reliable fragmenter/sender `sub_18003D410` (disassembly; the
Hex-Rays decompiler is unavailable in our idalib build). This REPLACES the earlier
guess in re/NOTES.md, which mistakenly read the app-level header as part of the
BUD framing.

Wire format of one fragment (the BUD record plaintext):

    off 0  u8       0x01                    constant
        1  u8       0x21 last fragment | 0x01 more fragments follow
        2  u8       channel id
        3  u32 be   message sequence number
        7  u32 be   total message length    <- FIRST fragment of a message only
      7|11 ...      payload fragment (an optional app-level header rides at the
                    front of the first fragment's payload; that header is the
                    app's business, not BUD's)

Sender facts from the same function:
  * per-channel state at ctx+0x160, stride 0xA8, indexed by channel id
  * retransmit ring of 4000 slots, slot stride 0x4F8; per-slot unacked flag at
    +0x4D4, send/first-send timestamps at +0x4D8 / +0x4E0
  * congestion window: at >= 100 unacked in flight the slot is marked pending
    (+0x4D4 = 1) instead of being sent
  * the BUD channel index used for the datagram is `channel_id + 2`
  * fragment payload capacity comes from ctx+0xDF8 (the negotiated MTU)

Acks: the unacked flag plus the two timestamps prove an ack path exists; the
handler that clears +0x4D4 has not been located yet, so ack parsing/emission is
NOT implemented here. Until it is, a peer will retransmit each message forever.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

HEADER_LEN = 7
TOTAL_LEN_LEN = 4  # the u32 total length that only the first fragment carries

# Per-fragment capacity AFTER the 7-byte header, hardcoded in bud_create as ctx+0xDF8
# (DLL 0x18003BB70: `*(_DWORD *)(v12 + 3576) = 1193`). 1193 + 7 == 1200 == the sealer's
# max plaintext. The receiver (sub_18003CF80) derives the expected fragment count as
# `(total_len + 4) / MTU` (rounded up), so every fragment but the last must carry
# exactly MTU bytes of post-header data, with the first fragment's 4-byte total length
# counting inside its MTU.
MTU = 1193

CONST_BYTE = 0x01
FLAG_LAST = 0x21
FLAG_MORE = 0x01

# BUD datagram channel index = reliable channel id + 2 (DLL: `add eax, 2`).
CHANNEL_INDEX_OFFSET = 2
# At >= this many unacked messages in flight the sender stops emitting.
CONGESTION_WINDOW = 100
RING_SLOTS = 4000


def build_fragments(channel: int, seq: int, payload: bytes, mtu: int = MTU) -> list[bytes]:
    """Fragment `payload` into reliable-channel frames for one message.

    `mtu` is the POST-header capacity of one fragment (default MTU = 1193), matching
    ctx+0xDF8. Every fragment but the last carries exactly `mtu` bytes of data; on the
    first fragment 4 of those bytes are the total-length prefix.

    `seq` is the sequence number of the FIRST fragment. Sequence numbers are
    per-fragment, not per-message: the sender increments once per fragment
    (`sub_1800DA680` in 0x18003D410) so each lands in its own consecutive ring slot,
    and the receiver (0x18003CF80) reads the total length at the cursor, derives the
    fragment count, waits for `seq .. seq+count-1`, then walks those slots in order.
    Reusing one seq for a whole message breaks that walk and the peer answers -12011.

    So the caller must advance its counter by `len(result)`, not by 1.
    """
    if not 0 <= channel <= 0xFF:
        raise ValueError(f"channel id out of range: {channel}")
    frames, offset, first = [], 0, True
    while True:
        room = mtu - (TOTAL_LEN_LEN if first else 0)
        if room <= 0:
            raise ValueError(f"mtu {mtu} too small for reliable framing")
        chunk = payload[offset:offset + room]
        offset += len(chunk)
        last = offset >= len(payload)
        frame = bytearray(struct.pack("!BBBI", CONST_BYTE, 0, channel,
                                      (seq + len(frames)) & 0xFFFFFFFF))
        frame[1] = FLAG_LAST if last else FLAG_MORE
        if first:
            frame += struct.pack("!I", len(payload))
        frame += chunk
        frames.append(bytes(frame))
        first = False
        if last:
            return frames


@dataclass
class Message:
    """A message being reassembled from fragments."""

    channel: int
    seq: int
    total: int | None = None
    chunks: list[bytes] = field(default_factory=list)

    @property
    def payload(self) -> bytes:
        return b"".join(self.chunks)

    @property
    def complete(self) -> bool:
        return self.total is not None and len(self.payload) >= self.total


def parse_fragment(frame: bytes) -> tuple[int, int, bool, int | None, bytes]:
    """Decode one fragment -> (channel, seq, is_last, total_len_or_None, payload).

    `total_len` is present only on a message's first fragment. Note the wire gives no
    explicit "first fragment" bit: a fragment carries the total length iff it is the
    first one of its sequence number, so callers track that per (channel, seq).
    """
    if len(frame) < HEADER_LEN:
        raise ValueError(f"short reliable fragment: {len(frame)} bytes")
    if frame[0] != CONST_BYTE:
        raise ValueError(f"bad reliable constant byte {frame[0]:#04x}")
    flag = frame[1]
    if flag not in (FLAG_LAST, FLAG_MORE):
        raise ValueError(f"bad fragment flag {flag:#04x}")
    channel = frame[2]
    seq = struct.unpack_from("!I", frame, 3)[0]
    return channel, seq, flag == FLAG_LAST, None, frame[HEADER_LEN:]


class Reassembler:
    """Reassembles reliable messages from per-fragment sequence numbers.

    Feed it fragment plaintexts; it yields completed (channel, start_seq, payload)
    tuples. Because sequence numbers are per-fragment, a message occupies consecutive
    numbers: the one that carries the 4-byte total length starts a message on its
    channel and the following numbers continue it (mirroring 0x18003CF80, which skips
    4 bytes on the first slot and 0 thereafter).
    """

    def __init__(self) -> None:
        self._open: dict[int, Message] = {}  # channel -> message in progress

    def feed(self, frame: bytes) -> tuple[int, int, bytes] | None:
        channel, seq, is_last, _, body = parse_fragment(frame)
        msg = self._open.get(channel)
        if msg is None:
            if len(body) < TOTAL_LEN_LEN:
                raise ValueError("first fragment too short for total length")
            msg = Message(channel, seq, struct.unpack_from("!I", body, 0)[0])
            self._open[channel] = msg
            body = body[TOTAL_LEN_LEN:]
        msg.chunks.append(body)
        if is_last or msg.complete:
            del self._open[channel]
            return channel, msg.seq, msg.payload[:msg.total]
        return None


if __name__ == "__main__":
    from bud import MAX_PLAINTEXT

    # Round-trip: fragment then reassemble, across single- and multi-fragment messages.
    for size in (0, 1, 100, MTU, MTU * 3 + 7, 6983):
        payload = bytes((i * 7 + size) & 0xFF for i in range(size))
        frames = build_fragments(channel=3, seq=42, payload=payload)
        assert all(len(f) <= MAX_PLAINTEXT for f in frames), "fragment exceeds sealer cap"
        # Every fragment but the last must carry exactly MTU post-header bytes, or the
        # receiver's (total+4)/MTU fragment count will not reconcile.
        for f in frames[:-1]:
            assert len(f) - HEADER_LEN == MTU, (size, len(f) - HEADER_LEN)
        # ...and the receiver's expected count must match what we produced.
        expected = -(-(size + TOTAL_LEN_LEN) // MTU)
        assert len(frames) == expected, (size, len(frames), expected)
        # Sequence numbers must be per-fragment and consecutive from the start seq.
        seqs = [parse_fragment(f)[1] for f in frames]
        assert seqs == list(range(42, 42 + len(frames))), seqs
        assert frames[-1][1] == FLAG_LAST
        assert all(f[1] == FLAG_MORE for f in frames[:-1])
        out = None
        r = Reassembler()
        for f in frames:
            out = r.feed(f) or out
        assert out == (3, 42, payload), f"round-trip failed at size {size}"

    # The captured client config fragment decodes with channel 0, seq 0, total 0x173.
    captured = bytes.fromhex("0121000000000000000173") + b"\x00" * 0x173
    ch, seq, last, _, body = parse_fragment(captured)
    assert (ch, seq, last) == (0, 0, True), (ch, seq, last)
    assert struct.unpack_from("!I", body, 0)[0] == 0x173
    print("reliable.py self-test OK (fragment/reassemble round-trip, captured frame)")
