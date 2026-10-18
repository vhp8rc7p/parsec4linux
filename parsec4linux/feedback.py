"""BUD feedback / ack packet (Parsec 150-105c), type byte 0x08.

Reversed from `bud_write_packet` (DLL 0x18003C650), the `bud_thread` loop
(0x18003CC60) and the per-channel retransmit pass (0x18003C380).

This is the ack. There is no separate ack message: each side periodically emits one
83-byte feedback packet carrying a cumulative-ack sequence number for every channel.
A peer releases its retransmit slots from that number. The Linux host never sent this,
which is exactly why a connected client retransmits its reliable batch forever
(see re/NOTES.md "the whole batch is retransmitted ~every few hundred ms").

Wire format (reliable.py's 7-byte header, with type 0x08):

    off 0  u8       0x01            constant
        1  u8       0x08            type = feedback
        2  u8       0x00            channel (bud_thread passes 0)
        3  u32 be   0x00000000      seq     (bud_thread passes 0)
        7  19 x u32 be              per-channel cumulative ack
                                    total = 7 + 76 = 83 = 0x53

Sender state, per channel, is a 12-byte entry in a 19-entry array (0xE4 bytes total,
memset at the top of bud_thread):

    +0  u32  highest sequence WE have received  -> what we advertise here
    +4  u32  the peer's ack of OUR sends        -> base of our outstanding send window
    +8  u32  (not touched by the paths reversed so far)

`bud_write_packet` serializes entry[+0] of each of the 19 entries; the retransmit pass
reads entry[+4] as the oldest unacked sequence and walks up to the send head at
chan+0x44.

Cadence: emitted on a timer from bud_thread (interval at qword_180373C78), not per
received packet. It is sent on BUD channel 0 regardless of which channels it reports.
"""
from __future__ import annotations

import struct

TYPE_FEEDBACK = 0x08
NUM_CHANNELS = 19  # 0x13, per the bud_thread loop bound
ENTRY_STRIDE = 12  # 19 * 12 == 0xE4
PACKET_LEN = 83  # 0x53, the length bud_write_packet hands the sealer

_HEADER = struct.pack("!BBBI", 0x01, TYPE_FEEDBACK, 0x00, 0x00000000)
assert len(_HEADER) == 7


def build_feedback(acks) -> bytes:
    """Serialize a feedback packet from `acks`, one cumulative ack per channel.

    `acks` must hold NUM_CHANNELS values (highest contiguous sequence received on
    each channel). Returns the 83-byte BUD record plaintext.
    """
    acks = list(acks)
    if len(acks) != NUM_CHANNELS:
        raise ValueError(f"need {NUM_CHANNELS} acks, got {len(acks)}")
    body = b"".join(struct.pack("!I", a & 0xFFFFFFFF) for a in acks)
    packet = _HEADER + body
    assert len(packet) == PACKET_LEN, len(packet)
    return packet


def parse_feedback(plaintext: bytes) -> list[int]:
    """Parse a received feedback packet -> the peer's per-channel cumulative acks.

    Index i is the peer's ack for the messages we sent on channel i, i.e. the value
    that belongs in our per-channel entry[+4].
    """
    if len(plaintext) != PACKET_LEN:
        raise ValueError(f"feedback packet must be {PACKET_LEN} bytes, got {len(plaintext)}")
    if plaintext[0] != 0x01 or plaintext[1] != TYPE_FEEDBACK:
        raise ValueError(f"not a feedback packet: {plaintext[:2].hex()}")
    return [struct.unpack_from("!I", plaintext, 7 + 4 * i)[0] for i in range(NUM_CHANNELS)]


class AckTracker:
    """Tracks per-channel cumulative acks in both directions.

    `received` feeds the feedback we emit; `peer_ack` is what the peer last told us,
    and bounds which of our sent messages may be released.
    """

    def __init__(self) -> None:
        self.received = [0] * NUM_CHANNELS  # entry[+0]
        self.peer_ack = [0] * NUM_CHANNELS  # entry[+4]

    def note_received(self, channel: int, seq: int) -> None:
        """Record that `seq` arrived on `channel`, advancing the cumulative ack."""
        if not 0 <= channel < NUM_CHANNELS:
            raise ValueError(f"channel {channel} outside 0..{NUM_CHANNELS - 1}")
        if seq > self.received[channel]:
            self.received[channel] = seq

    def apply_feedback(self, plaintext: bytes) -> list[int]:
        self.peer_ack = parse_feedback(plaintext)
        return self.peer_ack

    def feedback_packet(self) -> bytes:
        return build_feedback(self.received)


if __name__ == "__main__":
    # Round-trip, and check the exact header/length the DLL produces.
    acks = list(range(NUM_CHANNELS))
    pkt = build_feedback(acks)
    assert len(pkt) == PACKET_LEN
    assert pkt[:7] == bytes.fromhex("01080000000000")
    assert parse_feedback(pkt) == acks

    # An all-zero feedback is what a freshly connected host sends.
    assert build_feedback([0] * NUM_CHANNELS) == bytes.fromhex("01080000000000") + bytes(76)

    t = AckTracker()
    t.note_received(3, 5)
    t.note_received(3, 2)  # must not go backwards
    assert t.received[3] == 5
    assert parse_feedback(t.feedback_packet())[3] == 5
    t.apply_feedback(build_feedback([7] * NUM_CHANNELS))
    assert t.peer_ack[0] == 7
    print("feedback.py self-test OK (83-byte packet, header, round-trip, tracker)")
