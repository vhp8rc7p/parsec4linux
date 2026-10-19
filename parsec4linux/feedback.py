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
# Type 0x02 carries the SAME 19-slot ack vector, but with the header's channel and
# seq populated rather than zero -- an immediate ack naming what prompted it, instead
# of the timer-driven 0x08. Established by size: a captured 0x02 was 83 bytes, which
# is exactly 7 + 19*4, with ch=1 seq=3161 where 0x08 always carries ch=0 seq=0.
# A real client sent 3839 of these in one session; honouring them releases send-window
# slots as acks arrive instead of in ~30 ms lumps.
TYPE_MESSAGE_ACK = 0x02
ACK_TYPES = (TYPE_FEEDBACK, TYPE_MESSAGE_ACK)
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


def build_message_ack(acks, channel: int, seq: int) -> bytes:
    """Serialize a type-0x02 immediate ack for one received fragment.

    The receive path (DLL 0x18003C760) sends this the moment a reliable message
    completes, naming the {channel, seq} of the fragment that completed it. On the
    other side, that pair is the ONLY input to the RTT estimate: the sender looks up
    the fragment's send time in slot seq % 4000 and folds the sample in as
    rtt = 0.9*rtt + 0.1*sample. The 19-slot vector rides along but is not applied --
    cumulative acks still come only from 0x08.

    Which is why the client's HUD showed "Network 100.00ms" against us: its RTT is
    initialised to 100000 us (`mov [ctx+0DD8h], 186A0h` in 0x18003BB70), and without
    0x02 acks nothing ever moves it.
    """
    pkt = bytearray(build_feedback(acks))
    pkt[1] = TYPE_MESSAGE_ACK
    pkt[2] = channel & 0xFF
    pkt[3:7] = (seq & 0xFFFFFFFF).to_bytes(4, "big")
    return bytes(pkt)


def is_ack_packet(plaintext: bytes) -> bool:
    """True for either ack form, 0x08 (timer) or 0x02 (immediate)."""
    return (len(plaintext) == PACKET_LEN and plaintext[0] == 0x01
            and plaintext[1] in ACK_TYPES)


def parse_feedback(plaintext: bytes) -> list[int]:
    """Parse a received ack packet -> the peer's per-channel cumulative acks.

    Index i is the peer's ack for the messages we sent on channel i, i.e. the value
    that belongs in our per-channel entry[+4]. Accepts both 0x08 and 0x02, which share
    this payload.
    """
    if len(plaintext) != PACKET_LEN:
        raise ValueError(f"ack packet must be {PACKET_LEN} bytes, got {len(plaintext)}")
    if plaintext[0] != 0x01 or plaintext[1] not in ACK_TYPES:
        raise ValueError(f"not an ack packet: {plaintext[:2].hex()}")
    return [struct.unpack_from("!I", plaintext, 7 + 4 * i)[0] for i in range(NUM_CHANNELS)]


class AckTracker:
    """Tracks per-channel cumulative acks in both directions.

    `received` feeds the feedback we emit; `peer_ack` is what the peer last told us,
    and bounds which of our sent messages may be released.
    """

    def __init__(self) -> None:
        self.received = [0] * NUM_CHANNELS  # entry[+0]
        self.peer_ack = [0] * NUM_CHANNELS  # entry[+4]
        self.regressions = 0  # acks that arrived lower than what we already had

    def note_received(self, channel: int, seq: int) -> None:
        """Record that `seq` arrived on `channel`, advancing the cumulative ack."""
        if not 0 <= channel < NUM_CHANNELS:
            raise ValueError(f"channel {channel} outside 0..{NUM_CHANNELS - 1}")
        if seq > self.received[channel]:
            self.received[channel] = seq

    def apply_feedback(self, plaintext: bytes) -> list[int]:
        """Merge a received ack packet (0x08 or 0x02) into `peer_ack`.

        Monotonic per channel: a cumulative ack can only move forward. UDP reorders,
        so a late packet carrying older numbers must not drag the window base back and
        resurrect slots we already released. `regressions` counts how often that
        happened, which is also the check on whether reading 0x02's payload as acks is
        right -- a steady stream of regressions would mean it is not.
        """
        incoming = parse_feedback(plaintext)
        for i, value in enumerate(incoming):
            if value < self.peer_ack[i]:
                self.regressions += 1
            else:
                self.peer_ack[i] = value
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

    # cumulative acks must never regress: a reordered packet carrying older numbers
    # must not drag the window base back
    t.apply_feedback(build_feedback([3] * NUM_CHANNELS))
    assert t.peer_ack[0] == 7, t.peer_ack[0]
    assert t.regressions == NUM_CHANNELS, t.regressions
    # but forward progress still applies, per channel independently
    mixed = [7] * NUM_CHANNELS
    mixed[2] = 9
    t.apply_feedback(build_feedback(mixed))
    assert t.peer_ack[2] == 9 and t.peer_ack[0] == 7, t.peer_ack[:3]

    # type 0x02 shares the payload, but carries a channel and seq in the header
    imm = build_message_ack([11] * NUM_CHANNELS, channel=1, seq=3161)
    assert imm[:7] == bytes.fromhex("01020100000c59"), imm[:7].hex()
    assert len(imm) == PACKET_LEN
    assert is_ack_packet(imm) and is_ack_packet(pkt)
    assert parse_feedback(imm) == [11] * NUM_CHANNELS
    t.apply_feedback(imm)
    assert t.peer_ack[0] == 11, t.peer_ack[0]

    # non-ack packets are rejected rather than silently parsed
    assert not is_ack_packet(bytes.fromhex("012100000000") + bytes(77))
    assert not is_ack_packet(build_feedback([0] * NUM_CHANNELS)[:-1])
    for bad in (b"\x01\x21" + bytes(81), bytes(83)):
        try:
            parse_feedback(bad)
        except ValueError:
            pass
        else:
            raise AssertionError("should reject a non-ack packet")

    print("feedback.py self-test OK (83-byte packet, 0x08 + 0x02, monotonic tracker)")
