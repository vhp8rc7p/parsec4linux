"""BUD transport (Parsec 150-105c) — both directions.

BUD is Parsec's UDP transport. Each datagram is a DTLS-1.2-lookalike record whose
payload is AES-256-GCM. The framing and client->host crypto are verified against a live
150-105c session (see re/NOTES.md and tools/bud_decrypt.py); the host->client direction
is reconstructed from the same code path (DLL bud_create 0x18003BB70) and is the mirror:

    record layout
      0   u8    0x17                  "application_data" lookalike
      1   u16   0xFEFD                DTLS 1.2 lookalike
      3   u16   epoch                 0
      5   u48   seq                   starts at 1, +1 per datagram
      11  u16   length                plaintext_len + 16 (tag); informational
      13  16B   AES-GCM tag
      29  ...   ciphertext

    crypto
      key   = hexdecode(aes256)[0:32]
      salt  = hexdecode(aes256)[32:36]
      nonce = salt || epoch(2) || seq(6)      (12 bytes)
      AAD   = none

Key selection — RESOLVED by experiment 2026-10-19: there is ONE shared session key,
the host's own **answer** aes256, used in BOTH directions. `bud_create` is called once
with a single aes256 and every channel context shares it; the offer's aes256 is only
the client's candidate and is overridden by the answer.

So a host Session is built as Session(tx_aes256=answer_creds["aes256"],
rx_aes256=answer_creds["aes256"]).

Encrypting with the client's offer key instead leaves the client retransmitting at the
same rate as sending no acks at all (54.9 vs 59.3 copies/message); with the answer key
it falls to 4.6. See re/NOTES.md and tools/retransmit_stats.py.

The 19 Parsec channels all share this one key; the channel lives in the plaintext
(see reliable.py), not in separate crypto contexts.
"""
from __future__ import annotations

import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RECORD_TYPE = 0x17
DTLS_VERSION = 0xFEFD
HEADER = struct.Struct("!BHHIH")  # type, version, epoch, seq_hi32, (seq_lo16 | length)...
# seq is 48-bit so we lay the header out by hand rather than with one Struct.
HEADER_LEN = 13
TAG_LEN = 16
OVERHEAD = HEADER_LEN + TAG_LEN  # 29
# Sealer rejects anything larger (DLL 0x18003BE90: `cmp esi, 4B0h; jg -> 0xFFFF929C`).
MAX_PLAINTEXT = 0x4B0  # 1200


class BudCipher:
    """One direction of BUD AES-256-GCM, keyed by one party's aes256 credential."""

    def __init__(self, aes256_hex: str):
        secret = bytes.fromhex(aes256_hex)
        if len(secret) < 36:
            raise ValueError(f"aes256 credential too short: {len(secret)} bytes, need >= 36")
        self._gcm = AESGCM(secret[:32])
        self._salt = secret[32:36]

    def _nonce(self, epoch: int, seq: int) -> bytes:
        return self._salt + struct.pack("!H", epoch) + seq.to_bytes(6, "big")

    def seal(self, plaintext: bytes, seq: int, epoch: int = 0) -> bytes:
        """Encrypt `plaintext` into a full BUD datagram (header + tag + ciphertext)."""
        if len(plaintext) > MAX_PLAINTEXT:
            raise ValueError(f"BUD plaintext {len(plaintext)} > {MAX_PLAINTEXT}")
        ct_and_tag = self._gcm.encrypt(self._nonce(epoch, seq), plaintext, None)
        ciphertext, tag = ct_and_tag[:-TAG_LEN], ct_and_tag[-TAG_LEN:]
        # Non-standard: the DLL sealer computes r15 = plaintext_len + 29 (the full record
        # length) and writes htons(r15 + 16) here -- i.e. record_len + 16, NOT the DTLS
        # convention of ciphertext+tag. Receivers ignore it; we match the DLL byte-for-byte.
        length = len(plaintext) + OVERHEAD + TAG_LEN
        header = (
            struct.pack("!BHH", RECORD_TYPE, DTLS_VERSION, epoch)
            + seq.to_bytes(6, "big")
            + struct.pack("!H", length)
        )
        return header + tag + ciphertext

    def open(self, record: bytes) -> bytes:
        """Decrypt a received BUD datagram, returning plaintext. Raises on bad tag/format."""
        if len(record) < OVERHEAD:
            raise ValueError(f"short BUD record: {len(record)} bytes")
        if record[0] != RECORD_TYPE or struct.unpack_from("!H", record, 1)[0] != DTLS_VERSION:
            raise ValueError("not a BUD record")
        nonce = self._salt + record[3:11]  # epoch(2) || seq(6), already contiguous on the wire
        tag, ciphertext = record[13:29], record[29:]
        return self._gcm.decrypt(nonce, ciphertext + tag, None)


def is_bud(data: bytes) -> bool:
    return len(data) >= OVERHEAD and data[0] == RECORD_TYPE and data[1:3] == b"\xfe\xfd"


def record_seq(record: bytes) -> int:
    return int.from_bytes(record[5:11], "big")


class Session:
    """A full-duplex BUD session: send with tx cipher, receive with rx cipher.

    For a host:  Session(tx_aes256=offer["aes256"], rx_aes256=answer["aes256"]).
    Sequence numbers start at 1 and increment per datagram sent (verified: client seq starts 1).
    """

    def __init__(self, tx_aes256: str, rx_aes256: str, epoch: int = 0):
        self.tx = BudCipher(tx_aes256)
        self.rx = BudCipher(rx_aes256)
        self.epoch = epoch
        # The DLL keeps a separate record counter per BUD channel index
        # (ctx+0xAC + channel*12); first datagram on a channel uses seq 1.
        self._tx_seq: dict[int, int] = {}

    def encrypt(self, plaintext: bytes, channel: int = 0) -> bytes:
        seq = self._tx_seq.get(channel, 0) + 1
        self._tx_seq[channel] = seq
        return self.tx.seal(plaintext, seq, self.epoch)

    def decrypt(self, record: bytes) -> bytes:
        return self.rx.open(record)


if __name__ == "__main__":
    # Round-trip self-test with a synthetic credential (127-byte aes256 like bud_creds()).
    import secrets

    cred = secrets.token_bytes(127).hex()
    peer = BudCipher(cred)  # the "other side" decrypts with the sender's credential
    mine = BudCipher(cred)
    for seq, msg in enumerate([b"", b"\x01\x08hello", bytes(MAX_PLAINTEXT)], start=1):
        rec = mine.seal(msg, seq)
        assert is_bud(rec), rec[:4].hex()
        assert record_seq(rec) == seq
        assert peer.open(rec) == msg
        assert len(rec) == len(msg) + OVERHEAD
    # length field matches the DLL sealer: record_len + 16 == plaintext + 45
    big = mine.seal(bytes(1000), 5)
    assert struct.unpack_from("!H", big, 11)[0] == 1000 + OVERHEAD + TAG_LEN
    try:
        mine.seal(bytes(MAX_PLAINTEXT + 1), 6)
        raise AssertionError("oversized plaintext should be rejected")
    except ValueError:
        pass
    print("bud.py self-test OK (seal/open round-trip, framing, length field, MTU cap)")
