#!/usr/bin/env python3
"""Decrypt captured BUD datagrams from udp_raw.log (written by kessel_probe.py --answer).

BUD record (verified against Parsec 150-105c):
    0      1  type (0x17)            3  epoch (2)      5  seq (6)     11  length (2)
    13     GCM tag (16)
    29     ciphertext
Key = host aes256[0:32], nonce = host aes256[32:36] || epoch || seq, no AAD.
"""
import json
import os
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

LOG = os.path.expanduser("~/.config/parsec4linux/udp_raw.log")


def load_last_attempt(path=LOG):
    lines = open(path).read().splitlines()
    idx = max(i for i, l in enumerate(lines) if l.startswith("# offer_creds"))
    answer = json.loads(lines[idx + 1][len("# answer_creds "):])
    pkts = []
    for l in lines[idx + 2:]:
        if l.startswith("#"):
            continue
        src, hexdata = l.split()
        data = bytes.fromhex(hexdata)
        if data[:3] == b"\x17\xfe\xfd":
            pkts.append((src, data))
    return answer, pkts


class BudCipher:
    def __init__(self, aes256_hex):
        secret = bytes.fromhex(aes256_hex)
        self.gcm = AESGCM(secret[:32])
        self.salt = secret[32:36]

    def decrypt(self, rec):
        return self.gcm.decrypt(self.salt + rec[3:11], rec[29:] + rec[13:29], None)


def main():
    answer, pkts = load_last_attempt()
    cipher = BudCipher(answer["aes256"])
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 40
    seen = set()
    for src, rec in pkts[:limit]:
        pt = cipher.decrypt(rec)
        seq = int.from_bytes(rec[5:11], "big")
        key = (len(rec), pt[0])
        if key in seen:
            continue
        seen.add(key)
        print(f"seq={seq:4d} wire={len(rec):4d} pt={len(pt):4d} type={pt[0]:#04x} {pt[:64].hex()}")


if __name__ == "__main__":
    main()
