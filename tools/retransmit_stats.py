#!/usr/bin/env python3
"""Quantify client retransmission across capture logs, to test whether our ack works.

If the host's feedback packet is accepted, the client should send each reliable
message about ONCE. If it is ignored (wrong key, wrong format, wrong cadence) the
client keeps retransmitting on its RTO and the duplicate ratio stays high.

Usage: retransmit_stats.py LOG [LOG ...]
  e.g. retransmit_stats.py ~/.config/parsec4linux/udp_raw.log{.pre-ack,.txoffer,}
"""
import collections
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))
from parsec4linux import bud, feedback, reliable
from validate_capture import attempts


def stats(path):
    rows = []
    for n, (answer, offer, pkts) in enumerate(attempts(path), start=1):
        if not pkts:
            continue
        cipher = bud.BudCipher(answer["aes256"])
        counts = collections.Counter()
        fb = 0
        for _src, rec in pkts:
            try:
                pt = cipher.open(rec)
            except Exception:
                continue
            if len(pt) < reliable.HEADER_LEN:
                continue
            if pt[1] == feedback.TYPE_FEEDBACK:
                fb += 1
                continue
            if pt[1] not in (reliable.FLAG_LAST, reliable.FLAG_MORE):
                continue
            counts[(pt[2], int.from_bytes(pt[3:7], "big"))] += 1
        if not counts:
            rows.append((n, 0, 0, 0.0, fb))
            continue
        total = sum(counts.values())
        unique = len(counts)
        rows.append((n, total, unique, total / unique, fb))
    return rows


def main():
    paths = sys.argv[1:] or [os.path.expanduser("~/.config/parsec4linux/udp_raw.log")]
    print(f"{'log':<26} {'att':>3} {'reliable':>9} {'unique':>7} {'copies/msg':>11} {'feedback':>9}")
    print("-" * 70)
    for p in paths:
        if not os.path.exists(p):
            print(f"{os.path.basename(p):<26} (missing)")
            continue
        rows = stats(p)
        if not rows:
            print(f"{os.path.basename(p):<26} (no BUD records)")
            continue
        for n, total, unique, ratio, fb in rows:
            print(f"{os.path.basename(p):<26} {n:>3} {total:>9} {unique:>7} {ratio:>11.1f} {fb:>9}")
    print("\ncopies/msg ~1.0 => our ack is being honoured; high => client still retransmitting")
    return 0


if __name__ == "__main__":
    sys.exit(main())
