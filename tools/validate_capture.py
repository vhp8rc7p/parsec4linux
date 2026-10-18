#!/usr/bin/env python3
"""Validate the reversed BUD framing against a real capture.

Replays ~/.config/parsec4linux/udp_raw.log (written by kessel_probe.py --answer)
through parsec4linux/{bud,reliable,feedback}.py and reports whether the 7-byte
header reading from the DLL actually holds on live client traffic.

This is the real check on re/NOTES.md's framing section; the module self-tests only
prove internal consistency.

Usage: validate_capture.py [path-to-udp_raw.log]
"""
import collections
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))
from parsec4linux import bud, feedback, reliable

LOG = os.path.expanduser("~/.config/parsec4linux/udp_raw.log")


def attempts(path):
    """Yield (answer_creds, offer_creds, [(src, record)]) per connection attempt."""
    lines = open(path).read().splitlines()
    starts = [i for i, l in enumerate(lines) if l.startswith("# offer_creds")]
    for n, idx in enumerate(starts):
        end = starts[n + 1] if n + 1 < len(starts) else len(lines)
        offer = json.loads(lines[idx][len("# offer_creds "):])
        answer = json.loads(lines[idx + 1][len("# answer_creds "):])
        pkts = []
        for l in lines[idx + 2:end]:
            if l.startswith("#") or not l.strip():
                continue
            try:
                src, hexdata = l.split()
                data = bytes.fromhex(hexdata)
            except ValueError:
                continue
            if bud.is_bud(data):
                pkts.append((src, data))
        yield answer, offer, pkts


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else LOG
    total_ok = total_fail = 0
    for n, (answer, offer, pkts) in enumerate(attempts(path), start=1):
        if not pkts:
            continue
        print(f"\n=== attempt {n}: {len(pkts)} BUD records ===")
        # Client -> host: the host decrypts with its OWN answer aes256 (verified).
        cipher = bud.BudCipher(answer["aes256"])
        reasm = reliable.Reassembler()
        acks = feedback.AckTracker()
        types = collections.Counter()
        channels = collections.Counter()
        messages = []
        bad_const = unknown_type = decrypt_fail = 0
        seqs = collections.defaultdict(list)

        for src, rec in pkts:
            try:
                pt = cipher.open(rec)
            except Exception:
                decrypt_fail += 1
                continue
            total_ok += 1
            if len(pt) < reliable.HEADER_LEN:
                continue
            if pt[0] != reliable.CONST_BYTE:
                bad_const += 1
                continue
            mtype, channel = pt[1], pt[2]
            seq = int.from_bytes(pt[3:7], "big")
            types[mtype] += 1
            channels[channel] += 1
            seqs[(mtype, channel)].append(seq)

            if mtype == feedback.TYPE_FEEDBACK:
                try:
                    acks.apply_feedback(pt)
                except Exception as e:
                    print(f"  feedback parse failed: {e} (len={len(pt)})")
                continue
            if mtype in (reliable.FLAG_LAST, reliable.FLAG_MORE):
                try:
                    done = reasm.feed(pt)
                except Exception as e:
                    print(f"  reliable parse failed ch={channel} seq={seq}: {e}")
                    continue
                if done:
                    messages.append(done)
                continue
            unknown_type += 1

        print(f"  decrypted      : {len(pkts) - decrypt_fail}/{len(pkts)}"
              f"{'  <-- DECRYPT FAILURES' if decrypt_fail else ''}")
        print(f"  header byte0==1: {'all' if not bad_const else f'{bad_const} violations'}")
        print(f"  types seen     : {{{', '.join(f'{t:#04x}: {c}' for t, c in sorted(types.items()))}}}")
        print(f"  channels seen  : {dict(sorted(channels.items()))}")
        if unknown_type:
            print(f"  UNKNOWN types  : {unknown_type} records")
        total_fail += decrypt_fail + bad_const + unknown_type

        # Sequence numbers should be small and mostly monotonic if we read the field right.
        for (mtype, ch), s in sorted(seqs.items()):
            lo, hi = min(s), max(s)
            dupes = len(s) - len(set(s))
            print(f"    type {mtype:#04x} ch {ch}: {len(s)} recs, seq {lo}..{hi}, "
                  f"{dupes} retransmits")
            if hi > 1_000_000:
                print(f"      !! seq {hi} implausibly large - header offset likely wrong")

        print(f"  reassembled    : {len(messages)} complete messages")
        for ch, seq, payload in messages[:6]:
            printable = payload[:80]
            txt = "".join(chr(b) if 32 <= b < 127 else "." for b in printable)
            print(f"    ch={ch} seq={seq} len={len(payload)}: {txt}")

    print(f"\nsummary: {total_ok} records decrypted, {total_fail} framing anomalies")
    return 0 if total_ok and not total_fail else 1


if __name__ == "__main__":
    sys.exit(main())
