# parsec4linux

An unofficial **Parsec host for Linux**, built for personal use.

Parsec ships a Linux *client* but no Linux *host* — the hosting core is compiled out of
the Linux build (`ParsecHostStart` is a stub that returns `-5`, and `hosting_supported`
is hardcoded `false`), while all the signaling and client-side protocol code is present.
This implements the host side.

**Status: it works.** A real Parsec client connects and renders a smooth live stream of
the Linux desktop.

## What works

- kessel REST auth and WebSocket signaling; the host appears in the client's computer list
- ICE/STUN connectivity, NAT candidate exchange
- the BUD transport: AES-256-GCM, reliable fragmentation (MTU 1193), cumulative acks,
  retransmission with the host's own RTO curve, a 100-fragment congestion window
- app-level control messages and the video message format
- screen capture on Wayland via the `xdg-desktop-portal` ScreenCast portal + PipeWire,
  H.264 via x264, streamed at 30 fps

## Not implemented yet

- input (mouse/keyboard) — needs the client→host input messages decoded, then `uinput`
- audio — channel 2, message type `0x01`
- per-message acks (BUD type `0x02`), cursor, clipboard, multiple clients
- RTT measurement (the retransmit RTO currently assumes a fixed value)

## Layout

| path | what |
|---|---|
| `parsec4linux/bud.py` | BUD record crypto and framing |
| `parsec4linux/reliable.py` | reliable channel: fragmentation and reassembly |
| `parsec4linux/feedback.py` | the 83-byte type-`0x08` ack packet |
| `parsec4linux/app.py` | 13-byte control-message header |
| `parsec4linux/video.py` | 10-byte video header, keyframe detection |
| `tools/kessel_probe.py` | the host: signaling, ICE, BUD, video send |
| `tools/capture_h264.py` | capture + encode (PipeWire portal or a test pattern) |
| `tools/parsec_client.py` | a client that connects to a real host and decrypts it |
| `tools/validate_capture.py` | replays a capture through the framing to check it |
| `tools/retransmit_stats.py` | quantifies retransmission from a capture |
| `re/NOTES.md` | the reverse-engineering notes |

Every module under `parsec4linux/` has a self-test: `python <module>.py`.

`tools/parsec_client.py` is worth singling out. Several header fields (`kind`, `flags`,
the `+0` field) are produced by the encoder backend **at runtime**, so they cannot be
read out of the binary — the backend table is populated on startup and is empty in the
static image. Guessing them did not work. That tool connects to a real host, which hands
over the BUD session key in its `answer`, and dumps the decrypted stream so the real
values can simply be read off the wire. Measuring beat disassembly.

## Running it

Needs Python 3.12+, `websockets`, `cryptography`, and
`gstreamer1.0-plugins-{good,bad,ugly}` for `x264enc` / `h264parse`.

```sh
# credentials: ~/.config/parsec4linux/creds.json  {"email": "...", "password": "..."}
python tools/kessel_probe.py auth

# host the desktop (Wayland: approve the "share your screen" prompt once)
python tools/kessel_probe.py ws --answer --port 8000 --size 1280x720 --fps 30 \
    --name my-linux-host \
    --capture "python3 tools/capture_h264.py --source pipewire \
               --width 1280 --height 720 --fps 30 --keyint 30 --bitrate 3000"
```

Then connect to `my-linux-host` from any Parsec client.

Use `--source videotestsrc` instead to stream a test pattern, which needs no screen-capture
permission and is the right way to isolate protocol problems from capture problems.

## Notes on the binaries

Parsec's own binaries are **not** included and are excluded by `.gitignore`. The
reverse-engineering notes reference offsets in `parsecd-150-105c` (`.dll` / `.so`); supply
your own copy from your own installation. Offsets are build-specific — the engine library
auto-updates, so a different build will not match.

`re/NOTES.md` also records the IDA workflow, because a stale unpacked database silently
breaks the decompiler: clear any `.id0`/`.id1`/`.id2`/`.nam`/`.til` next to the binary and
open the *binary*, not the `.i64`.

## Scope

This is an interoperability project for personal use: running a host on hardware the
vendor doesn't support, talking to the vendor's own client, with the author's own account.
It is not affiliated with or endorsed by Parsec/Unity. Check Parsec's terms before using
it, and don't use it against accounts or machines that aren't yours.
