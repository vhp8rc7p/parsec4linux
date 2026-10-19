# parsec4linux

An unofficial **Parsec host for Linux**, built for personal use.

*[中文说明](README.zh-CN.md)*

Parsec ships a Linux *client* but no Linux *host*: you can connect *from* Linux, not
*to* it. This implements the missing host side, so a Linux machine can be the one being
remote-controlled.

**Status: it works.** A real Parsec client connects, renders a smooth live stream of the
Linux desktop, and drives its mouse and keyboard.

## Tested on

Exactly one configuration, so treat everything else as unverified:

| | |
|---|---|
| host OS | Ubuntu 24.04.2 LTS, kernel 6.17.0-23-generic |
| display server | **Wayland** (GNOME Shell 46.0) — not X11; capture goes through the portal, and input through `uinput` because XTEST doesn't work here |
| host hardware | a VMware virtual machine, software encode only (no GPU encoder) |
| desktop size | resizable with the VM window; seen at 1482×537 and 2554×1367. The odd height is why encode sizes are rounded down to even — x264 refuses to start otherwise. |
| Python | 3.12.3 |
| GStreamer | 1.24.2, x264enc 1.24.1 |
| PipeWire / portal | libpipewire 1.0.5, xdg-desktop-portal 1.18.4 |
| client | stock Parsec client on Windows 10, 1920×1080 |
| Parsec engine | `150-105c` |

Nothing here is X11-specific, but nothing here has been *run* on X11 either. Arch, other
distros, and non-GNOME Wayland compositors should work in principle: capture only needs
a ScreenCast portal and input only needs `/dev/uinput`. Untested.

## What works

- kessel REST auth and WebSocket signaling; the host appears in the client's computer list
- ICE/STUN connectivity, NAT candidate exchange
- the BUD transport: AES-256-GCM, reliable fragmentation (MTU 1193), cumulative and
  per-message acks, measured RTT, retransmission with the host's own RTO curve, a
  100-fragment congestion window
- the client's HUD statistics: real **Network** (it only updates from per-message acks)
  and **Encode** (per-frame capture-to-encoded time)
- app-level control messages and the video message format
- screen capture on Wayland via the `xdg-desktop-portal` ScreenCast portal + PipeWire,
  H.264 via x264, at 30 fps
- **native-resolution encoding, aspect never distorted.** The desktop is encoded at its
  own size, scaled down only if it exceeds 1920×1080 — which is what Parsec's own host
  does — and rounded down to even dimensions so x264 will start. The true size travels
  in every frame header.
- any desktop size, including resizing it while streaming: the encode size is pinned
  when capture starts, so a resize never reinitialises the encoder or drops the
  connection
- **mouse and keyboard input**, injected via `uinput` as an absolute pointer plus a
  keyboard device

## Not implemented yet

- **scroll wheel and gamepad**: decoded, but their field layouts are inferred from the
  SDK enum rather than observed on the wire. `parsec4linux/input.py` records which
  messages are confirmed, and the host logs any inferred layout it meets, so a wrong
  guess shows up instead of silently mis-injecting.
- **client-requested resolution.** The client can ask the host to change its screen
  resolution (`resolutionX`/`resolutionY` in its config message); we ignore it. A
  consequence: resizing the desktop mid-session doesn't re-pick the encode size until
  the host is restarted.
- **noticing that the client left.** The host keeps streaming until its run time ends;
  Parsec's own gives up after 60 s without a packet.
- audio — channel 2, message type `0x01`
- cursor shape (the client always shows a plain arrow), clipboard, multiple clients

## Layout

| path | what |
|---|---|
| `parsec4linux/bud.py` | BUD record crypto and framing |
| `parsec4linux/reliable.py` | reliable channel: fragmentation and reassembly |
| `parsec4linux/feedback.py` | the 83-byte ack packets, `0x08` (cumulative) and `0x02` (per-message) |
| `parsec4linux/app.py` | 13-byte control-message header |
| `parsec4linux/video.py` | 10-byte video header, keyframe detection, encode sizing |
| `parsec4linux/input.py` | client→host input messages, Parsec→Linux keycodes |
| `tools/kessel_probe.py` | the host: signaling, ICE, BUD, video send |
| `tools/capture_h264.py` | capture + encode (PipeWire portal or a test pattern) |
| `tools/inject_input.py` | injects input into the desktop via `/dev/uinput` |
| `tools/parsec_client.py` | a client that connects to a real host and decrypts it |
| `tools/validate_capture.py` | replays a capture through the framing to check it |
| `tools/retransmit_stats.py` | quantifies retransmission from a capture |
| `re/NOTES.md` | protocol notes: wire formats, measured constants, what's unverified |

Every module under `parsec4linux/` has a self-test: `python -m parsec4linux.<module>`.

`tools/parsec_client.py` is worth singling out. Several header fields (`kind`, `flags`,
the `+0` field) are produced by the encoder backend **at runtime** and cannot be read
out of the binary at all. Guessing them did not work. That tool connects to a real host,
which hands over the BUD session key in its `answer`, and dumps the decrypted stream so
the real values can be read straight off the wire. Measuring beat disassembly — and the
same approach settled the input formats later, from the host's own logs.

## Running it

**You do not need Parsec installed on the Linux machine.** This host is pure Python and
never loads any Parsec code — it speaks the protocol over the network. What you do need:

- a **Parsec account**, since the host signs in to Parsec's own servers to be listed
- the normal **Parsec client** on whatever machine you connect *from*
- Python 3.12+, `websockets`, `cryptography`
- `gstreamer1.0-plugins-{good,bad,ugly}` for `x264enc` / `h264parse`
- for input, write access to `/dev/uinput`:
  ```sh
  sudo setfacl -m u:$USER:rw /dev/uinput          # until reboot
  # permanent:
  echo 'KERNEL=="uinput", MODE="0660", GROUP="input", OPTIONS+="static_node=uinput"' \
    | sudo tee /etc/udev/rules.d/99-parsec4linux-uinput.rules
  sudo usermod -aG input $USER                     # then log out and back in
  ```

```sh
# credentials: ~/.config/parsec4linux/creds.json  {"email": "...", "password": "..."}
python tools/kessel_probe.py auth

# host the desktop (Wayland: approve the "share your screen" prompt once)
python tools/kessel_probe.py ws --answer --port 8000 --fps 30 \
    --name my-linux-host \
    --inject "python3 tools/inject_input.py --desktop 2554x1367" \
    --capture "python3 tools/capture_h264.py --source pipewire \
               --fps 30 --keyint 30 --bitrate 3000"
```

Then connect to `my-linux-host` from any Parsec client.

Notes on the invocation:

- The encode size is **detected**, not specified. `--max-w` / `--max-h` (default
  1920×1080) cap it; `--native-off` restores the old fixed `--width`×`--height`
  behaviour.
- `--desktop WxH` should be your real desktop size. It makes the injected cursor line up
  with the client's own cursor, by declaring the absolute axes at the screen's size so
  the compositor maps them 1:1.
- Drop `--inject` to stream without accepting input.
- The capture runs under the system `python3` because it needs `gi` (PyGObject), which a
  venv typically lacks; the host itself can run in a venv.
- `python3 tools/inject_input.py --selftest` checks input injection on its own, with no
  client involved — it walks the cursor around a square.
- `--source videotestsrc` streams a test pattern instead, which needs no screen-capture
  permission and is the right way to isolate protocol problems from capture problems.
- `--cursor hidden` leaves the real cursor out of the stream, like Parsec does, so you
  see only the client's own cursor. `embedded` shows both, which is how you check
  that they line up.

## Scope

This is an interoperability project for personal use: running a host on hardware the
vendor doesn't support, talking to the vendor's own client, with the author's own
account. It is not affiliated with or endorsed by Parsec/Unity. Check Parsec's terms
before using it, and don't use it against accounts or machines that aren't yours.
