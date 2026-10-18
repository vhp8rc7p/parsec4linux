# parsec4linux – reverse engineering notes

Target build: **150-105c** (Windows `parsecd-150-105c.dll`, Linux `parsecd-150-105c.so`).
`parsecd.exe` / `/usr/bin/parsecd` are thin loaders; the versioned engine lib is the real app
and is auto-updated, so all offsets below are build-specific.

## IDA workflow (read this before opening anything)

There is **no good `.i64`**. The old one was built from a database a crashed IDA left
unpacked; idalib unpacks it on open and then dies with a null-deref (see
`re/ida-*.dmp`). It is quarantined in `re/ida-backup/` — do not reopen it.

Working recipe: make sure **no** `.id0/.id1/.id2/.nam/.til` sit next to the binary, then
open the *binary* path with auto-analysis on. Hex-Rays then works. If `decompile`
returns "Decompilation failed" and health shows `auto_analysis_ready: false`, a stale
unpacked database is the cause — clear it and reopen.

Also broken in our idalib: `search_text` hard-crashes the worker (`WinError 10054`).
Navigate by address and `xrefs_to` instead.

## Key finding: Linux host is compiled out at the engine layer only

| Layer | Windows .dll | Linux .so |
|---|---|---|
| App hosting logic (`../src/app/hosting.c`) | present | **present** |
| `hosting_start` | `0x1800702A0` | `0x61740` |
| Core init (`ParsecInit`-like) | `0x1800A0210` | `0x193D0` |
| Core host start (`ParsecHostStart`-like) | `0x1800A24B0` (real) | `0x88440` → `return -5` (stub) |
| Host object / pipeline builder | `0x1800AF5B0` | absent |
| `hosting_supported` flag sent to UI | — | `0x2CC60` hardcodes `false` |

So signaling, kessel auth and client-side protocol code ship on Linux; the host core
(capture → encode → packetize, server side of the handshake) does not. We must
implement the host side ourselves, using the DLL as reference.

## Protocol stack (as far as known)

1. **kessel REST** – `https://kessel-api.parsec.app` – `/v2/auth`, `/v2/hosts?mode=desktop`,
   `/me` polled every ~10 s by the host.
2. **kessel WS signaling** – `kessel-ws.parsec.app`, host auth string
   `peer_id=%s:host_secret=%s:connection_name=%s`. Actions seen:
   `offer`, `answer`, `offer_cancel`, `offer_relay`, `answer_relay`, `offer_cancel_relay`,
   candidates. Dispatcher: `signal_event_dispatch` / `signal_thread`.
3. **STUN / P2P** – `stun.parsec.app:3478`, `stun6.parsec.app`; candidate types `STUN_RFLX`, `STUN_P2P`.
4. **BUD** transport – UDP, own encryption `BUD AES_GCM = 256` (log). Threads `bud_thread`,
   `bud_write_packet`. libmatoya `MTY_DTLS*` also linked (open source, MIT:
   github.com/snowcone-ltd/libmatoya) – role vs BUD still to be determined.
5. Parsec app messages – video (h264/h265), audio (opus?), input, clipboard, etc.

## kessel REST auth (DLL `0x180003D20`)
`POST https://kessel-api.parsec.app/v2/auth`
```json
{"email": "...", "password": "...",
 "session_scopes": ["ws.host", "ws.client", "api.writer"],
 "host_peer_id": "<optional, existing host id>", "tfa": "<optional 2FA code>"}
```
Headers (every kessel request, `0x180003680` builds User-Agent):
```
X-Parsec-OS: <os name>            X-Parsec-OS-Version: <ver>
X-Parsec-Platform: windows|linux  X-Parsec-App-Version: 150-105c
X-Parsec-Device-ID: <id>          User-Agent: parsec/150-105c ... libmatoya/<ver>
Content-Type: application/json
```
Note: `peer_id=%s:host_secret=%s:connection_name=%s` is only local IPC for `parsec://`
links (`0x180056D60`), not network auth.

## kessel WS signaling (thread `0x1800D2730`, dispatch `0x1800D1BC0`)
`wss://kessel-ws.parsec.app:443/?session_id=<sid>&role=host&version=1&build=150-105c&sdk_version=393216`
(`sdk_version` = 0x60000), header `Authorization: Bearer <session_id>` + X-Parsec-* above.
Reconnect backoff 30 s doubling, cap 300 s. Close code 1001 → -3009; HTTP 401 → -3008; 412 → -6107.

Incoming `{"action": ..., "payload": {...}}`:
| action | payload |
|---|---|
| `sdk` | opaque, passed through |
| `close` | `reason`: HOST_NOT_FOUND, USER_UNCONFIRMED, TFA_REQUIRED, NO_PERMISSION, INVALID_MSG, ACCESSLINK_*, TEAM_DEACTIVATED, OUT_OF_COMPLIANCE, INVALID_SESSION |
| `offer_relay` | parsed by `0x1800D1930` (TODO) |
| `offer_cancel_relay` | `from`, `attempt_id` |
| `answer_relay` | `from`, `attempt_id`, `approved`, `data` (client side) |
| `candex_relay` | `from`, `attempt_id`, `data: {ip, port, lan, from_stun, sync}` |

Outgoing (queued, sender `0x1800D2610`): `candex`, `answer`, … (TODO: exact schemas)

### `conn_update` (host → kessel, DLL `0x1800D2F50`) – VERIFIED makes host fully listed
```json
{"version":1,"action":"conn_update","payload":{
 "loader_v":0,"service_v":0,"os":"Ubuntu 24.04.2 LTS","os_v":"6.17...","platform":"linux",
 "app_v":"150-105c","sdk_v":393216,"device_id":"...","mode":"desktop","name":"vm",
 "desc":"","game_id":"","secret":"","max_players":20,"players":0,"public":false,
 "guests":[{"guest_id":0,"user_id":0,"gamepad":false,"keyboard":false,"mouse":false}]}}
```
`secret` is only sent if ≥ 8 chars, else "". `mode` "desktop" / "game".

### Outgoing envelope (`0x1800D1760`), answer (`0x1800D40C0`), candex (`0x1800D34B0`)
```json
{"version":1,"action":"answer","payload":{"to":"<peer_id of offerer>","attempt_id":"...",
  "approved":true,
  "data":{"ver_data":1,
          "versions":{"p2p":1,"bud":1,"init":1,"video":1,"audio":1,"control":1},
          "creds":{"ice_ufrag":"","ice_pwd":"","fingerprint":"","aes256":""}}}}
{"version":1,"action":"candex","payload":{"to":"...","attempt_id":"...",
  "data":{"ver_data":1,"versions":{...},"ip":"1.2.3.4","port":1234,
          "lan":true,"from_stun":false,"sync":false}}}
```
`creds` only present when approved. After approving, host sends candex for its local
(`a1+698`, sync=1?) and STUN-reflexive (`a1+770`) addresses. Port is the host's BUD UDP port.

### `offer_relay` payload (parser `0x1800D1930`, creds `0x1800D1620`)
```
{from, attempt_id, is_owner, skip_approval,
 permissions:{gamepad,keyboard,mouse}, user:{name,id,has_avatar},
 data:{mode, creds:{ice_ufrag, ice_pwd, fingerprint, aes256}}}
```
**The BUD AES-256-GCM key (`aes256`) and DTLS fingerprint travel inside the signaling
offer/answer** – no separate key exchange to reverse. Answer presumably mirrors
`{approved, data:{creds:{...}}}` (client-side parser in `answer_relay` case uses the same
`0x1800D1620`).

## Verified live (2026-10-19, tools/kessel_probe.py on the VM)
- `/v2/auth` with `X-Parsec-Platform: linux` → HTTP 201 `{session_id, user_id, host_peer_id, version}`.
  No 2FA / device confirmation was required. A new `host_peer_id` is issued per device.
- WS `role=host` with that session: upgrade accepted, socket held open, no messages pushed while idle.
- `GET /v2/hosts?mode=desktop` while connected: our peer is listed `online: true`, but with
  `name: ""`, `build: ""`, `OS: ""`, `max_players: 0`. Real Windows hosts report name, build,
  OS, `max_players: 20` → the official host sends some host-info update we don't yet. TODO: find it.

## P2P layer – VERIFIED live 2026-10-19 (tools/stun.py, tools/bud_decrypt.py)

### ICE (standard RFC 5389/8445, libwebrtc flavour)
- Client sends Binding Requests from its BUD port to our candex ip:port.
  USERNAME = `<host ufrag>:<client ufrag>`, attrs: GOOG-NETWORK-INFO 0xC057, ICE-CONTROLLING,
  PRIORITY, MESSAGE-INTEGRITY (HMAC-SHA1, key = **host ice_pwd**), FINGERPRINT.
- Host replies Binding Success (XOR-MAPPED-ADDRESS + MI with host pwd + FP) and sends a
  triggered check (USERNAME `<client ufrag>:<host ufrag>`, ICE-CONTROLLED, MI with client pwd).
  Client answers with valid Binding Success. → client proceeds to BUD.

### BUD record format
```
off 0  u8   0x17            (DTLS "application_data" lookalike)
    1  u16  0xFEFD          (DTLS 1.2 lookalike)
    3  u16  epoch (0)
    5  u48  seq (starts at 1, +1 per datagram)
   11  u16  length (= datagram_len + 16; unused by us)
   13  16B  AES-GCM tag
   29  ...  ciphertext
```
Crypto (`bud_create` DLL `0x18003BB70`, libmatoya `MTY_AESGCMCreate`):
key = hexdecode(**host's own answer aes256**)[0:32], salt = [32:36],
nonce = salt ‖ epoch ‖ seq (12 B), **no AAD**. Client→host direction verified.
(Host→client presumably uses the client's offer aes256 – to verify.)
21 channel contexts share the same key.

### BUD plaintext (client → host, first seconds)
- type 0x01 0x08 …, 83 B: feedback/stats packet = `bud_write_packet` (`0x18003C650`):
  `[1][a4][a3][u32 be][19 × u32 be]`. Sent continuously.
- type 0x01 0x21 …: reliable messages. seq 18 = client config JSON:
```json
{"mediaContainer":0,"_max_h":8192,"resolutionX":1920,"channels":2,"resolutionY":1080,
 "_VideoProtocolVersion":1,"_cache_cursor":true,"_max_w":8192,"refreshRate":60,"rawAudio":false,
 "_version":1,"channelMask":3,"resolutions":[{"height":1080,"width":1920},...],"_flags":9}
```
  header before JSON: `01 21 0000 0000 0000 0001 73 00 0001 66 00000000 00000000 0b` (TODO decode)
  seq 19/20: `01 21 0000 0000 01 0000000d … 23`; seq 21/22: `01 21 … 0e 00000001 0000000[9|a] 00000000 11 00`
- The whole batch is retransmitted ~every few hundred ms because the host never acks.

### BUD message framing – VERIFIED from the DLL (replaces the old guess)

Every BUD plaintext starts with the **same 7-byte header**. Byte 1 is a *type*, not a
channel/flag blob. The old guess above was wrong: it read the app-level header as part
of the BUD framing. Implemented in `parsec4linux/reliable.py` + `feedback.py`.

```
off 0  u8       0x01                 constant
    1  u8       type: 0x21 = reliable, last fragment
                      0x01 = reliable, more fragments follow
                      0x08 = feedback / ack (see below)
    2  u8       channel id
    3  u32 be   sequence number
    7  u32 be   total message length  <- FIRST fragment of a reliable message only
  7|11 ...      payload (an app-level header rides at the front of the first
                fragment's payload; that header is the app's business, not BUD's)
```

Re-reading the captured client config with this: `01 21 00 | 00000000 | 00000173` =
reliable/last, channel 0, seq 0, total length 0x173. Everything from `00 00 01 66`
onward is the **app** header, which is why the old reading looked so strange.

Sender (`sub_18003D410`, the reliable fragmenter):
- per-channel state at `ctx+0x160`, stride `0xA8`; **19 channels** (not 21 — the
  `bud_thread` loop bound is `0x13`)
- retransmit ring: **4000 slots**, stride `0x4F8` (1272); per slot:
  `+0x4D0` length, `+0x4D4` pending flag, `+0x4D8`/`+0x4E0` timestamps,
  `+0x4E8` rtt, `+0x4EC` liveness (must be 1), `+0x4F0` retx count, `+0x4F4` lost flag
- **congestion window 100**: at >= 100 unacked in flight the slot is marked pending
  instead of sent
- the BUD datagram channel index on the wire is **channel id + 2**
- fragment payload capacity from `ctx+0xDF8` (negotiated MTU)

### Feedback / ack packet (type 0x08) – VERIFIED, this is the missing piece

There is **no separate ack message**. Each side periodically emits one 83-byte packet
carrying a cumulative ack per channel; the peer releases retransmit slots from it.
The Linux host never sent this, which is exactly why a connected client retransmits
its reliable batch forever.

```
01 08 00 | 00000000 | 19 x u32 be      = 7 + 76 = 83 bytes (0x53)
```
Header is fixed: `bud_thread` passes channel 0 and seq 0. Built by `bud_write_packet`
(`0x18003C650`) from a 19-entry, 12-bytes-per-entry array (`0xE4` total, memset at the
top of `bud_thread`):
```
+0  u32  highest seq WE received   -> serialized into the feedback packet
+4  u32  the peer's ack of OUR sends -> base of our outstanding send window
+8  u32  (untouched in the paths reversed so far)
```
Cadence: on a timer (interval `qword_180373C78`), **not** per received packet, and
always on BUD channel 0 regardless of which channels it reports.

Retransmit timer (`sub_18003C380`, confirmed in pseudocode):
```
rto = clamp(2 * (retx_count + 1) * rtt, 50 ms, 1000 ms)
resend when elapsed > rto + 30 ms
```
`unk_180330D60` is a table of float triples indexed by `ctx+0xDDC` (congestion profile)
giving the `a*x + b` thresholds used to decide "still in flight" vs "lost".

### App-level header – VERIFIED live 2026-10-19 (13 bytes, in front of the payload)

Sits at the front of the first fragment's payload, i.e. after BUD's 7-byte header and
the 4-byte total length. Confirmed against both the capture and a live session.

```
+0   u32 be  payload length (excludes these 13 bytes)
+4   u32 be  field1 — seen 0, 7, 9, 10, 0x48d, 0x481 (meaning TBD)
+8   u32 be  always 0 so far
+12  u8      message type
```
Types seen from the client: `0x0b` client config JSON, `0x23` empty (keepalive?),
`0x11` 1-byte/text payload, `0x0d` small counter-ish, `0x03` carries 0x48d/0x481 in
field1. Example: `0000015a 00000000 00000000 0b` + 346-byte JSON.

Caveat: for `type=0x0d` the length field disagreed with the body size in the offline
capture (claims 1–4 bytes, body empty), so either field1/length mean something else for
that type or those messages are truncated. Not yet understood.

### Host → client send key – RESOLVED 2026-10-19: ONE shared session key (the answer)

`bud_create` is called **once** with a single `aes256` and all channel contexts share
it. The binary does not show which creds feed it, so this was settled by experiment
with `tools/retransmit_stats.py` (copies per reliable message; ~1.0 = our ack is being
honoured, high = the client is still retransmitting on its RTO):

| run | copies/msg |
|---|---|
| no feedback sent at all | 59.3 / 41.1 |
| feedback encrypted with the client's **offer** key | 54.9 — no effect, wrong key |
| feedback encrypted with our own **answer** key | **4.6 — ~12x drop, ack honoured** |

**So both directions use the host's own answer `aes256`.** The offer's `aes256` is the
client's candidate and is overridden by the answer. This also confirms the whole
feedback design end-to-end on a live connection: 83-byte layout, 19 per-channel
cumulative acks, the 30 ms cadence and the 7-byte header are all correct.

Residual 4.6 (not 1.0) is most likely the startup transient — the client bursts its
config messages and retransmits once or twice in the ~50 ms before our first ack lands
(its RTO floor is 50 ms, we ack every 30 ms). Possible second cause: we advertise the
highest seq seen, but messages arrive out of order (0–4, 7, 10, then 5,6,9, 11,12), so
if the field is the highest *contiguous* seq our value is wrong during gaps. Worth
testing.

A live client now reaches the video stage and reports *"the host isn't sending any
video data"* — signaling, ICE, BUD and the ack all succeed, and it times out waiting
for video. **Video is the next blocker.**

### Video packet format – REVERSED 2026-10-19 (`proto_video_write` 0x1800A5230)

The last big protocol unknown. Implemented in `parsec4linux/video.py`.

Transport discovery: `nat_init_proto` (0x18009D670) builds a 536-byte transport object
and installs a vtable; for BUD (proto 1) the slots are
```
obj+8  bud ctx (bud_create)      obj+16 sub_18003CF80   obj+24 sub_18003D110
obj+32 sub_18003D2B0 (receive: walks the ring releasing slots, advances read cursor)
obj+40 sub_18003D410 (SEND - the reliable fragmenter)   obj+48 sub_18003D6D0
```
SCTP (proto 2) fills only +16/+40/+48, so +24/+32 are BUD-only. There is exactly **one
send slot**: everything, video included, goes through the reliable fragmenter.
"Unreliable" is a per-channel policy, enforced in the retransmit pass
(`if (!a5 || v13 >= a6 || slot+1268)` decides drop vs retransmit; `chan+384` is the
per-channel window limit), not a second transport.

Send signature (obj+40):
```
send(bud_ctx, channel_u8, hdr_ptr, hdr_len_u8, payload_ptr, payload_len, flags)
```
The fragmenter places `hdr` right after the first fragment's 4-byte total length, so
the app header rides at the front of the message and the payload follows.

**Video packet:**
```
BUD 7-byte header | u32 be total len | 10-byte video header | encoded frame verbatim
  +0  u32  timestamp / frame counter
  +4  u16  width
  +6  u16  height
  +8  u8   frame kind (client cfg field, else 1)
  +9  u8   flags = (qp & 7) | 0x08 | 0x10 | 0x20   (the 0x1800A9E70 stats path also ORs 0x60)
```
Channel = `stream_index ? stream_index + 2 : 1`, so the **primary stream is channel 1**.
Payload is the encoder's output **verbatim** when the client requests
`mediaContainer: 0` (what a real client sends); only `mediaContainer == 2` goes through
a repacker (`sub_18009CBF0`), which we do not need.

**Byte order: RESOLVED — little-endian.** `proto_video_write` writes these fields with
plain assignments and no `htonl`/`htons` (unlike the control path, which byte-swaps
explicitly), and a live client rendered a frame with the LE header. So the video header
is native/LE while control messages are big-endian.

## SMOOTH LIVE VIDEO — 2026-10-19 (header values measured, not guessed)

Playback stuttered (~1 s freezes) until the video header fields were measured off a
real Windows host with `tools/parsec_client.py`. Every guessed value was wrong:

| field | guessed | **real host** |
|---|---|---|
| `+0` timestamp | frame counter, then elapsed ms | **constant `1`** — not a clock, not a counter |
| `+8` kind | 1 / 3 / 0 (I vs P) | **`0x02` for every frame** |
| `+9` flags | `0x10` | **`0x01` delta, `0x21` keyframe, `0x61` first frame** |

So `0x20` = keyframe bit, `0x40` = stream start, `0x01` always set, and `0x10` is a bit
the host never sets. Byte order confirmed **little-endian** (1920x1080 decodes cleanly).
A real host's keyframe header is `01000000 8007 3804 02 21`; `video.build_raw_header`
reproduces it byte-for-byte.

**Why the binary could not answer this:** `kind` is `v52 = *(a19 + 8)`, written by the
encoder backend at runtime. The backend table `unk_1805A5360` is populated on startup,
so its pointers are null/meaningless in the static image — chasing them led into
unrelated clipboard code. Measuring the wire was the only reliable route.

### tools/parsec_client.py — connect to a real host and decrypt what it sends

The measuring instrument, and reusable for audio/input/cursor next. It works because
**the host generates the BUD session key and hands it to us in its `answer`**, so a
client can decrypt everything the host sends.

Offer schema, from the client's own builder (DLL `0x1800D3700`):
```json
{"version":1,"action":"offer","payload":{
  "to":"<host peer_id>", "attempt_id":"%08x-%08x-%08x-%08x-%08x-%08x",
  "secret":"", "access_link_id":"",
  "data":{"ver_data":1,"versions":{...},"creds":{...},"mode":1}}}
```
* `mode` is an **integer** (1), not `"desktop"` — sending a string got the offer
  silently ignored, with no `close` and no error.
* `secret` / `access_link_id`: a 27-char alphanumeric argument goes in
  `access_link_id`, anything else in `secret`; both empty for a plain owner connect.

ICE gotcha: pair on the address the **host checks us from**, not the first candidate
that answers. The first responder was a VirtualBox host-only address (`192.168.56.1`)
the VM cannot route back to, so our acks went nowhere and the host never streamed.

The host needs the **full client init burst** before it starts video, not just the
config. Replaying the captured sequence (seq 0-10, `tools/` + `client_init.json`) works:
```
0x0b config JSON | 0x23 x2 | 0x11 f1=9 | 0x11 f1=10 | 0x23 x2 | 0x0d f0=1..4 f1=9
```
(Skip `0x11` with `field1 == 7` — that is clipboard text from the captured machine.)

### Newly observed, not yet implemented
* **BUD type `0x02` = per-message ack.** The host sent exactly 11, matching our 11 init
  message seqs, so acknowledgement is finer-grained than the cumulative `0x08` feedback.
* **Channel 2 is audio** — type `0x01`, ~323 B messages.
* Host→client control types seen live: `0x1c`, `0x19` (1048/1088 B, f1=9), `0x11`
  (f1=18/22/24), `0x1d`, `0x15` (f1=uptime), `0x09` (21 B).
* That host negotiated **H.265**; our H.264 is accepted too.

## LIVE VIDEO WORKING — 2026-10-19

A real Parsec client rendered **continuous live-encoded video** from our Linux host: a
moving test pattern at 1280x720/30 fps, via `tools/capture_h264.py` (GStreamer
videotestsrc -> x264enc -> h264parse -> appsink) piped into `kessel_probe.py --capture`.
Motion, P-frames and multi-fragment messages (up to 4 fragments/frame) all work.

The encoder runs as a separate process under the SYSTEM python3, because GStreamer's
`gi` bindings are not in the p4l venv; frames cross as `[u32 le length][Annex-B frame]`
on stdout. Needs `gstreamer1.0-plugins-{bad,ugly}` for `h264parse` / `x264enc`.

x264 settings that a client accepts: `tune=zerolatency speed-preset=ultrafast
bframes=0 key-int-max=<fps>` plus `h264parse config-interval=-1` so SPS/PPS repeat on
every keyframe.

## FIRST FRAME DISPLAYED — 2026-10-19

A real Parsec client rendered a frame from our Linux host: a solid blue
(`ffmpeg color=0x3080c0`) 320x180 H.264 IDR. Confirmed working combination:

```
control channel 0: app 0x1D stream_init {stream=0, ts, 0}   (sent once, before frames)
video   channel 1: 10-byte LE header + Annex-B frame verbatim, kind=1, flags=0x10
MTU 1193 per fragment, BUD sealed with our own answer aes256
```
Reproduce with:
```
kessel_probe.py ws --answer --port 8000 --tx-key answer \
    --video /tmp/tiny.h264 --fps 30 --size 320x180 --kind 1 --flags 0x10
```

### Multi-fragment — FIXED: sequence numbers are per-FRAGMENT, not per-message

A 6-fragment 1920x1080 frame now renders. The bug was ours: we stamped every fragment
of a message with the same sequence number. The sender increments once **per fragment**
(`sub_1800DA680` in 0x18003D410, `mov edi, eax`) so each fragment occupies its own
consecutive ring slot, and the reader (0x18003CF80) reads the total length at the
cursor, derives `(total+4)/1193` as the count, waits for `seq .. seq+count-1`, then
walks those slots advancing the cursor. One seq per message makes that walk fail, and
the peer answers -12011. Callers must advance their counter by the fragment count.

Single-fragment messages hid this, which is why the 838-byte frame worked first.

### Historical: how -12011 was diagnosed

A 6973-byte 1920x1080 frame (6 fragments) produced client error **-12011**; the
838-byte single-fragment frame works. `-12011` (0xFFFFD115) comes from the BUD **read**
(`sub_18003CF80`, the transport's +16 slot) in two places:
```
if ( a4 < v13 ) return -12011;              // caller's buffer smaller than total length
v16 = *(_DWORD *)(v15 + 1232) - v12;
if ( v16 > (int)v13 ) break; ... -12011      // fragment sizes don't sum to the total
```
Receiver details: total length is read at **slot+0** and the copy starts at **slot+4**
on the first fragment (`v12 = 4`, then 0), so the receive path strips the 7-byte header
and stores `[u32 be total_len][payload...]`. Expected fragment count is
`(total_len + 4) / 1193` rounded up, so every fragment but the last must carry exactly
1193 post-header bytes. `reliable.py`'s self-test asserts our output satisfies exactly
that, so our fragmentation is arithmetically consistent.

CAVEAT on the experiment: the failing run also had `kind=3` (a misreading — `a7` is
`*(a19+8)`, not the `v175[0]=3` in the capture loop). So size and `kind` both changed
between the failing and working runs. **Next test: a multi-fragment frame with
`kind=1`,** to tell those apart before chasing the client's buffer size.

### Control-message app header – 13 bytes (`{3 x u32 be, u8 type}`, type LAST)

Confirmed from both the capture and the DLL's send calls. The three u32s are
type-specific, which is why the earlier "field0 = payload length" reading fitted the
config message but not the others. Host→client types seen: `0x1D` (stream init,
carries stream index + timestamp), `0x10` (on/off, field0 = 1/0), `0x15` (every 30
frames, carries uptime + stream), `0x22` (cursor/stats, 13-byte hdr + 16-byte payload).
Client→host types seen: `0x0b` config JSON, `0x23`, `0x11`, `0x0d`, `0x03`.

### Host pipeline (`0x1800AF5B0`) – for the Linux reimplementation

12096-byte host object. Spawns **5 per-stream capture/encode threads**
(`sub_1800ABCA0`, ~1 MB buffer each) plus `sub_1800ADA60`, `sub_1800AEFF0`,
`sub_1800AD180`, `sub_1800AD720`. Input injection uses user32
`CreateSyntheticPointerDevice` / `InjectSyntheticPointerInput` (Windows-only; Linux
needs `uinput`).

Per-stream loop (`sub_1800ABCA0`): grab (`sub_180047800`) → encode → `0x1800A9E70`
(per-client dispatch) → `proto_video_write`. Encoder backends live in a 5-entry table
at `unk_1805A5360` (64 B each) with vtable `+24 init(obj, dev, w, h, session, cfg)`,
`+40 reconfigure(cfg)`, `+48 submit`, `+56 available?`; logs `encode_init`,
`encode_x`, `encode_y`. Config `v150` = `[fps, codec & 0x3F, bitrate]`; fps clamped to
60; frames above 1920x1080 go through a scaler; hard cap 0x2000 x 0x10E0.

### BUD sealer limits (`sub_18003BE90`)
- **max plaintext 1200 bytes** (`cmp esi, 4B0h; jg -> 0xFFFF929C`)
- the 2-byte length field is **record_len + 16** (= plaintext + 45), i.e. *not* the DTLS
  convention of ciphertext+tag. Receivers ignore it; we match the DLL byte-for-byte.
- sends via `WSASendMsg`, one scatter-gather buffer of exactly `plaintext + 29`
**Privacy:** the client pushes its clipboard to the host right after connecting (type 7), so
`udp_raw.log` can contain clipboard contents.

## Test loop available
- Windows host (this PC) + Linux client in VMware VM `192.168.179.134` (user `v`, VMnet8
  NAT, SSH key auth already set up). Note `192.168.137.x` is this host's Windows
  ICS/hotspot subnet, not the VM network.
  already connect successfully (Windows log 2026-10-19 00:43, `net = BUD|...|64361`).
- Reference observations from that session: dxgi 1.5, BGRA, NVENC, h265, 1680x1050.

## Implementation status (`parsec4linux/`)
All three modules have `__main__` self-tests; `reliable.py` also decodes the real
captured client-config frame.

| module | covers | verified against |
|---|---|---|
| `bud.py` | record crypto both directions, 1200-byte cap, DLL-exact length field | sealer `0x18003BE90` + live capture |
| `reliable.py` | 7-byte header, fragmentation + reassembly | fragmenter `0x18003D410` + captured frame |
| `feedback.py` | the ack: 83-byte type-0x08 packet, 19 per-channel cumulative acks | `bud_write_packet`, `bud_thread`, `sub_18003C380` |

Host→client crypto note: the receiver decrypts with the key the *sender* advertised, so
a host sends with the client's **offer** `aes256` and receives with its own **answer**
`aes256`. Client→host is verified live; host→client is the mirror and still needs a
live check.

## Next steps
- [x] Milestone 1: Linux program registers as host and appears in a client's list.
- [x] Reliable framing + ack format reversed and implemented.
- [ ] Wire `feedback.py` into the probe's `--answer` path on a timer; confirm on the VM
      that the client's retransmit storm stops. **First observable win.**
- [x] Reverse the **app-level** header — 13 bytes for control, 10 bytes for video.
- [x] Reverse the **video packet format** (`proto_video_write`). All protocol unknowns
      needed for a first frame are now mapped.
- [x] **Send a frame** — done, and smooth once the header values were measured.
- [x] Confirm the video header's byte order live — little-endian.
- [ ] **Real screen capture.** The pipeline is built and proven with `videotestsrc`;
      swap to `pipewiresrc` via the ScreenCast portal (`capture_h264.py --source
      pipewire`, portal code already written). GNOME/Wayland needs an interactive
      "share your screen" approval on the VM's own display the first time;
      `persist_mode=2` then caches a restore token. **This is the next step.**
- [ ] Input: decode the client→host input messages (use `parsec_client.py` to watch a
      real host, then inject with `uinput` — the Windows host's
      `CreateSyntheticPointerDevice` has no Linux equivalent).
- [ ] Audio: channel 2, type `0x01`, ~323 B messages.
- [ ] Implement BUD type `0x02` per-message acks.
- [ ] Measure RTT instead of assuming it (retransmit RTO currently hardcodes 120 ms).
- [ ] Capture pipeline: the VM is Ubuntu 24.04 / **GNOME on Wayland**, so capture is
      **PipeWire via `xdg-desktop-portal` ScreenCast**, not X11/XShm. Needs a portal
      session; a VM/headless GNOME may need remote-desktop portal permissions.
      Software encode (x264/x265) — no GPU encoder in the VM.
- [ ] Input injection via `uinput`; audio via opus.
