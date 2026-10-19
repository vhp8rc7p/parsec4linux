#!/usr/bin/env python3
"""Milestone-1 probe: authenticate against kessel and hold a host signaling socket.

Credentials:  ~/.config/parsec4linux/creds.json   {"email": "...", "password": "..."}
Session cache: ~/.config/parsec4linux/session.json (both chmod 600)

Usage:
  kessel_probe.py auth [--tfa CODE] [--platform linux|windows]
  kessel_probe.py ws   [--platform linux|windows] [--seconds N]
"""
import argparse
import asyncio
import collections
import json
import os
import platform
import secrets
import shlex
import socket
import struct
import time
import ssl
import sys
import urllib.error
import urllib.request

import websockets

import stun

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))
from parsec4linux import audio as paudio, app, bud, feedback, reliable, video  # noqa: E402
from parsec4linux import input as pinput  # noqa: E402

# bud_thread emits feedback every 30 ms (DLL 0x18003CC60: `>= 30.0`).
FEEDBACK_INTERVAL = 0.030

# Which aes256 we ENCRYPT with: "answer" (our own, one shared session key) or
# "offer" (the client's, a key per direction). Set from --tx-key.
TX_KEY = "answer"

# Synthetic video, set from --video/--fps/--size. VIDEO_FRAME stays None unless asked.
VIDEO_FRAME = None
VIDEO_FPS = 30
VIDEO_W = 1920
VIDEO_H = 1080
# Timestamp units for the video header's +0 u32. The DLL feeds it an atomic counter,
# but a counter and a millisecond clock are indistinguishable in the disassembly, and a
# client that treats it as ms would stall when fed 0,1,2,3 at 30 fps.
# Measured off a real Windows host with tools/parsec_client.py (see re/NOTES.md):
#   +0 timestamp : constant 1 -- NOT a clock or a frame counter
#   +8 kind      : constant 0x02 for every frame
#   +9 flags     : 0x01 delta, 0x21 keyframe (0x20 = keyframe bit),
#                  0x61 on the very first frame (0x40 = stream start)
VIDEO_TS = "const"  # "const" = the observed constant 1
VIDEO_TS_CONST = 1
VIDEO_KIND = 0x02
VIDEO_KIND_P = 0x02
VIDEO_FLAGS_DELTA = 0x01
VIDEO_FLAGS_KEY = 0x21
VIDEO_FLAGS_FIRST = 0x61
VIDEO_FLAGS = 0x10
CAPTURE_CMD = None
INJECT_CMD = None
# tools/display_mode.py, to honour the resolution a client asks for. None = log only.
RESOLUTION_CMD = None
# tools/capture_audio.py: Opus packets, one record each. None = no audio.
AUDIO_CMD = None
# A connected client acks every 30 ms, so this much silence means it has gone. There
# is no goodbye message in BUD or signaling; the DLL's own hard limit is 60 s
# (bud_thread, -12007), far too slow to give the desktop its resolution back.
CLIENT_TIMEOUT = 5.0
# res_requested before any 0x0b has arrived -- distinct from None ("keep the
# host's resolution"), which still owes a restore if we changed it earlier.
NO_CONFIG = object()

# Retransmission (DLL 0x18003C380). We have no RTT measurement yet, so assume a LAN-ish
# value; the RTO floor of 50 ms dominates anyway.
# Initial RTT estimate, used only until the first real sample arrives. RTT is now
# measured (see _note_rtt), as the DLL does -- it keeps a live value at ctx+0xDD8.
RTT_MS = 120.0
MAX_RETX = 10
# Congestion window: the DLL stops emitting at >= 100 unacked (0x18003C380 `cmp ebp, 64h`).
CWND = 100

# Congestion profiles from the DLL's table at unk_180330D60, float triples indexed by
# ctx+0xDDC. A message counts as "late" when elapsed > a * rtt + b. The host exports
# that late count so the encoder can back off at the source instead of discarding
# frames that were already encoded -- which is what we still do (self.dropped).
# Profile 0 is (0, 0): everything is immediately late.
CONGESTION_PROFILES = ((0.0, 0.0), (1.1, 20.0), (1.5, 50.0))
CONGESTION_PROFILE = 1

API = "https://kessel-api.parsec.app"
WS = "wss://kessel-ws.parsec.app:443"
BUILD = "150-105c"
SDK_VERSION = 0x60000

CFG = os.path.expanduser("~/.config/parsec4linux")
CREDS = os.path.join(CFG, "creds.json")
SESSION = os.path.join(CFG, "session.json")
DEVICE = os.path.join(CFG, "device_id")
RAW_LOG = os.path.join(CFG, "ws_raw.log")
UDP_LOG = os.path.join(CFG, "udp_raw.log")

SECRET_KEYS = {"session_id", "password", "token", "secret", "host_secret", "id"}


def save_private(path, text):
    os.makedirs(CFG, mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)


def device_id():
    if not os.path.exists(DEVICE):
        save_private(DEVICE, secrets.token_hex(16))
    return open(DEVICE).read().strip()


def headers(plat, session_id=None):
    h = {
        "X-Parsec-OS": platform.node() or "no-name",
        "X-Parsec-OS-Version": platform.release(),
        "X-Parsec-Platform": plat,
        "X-Parsec-App-Version": BUILD,
        "X-Parsec-Device-ID": device_id(),
        "User-Agent": f"parsec/{BUILD} {plat}/{platform.release()} libmatoya/0",
        "Content-Type": "application/json",
    }
    if session_id:
        h["Authorization"] = f"Bearer {session_id}"
    return h


def redact(obj):
    """Show response structure without leaking tokens."""
    if isinstance(obj, dict):
        return {k: ("<redacted>" if k in SECRET_KEYS and isinstance(v, str) else redact(v))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj


def find_key(obj, key):
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        for v in obj.values():
            r = find_key(v, key)
            if r is not None:
                return r
    return None


def cmd_auth(args):
    creds = json.load(open(CREDS))
    body = {
        "email": creds["email"],
        "password": creds["password"],
        "session_scopes": ["ws.host", "ws.client", "api.writer"],
    }
    if args.tfa:
        body["tfa"] = args.tfa
    req = urllib.request.Request(API + "/v2/auth", data=json.dumps(body).encode(),
                                 headers=headers(args.platform), method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            status, raw = r.status, r.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    print("HTTP", status)
    try:
        resp = json.loads(raw)
    except ValueError:
        print(raw[:500])
        return 1
    print(json.dumps(redact(resp), indent=2))
    if status == 200 or status == 201:
        save_private(SESSION, json.dumps(resp))
        print("session saved to", SESSION)
        return 0
    return 1


def cmd_hosts(args):
    sid = find_key(json.load(open(SESSION)), "session_id")
    req = urllib.request.Request(API + "/v2/hosts?mode=desktop", headers=headers(args.platform, sid))
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            status, raw = r.status, r.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    print("HTTP", status)
    try:
        print(json.dumps(redact(json.loads(raw)), indent=2))
    except ValueError:
        print(raw[:500])
    return 0 if status == 200 else 1


def os_pretty():
    try:
        for line in open("/etc/os-release"):
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return "Linux"


def conn_update(args):
    """Host status update, mirrors DLL 0x1800D2F50."""
    return {
        "version": 1,
        "action": "conn_update",
        "payload": {
            "loader_v": 0,
            "service_v": 0,
            "os": os_pretty(),
            "os_v": platform.release(),
            "platform": args.platform,
            "app_v": BUILD,
            "sdk_v": SDK_VERSION,
            "device_id": device_id(),
            "mode": "desktop",
            "name": args.name,
            "desc": "",
            "game_id": "",
            "secret": "",
            "max_players": 20,
            "players": 0,
            "public": False,
            "guests": [],
        },
    }


def envelope(action, to, payload, with_data):
    """Outgoing signaling envelope, mirrors DLL 0x1800D1760."""
    body = {"to": to, **payload}
    if with_data is not None:
        body["data"] = {
            "ver_data": 1,
            "versions": {"p2p": 1, "bud": 1, "init": 1, "video": 1, "audio": 1, "control": 1},
            **with_data,
        }
    return {"version": 1, "action": action, "payload": body}


def bud_creds():
    """BUD-mode creds, mirrors DLL 0x1800A14C0 (mode != 2)."""
    import base64
    return {
        "ice_ufrag": base64.b64encode(secrets.token_bytes(4)).decode(),
        "ice_pwd": base64.b64encode(secrets.token_bytes(24)).decode(),
        "fingerprint": secrets.token_bytes(32).hex(),
        "aes256": secrets.token_bytes(127).hex(),
    }


def lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))  # no packet sent; just picks the outbound interface
        return s.getsockname()[0]
    finally:
        s.close()


# creds of the attempt currently being answered: {"local": {...}, "remote": {...}, "tie": bytes}
ATTEMPT = {}

# The live UdpLogger, so a new offer can tear down the session keyed to the old one.
UDP = None


class UdpLogger(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        global UDP
        UDP = self
        self.transport = transport
        self.checked = set()
        self.session = None          # bud.Session, built once creds are known
        self.acks = feedback.AckTracker()
        self.reassembler = reliable.Reassembler()
        self.feedback_task = None
        self.video_task = None
        self.audio_task = None
        self.audio_packets = 0
        self._audio_last = None
        self.audio_max_gap = 0.0  # ms, per log line
        self.audio_late = 0         # packets > 60 ms after the previous one
        self._cpu_prev = None
        self.peer = None
        self._msg_seq = {}  # app channel -> next message sequence number
        self.unacked = collections.defaultdict(dict)  # channel -> {seq: (frame, sent, retx)}
        self.retx_total = 0
        self.dropped = 0
        self._t0 = None
        self.inject = None           # uinput child process
        self.input_seen = {}
        self.input_inferred = set()
        self.motion_extent = [1 << 30, -(1 << 30), 1 << 30, -(1 << 30)]
        self.cap_size = None         # (w, h) last reported by the capture child
        self.rtt_ms = None           # measured, smoothed; None until the first sample
        self.rtt_samples = 0
        self.rtt_min = self.rtt_max = None
        self.late = 0                # fragments past the profile's threshold
        self.imm_acks = 0            # type 0x02
        self.timer_acks = 0          # type 0x08
        self.msg_acks_sent = 0       # 0x02s WE sent: the client's only RTT source
        self.enc_ms = None           # smoothed capture -> encoded, for the log
        self.frames_sent = 0         # paces the 0x15 encode heartbeat
        self.frame_interval_ms = 0.0
        self.last_rx = None          # monotonic time of the last BUD packet
        self.watchdog_task = None
        self.capture_proc = None
        self._capture_restart = False
        self.res_applied = False     # we changed the desktop mode and owe a restore
        self.res_requested = NO_CONFIG  # (w, h), None = keep, or none yet

    def reset_session(self):
        """Drop the session so the next datagram rebuilds it from the new attempt's creds.

        Each reconnect carries fresh aes256/ice creds, so a session pinned to the old
        attempt can neither decrypt the new client nor be decrypted by it.
        """
        for task in (self.feedback_task, self.video_task, self.audio_task):
            if task is not None:
                task.cancel()
        self.feedback_task = self.video_task = self.audio_task = None
        self.audio_packets = 0
        self.session = None
        self.peer = None
        self.checked = set()
        self._msg_seq = {}
        self.unacked = collections.defaultdict(dict)
        self.retx_total = 0
        self.dropped = 0
        self._t0 = None
        self.cap_size = None
        self.rtt_ms = None
        self.rtt_samples = 0
        self.rtt_min = self.rtt_max = None
        self.imm_acks = self.timer_acks = 0
        self.msg_acks_sent = 0
        self.enc_ms = None
        self.frames_sent = 0
        self.late = 0
        self.acks = feedback.AckTracker()
        self.reassembler = reliable.Reassembler()
        self.last_rx = None
        self.capture_proc = None
        self._capture_restart = False
        self.res_requested = NO_CONFIG  # next client states its own; res_applied stays
        print("   session reset for new attempt")

    def _ensure_session(self, addr):
        """Build the BUD session on first datagram and start the feedback timer.

        Receiving with our own ANSWER aes256 is verified live. The send key is still
        open: `bud_create` is called once with a single aes256 and all channel
        contexts share it, which suggests ONE session key chosen by the answerer
        (tx_key=answer). The alternative is a key per direction, where we would send
        with the client's offer key (tx_key=offer). Selectable so we can settle it
        by experiment -- sending with the offer key produced no effect at all: the
        client went on retransmitting, i.e. it never accepted our feedback.
        """
        if self.session is not None or not ATTEMPT:
            return
        tx = ATTEMPT["local" if TX_KEY == "answer" else "remote"]["aes256"]
        self.session = bud.Session(tx_aes256=tx, rx_aes256=ATTEMPT["local"]["aes256"])
        print(f"  (tx key = {TX_KEY})")
        if VIDEO_FRAME is not None or CAPTURE_CMD:
            self.video_task = asyncio.get_running_loop().create_task(self._video_loop())
        if AUDIO_CMD:
            self.audio_task = asyncio.get_running_loop().create_task(self._audio_loop())
        if INJECT_CMD and self.inject is None:
            # Started once and kept across reconnects: recreating the uinput devices
            # would make the compositor re-probe them on every attempt.
            asyncio.get_running_loop().create_task(self._start_inject())
        self.peer = addr
        self.last_rx = time.monotonic()
        self.feedback_task = asyncio.get_running_loop().create_task(self._feedback_loop())
        if self.watchdog_task is None:
            self.watchdog_task = asyncio.get_running_loop().create_task(self._watchdog())
        print(f"BUD session up with {addr[0]}:{addr[1]}; feedback every "
              f"{FEEDBACK_INTERVAL * 1000:.0f} ms")

    async def _feedback_loop(self):
        """Emit the type-0x08 ack packet on a timer, as bud_thread does."""
        while True:
            await asyncio.sleep(FEEDBACK_INTERVAL)
            if self.session is None or self.peer is None:
                continue
            try:
                # Feedback always rides BUD channel index 0 (bud_write_packet
                # passes channel 0 to the sealer).
                self.transport.sendto(
                    self.session.encrypt(self.acks.feedback_packet(), channel=0), self.peer)
                self._retransmit_due(time.monotonic())
            except Exception as e:  # keep the probe alive; we want the log
                print("feedback send failed:", e)
                return

    def _release_acked(self, now):
        """Drop fragments the peer's cumulative acks now cover, and sample RTT.

        Called on every ack packet, not just on the feedback timer, so the send window
        drains as acks arrive rather than in ~30 ms lumps.

        RTT is sampled only from fragments that were never retransmitted (Karn's
        algorithm): once a fragment has been sent twice there is no way to tell which
        copy the ack refers to, and timing it against the latest send systematically
        underestimates RTT, which shortens the RTO and causes more spurious resends.
        """
        for channel, pending in self.unacked.items():
            acked = self.acks.peer_ack[channel] if channel < feedback.NUM_CHANNELS else 0
            for seq in [s for s in pending if s <= acked]:
                _frame, last_sent, retx = pending.pop(seq)
                if retx == 0:
                    sample = (now - last_sent) * 1000.0
                    if 0.0 < sample < 10000.0:
                        self._note_rtt(sample)

    def _note_rtt(self, sample_ms):
        """Smooth an RTT sample the way TCP does (alpha 1/8)."""
        if self.rtt_ms is None:
            self.rtt_ms = sample_ms
        else:
            self.rtt_ms += (sample_ms - self.rtt_ms) / 8.0
        self.rtt_samples += 1
        self.rtt_min = sample_ms if self.rtt_min is None else min(self.rtt_min, sample_ms)
        self.rtt_max = sample_ms if self.rtt_max is None else max(self.rtt_max, sample_ms)

    def _rto_ms(self, retx):
        """The DLL's own curve (0x18003C380), fed a measured RTT.

        rto = clamp(2 * (retx + 1) * rtt, 50 ms, 1000 ms), resend when elapsed > rto + 30 ms.

        The old 250 ms floor here was a workaround for having no RTT at all: acks only
        reached us on the 30 ms feedback timer, so a short RTO resent everything before
        an ack could physically arrive. With measured RTT and 0x02 acks honoured, the
        DLL's real 50 ms floor is safe.
        """
        rtt = self.rtt_ms if self.rtt_ms is not None else RTT_MS
        return max(50.0, min(1000.0, 2.0 * (retx + 1) * rtt)) + 30.0

    def _retransmit_due(self, now):
        """Resend unacked fragments past their RTO, mirroring DLL 0x18003C380.

        Without this a single lost datagram wedges the client's reader until the next
        IDR, which is the stutter we saw.
        """
        self._release_acked(now)
        a, b = CONGESTION_PROFILES[CONGESTION_PROFILE]
        rtt = self.rtt_ms if self.rtt_ms is not None else RTT_MS
        late_threshold = a * rtt + b
        late = 0
        for channel, pending in self.unacked.items():
            # The DLL caps work by the congestion window alone, with no per-pass
            # limit; the window (CWND) already bounds how much can be outstanding.
            for seq, rec in sorted(pending.items()):
                frame, last_sent, retx = rec
                if retx > 0 or (now - last_sent) * 1000.0 > late_threshold:
                    late += 1
                if (now - last_sent) * 1000.0 <= self._rto_ms(retx):
                    continue
                if retx >= MAX_RETX:
                    del pending[seq]
                    continue
                bud_channel = channel + reliable.CHANNEL_INDEX_OFFSET
                self.transport.sendto(self.session.encrypt(frame, channel=bud_channel),
                                      self.peer)
                pending[seq] = (frame, now, retx + 1)
                self.retx_total += 1
        self.late = late

    def _send_message(self, channel, payload):
        """Fragment one app-level message and put each fragment on the wire.

        `channel` is the app/reliable channel id (0 control, 1 primary video); the BUD
        record counter is indexed by channel + 2 (the fragmenter's `add eax, 2`).
        """
        seq = self._msg_seq.get(channel, 0)
        frames = reliable.build_fragments(channel, seq, payload)  # capacity = reliable.MTU
        # Sequence numbers are per-FRAGMENT: advance by the fragment count, not by 1,
        # or the next message overlaps this one's slots and the peer answers -12011.
        self._msg_seq[channel] = seq + len(frames)
        bud_channel = channel + reliable.CHANNEL_INDEX_OFFSET
        now = time.monotonic()
        for i, frame in enumerate(frames):
            self.transport.sendto(self.session.encrypt(frame, channel=bud_channel),
                                  self.peer)
            self.unacked[channel][seq + i] = (frame, now, 0)
        return len(frames)

    def _timestamp(self, frame_no):
        if VIDEO_TS == "const":
            return VIDEO_TS_CONST
        if VIDEO_TS == "frames":
            return frame_no
        if self._t0 is None:
            self._t0 = time.monotonic()
        return int((time.monotonic() - self._t0) * 1000.0)

    def _send_frame(self, frame_no, frame):
        """Send one encoded frame; False if the congestion window made us drop it."""
        if len(self.unacked[video.PRIMARY_CHANNEL]) >= CWND:
            self.dropped += 1
            return False
        key = video.is_keyframe(frame)
        if frame_no == 0:
            flags = VIDEO_FLAGS_FIRST
        elif key:
            flags = VIDEO_FLAGS_KEY
        else:
            flags = VIDEO_FLAGS_DELTA
        # Prefer the size the capture actually reported over the --size default: the
        # client reads width/height out of every frame header, so telling it the real
        # encode size is what makes native-resolution and resizing work.
        w, h = self.cap_size or (VIDEO_W, VIDEO_H)
        hdr = video.build_raw_header(self._timestamp(frame_no), w, h,
                                     VIDEO_KIND if key else VIDEO_KIND_P, flags)
        payload = hdr + frame
        n = self._send_message(video.PRIMARY_CHANNEL, payload)
        if frame_no % max(1, VIDEO_FPS) == 0:
            pend = sum(len(v) for v in self.unacked.values())
            print(f">> video frame {frame_no} ({len(payload)} B, {n} fragments, "
                  f"retx={self.retx_total}, unacked={pend}, dropped={self.dropped}, "
                  f"{'IDR' if key else 'P'})")
            rtt = (f"{self.rtt_ms:.1f}ms (n={self.rtt_samples}, "
                   f"{self.rtt_min:.1f}..{self.rtt_max:.1f})"
                   if self.rtt_ms is not None else "unmeasured")
            print(f"   rtt={rtt} rto={self._rto_ms(0):.0f}ms "
                  f"late={self.late} acks: 0x02={self.imm_acks} 0x08={self.timer_acks} "
                  f"regressions={self.acks.regressions}")
            if self.input_seen:
                x0, x1, y0, y1 = self.motion_extent
                extent = f" motion x {x0}..{x1} y {y0}..{y1}" if x1 >= x0 else ""
                print(f"   input: {self.input_seen}{extent}")
            if self.enc_ms is not None:
                print(f"   encode={self.enc_ms:.1f}ms (smoothed) interval="
                      f"{self.frame_interval_ms:.1f}ms msg_acks_sent={self.msg_acks_sent} "
                      f"audio_packets={self.audio_packets} audio_late={self.audio_late} "
                      f"audio_max_gap={self.audio_max_gap:.0f}ms cpu_idle={self._cpu_idle()}")
                self.audio_max_gap = 0.0
        return True

    def _cpu_idle(self):
        """Whole-VM idle % since the last call, from /proc/stat ("?" elsewhere).

        The quickest way to tell a starved machine from a congested network.
        """
        try:
            with open("/proc/stat") as f:
                vals = [int(v) for v in f.readline().split()[1:]]
        except OSError:
            return "?"
        idle, total = vals[3] + vals[4], sum(vals)
        prev, self._cpu_prev = self._cpu_prev, (idle, total)
        if prev is None or total == prev[1]:
            return "?"
        return f"{100 * (idle - prev[0]) / (total - prev[1]):.0f}%"

    def _send_frame_stats(self, encode_ms, interval_ms):
        """0x22 after each sent frame -- what the client HUD's "Encode" reads.

        The DLL fills four slots; we can only honestly measure two. `encode_ms` is
        capture -> encoded, measured in the capture child per frame, which is what the
        DLL puts in slot [2]. It also goes in [0] (total): our capture-to-send path has
        nothing else that takes measurable time. [1] capture is folded into the encode
        figure rather than invented, so it is 0.
        """
        if encode_ms is None:
            return
        self.enc_ms = (encode_ms if self.enc_ms is None
                       else 0.9 * self.enc_ms + 0.1 * encode_ms)
        self._send_message(app.CONTROL_CHANNEL,
                           app.frame_stats(0, encode_ms, 0.0, encode_ms, interval_ms))
        # The HUD's "Encode" comes from THIS, not from 0x22 (which only feeds the
        # client's graph history): every 30 frames, the smoothed encode time in us,
        # exactly as the DLL sends it (lrint(ewma_ms * 1000.0)).
        self.frames_sent += 1
        if self.frames_sent % 30 == 0:
            self._send_message(app.CONTROL_CHANNEL,
                               app.heartbeat(round(self.enc_ms * 1000), 0))

    async def _video_loop(self):
        """Send video on channel 1, after a 0x1D stream-init on channel 0.

        Either replays one pre-encoded frame (--video, good for isolating protocol
        bugs) or streams live frames from tools/capture_h264.py (--capture).
        """
        await asyncio.sleep(0.2)  # let the client finish its own init burst
        while True:
            # 0x1D goes out whenever the encoder (re)starts -- the DLL sends it on the
            # first frame after encode init -- so a capture restarted at a new
            # resolution is announced the same way as the first one.
            try:
                n = self._send_message(app.CONTROL_CHANNEL, app.stream_init(0, 0))
                print(f">> control 0x1D stream_init ({n} fragment(s))")
            except Exception as e:
                print("stream_init failed:", e)
                return
            if not CAPTURE_CMD:
                await self._replay_static()
                return
            await self._stream_capture()
            if not self._capture_restart or self.session is None:
                return
            self._capture_restart = False
            old = self.capture_proc
            if old is not None:  # let the old portal session close before opening one
                try:
                    await asyncio.wait_for(old.wait(), 3.0)
                except TimeoutError:
                    old.kill()
            print(">> capture restarting (desktop resolution changed)")

    async def _audio_loop(self):
        """Stream Opus packets from tools/capture_audio.py on app channel 2.

        Record: [u32 le length][one Opus packet], 20 ms of 48 kHz stereo each. Each one
        becomes a message with the 15-byte audio header (parsec4linux/audio.py), plus
        nothing else: see audio.py on why the audio heartbeat is not sent.
        """
        await asyncio.sleep(0.2)  # same settling delay as video
        proc = await asyncio.create_subprocess_exec(
            *AUDIO_CMD, stdout=asyncio.subprocess.PIPE, stderr=None)
        print(">> audio started:", " ".join(AUDIO_CMD))
        try:
            while True:
                (size,) = struct.unpack("<I", await proc.stdout.readexactly(4))
                if size > 1 << 20:
                    print("audio: implausible packet size", size)
                    return
                packet = await proc.stdout.readexactly(size)
                # Gaps between packets as WE see them: a capture that is fine (no
                # "capture lost" line) but arrives here late means this process was
                # starved, not the capture.
                now = time.monotonic()
                if self._audio_last is not None:
                    gap = (now - self._audio_last) * 1000
                    self.audio_max_gap = max(self.audio_max_gap, gap)
                    if gap > 60:
                        self.audio_late += 1
                self._audio_last = now
                if self.session is None or self.peer is None:
                    continue
                self._send_message(paudio.CHANNEL, paudio.build_message(packet))
                self.audio_packets += 1
        except asyncio.IncompleteReadError:
            print("audio ended")
        except Exception as e:
            print("audio capture/send failed:", e)
        finally:
            if proc.returncode is None:
                proc.terminate()

    def _restart_capture(self):
        """End the running capture so _video_loop starts a fresh one.

        The capture pins its encode size at startup, so a new desktop resolution needs
        a new capture to be encoded natively rather than scaled to the old size. The
        portal's restore token is reused, so this does not prompt again.
        """
        proc = self.capture_proc
        if proc is None or proc.returncode is not None:
            return
        self._capture_restart = True
        proc.terminate()

    async def _replay_static(self):
        interval = 1.0 / max(1, VIDEO_FPS)
        frame_no = 0
        while True:
            await asyncio.sleep(interval)
            if self.session is None or self.peer is None:
                continue
            try:
                self._send_frame(frame_no, VIDEO_FRAME)
                frame_no += 1
            except Exception as e:
                print("video send failed:", e)
                return

    async def _stream_capture(self):
        """Read capture records and forward them.

        Record: [u32 le length][u16 le width][u16 le height][u32 le encode_us][payload].
        The dimensions ride along with every frame so the video header can carry the
        true encode size, and so a mid-stream resolution change needs no renegotiation
        -- which is why Parsec puts width/height in each frame header in the first
        place. encode_us is that frame's capture -> encoded latency (0 = unknown),
        forwarded to the client in a 0x22 so its HUD can show it.
        """
        proc = await asyncio.create_subprocess_exec(
            *CAPTURE_CMD, stdout=asyncio.subprocess.PIPE, stderr=None)
        self.capture_proc = proc
        print(">> capture started:", " ".join(CAPTURE_CMD))
        frame_no = 0
        last_frame_at = None
        try:
            while True:
                hdr = await proc.stdout.readexactly(12)
                size, cap_w, cap_h, enc_us = struct.unpack("<IHHI", hdr)
                if size > 8 << 20:
                    print("capture: implausible frame size", size)
                    return
                if cap_w and cap_h and (cap_w, cap_h) != (self.cap_size or ()):
                    if self.cap_size:
                        print(f">> capture size changed "
                              f"{self.cap_size[0]}x{self.cap_size[1]} -> "
                              f"{cap_w}x{cap_h}; the header follows it per frame")
                    else:
                        print(f">> capture reports {cap_w}x{cap_h}")
                    self.cap_size = (cap_w, cap_h)
                    # The client reports absolute motion in the size we advertise in
                    # the frame header, so the injector's scaling has to follow it.
                    self._inject_send({"t": "space", "w": cap_w, "h": cap_h})
                frame = await proc.stdout.readexactly(size)
                if self.session is None or self.peer is None:
                    continue  # between attempts; drop rather than queue stale frames
                now = time.monotonic()
                interval = 0.0 if last_frame_at is None else (now - last_frame_at) * 1000
                last_frame_at = now
                self.frame_interval_ms = interval
                if self._send_frame(frame_no, frame):
                    self._send_frame_stats(enc_us / 1000.0 if enc_us else None, interval)
                frame_no += 1
        except asyncio.IncompleteReadError:
            print("capture ended")
        except Exception as e:
            print("capture/send failed:", e)
        finally:
            if proc.returncode is None:
                proc.terminate()

    def _handle_app_message(self, payload):
        """Route a reassembled app message. Input goes to the uinput child."""
        if len(payload) < app.HEADER_LEN:
            return
        if payload[app.HEADER_LEN - 1] == app.TYPE_CONFIG:
            self._on_client_config(payload)
            return
        ev = pinput.decode(payload)
        if ev is None:
            return  # control message; logged by the caller
        self.input_seen[ev["kind"]] = self.input_seen.get(ev["kind"], 0) + 1
        if not ev["confirmed"]:
            # A layout we inferred rather than measured. Print it once per type so a
            # wrong guess is visible in the log instead of silently mis-injecting.
            if ev["kind"] not in self.input_inferred:
                self.input_inferred.add(ev["kind"])
                print(f"   !! {ev['kind']} (INFERRED layout) fields={ev['raw']} "
                      f"decoded={({k: v for k, v in ev.items() if k not in ('raw', 'kind', 'type', 'confirmed')})}")
        if self.inject is None:
            return
        line = None
        if ev["type"] == pinput.TYPE_MOUSE_MOTION:
            line = {"t": "motion", "x": ev["x"], "y": ev["y"], "rel": ev["relative"]}
            self._note_motion(ev["x"], ev["y"])
        elif ev["type"] == pinput.TYPE_MOUSE_BUTTON:
            line = {"t": "button", "b": ev["button"], "p": ev["pressed"]}
        elif ev["type"] == pinput.TYPE_MOUSE_WHEEL:
            line = {"t": "wheel", "x": ev["x"], "y": ev["y"]}
        elif ev["type"] == pinput.TYPE_KEYBOARD:
            line = {"t": "key", "code": ev["code"], "p": ev["pressed"]}
        if line is None:
            return
        self._inject_send(line)

    def _on_client_config(self, payload):
        """0x0b: the client's config JSON, sent on connect and again when it changes.

        Parsed host-side by 0x1800A5400. `resolutionX`/`resolutionY` is what the client
        wants the host desktop to be; 0 (and 0xFFFF) mean "leave it", which on Windows
        restores the original mode. `resolutions` repeats it per stream for multiple
        monitors; only stream 0 exists here.
        """
        hdr = app.parse(payload)
        body = payload[app.HEADER_LEN:app.HEADER_LEN + hdr["field0"]] or \
            payload[app.HEADER_LEN:]
        try:
            cfg = json.loads(body.rstrip(b"\0").decode())
        except ValueError as e:
            print(f"   0x0b config not JSON ({e}): {body[:80]!r}")
            return
        w, h = int(cfg.get("resolutionX") or 0), int(cfg.get("resolutionY") or 0)
        if not (w and h) and cfg.get("resolutions"):
            first = cfg["resolutions"][0]
            w, h = int(first.get("width") or 0), int(first.get("height") or 0)
        fps = int(cfg.get("refreshRate") or 60)
        print(f"<< client config: resolution {w}x{h} @ {fps} "
              f"(raw {json.dumps({k: cfg.get(k) for k in ('resolutionX', 'resolutionY', 'refreshRate', 'resolutions')})})")
        keep = not (w and h) or 0xFFFF in (w, h)
        want = None if keep else (w, h)
        if want == self.res_requested:
            return
        self.res_requested = want
        if RESOLUTION_CMD is None:
            print("   (no --resolution-cmd: request logged, desktop left alone)")
            return
        if keep:
            if self.res_applied:
                asyncio.get_running_loop().create_task(self._restore_resolution())
            return
        asyncio.get_running_loop().create_task(self._set_resolution(w, h, fps))

    async def _run_display_cmd(self, *args):
        proc = await asyncio.create_subprocess_exec(
            *RESOLUTION_CMD, *args, stdout=asyncio.subprocess.PIPE)
        out, _ = await proc.communicate()
        try:
            return json.loads(out.decode().strip().splitlines()[-1])
        except (ValueError, IndexError):
            return {"ok": False, "error": f"no JSON from display helper: {out[:200]!r}"}

    async def _set_resolution(self, w, h, fps):
        res = await self._run_display_cmd("set", f"{w}x{h}", "--fps", str(fps))
        if not res.get("ok"):
            print(f"!! resolution {w}x{h} not applied: {res.get('error')}")
            return
        self.res_applied = True
        print(f">> desktop resolution: asked {w}x{h}, set {res['mode']}"
              f"{'' if res.get('changed') else ' (already current)'}")
        if res.get("changed"):
            await asyncio.sleep(0.5)  # let the compositor settle before re-capturing
            self._restart_capture()

    async def _restore_resolution(self):
        res = await self._run_display_cmd("restore")
        if not res.get("ok"):
            print(f"!! resolution restore failed: {res.get('error')}")
            return
        self.res_applied = False
        if res.get("changed"):
            print(f">> desktop resolution restored to {res['mode']}")
            self._restart_capture()

    async def _watchdog(self):
        """Notice a client that has gone, and give the desktop back.

        Ends the stream (no more encoding for nobody) and restores the resolution if
        the client had changed it.
        """
        while True:
            await asyncio.sleep(1.0)
            if self.session is None or self.last_rx is None:
                continue
            silent = time.monotonic() - self.last_rx
            if silent < CLIENT_TIMEOUT:
                continue
            print(f"!! client silent for {silent:.1f} s: treating it as disconnected")
            self.reset_session()
            if self.res_applied and RESOLUTION_CMD is not None:
                await self._restore_resolution()

    def _inject_send(self, line):
        """Write one JSON event to the injector child, if one is running."""
        if self.inject is None:
            return
        try:
            self.inject.stdin.write((json.dumps(line) + "\n").encode())
        except Exception as e:
            print(f"   inject write failed: {e}")
            self.inject = None

    def _note_motion(self, x, y):
        """Track the observed coordinate extent.

        Absolute motion arrives in the size we advertise in the video header, which
        this extent is what established: advertising 1914x884 produced y 0..884,
        where an earlier session advertising 1920x1080 produced y 0..1077. Keep
        logging it -- it is the check that the space still tracks the header.
        """
        b = self.motion_extent
        b[0], b[1] = min(b[0], x), max(b[1], x)
        b[2], b[3] = min(b[2], y), max(b[3], y)

    async def _start_inject(self):
        if not INJECT_CMD:
            return
        try:
            self.inject = await asyncio.create_subprocess_exec(
                *INJECT_CMD, stdin=asyncio.subprocess.PIPE, stderr=None)
            print(">> inject started:", " ".join(INJECT_CMD))
            # The capture may already have reported its size; the injector starts
            # with a guess, so hand it the real one rather than waiting for a change.
            if self.cap_size:
                self._inject_send({"t": "space",
                                   "w": self.cap_size[0], "h": self.cap_size[1]})
        except Exception as e:
            print(f"!! inject failed to start ({e}); input will be logged only")
            self.inject = None

    def _handle_bud(self, data, addr):
        self._ensure_session(addr)
        if self.session is None:
            print(f"BUD << {len(data)} B but no attempt creds yet, ignored")
            return
        try:
            pt = self.session.decrypt(data)
        except Exception as e:
            print(f"BUD << decrypt failed ({e}); wrong key/direction?")
            return
        self.last_rx = time.monotonic()
        msg_type, channel = pt[1], pt[2]
        seq = int.from_bytes(pt[3:7], "big")
        if feedback.is_ack_packet(pt):
            # Both ack forms carry the same 19-slot vector: 0x08 on a timer, 0x02
            # immediately for a specific channel/seq. Honouring 0x02 is what lets the
            # send window drain promptly -- a real client sends thousands of them.
            peer_acks = self.acks.apply_feedback(pt)
            self._release_acked(time.monotonic())
            if msg_type == feedback.TYPE_MESSAGE_ACK:
                self.imm_acks += 1
                if self.imm_acks <= 3 or self.imm_acks % 2000 == 0:
                    print(f"BUD << 0x02 immediate ack #{self.imm_acks} "
                          f"(ch={channel} seq={seq}), peer acked {peer_acks[:4]}..., "
                          f"regressions={self.acks.regressions}")
            else:
                self.timer_acks += 1
            return
        self.acks.note_received(channel, seq)
        if msg_type in (reliable.FLAG_LAST, reliable.FLAG_MORE):
            done = self.reassembler.feed(pt)
            kind = "last" if msg_type == reliable.FLAG_LAST else "more"
            print(f"BUD << reliable ch={channel} seq={seq} ({kind}) pt={len(pt)}")
            if done:
                # Immediate 0x02 naming this fragment, as the DLL's receive path does on
                # message completion. It is the client's only RTT sample source; without
                # it the client's HUD "Network" sits at its 100 ms initial value forever.
                self.transport.sendto(self.session.encrypt(
                    feedback.build_message_ack(self.acks.received, channel, seq),
                    channel=0), self.peer)
                self.msg_acks_sent += 1
                ch, dseq, payload = done
                print(f"   -> message complete ch={ch} seq={dseq} len={len(payload)}: "
                      f"{payload[:48].hex()}")
                self._handle_app_message(payload)
        else:
            print(f"BUD << type={msg_type:#04x} ch={channel} seq={seq} pt={len(pt)}")

    def datagram_received(self, data, addr):
        with open(UDP_LOG, "a") as f:
            f.write(f"{addr[0]}:{addr[1]} {data.hex()}\n")
        if bud.is_bud(data):
            self._handle_bud(data, addr)
            return
        if not stun.is_stun(data):
            print(f"UDP << {addr[0]}:{addr[1]} non-STUN len={len(data)} {data[:48].hex()}")
            return
        mtype, txid, attrs = stun.parse(data)
        if not ATTEMPT:
            print(f"STUN << {addr} type={mtype:#06x} (no attempt yet, ignored)")
            return
        local, remote = ATTEMPT["local"], ATTEMPT["remote"]
        if mtype == stun.BINDING_REQUEST:
            ok = stun.check_integrity(data, local["ice_pwd"])
            nominated = stun.USE_CANDIDATE in attrs
            print(f"STUN << check from {addr[0]}:{addr[1]} integrity={ok} use_candidate={nominated}")
            if not ok:
                return
            self.transport.sendto(stun.success_response(txid, addr[0], addr[1], local["ice_pwd"]), addr)
            if addr not in self.checked:  # triggered check back to the client
                self.checked.add(addr)
                _, req = stun.binding_request(local["ice_ufrag"], remote["ice_ufrag"],
                                              remote["ice_pwd"], ATTEMPT["tie"])
                self.transport.sendto(req, addr)
                print(f"STUN >> success + triggered check to {addr[0]}:{addr[1]}")
        elif mtype == stun.BINDING_SUCCESS:
            ok = stun.check_integrity(data, remote["ice_pwd"])
            print(f"STUN << success from {addr[0]}:{addr[1]} integrity={ok}")
        else:
            print(f"STUN << {addr} type={mtype:#06x}")


async def handle_offer(ws, msg, args):
    p = msg["payload"]
    attempt, peer = p["attempt_id"], p["from"]
    print(f"offer from {p['user']['name']} mode={p['data'].get('mode')} -> answering")
    creds = bud_creds()
    ATTEMPT.update(local=creds, remote=p["data"]["creds"], tie=secrets.token_bytes(8))
    if UDP is not None:
        UDP.reset_session()  # new attempt => new keys; discard the old session
    with open(UDP_LOG, "a") as f:  # keep both sides' creds next to the packets they protect
        f.write("# offer_creds " + json.dumps(p["data"]["creds"]) + "\n")
        f.write("# answer_creds " + json.dumps(creds) + "\n")
    await ws.send(json.dumps(envelope("answer", peer,
                                      {"attempt_id": attempt, "approved": True},
                                      {"creds": creds})))
    cand = {"ip": lan_ip(), "port": args.port, "lan": True, "from_stun": False, "sync": False}
    await ws.send(json.dumps(envelope("candex", peer, {"attempt_id": attempt}, cand)))
    print(">> answer + candex", cand)


async def ws_session(args):
    resp = json.load(open(SESSION))
    sid = find_key(resp, "session_id") or find_key(resp, "id")
    if not sid:
        print("no session id in", SESSION)
        return 1
    url = f"{WS}/?session_id={sid}&role=host&version=1&build={BUILD}&sdk_version={SDK_VERSION}"
    for path in (RAW_LOG, UDP_LOG):
        if not os.path.exists(path):
            save_private(path, "")
    if args.answer:
        loop = asyncio.get_running_loop()
        await loop.create_datagram_endpoint(UdpLogger, local_addr=("0.0.0.0", args.port))
        print("UDP listening on", args.port)
    print("connecting", url.replace(sid, "<sid>"))
    try:
        async with websockets.connect(url, additional_headers=headers(args.platform, sid),
                                      ssl=ssl.create_default_context(), open_timeout=10) as ws:
            update = conn_update(args)
            await ws.send(json.dumps(update))
            print(">> conn_update", json.dumps(update["payload"]).replace(device_id(), "<dev>"))
            print("connected; listening", args.seconds, "s")
            try:
                async with asyncio.timeout(args.seconds):
                    async for msg in ws:
                        with open(RAW_LOG, "a") as f:  # unredacted, for analysis; 600 via save_private
                            f.write(msg if isinstance(msg, str) else msg.hex())
                            f.write("\n")
                        try:
                            parsed = json.loads(msg)
                        except ValueError:
                            print("<< (raw)", msg[:300])
                            continue
                        print("<<", parsed.get("action"), json.dumps(redact(parsed.get("payload")))[:400])
                        if args.answer and parsed.get("action") == "offer_relay":
                            await handle_offer(ws, parsed, args)
            except TimeoutError:
                pass
            finally:
                # Never leave the desktop at a client's resolution after we exit.
                if UDP is not None and UDP.res_applied and RESOLUTION_CMD is not None:
                    UDP.reset_session()
                    await UDP._restore_resolution()
            print("done, close code", ws.close_code)
    except websockets.InvalidStatus as e:
        print("upgrade rejected: HTTP", e.response.status_code, e.response.body[:300])
        return 1
    return 0


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("auth")
    a.add_argument("--tfa")
    a.add_argument("--platform", default="linux")
    w = sub.add_parser("ws")
    w.add_argument("--platform", default="linux")
    w.add_argument("--seconds", type=int, default=60)
    w.add_argument("--name", default=platform.node() or "linux-host")
    w.add_argument("--answer", action="store_true", help="approve offers and log client UDP")
    w.add_argument("--port", type=int, default=8000, help="UDP port advertised in candex")
    w.add_argument("--tx-key", choices=("answer", "offer"), default="answer",
                   help="aes256 used to ENCRYPT host->client (default: answer)")
    w.add_argument("--video", help="Annex-B H.264 file to send repeatedly on channel 1")
    w.add_argument("--capture", help="command emitting [u32le len][frame] records "
                                     "(see tools/capture_h264.py); overrides --video")
    w.add_argument("--inject", help="command reading JSON input events on stdin "
                                    "(see tools/inject_input.py)")
    w.add_argument("--audio",
                   help="command writing Opus packets as [u32 le len][packet] records "
                        "(see tools/capture_audio.py); without it no audio is sent")
    w.add_argument("--resolution-cmd",
                   help="honour the resolution a client asks for, via this command "
                        "(see tools/display_mode.py); without it requests are only "
                        "logged")
    w.add_argument("--fps", type=int, default=30)
    w.add_argument("--size", default="1920x1080", help="WxH advertised in the video header")
    w.add_argument("--big-endian-header", action="store_true",
                   help="byte-swap the 10-byte video header (see video.py caveat)")
    w.add_argument("--ts", choices=("ms", "frames"), default="ms",
                   help="video header timestamp units (default ms)")
    w.add_argument("--kind-p", type=lambda s: int(s, 0), default=0,
                   help="video header 'kind' for non-IDR frames (default 0)")
    w.add_argument("--kind", type=lambda s: int(s, 0), default=3,
                   help="video header 'kind' byte (+8); DLL forces 3 on the first frame")
    w.add_argument("--flags", type=lambda s: int(s, 0), default=0x10,
                   help="video header flags byte (+9); 0x10 = host session active")
    h = sub.add_parser("hosts")
    h.add_argument("--platform", default="linux")
    args = p.parse_args()
    if getattr(args, "tx_key", None):
        global TX_KEY, VIDEO_FRAME, VIDEO_FPS, VIDEO_W, VIDEO_H
        global VIDEO_KIND, VIDEO_KIND_P, VIDEO_FLAGS, CAPTURE_CMD, VIDEO_TS
        global INJECT_CMD, RESOLUTION_CMD, AUDIO_CMD
        TX_KEY = args.tx_key
        if getattr(args, "audio", None):
            AUDIO_CMD = shlex.split(args.audio)
        if getattr(args, "resolution_cmd", None):
            RESOLUTION_CMD = shlex.split(args.resolution_cmd)
        VIDEO_FPS = args.fps
        VIDEO_W, VIDEO_H = (int(x) for x in args.size.split("x"))
        video.BIG_ENDIAN_HEADER = args.big_endian_header
        VIDEO_KIND, VIDEO_FLAGS = args.kind, args.flags
        VIDEO_KIND_P = args.kind_p
        VIDEO_TS = args.ts
        if args.capture:
            CAPTURE_CMD = shlex.split(args.capture)
        if getattr(args, "inject", None):
            INJECT_CMD = shlex.split(args.inject)
        if args.video:
            with open(args.video, "rb") as f:
                VIDEO_FRAME = f.read()
            print(f"video: {len(VIDEO_FRAME)} B from {args.video}, "
                  f"{VIDEO_W}x{VIDEO_H} @ {VIDEO_FPS} fps, "
                  f"header={'be' if video.BIG_ENDIAN_HEADER else 'le'}")
    if args.cmd == "auth":
        return cmd_auth(args)
    if args.cmd == "hosts":
        return cmd_hosts(args)
    return asyncio.run(ws_session(args))


if __name__ == "__main__":
    sys.exit(main())
