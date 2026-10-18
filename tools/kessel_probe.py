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
from parsec4linux import app, bud, feedback, reliable, video  # noqa: E402

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

# Retransmission (DLL 0x18003C380). We have no RTT measurement yet, so assume a LAN-ish
# value; the RTO floor of 50 ms dominates anyway.
# The peer's feedback (its ack) only arrives every ~200 ms under load, so an 80 ms RTO
# resends everything before its ack can physically arrive. Keep the RTO above that.
RTT_MS = 120.0
MAX_RETX = 10
# Congestion window: the DLL stops emitting at >= 100 unacked (0x18003C380 `cmp ebp, 64h`).
CWND = 100
# Resend only the oldest few per pass. Cumulative acks mean one hole makes everything
# after it look unacked; blasting all of them is a self-inflicted storm.
RETX_PER_PASS = 4

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
        self.peer = None
        self._msg_seq = {}  # app channel -> next message sequence number
        self.unacked = collections.defaultdict(dict)  # channel -> {seq: (frame, sent, retx)}
        self.retx_total = 0
        self.dropped = 0
        self._t0 = None

    def reset_session(self):
        """Drop the session so the next datagram rebuilds it from the new attempt's creds.

        Each reconnect carries fresh aes256/ice creds, so a session pinned to the old
        attempt can neither decrypt the new client nor be decrypted by it.
        """
        for task in (self.feedback_task, self.video_task):
            if task is not None:
                task.cancel()
        self.feedback_task = self.video_task = None
        self.session = None
        self.peer = None
        self.checked = set()
        self._msg_seq = {}
        self.unacked = collections.defaultdict(dict)
        self.retx_total = 0
        self.dropped = 0
        self._t0 = None
        self.acks = feedback.AckTracker()
        self.reassembler = reliable.Reassembler()
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
        self.peer = addr
        self.feedback_task = asyncio.get_running_loop().create_task(self._feedback_loop())
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

    def _retransmit_due(self, now):
        """Resend unacked fragments past their RTO, mirroring DLL 0x18003C380.

        rto = clamp(2 * (retx + 1) * rtt, 50 ms, 1000 ms), resend when elapsed > rto + 30 ms.
        Without this a single lost datagram wedges the client's reader until the next
        IDR, which is the stutter we saw.
        """
        for channel, pending in self.unacked.items():
            acked = self.acks.peer_ack[channel] if channel < feedback.NUM_CHANNELS else 0
            for seq in [s for s in pending if s <= acked]:
                del pending[seq]  # cumulative ack covers it
            sent_this_pass = 0
            for seq, rec in sorted(pending.items()):
                if sent_this_pass >= RETX_PER_PASS:
                    break
                frame, last_sent, retx = rec
                rto = min(1000.0, 2.0 * (retx + 1) * RTT_MS)
                rto = max(250.0, rto) + 30.0
                if (now - last_sent) * 1000.0 <= rto:
                    continue
                if retx >= MAX_RETX:
                    del pending[seq]
                    continue
                bud_channel = channel + reliable.CHANNEL_INDEX_OFFSET
                self.transport.sendto(self.session.encrypt(frame, channel=bud_channel),
                                      self.peer)
                pending[seq] = (frame, now, retx + 1)
                self.retx_total += 1
                sent_this_pass += 1

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
        if len(self.unacked[video.PRIMARY_CHANNEL]) >= CWND:
            self.dropped += 1
            return
        key = video.is_keyframe(frame)
        if frame_no == 0:
            flags = VIDEO_FLAGS_FIRST
        elif key:
            flags = VIDEO_FLAGS_KEY
        else:
            flags = VIDEO_FLAGS_DELTA
        hdr = video.build_raw_header(self._timestamp(frame_no), VIDEO_W, VIDEO_H,
                                     VIDEO_KIND if key else VIDEO_KIND_P, flags)
        payload = hdr + frame
        n = self._send_message(video.PRIMARY_CHANNEL, payload)
        if frame_no % max(1, VIDEO_FPS) == 0:
            pend = sum(len(v) for v in self.unacked.values())
            print(f">> video frame {frame_no} ({len(payload)} B, {n} fragments, "
                  f"retx={self.retx_total}, unacked={pend}, dropped={self.dropped}, "
                  f"{'IDR' if key else 'P'})")

    async def _video_loop(self):
        """Send video on channel 1, after a 0x1D stream-init on channel 0.

        Either replays one pre-encoded frame (--video, good for isolating protocol
        bugs) or streams live frames from tools/capture_h264.py (--capture).
        """
        await asyncio.sleep(0.2)  # let the client finish its own init burst
        try:
            n = self._send_message(app.CONTROL_CHANNEL, app.stream_init(0, 0))
            print(f">> control 0x1D stream_init ({n} fragment(s))")
        except Exception as e:
            print("stream_init failed:", e)
            return
        if CAPTURE_CMD:
            await self._stream_capture()
        else:
            await self._replay_static()

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
        """Read [u32 le length][frame] records from capture_h264.py and forward them."""
        proc = await asyncio.create_subprocess_exec(
            *CAPTURE_CMD, stdout=asyncio.subprocess.PIPE, stderr=None)
        print(">> capture started:", " ".join(CAPTURE_CMD))
        frame_no = 0
        try:
            while True:
                hdr = await proc.stdout.readexactly(4)
                size = struct.unpack("<I", hdr)[0]
                if size > 8 << 20:
                    print("capture: implausible frame size", size)
                    return
                frame = await proc.stdout.readexactly(size)
                if self.session is None or self.peer is None:
                    continue  # between attempts; drop rather than queue stale frames
                self._send_frame(frame_no, frame)
                frame_no += 1
        except asyncio.IncompleteReadError:
            print("capture ended")
        except Exception as e:
            print("capture/send failed:", e)
        finally:
            if proc.returncode is None:
                proc.terminate()

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
        msg_type, channel = pt[1], pt[2]
        seq = int.from_bytes(pt[3:7], "big")
        if msg_type == feedback.TYPE_FEEDBACK:
            peer_acks = self.acks.apply_feedback(pt)
            print(f"BUD << feedback, peer acked {peer_acks[:4]}...")
            return
        self.acks.note_received(channel, seq)
        if msg_type in (reliable.FLAG_LAST, reliable.FLAG_MORE):
            done = self.reassembler.feed(pt)
            kind = "last" if msg_type == reliable.FLAG_LAST else "more"
            print(f"BUD << reliable ch={channel} seq={seq} ({kind}) pt={len(pt)}")
            if done:
                ch, dseq, payload = done
                print(f"   -> message complete ch={ch} seq={dseq} len={len(payload)}: "
                      f"{payload[:48].hex()}")
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
        TX_KEY = args.tx_key
        VIDEO_FPS = args.fps
        VIDEO_W, VIDEO_H = (int(x) for x in args.size.split("x"))
        video.BIG_ENDIAN_HEADER = args.big_endian_header
        VIDEO_KIND, VIDEO_FLAGS = args.kind, args.flags
        VIDEO_KIND_P = args.kind_p
        VIDEO_TS = args.ts
        if args.capture:
            CAPTURE_CMD = shlex.split(args.capture)
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
