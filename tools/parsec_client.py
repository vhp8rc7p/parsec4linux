#!/usr/bin/env python3
"""Connect to a REAL Parsec host as a client and dump what it sends, decrypted.

Why this exists: we reversed `proto_video_write`'s 10-byte header, but its `kind` and
`flags` values come from the encoder backend at runtime, so they cannot be read out of
the static binary. Guessing them did not work. This gets ground truth instead — the
host generates the BUD session key and hands it to us in its `answer`, so as a client
we can decrypt every byte a real Windows host sends and read the actual header values,
the control-message sequence, the timestamp units and the fragmentation.

Usage:
  parsec_client.py --host-peer-id <peer_id> [--port 9000] [--seconds 60]
  parsec_client.py --host-name CLEVO

Dumps to stdout plus a raw log at ~/.config/parsec4linux/client_rx.log
"""
import argparse
import asyncio
import collections
import json
import os
import secrets
import socket
import ssl
import sys
import urllib.request

import websockets

import stun
import kessel_probe as kp

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))
from parsec4linux import app, bud, feedback, reliable, video  # noqa: E402

RX_LOG = os.path.join(kp.CFG, "client_rx.log")

# The exact config a real 150-105c client sent us (from re/NOTES.md), so the host
# configures its encoder the same way it would for a genuine client.
CLIENT_CONFIG = {
    "mediaContainer": 0, "_max_h": 8192, "resolutionX": 1920, "channels": 2,
    "resolutionY": 1080, "_VideoProtocolVersion": 1, "_cache_cursor": True,
    "_max_w": 8192, "refreshRate": 60, "rawAudio": False, "_version": 1,
    "channelMask": 3, "resolutions": [{"height": 1080, "width": 1920}], "_flags": 9,
}


def attempt_id():
    """Six 8-hex-digit groups, matching the ids real clients use."""
    return "-".join(secrets.token_hex(4) for _ in range(6))


def find_host(name, platform):
    sid = kp.find_key(json.load(open(kp.SESSION)), "session_id")
    req = urllib.request.Request(kp.API + "/v2/hosts?mode=desktop",
                                 headers=kp.headers(platform, sid))
    with urllib.request.urlopen(req, timeout=15) as r:
        hosts = json.load(r)["data"]
    for h in hosts:
        if h.get("name") == name:
            return h["peer_id"]
    raise SystemExit(f"host {name!r} not found; saw "
                     f"{[h.get('name') for h in hosts]}")


class ClientProto(asyncio.DatagramProtocol):
    """Receives from the host: ICE checks, then BUD. Decrypts and dumps everything."""

    def __init__(self, state):
        self.st = state
        self.acks = feedback.AckTracker()
        self.reasm = reliable.Reassembler()
        self.seen_types = collections.Counter()
        self.frames = 0
        self.feedback_task = None
        self._msg_seq = {}

    def connection_made(self, transport):
        self.transport = transport

    def _start_feedback(self):
        if self.feedback_task is None:
            self.feedback_task = asyncio.get_running_loop().create_task(self._fb_loop())

    async def _fb_loop(self):
        while True:
            await asyncio.sleep(kp.FEEDBACK_INTERVAL)
            if not self.st.get("session") or not self.st.get("peer"):
                continue
            try:
                self.transport.sendto(
                    self.st["session"].encrypt(self.acks.feedback_packet(), channel=0),
                    self.st["peer"])
            except Exception as e:
                print("feedback failed:", e)
                return

    def send_message(self, channel, payload):
        seq = self._msg_seq.get(channel, 0)
        frames = reliable.build_fragments(channel, seq, payload)
        self._msg_seq[channel] = seq + len(frames)
        bud_ch = channel + reliable.CHANNEL_INDEX_OFFSET
        for f in frames:
            self.transport.sendto(self.st["session"].encrypt(f, channel=bud_ch),
                                  self.st["peer"])
        return len(frames)

    def datagram_received(self, data, addr):
        with open(RX_LOG, "a") as f:
            f.write(f"{addr[0]}:{addr[1]} {data.hex()}\n")
        if stun.is_stun(data):
            self._ice(data, addr)
            return
        if not bud.is_bud(data):
            print(f"?? {len(data)} B {data[:16].hex()}")
            return
        sess = self.st.get("session")
        if sess is None:
            return
        try:
            pt = sess.decrypt(data)
        except Exception as e:
            print(f"decrypt failed: {e}")
            return
        self._bud(pt)

    def _ice(self, data, addr):
        mtype, txid, attrs = stun.parse(data)
        local, remote = self.st["local"], self.st["remote"]
        if mtype == stun.BINDING_REQUEST:
            ok = stun.check_integrity(data, local["ice_pwd"])
            self.transport.sendto(
                stun.success_response(txid, addr[0], addr[1], local["ice_pwd"]), addr)
            print(f"STUN << check from {addr[0]}:{addr[1]} integrity={ok} -> success")
            # The host checking us from this address is the strongest evidence of the
            # path it actually uses. Prefer it over whichever candidate merely answered
            # first -- that picked a VirtualBox host-only address the VM cannot route to.
            if ok and self.st.get("peer") != addr:
                print(f"   retargeting peer {self.st.get('peer')} -> {addr}")
                self.st["peer"] = addr
                if not self.st.get("inited"):
                    self.st["inited"] = True
                    self.st["paired"] = True
                    self._start_feedback()
                    try:
                        self._send_init()
                    except Exception as e:
                        print("init send failed:", e)
        elif mtype == stun.BINDING_SUCCESS:
            ok = stun.check_integrity(data, remote["ice_pwd"])
            print(f"STUN << success from {addr[0]}:{addr[1]} integrity={ok}")
            if ok and not self.st.get("paired"):
                self.st["paired"] = True
                self.st["peer"] = addr
                self._start_feedback()
                print(f"ICE candidate usable: {addr[0]}:{addr[1]} "
                      f"(waiting for the host's own check before init)")

    def _send_init(self):
        """Send the client's init handshake.

        Prefers replaying the exact messages a real 150-105c client sent (captured
        when one connected to our own host), because the host clearly needs more than
        the config before it starts streaming. Clipboard messages (type 0x11 with
        field1 == 7) are skipped: they carry the captured machine's clipboard and are
        irrelevant to video.
        """
        if self.st.get("init"):
            for m in self.st["init"]:
                payload = bytes.fromhex(m["hex"])
                h = app.parse(payload)
                if h["type"] == app.TYPE_CLIENT_11 and h["field1"] == 7:
                    continue  # clipboard, skip
                self.send_message(m["channel"], payload)
                print(f">> init type={h['type']:#04x} f0={h['field0']} "
                      f"f1={h['field1']} len={len(h['payload'])}")
            return
        body = json.dumps(CLIENT_CONFIG).encode()
        self.send_message(app.CONTROL_CHANNEL,
                          app.build(app.TYPE_CONFIG, len(body), 0, 0) + body)
        print(f">> client config 0x0b ({len(body)} B)")

    def _bud(self, pt):
        if len(pt) < reliable.HEADER_LEN:
            return
        mtype, channel = pt[1], pt[2]
        seq = int.from_bytes(pt[3:7], "big")
        if mtype == feedback.TYPE_FEEDBACK:
            self.acks.apply_feedback(pt)
            return
        if mtype not in (reliable.FLAG_LAST, reliable.FLAG_MORE):
            print(f"<< unknown type {mtype:#04x} ch={channel} seq={seq}")
            return
        self.acks.note_received(channel, seq)
        try:
            done = self.reasm.feed(pt)
        except Exception as e:
            print(f"reassembly failed ch={channel} seq={seq}: {e}")
            return
        if not done:
            return
        ch, start, payload = done
        if ch == video.PRIMARY_CHANNEL:
            self._dump_video(start, payload)
        else:
            self._dump_control(ch, start, payload)

    def _dump_video(self, seq, payload):
        """THE POINT OF THIS TOOL: real video headers from a real host."""
        self.frames += 1
        h = video.parse_header(payload)
        body = payload[video.HEADER_LEN:]
        nals = sorted(set(video.iter_nal_types(body)))
        key = video.is_keyframe(body)
        if self.frames <= 40 or self.frames % 60 == 0:
            print(f"VIDEO seq={seq:<6} hdr={payload[:video.HEADER_LEN].hex()} "
                  f"ts={h['timestamp']:<10} {h['width']}x{h['height']} "
                  f"kind={h['kind']:#04x} flags={h['flags']:#04x} "
                  f"len={len(body):<6} nals={nals} {'IDR' if key else 'P'}")

    def _dump_control(self, ch, seq, payload):
        try:
            c = app.parse(payload)
        except Exception:
            print(f"CTRL ch={ch} seq={seq} raw={payload[:32].hex()}")
            return
        self.seen_types[c["type"]] += 1
        if self.seen_types[c["type"]] <= 3:
            body = c["payload"]
            txt = ""
            if body[:1] == b"{":
                txt = body[:120].decode("utf-8", "replace")
            print(f"CTRL ch={ch} type={c['type']:#04x} "
                  f"f0={c['field0']} f1={c['field1']} f2={c['field2']} "
                  f"len={len(body)} {txt}")


async def run(args):
    sid = kp.find_key(json.load(open(kp.SESSION)), "session_id")
    if not sid:
        raise SystemExit("no session; run kessel_probe.py auth first")
    peer = args.host_peer_id or find_host(args.host_name, args.platform)
    print("target host peer_id:", peer)

    creds = kp.bud_creds()
    att = attempt_id()
    state = {"local": creds, "remote": None, "session": None, "peer": None,
             "tie": secrets.token_bytes(8), "init": None}
    if args.init and os.path.exists(args.init):
        state["init"] = json.load(open(args.init))
        print(f"replaying {len(state['init'])} captured init messages from {args.init}")
    if not os.path.exists(RX_LOG):
        kp.save_private(RX_LOG, "")

    loop = asyncio.get_running_loop()
    _, proto = await loop.create_datagram_endpoint(lambda: ClientProto(state),
                                                  local_addr=("0.0.0.0", args.port))
    print("UDP listening on", args.port)

    url = (f"{kp.WS}/?session_id={sid}&role=client&version=1&build={kp.BUILD}"
           f"&sdk_version={kp.SDK_VERSION}")
    async with websockets.connect(url, additional_headers=kp.headers(args.platform, sid),
                                  ssl=ssl.create_default_context(),
                                  open_timeout=10) as ws:
        # Schema from the client's own offer builder, DLL 0x1800D3700:
        #   payload: attempt_id, secret, access_link_id   (both empty unless joining
        #            via a password/access link)
        #   data:    ver_data, versions, creds, mode  -- mode is an INTEGER (1), not
        #            the string "desktop"; our host log showed a real client sending
        #            `mode=1`, and a type mismatch here is why our offer was ignored.
        offer = {"version": 1, "action": "offer", "payload": {
            "to": peer, "attempt_id": att,
            "secret": "", "access_link_id": "",
            "data": {"ver_data": 1,
                     "versions": {"p2p": 1, "bud": 1, "init": 1, "video": 1,
                                  "audio": 1, "control": 1},
                     "mode": 1, "creds": creds}}}
        await ws.send(json.dumps(offer))
        print(">> offer sent, attempt", att)

        try:
            async with asyncio.timeout(args.seconds):
                async for raw in ws:
                    msg = json.loads(raw)
                    action, p = msg.get("action"), msg.get("payload") or {}
                    if action == "answer_relay":
                        approved = p.get("approved")
                        host_creds = (p.get("data") or {}).get("creds")
                        print(f"<< answer_relay approved={approved} "
                              f"creds={'yes' if host_creds else 'no'}")
                        if not host_creds:
                            print("   no creds -> cannot decrypt; aborting")
                            return 1
                        state["remote"] = host_creds
                        # The session key is the ANSWER's aes256, generated by the host.
                        state["session"] = bud.Session(tx_aes256=host_creds["aes256"],
                                                       rx_aes256=host_creds["aes256"])
                        with open(RX_LOG, "a") as f:
                            f.write("# host_creds " + json.dumps(host_creds) + "\n")
                            f.write("# our_creds " + json.dumps(creds) + "\n")
                    elif action == "candex_relay":
                        d = p.get("data") or {}
                        ip, port = d.get("ip"), d.get("port")
                        print(f"<< candex_relay {ip}:{port} lan={d.get('lan')}")
                        if ip and port and state["remote"]:
                            # Only (re)target before ICE picks a path. Candidates keep
                            # arriving after pairing, and overwriting `peer` with a
                            # later one sent our acks down an unpaired path, so the
                            # host never saw us alive and never started streaming.
                            if not state.get("paired"):
                                state["peer"] = (ip, port)
                            _, req = stun.binding_request(
                                creds["ice_ufrag"], state["remote"]["ice_ufrag"],
                                state["remote"]["ice_pwd"], state["tie"],
                                controlling=True, use_candidate=True)
                            proto.transport.sendto(req, (ip, port))
                            print(f">> STUN check to {ip}:{port} (controlling)")
                    elif action == "close":
                        print("<< close", p)
                        return 1
                    else:
                        print("<<", action, json.dumps(kp.redact(p))[:200])
        except TimeoutError:
            pass
    print(f"\ndone: {proto.frames} video frames, control types seen "
          f"{ {hex(k): v for k, v in proto.seen_types.items()} }")
    return 0


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host-peer-id")
    p.add_argument("--host-name", default="CLEVO")
    p.add_argument("--platform", default="linux")
    p.add_argument("--port", type=int, default=9000)
    p.add_argument("--seconds", type=int, default=60)
    p.add_argument("--init", default=os.path.expanduser("~/parsec4linux/client_init.json"),
                   help="replay this captured client init sequence (from extract_init)")
    args = p.parse_args()
    return asyncio.run(run(args))


if __name__ == "__main__":
    sys.exit(main())
