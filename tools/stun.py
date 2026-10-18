"""Minimal ICE/STUN (RFC 5389 / 8445) short-term-credential messages, as used by Parsec P2P.

Verified against a live Parsec 150-105c client: checks carry USERNAME "<remote ufrag>:<local ufrag>",
GOOG-NETWORK-INFO (0xC057), ICE-CONTROLLING, PRIORITY, MESSAGE-INTEGRITY (HMAC-SHA1 keyed with the
receiver's ice_pwd) and FINGERPRINT.
"""
import hmac
import hashlib
import ipaddress
import os
import struct
import zlib

MAGIC = 0x2112A442
BINDING_REQUEST = 0x0001
BINDING_SUCCESS = 0x0101

USERNAME = 0x0006
MESSAGE_INTEGRITY = 0x0008
XOR_MAPPED_ADDRESS = 0x0020
PRIORITY = 0x0024
USE_CANDIDATE = 0x0025
FINGERPRINT = 0x8028
ICE_CONTROLLED = 0x8029
ICE_CONTROLLING = 0x802A
GOOG_NETWORK_INFO = 0xC057


def is_stun(data):
    return len(data) >= 20 and data[0] < 2 and struct.unpack_from("!I", data, 4)[0] == MAGIC


def parse(data):
    mtype, length = struct.unpack_from("!HH", data, 0)
    txid = data[8:20]
    attrs, i = {}, 20
    while i + 4 <= 20 + length:
        t, n = struct.unpack_from("!HH", data, i)
        attrs[t] = data[i + 4:i + 4 + n]
        i += 4 + n + (-n % 4)
    return mtype, txid, attrs


def check_integrity(data, key):
    """Validate MESSAGE-INTEGRITY of a received message with `key` (the local ice_pwd)."""
    i = 20
    while i + 4 <= len(data):
        t, n = struct.unpack_from("!HH", data, i)
        if t == MESSAGE_INTEGRITY:
            hdr = bytearray(data[:i])
            struct.pack_into("!H", hdr, 2, i + 24 - 20)
            return hmac.compare_digest(hmac.new(key.encode(), bytes(hdr), hashlib.sha1).digest(),
                                       data[i + 4:i + 24])
        i += 4 + n + (-n % 4)
    return False


def _attr(t, value):
    return struct.pack("!HH", t, len(value)) + value + b"\0" * (-len(value) % 4)


def _xor_address(ip, port, txid):
    addr = ipaddress.ip_address(ip)
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    xport = port ^ (MAGIC >> 16)
    if addr.version == 4:
        xip = int(addr) ^ MAGIC
        return struct.pack("!BBHI", 0, 1, xport, xip)
    mask = struct.pack("!I", MAGIC) + txid
    xip = bytes(a ^ b for a, b in zip(addr.packed, mask))
    return struct.pack("!BBH", 0, 2, xport) + xip


def build(mtype, txid, attrs, key):
    """Serialize with MESSAGE-INTEGRITY (keyed with `key`) and FINGERPRINT appended."""
    body = b"".join(_attr(t, v) for t, v in attrs)
    hdr = struct.pack("!HHI", mtype, len(body) + 24, MAGIC) + txid
    mi = hmac.new(key.encode(), hdr + body, hashlib.sha1).digest()
    body += _attr(MESSAGE_INTEGRITY, mi)
    hdr = struct.pack("!HHI", mtype, len(body) + 8, MAGIC) + txid
    crc = (zlib.crc32(hdr + body) ^ 0x5354554E) & 0xFFFFFFFF
    body += _attr(FINGERPRINT, struct.pack("!I", crc))
    return hdr + body


def success_response(txid, src_ip, src_port, local_pwd):
    """Binding Success for a check we received; integrity keyed with our own ice_pwd."""
    return build(BINDING_SUCCESS, txid, [(XOR_MAPPED_ADDRESS, _xor_address(src_ip, src_port, txid))],
                 local_pwd)


def binding_request(local_ufrag, remote_ufrag, remote_pwd, tie_breaker,
                    priority=0x6E001EFF, controlling=False, use_candidate=False):
    """A connectivity check towards the remote candidate.

    `controlling=False` is the host/answerer side (ICE-CONTROLLED); the client/offerer
    is ICE-CONTROLLING and is the one that may nominate with USE-CANDIDATE.
    """
    txid = os.urandom(12)
    attrs = [
        (USERNAME, f"{remote_ufrag}:{local_ufrag}".encode()),
        (ICE_CONTROLLING if controlling else ICE_CONTROLLED, tie_breaker),
        (PRIORITY, struct.pack("!I", priority)),
    ]
    if use_candidate:
        attrs.append((USE_CANDIDATE, b""))
    return txid, build(BINDING_REQUEST, txid, attrs, remote_pwd)
