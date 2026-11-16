#!/usr/bin/env python3
"""Minimal STUN probe (RFC 5389 Binding Request) — checks that a STUN server answers and which public address it saw.

    python3 stun_probe.py <host> [port]      # exit 0 and prints the XOR-MAPPED-ADDRESS on success

Standard library only (runs on test clients without extra packages).
"""
import os
import socket
import struct
import sys
import zlib

MAGIC = 0x2112A442


def binding_request(txid: bytes) -> bytes:
    """Binding Request as sent by the Tailscale client: Tailscale's STUN server (stund, embedded DERP) ignores any
    request that lacks SOFTWARE="tailnode" followed by a valid FINGERPRINT attribute (net/stun ParseBindingRequest)."""
    software = struct.pack("!HH", 0x8022, 8) + b"tailnode"
    header = struct.pack("!HHI12s", 0x0001, len(software) + 8, MAGIC, txid)
    fingerprint = (zlib.crc32(header + software) & 0xFFFFFFFF) ^ 0x5354554E
    return header + software + struct.pack("!HHI", 0x8028, 4, fingerprint)


def probe(host: str, port: int = 3478, timeout: float = 3.0) -> tuple[str, int]:
    txid = os.urandom(12)
    req = binding_request(txid)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(req, (host, port))
        data, _ = s.recvfrom(2048)
    mtype, mlen, magic, rtx = struct.unpack("!HHI12s", data[:20])
    if mtype != 0x0101 or magic != MAGIC or rtx != txid:
        raise RuntimeError(f"unexpected response type=0x{mtype:04x}")
    pos = 20
    while pos < 20 + mlen:
        atype, alen = struct.unpack("!HH", data[pos:pos + 4])
        val = data[pos + 4:pos + 4 + alen]
        if atype == 0x0020 and val[1] == 0x01:  # XOR-MAPPED-ADDRESS, IPv4
            xport = struct.unpack("!H", val[2:4])[0] ^ (MAGIC >> 16)
            xaddr = struct.unpack("!I", val[4:8])[0] ^ MAGIC
            return socket.inet_ntoa(struct.pack("!I", xaddr)), xport
        pos += 4 + alen + (-alen % 4)
    raise RuntimeError("no XOR-MAPPED-ADDRESS in response")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    try:
        ip, port = probe(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 3478)
    except Exception as e:  # noqa: BLE001
        print(f"STUN FAIL: {e}")
        sys.exit(1)
    print(f"STUN OK: server saw {ip}:{port}")
