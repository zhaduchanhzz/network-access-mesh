#!/usr/bin/env python3
"""P5-T03 / V-27 — bắt gói DNS + SNI (+ đích TCP 80/443, UDP 3478) trên một VM lab và gán cho UID của tiến trình.

    python3 capture.py run <giây> <pcap> <out.json>     # tcpdump (sudo -n) + lấy mẫu /proc/net/{tcp,udp} mỗi 0,2 s
    python3 capture.py parse <pcap> <map.json> <out.json>

Node tạm (vnode.sh) chạy dưới user thường, tailscaled của hệ thống chạy root ⇒ cổng nguồn của mỗi luồng được gán UID
nhờ /proc/net/* (cột uid) — tách được lưu lượng của node tạm khỏi nền (tailscaled hệ thống, systemd-resolved, apt…).
Truy vấn DNS qua stub 127.0.0.53 được gán theo socket gửi tới stub. Không lưu payload: chỉ tên truy vấn, SNI, đích.
"""
from __future__ import annotations

import json
import os
import socket
import struct
import subprocess
import sys
import time

FILTER = "udp port 53 or tcp port 53 or tcp port 443 or tcp port 80 or udp port 3478 or udp port 41641"


def sample(path: str) -> dict:
    """{(proto, local_port): uid} từ /proc/net/{tcp,udp}."""
    out = {}
    for proto in ("tcp", "udp"):
        try:
            for ln in open(f"/proc/net/{proto}").read().splitlines()[1:]:
                f = ln.split()
                lport = int(f[1].split(":")[1], 16)
                out[f"{proto}:{lport}"] = int(f[7])
        except OSError:
            pass
    return out


def run(secs: float, pcap: str, outj: str) -> None:
    p = subprocess.Popen(["sudo", "-n", "tcpdump", "-i", "any", "-nn", "-s", "512", "-U", "-w", pcap, FILTER],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    seen: dict[str, int] = {}
    end = time.time() + secs
    while time.time() < end:
        for k, v in sample("").items():
            seen.setdefault(k, v)
        time.sleep(0.2)
    subprocess.run(["sudo", "-n", "kill", "-INT", str(p.pid)])
    time.sleep(1)
    subprocess.run(["sudo", "-n", "chmod", "0644", pcap])
    parse(pcap, seen, outj)


def qname(b: bytes, off: int) -> str:
    labels = []
    while off < len(b) and b[off]:
        n = b[off]
        if n & 0xC0:
            break
        labels.append(b[off + 1:off + 1 + n].decode("ascii", "replace"))
        off += 1 + n
    return ".".join(labels)


def sni(payload: bytes) -> str:
    try:
        if payload[0] != 0x16 or payload[5] != 0x01:
            return ""
        i = 9 + 2 + 32
        i += 1 + payload[i]
        i += 2 + struct.unpack("!H", payload[i:i + 2])[0]
        i += 1 + payload[i]
        end = i + 2 + struct.unpack("!H", payload[i:i + 2])[0]
        i += 2
        while i + 4 <= end:
            t, ln = struct.unpack("!HH", payload[i:i + 4])
            if t == 0:
                return payload[i + 9:i + 9 + struct.unpack("!H", payload[i + 7:i + 9])[0]].decode("ascii", "replace")
            i += 4 + ln
    except (IndexError, struct.error):
        pass
    return ""


def parse(pcap: str, seen, outj: str) -> None:
    if isinstance(seen, str):
        seen = json.load(open(seen))
    data = open(pcap, "rb").read()
    magic = struct.unpack("<I", data[:4])[0]
    endian = "<" if magic in (0xA1B2C3D4, 0xA1B23C4D) else ">"
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    pos, flows = 24, {}
    while pos + 16 <= len(data):
        ts, tus, incl, orig = struct.unpack(endian + "IIII", data[pos:pos + 16])
        pkt = data[pos + 16:pos + 16 + incl]
        pos += 16 + incl
        hl = 16 if linktype == 113 else 20 if linktype == 276 else 14
        proto_eth = struct.unpack("!H", pkt[14:16])[0] if linktype == 113 else (struct.unpack("!H", pkt[0:2])[0] if linktype == 276 else 0x0800)
        if proto_eth != 0x0800:
            continue
        ip = pkt[hl:]
        if len(ip) < 20:
            continue
        ihl = (ip[0] & 0x0F) * 4
        proto = ip[9]
        src, dst = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
        l4 = ip[ihl:]
        if proto == 17 and len(l4) >= 8:
            sp, dp = struct.unpack("!HH", l4[:4])
            body = l4[8:]
            if dp == 53 and len(body) > 12:
                key = ("dns", qname(body, 12))
                uid = seen.get(f"udp:{sp}", "?")
                flows.setdefault((uid, "dns-query", f"{dst}", key[1]), [ts, 0])[1] += 1
            elif dp in (3478, 41641):
                uid = seen.get(f"udp:{sp}", "?")
                flows.setdefault((uid, f"udp/{dp}", dst, ""), [ts, 0])[1] += 1
        elif proto == 6 and len(l4) >= 20:
            sp, dp = struct.unpack("!HH", l4[:4])
            off = (l4[12] >> 4) * 4
            payload = l4[off:]
            flags = l4[13]
            if dp in (80, 443, 53) and (flags & 0x02 or payload):
                name = sni(payload) if dp == 443 and payload else ""
                if flags & 0x02 and not (flags & 0x10):   # SYN
                    k = (seen.get(f"tcp:{sp}", "?"), f"tcp/{dp}", dst, "")
                    flows.setdefault(k, [ts, 0])[1] += 1
                if name:
                    k = (seen.get(f"tcp:{sp}", "?"), "tls-sni", dst, name)
                    flows.setdefault(k, [ts, 0])[1] += 1
    rows = [{"uid": k[0], "kind": k[1], "dst": k[2], "name": k[3], "first": v[0], "count": v[1]} for k, v in flows.items()]
    json.dump({"rows": rows, "linktype": linktype}, open(outj, "w"), indent=0)
    print(f"{len(rows)} luồng")


if __name__ == "__main__":
    if sys.argv[1] == "run":
        run(float(sys.argv[2]), sys.argv[3], sys.argv[4])
    else:
        parse(sys.argv[2], sys.argv[3], sys.argv[4])
