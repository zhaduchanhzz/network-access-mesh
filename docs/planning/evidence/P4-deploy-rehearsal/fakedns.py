#!/usr/bin/env python3
"""dep4 — "DNS công khai" giả cho bước 4 (dns.ensure) của tenant.provision: trả lời A <bất kỳ>.mesh.<domain> → IP
công khai giả (bản ghi wildcard *.mesh của staging — cf_dns.py), NXDOMAIN cho mọi tên khác. Chỉ UDP, chỉ diễn tập.
  python3 fakedns.py <bind ip> <suffix> <answer ip>
"""
import socket
import struct
import sys

bind, suffix, answer = sys.argv[1], sys.argv[2].lower().strip("."), socket.inet_aton(sys.argv[3])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((bind, 53))
while True:
    data, peer = s.recvfrom(512)
    try:
        tid, flags, qd = struct.unpack(">HHH", data[:6])
        i, labels = 12, []
        while data[i]:
            labels.append(data[i + 1:i + 1 + data[i]].decode("ascii", "replace"))
            i += 1 + data[i]
        qtype = struct.unpack(">H", data[i + 1:i + 3])[0]
        q = data[12:i + 5]
        name = ".".join(labels).lower()
        ok = name.endswith("." + suffix) and name.count(".") == suffix.count(".") + 1
        if ok and qtype == 1:
            hdr = struct.pack(">HHHHHH", tid, 0x8180, 1, 1, 0, 0)
            rr = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + answer
            s.sendto(hdr + q + rr, peer)
        else:
            rcode = 0 if ok else 3
            s.sendto(struct.pack(">HHHHHH", tid, 0x8180 | rcode, 1, 0, 0, 0) + q, peer)
    except Exception:  # noqa: BLE001 — gói hỏng: bỏ qua
        continue
