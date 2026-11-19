#!/usr/bin/env python3
"""dep4 — đo gián đoạn trong lúc nâng cấp/rollback (chạy trên VM 110, ngoài host lồng, như một máy trong LAN / ngoài
Internet). Mỗi 0,5 s, mỗi đích một request mới (TLS kiểm bằng CA thử, SNI đúng tên):
  api-lan   GET https://app.<d>/api/v1/tenants  qua LAN (10.77.4.10)  mong đợi 401 (không dùng /auth/*: giới hạn tần suất đăng nhập theo IP)
  key-lan   GET https://tenant-a.mesh.<d>/key?v=113  qua LAN                    mong đợi 200
  key-vps   GET https://tenant-a.mesh.<d>/key?v=113  qua "VPS" (192.88.99.10) mong đợi 200
  keyb-vps  GET https://tenant-b.mesh.<d>/key?v=113  qua "VPS"                  mong đợi 200
  spa-lan   GET https://app.<d>/                     qua LAN                    ghi mã (404 ở v8, 200 từ v9)
Ghi JSON lines (t, đích, mã, ms) vào file; `summary <file> [from to]` in các khoảng lỗi (mã khác mong đợi) theo đích.
  python3 probe.py run <out.jsonl>          (dừng bằng file <out.jsonl>.stop)
  python3 probe.py summary <out.jsonl>
"""
import http.client
import json
import os
import socket
import ssl
import sys
import time

D = "dep4.test"
CA = os.path.expanduser("~/dep4/ca.crt")
LAN, VPS = "10.77.4.10", "192.88.99.10"
TARGETS = [("api-lan", LAN, f"app.{D}", "/api/v1/tenants", 401),
           ("key-lan", LAN, f"tenant-a.mesh.{D}", "/key?v=113", 200),
           ("key-vps", VPS, f"tenant-a.mesh.{D}", "/key?v=113", 200),
           ("keyb-vps", VPS, f"tenant-b.mesh.{D}", "/key?v=113", 200),
           ("spa-lan", LAN, f"app.{D}", "/", None)]


def once(ctx, ip, host, path):
    t0 = time.time()
    try:
        raw = socket.create_connection((ip, 443), timeout=3)
        conn = http.client.HTTPConnection(ip, 443, timeout=3)
        conn.sock = ctx.wrap_socket(raw, server_hostname=host)
        conn.request("GET", path, headers={"Host": host, "User-Agent": "dep4-probe"})
        code = conn.getresponse().status
        conn.close()
    except Exception as e:  # noqa: BLE001
        code = f"ERR:{type(e).__name__}"
    return code, int((time.time() - t0) * 1000)


def run(out):
    ctx = ssl.create_default_context(cafile=CA)
    with open(out, "a", encoding="utf-8") as f:
        while not os.path.exists(out + ".stop"):
            t = time.time()
            for name, ip, host, path, _ in TARGETS:
                code, ms = once(ctx, ip, host, path)
                f.write(json.dumps({"t": round(t, 2), "n": name, "c": code, "ms": ms}) + "\n")
            f.flush()
            time.sleep(max(0.0, 0.5 - (time.time() - t)))


def summary(path, t_from=0.0, t_to=1e12):
    want = {n: w for n, _, _, _, w in TARGETS}
    rows = [json.loads(x) for x in open(path, encoding="utf-8")]
    rows = [r for r in rows if t_from <= r["t"] <= t_to]
    for name in want:
        rs = [r for r in rows if r["n"] == name]
        if not rs:
            continue
        bad, cur, codes = [], None, {}
        for r in rs:
            codes[str(r["c"])] = codes.get(str(r["c"]), 0) + 1
            ok = want[name] is None or r["c"] == want[name]
            if not ok and cur is None:
                cur = [r["t"], r["t"], str(r["c"])]
            elif not ok:
                cur[1] = r["t"]
            elif cur is not None:
                bad.append(cur)
                cur = None
        if cur:
            bad.append(cur)
        spans = ", ".join(f"{time.strftime('%H:%M:%S', time.gmtime(a))}+{b - a + 0.5:.1f}s({c})" for a, b, c in bad)
        print(f"{name:9} n={len(rs):5} mã={codes} lỗi={len(bad)} khoảng [{spans}]")


if __name__ == "__main__":
    if sys.argv[1] == "run":
        run(sys.argv[2])
    else:
        summary(sys.argv[2], *(float(x) for x in sys.argv[3:5]))
