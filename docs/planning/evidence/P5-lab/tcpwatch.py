#!/usr/bin/env python3
"""P5-T04/T07/T07a — dò TCP thật liên tục qua một node Tailscale tạm (vnode.sh: SOCKS5 trên 127.0.0.1) và ghi mốc đổi
trạng thái theo đồng hồ của VM (NTP).

    python3 tcpwatch.py <socks port> <giây> <log> <ip:port> [<ip:port> …] [--every 0.5] [--stream ip:port]

Mỗi `--every` giây, với mỗi đích: một kết nối MỚI qua SOCKS5 (timeout 1,5 s) + đọc banner ⇒ OPEN/FAIL. Mỗi lần đổi trạng
thái ghi một dòng JSON {"t": epoch, "dst", "state", "detail"}; mỗi 30 s một dòng "tick" (số lần thử). `--stream`: thêm
một kết nối GIỮ MỞ tới listener `sink` (gửi 1 dòng mỗi 0,2 s, đọc lại không cần) — ghi lúc gửi lỗi/đóng (luồng đang
có bị cắt khi nào). Chỉ thư viện chuẩn.
"""
from __future__ import annotations

import json
import socket
import struct
import sys
import threading
import time


def socks_connect(sport: int, ip: str, port: int, timeout: float) -> socket.socket:
    s = socket.create_connection(("127.0.0.1", sport), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(b"\x05\x01\x00")
    if s.recv(2) != b"\x05\x00":
        raise OSError("socks auth")
    s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(ip) + struct.pack("!H", port))
    rep = s.recv(10)
    if len(rep) < 2 or rep[1] != 0:
        raise OSError(f"socks rep {rep[1] if len(rep) > 1 else '?'}")
    return s


def main(argv: list[str]) -> int:
    sport, secs, logf = int(argv[1]), float(argv[2]), argv[3]
    every, stream, dsts = 0.5, "", []
    i = 4
    while i < len(argv):
        if argv[i] == "--every":
            every = float(argv[i + 1]); i += 2
        elif argv[i] == "--stream":
            stream = argv[i + 1]; i += 2
        else:
            dsts.append(argv[i]); i += 1
    out = open(logf, "a", buffering=1)
    lock = threading.Lock()

    def emit(**kw) -> None:
        with lock:
            out.write(json.dumps({"t": round(time.time(), 3), **kw}) + "\n")

    end = time.time() + secs
    emit(event="start", dsts=dsts, every=every, stream=stream)
    if stream:
        def run_stream() -> None:
            ip, port = stream.rsplit(":", 1)
            while time.time() < end:
                try:
                    s = socks_connect(sport, ip, int(port), 3.0)
                except OSError as e:
                    emit(dst="stream", state="FAIL", detail=f"connect {e}")
                    time.sleep(1)
                    continue
                emit(dst="stream", state="OPEN", detail="connected")
                s.settimeout(5.0)
                n = 0
                try:
                    while time.time() < end:
                        s.sendall(f"{n} {time.time():.3f}\n".encode())
                        n += 1
                        time.sleep(0.2)
                    break
                except OSError as e:
                    emit(dst="stream", state="FAIL", detail=f"send after {n} lines: {type(e).__name__}")
                finally:
                    s.close()
        threading.Thread(target=run_stream, daemon=True).start()
    state: dict[str, str] = {}
    tries = {d: 0 for d in dsts}

    def probe_loop(d: str) -> None:   # một luồng cho mỗi đích: đích bị chặn (timeout) không làm chậm đích khác
        ip, port = d.rsplit(":", 1)
        while time.time() < end:
            t0 = time.time()
            try:
                s = socks_connect(sport, ip, int(port), 1.5)
                s.settimeout(1.5)
                b = s.recv(100).decode("utf-8", "replace").strip()
                s.close()
                st, det = ("OPEN", b[:40]) if b else ("FAIL", "no banner")
            except (OSError, socket.timeout) as e:
                st, det = "FAIL", type(e).__name__ + " " + str(e)[:40]
            tries[d] += 1
            if state.get(d) != st:
                state[d] = st
                emit(dst=d, state=st, detail=det, at_try=tries[d], t_try=round(t0, 3))
            time.sleep(max(0.0, every - (time.time() - t0)))

    threads = [threading.Thread(target=probe_loop, args=(d,), daemon=True) for d in dsts]
    for th in threads:
        th.start()
    while time.time() < end:
        time.sleep(min(30.0, max(0.0, end - time.time())))
        emit(event="tick", tries=dict(tries), state=dict(state))
    for th in threads:
        th.join(timeout=3)
    emit(event="end", tries=tries, state=state)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
