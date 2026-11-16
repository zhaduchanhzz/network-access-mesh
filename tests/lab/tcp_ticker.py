#!/usr/bin/env python3
"""Continuous TCP flow between two tailnet clients — measures the largest gap of a tunnel (AC-18 (iii), V-10).

    python3 tcp_ticker.py serve <bind_ip> <port> [interval_ms]   # one connection at a time, one line per interval
    python3 tcp_ticker.py watch <ip> <port> <seconds>            # one TCP connection; prints a JSON summary

The summary has the number of lines received, the largest gap between two consecutive lines (and when it started),
and whether the connection ended early (EOF/reset). Standard library only.
"""
from __future__ import annotations

import json
import socket
import sys
import time


def serve(bind_ip: str, port: int, interval_ms: int) -> None:
    with socket.create_server((bind_ip, port), reuse_port=False) as srv:
        while True:
            conn, _ = srv.accept()
            seq = 0
            with conn:
                try:
                    while True:
                        conn.sendall(f"{seq} {time.time():.3f}\n".encode())
                        seq += 1
                        time.sleep(interval_ms / 1000)
                except OSError:
                    continue


def watch(ip: str, port: int, seconds: float) -> dict:
    start = time.time()
    s = socket.create_connection((ip, port), timeout=10)
    s.settimeout(1.0)
    buf, lines, last, max_gap, gap_at, ended = b"", 0, None, 0.0, None, None
    while time.time() - start < seconds:
        try:
            chunk = s.recv(4096)
        except socket.timeout:
            continue
        except OSError as e:
            ended = f"{type(e).__name__} at +{time.time() - start:.1f}s"
            break
        if not chunk:
            ended = f"EOF at +{time.time() - start:.1f}s"
            break
        buf += chunk
        while b"\n" in buf:
            _, buf = buf.split(b"\n", 1)
            now = time.time()
            if last is not None and now - last > max_gap:
                max_gap, gap_at = now - last, time.strftime("%H:%M:%S", time.localtime(last))
            last = now
            lines += 1
    s.close()
    return {"lines": lines, "max_gap_ms": round(max_gap * 1000), "max_gap_started": gap_at,
            "ended_early": ended, "duration_s": round(time.time() - start, 1)}


def main() -> int:
    if len(sys.argv) >= 4 and sys.argv[1] == "serve":
        serve(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]) if len(sys.argv) > 4 else 50)
        return 0
    if len(sys.argv) == 5 and sys.argv[1] == "watch":
        print(json.dumps(watch(sys.argv[2], int(sys.argv[3]), float(sys.argv[4]))))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
