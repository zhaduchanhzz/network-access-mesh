#!/usr/bin/env python3
"""Basic health probe of the tenant control planes through the edge (P1-T13; §16.2 — public part).

For every tenant slug: HTTPS GET /key?v=<capver> (control plane answers with its Noise public key) and
GET /derp/probe (embedded DERP) through the edge — TLS verified with SNI = tenant host while connecting to the entry
IP — plus one STUN binding to the shared STUN responder of the entry point.

    python3 health_probe.py <entry_ip> <mesh_domain> <slug> [<slug> ...]            # one round
    python3 health_probe.py --watch <seconds> --interval <s> <entry_ip> <mesh_domain> <slug> ...

One line per tenant and round: `<time> <slug> key=<status> derp=<status> <ms>`; exit code 0 only if every check of
every round passed. --watch is used to measure outages (e.g. while restarting one tenant). Standard library only.
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import socket
import ssl
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from stun_probe import probe as stun_probe  # noqa: E402

CAPVER = 113   # minimum capability version accepted by Headscale 0.29.x (RT-09)


def get(entry_ip: str, host: str, path: str, timeout: float = 4.0) -> tuple[int | None, bytes]:
    ctx = ssl.create_default_context()
    try:
        raw = socket.create_connection((entry_ip, 443), timeout=timeout)
        tls = ctx.wrap_socket(raw, server_hostname=host)
        conn = http.client.HTTPConnection(entry_ip, 443, timeout=timeout)
        conn.sock = tls
        conn.request("GET", path, headers={"Host": host})
        r = conn.getresponse()
        body = r.read()
        conn.close()
        return r.status, body
    except (OSError, ssl.SSLError, http.client.HTTPException):
        return None, b""


def check(entry_ip: str, domain: str, slug: str) -> tuple[bool, str]:
    host = f"{slug}.{domain}"
    t0 = time.monotonic()
    st_key, body = get(entry_ip, host, f"/key?v={CAPVER}")
    try:
        key_ok = st_key == 200 and json.loads(body).get("publicKey", "").startswith("mkey:")
    except ValueError:
        key_ok = False
    st_derp, _ = get(entry_ip, host, "/derp/probe")
    ms = (time.monotonic() - t0) * 1000
    ok = key_ok and st_derp == 200
    return ok, f"{slug} key={st_key} derp={st_derp} {ms:.0f}ms{'' if ok else ' FAIL'}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--watch", type=float, default=0, help="keep probing for this many seconds")
    ap.add_argument("--interval", type=float, default=1.0)
    ap.add_argument("--no-stun", action="store_true")
    ap.add_argument("entry_ip")
    ap.add_argument("mesh_domain")
    ap.add_argument("slugs", nargs="+")
    a = ap.parse_args()
    all_ok = True
    if not a.no_stun:
        try:
            addr = stun_probe(a.entry_ip)
            print(f"{time.strftime('%H:%M:%S')} stun {a.entry_ip}:3478 ok mapped={addr[0]}:{addr[1]}")
        except (OSError, RuntimeError) as e:
            print(f"{time.strftime('%H:%M:%S')} stun {a.entry_ip}:3478 FAIL {e}")
            all_ok = False
    end = time.monotonic() + a.watch
    while True:
        stamp = time.strftime("%H:%M:%S") + f".{int(time.time() * 1000) % 1000:03d}"
        for slug in a.slugs:
            ok, line = check(a.entry_ip, a.mesh_domain, slug)
            all_ok &= ok
            print(f"{stamp} {line}", flush=True)
        if time.monotonic() >= end:
            break
        time.sleep(a.interval)
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
