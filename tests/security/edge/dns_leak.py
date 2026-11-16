#!/usr/bin/env python3
"""V-03 / P1-T12d: requests for tenant hostnames that do not exist (random labels valid for the slug regex) and for
a stopped tenant must end in the same 404 as a blocked path, with no DNS query leaving the host (§14.6).

Run inside the network namespace of a container on mg-edge (like conformance.py) while tcpdump captures port 53 on
the host; this script only produces the traffic and the latency figures:

    python3 dns_leak.py --edge 10.249.0.2 --mesh-domain D --count 1000 --blocked-host tenant-a [--stopped SLUG]

Prints status counts and p50/p95/max latency per group, plus the label prefix used (grep it in the capture).
Standard library only.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import http.client
import random
import socket
import ssl
import statistics
import string
import sys
import time


def get(edge: str, host: str, path: str) -> tuple[int | None, float]:
    t0 = time.monotonic()
    try:
        raw = socket.create_connection((edge, 443), timeout=10)
        tls = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
        conn = http.client.HTTPConnection(edge, 443, timeout=10)
        conn.sock = tls
        conn.request("GET", path, headers={"Host": host})
        st = conn.getresponse().status
        conn.close()
    except (OSError, ssl.SSLError, http.client.HTTPException):
        st = None
    return st, (time.monotonic() - t0) * 1000


def run(edge: str, jobs: list[tuple[str, str]], workers: int = 8) -> list[tuple[int | None, float]]:
    with concurrent.futures.ThreadPoolExecutor(workers) as ex:
        return list(ex.map(lambda j: get(edge, *j), jobs))


def summary(name: str, res: list[tuple[int | None, float]]) -> None:
    codes: dict = {}
    for st, _ in res:
        codes[st] = codes.get(st, 0) + 1
    lat = sorted(ms for _, ms in res)
    p95 = lat[max(0, int(len(lat) * 0.95) - 1)]
    print(f"{name}: n={len(res)} status={codes} latency p50={statistics.median(lat):.1f}ms p95={p95:.1f}ms "
          f"max={lat[-1]:.1f}ms")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--edge", required=True)
    ap.add_argument("--mesh-domain", required=True)
    ap.add_argument("--count", type=int, default=1000)
    ap.add_argument("--blocked-host", required=True, help="slug of a running tenant (blocked path baseline)")
    ap.add_argument("--stopped", help="slug of a stopped tenant")
    a = ap.parse_args()
    rnd = random.Random()
    prefix = "zq" + "".join(rnd.choices(string.ascii_lowercase, k=4))
    alphabet = string.ascii_lowercase + string.digits + "-"
    labels = [prefix + "".join(rnd.choices(alphabet, k=rnd.randint(2, 20))) + rnd.choice(string.ascii_lowercase)
              for _ in range(a.count)]
    print(f"label prefix: {prefix} (every random label starts with it)")
    blocked = run(a.edge, [(f"{a.blocked_host}.{a.mesh_domain}", "/api/v1/apikey")] * 200)
    summary(f"blocked path ({a.blocked_host} /api/v1/apikey)", blocked)
    rnd_res = run(a.edge, [(f"{lab}.{a.mesh_domain}", "/key?v=113") for lab in labels])
    summary(f"random valid labels ({a.count})", rnd_res)
    rc = 0 if all(st == 404 for st, _ in rnd_res + blocked) else 1
    if a.stopped:
        stopped = run(a.edge, [(f"{a.stopped}.{a.mesh_domain}", "/key?v=113")] * 100)
        summary(f"stopped tenant ({a.stopped})", stopped)
        rc |= 0 if all(st == 404 for st, _ in stopped) else 1
    print("ALL 404" if rc == 0 else "NOT ALL 404")
    return rc


if __name__ == "__main__":
    sys.exit(main())
