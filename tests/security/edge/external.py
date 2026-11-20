#!/usr/bin/env python3
"""AC-20 from the Internet (P1-T18; §15.1, §22.2 of the master plan): run from a machine OUTSIDE the platform.

    python -I tests/security/edge/external.py <public_entry_ipv4> <mesh_domain> <tenant[,tenant...]> [--admin-public]

1. TCP connect scan of the public entry IP: ports 1-1024 plus the service ports of the platform and common services
   (PostgreSQL, Caddy admin, Docker API, listener admin/metrics, tunnel-facing ports, gRPC, ...). Prints the open set;
   the caller compares it with the port matrix (§15.1) — on the staging VPS: 22, 80, 443, 587 (mail of the owner).
2. On every tenant hostname plus one that does not exist: every forbidden path and traversal of conformance.py ⇒ 404
   (or no answer); /bootstrap-dns answers the entry IP; :80 /generate_204 ⇒ 204 and any other :80 path ⇒ 308 to https;
   /key?v=113 ⇒ 200 for real tenants; a foreign SNI gets no TLS; admin.<base domain> is not served by the entry —
   or, with --admin-public (edge template v11, admin_public — owner's decision 2026-11-20), it is: the SPA on /,
   /api/v1/auth/session ⇒ 401 from the api, and every Keycloak console path (master realm, /admin/*, impersonation)
   ⇒ 401 of the api's console gate without a session — never Keycloak.
From outside there is no upstream log, so "the edge answered 404" is the criterion (the LAN-side run of conformance.py
proves nothing reaches the instance). Prints statuses only; exit code 0 = every check passed. Standard library only.
"""
from __future__ import annotations

import concurrent.futures as cf
import json
import pathlib
import socket
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import conformance as c  # noqa: E402

SERVICE_PORTS = [1080, 1433, 2019, 2375, 2376, 2379, 3000, 3306, 3389, 3478, 3479, 4222, 5000, 5432, 5601, 5672,
                 6060, 6379, 6443, 7946, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 9091, 9093, 9100, 9200,
                 9443, 10250, 11211, 15672, 27017, 50000, 50443, 51820]


def scan(entry: str) -> dict[int, str]:
    def probe(port: int) -> tuple[int, str]:
        s = socket.socket()
        s.settimeout(2.0)
        try:
            s.connect((entry, port))
            return port, "open"
        except socket.timeout:
            return port, "filtered"
        except ConnectionRefusedError:
            return port, "closed"
        except OSError as e:
            return port, f"error {e.errno}"
        finally:
            s.close()

    ports = sorted(set(range(1, 1025)) | set(SERVICE_PORTS))
    with cf.ThreadPoolExecutor(max_workers=128) as ex:
        return dict(ex.map(probe, ports))


def main(argv: list[str]) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    admin_public = "--admin-public" in argv
    argv = [x for x in argv if x != "--admin-public"]
    if len(argv) != 4:
        print(__doc__)
        return 2
    entry, domain, tenants = argv[1], argv[2], [t for t in argv[3].split(",") if t]
    res = scan(entry)
    open_ports = [p for p, st in res.items() if st == "open"]
    closed = [p for p, st in res.items() if st == "closed"]
    print(f"TCP scan {entry}: {len(res)} ports (1-1024 + {len(SERVICE_PORTS)} service ports) — open {open_ports}; "
          f"closed(RST) {len(closed)}; filtered/timeout {len(res) - len(open_ports) - len(closed)}")

    r = c.Result()
    hosts = [f"{t}.{domain}" for t in tenants] + [f"nope-tenant.{domain}"]
    for host in hosts:
        for path in c.FORBIDDEN_PUBLIC:
            for method in (("GET", "POST") if path == "/verify" else ("GET",)):
                st, _, _ = c.https(entry, host, method, path)
                r.check(st == 404, f"{host} {method} {path}", f"status {st}")
        for path in c.TRAVERSAL:
            if c.allowed_public(c.normalized(path)):
                continue
            st, _, _ = c.https(entry, host, "GET", path)
            r.check(st is None or st >= 400, f"{host} traversal {path}", f"status {st}")
        st, _, body = c.https(entry, host, "GET", f"/bootstrap-dns?q={host}")
        try:
            doc = json.loads(body)
        except ValueError:
            doc = None
        r.check(st == 200 and doc == {host: [entry]}, f"{host} /bootstrap-dns ⇒ entry IP", f"{st} {body[:80]!r}")
        st, _, _ = c.plain(f"{entry}:80", "GET", "/generate_204", headers={"Host": host})
        r.check(st == 204, f"{host} :80 /generate_204", f"status {st}")
        st, hdr, _ = c.plain(f"{entry}:80", "GET", "/api/v1/apikey", headers={"Host": host})
        r.check(st == 308 and hdr.get("Location", "").startswith("https://"), f"{host} :80 other path ⇒ https",
                f"status {st}")
    for t in tenants:
        st, _, _ = c.https(entry, f"{t}.{domain}", "GET", "/key?v=113")
        r.check(st == 200, f"{t}.{domain} /key?v=113 ⇒ 200", f"status {st}")
    st, _, _ = c.https(entry, "example.com", "GET", "/")
    r.check(st is None, "foreign SNI example.com: no TLS (strict SNI, no default certificate)", f"status {st}")
    admin = f"admin.{domain.split('.', 1)[1]}"
    st, err, body = c.https(entry, admin, "GET", "/")
    if not admin_public:
        r.check(st is None or st == 404, f"{admin} not served by the public entry", f"status {st} {err if st is None else ''}")
    else:
        r.check(st == 200 and b'id="root"' in body, f"{admin} / ⇒ the SPA (admin public)", f"status {st}")
        st, _, _ = c.https(entry, admin, "GET", "/api/v1/auth/session")
        r.check(st == 401, f"{admin} /api/v1/auth/session ⇒ 401 from the api", f"status {st}")
        c.check_console_gate(r, entry, admin, 443)
    return r.done(f"AC-20 external ({len(hosts)} hostnames)")


if __name__ == "__main__":
    sys.exit(main(sys.argv))
