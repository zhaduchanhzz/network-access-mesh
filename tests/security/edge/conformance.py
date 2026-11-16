#!/usr/bin/env python3
"""Edge conformance test (P1-T10a; §14.6 of the master plan; edge side of AC-20 and T-05).

Runs against a deployed edge. A fake tenant upstream (echo_upstream.py, alias hs-<echo slug>) records every request
that reaches "Headscale", so the test can prove that forbidden paths never leave the edge and that internal tokens
are stripped. Subcommands (each prints PASS/FAIL lines; exit code 0 = every check passed):

  public      --edge IP --mesh-domain D --echo SLUG --entry-ip IP [--tenants a,b] [--missing SLUG] [--log FILE]
  stopped     --edge IP --mesh-domain D --slug SLUG                  (tenant container stopped ⇒ uniform 404)
  admin       --edge IP:PORT --token-file F --echo SLUG [--log FILE] [--other-token-file F]
  metrics     --edge IP:PORT --token-file F --echo SLUG [--log FILE] [--other-token-file F]
  unreachable --targets IP:PORT[,IP:PORT...]                         (every target must refuse or time out)
  real-api    --via admin|public --edge ADDR --key-file F --instance SLUG [--token-file F] [--mesh-domain D]
              (a real, short-lived Headscale API key read from a root-only file; never printed)

--log is the echo upstream's JSONL file; without it, upstream-side assertions are skipped (e.g. when run from a
LAN client). Token files are read, never printed. Standard library only.
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import posixpath
import random
import socket
import ssl
import string
import sys
import urllib.parse

ALLOWED_PUBLIC = ["/ts2021", "/key", "/machine/ping-response", "/derp", "/derp/*", "/register/*", "/auth/*",
                  "/oidc/callback"]
FORBIDDEN_PUBLIC = ["/", "/api/v1/apikey", "/api/v1/user", "/api/v1/node", "/api/v1/policy", "/swagger",
                    "/swagger/v1/openapiv2.json", "/verify", "/version", "/health", "/metrics", "/debug/pprof/",
                    "/debug/policy", "/apple", "/apple/macos", "/windows", "/windows/tailscale.reg", "/register",
                    "/derpx", "/keys", "/ts2021x"]
TRAVERSAL = ["/derp/../api/v1/apikey", "/derp/%2e%2e/api/v1/apikey", "/derp/..%2fapi/v1/apikey",
             "/derp/%2e%2e%2fapi/v1/apikey", "/key/../api/v1/apikey", "/register/../api/v1/apikey",
             "/auth/..%2f..%2fapi/v1/apikey", "/derp/./../api/v1/apikey", "/derp/probe/../../debug/pprof/",
             "//api/v1/apikey", "/API/v1/apikey", "/%2fapi/v1/apikey", "/derp/..\\api/v1/apikey",
             "/derp/%5c..%5capi/v1/apikey", "/key/.", "/derp/./probe", "/register/..", "/auth/%2e"]
ALLOWED_SAMPLES = ["/key?v=113", "/ts2021", "/derp", "/derp/probe", "/derp/latency-check", "/machine/ping-response",
                   "/register/abc", "/auth/abc", "/oidc/callback"]
MARKER = '"mg-echo": true'


class Result:
    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0

    def check(self, ok: bool, name: str, detail: str = "") -> None:
        if ok:
            self.passed += 1
        else:
            self.failed += 1
            print(f"FAIL {name}{': ' + detail if detail else ''}")

    def done(self, title: str) -> int:
        print(f"{'PASS' if not self.failed else 'FAIL'} {title}: {self.passed} checks passed, {self.failed} failed")
        return 1 if self.failed else 0


class EchoLog:
    """Reads the echo upstream's JSONL log incrementally: new() returns entries appended since the last call."""

    def __init__(self, path: str | None) -> None:
        self.path = path
        self.offset = os.path.getsize(path) if path and os.path.exists(path) else 0

    def new(self) -> list[dict] | None:
        if not self.path:
            return None
        with open(self.path, encoding="utf-8") as f:
            f.seek(self.offset)
            data = f.read()
            self.offset = f.tell()
        return [json.loads(line) for line in data.splitlines() if line.strip()]


def normalized(raw_path: str) -> str:
    p = urllib.parse.unquote(raw_path.split("?", 1)[0]).replace("\\", "/")
    p = posixpath.normpath(p)
    return "/" if p in (".", "//") else p


def allowed_public(path: str) -> bool:
    for a in ALLOWED_PUBLIC:
        if a.endswith("/*") and path.startswith(a[:-1]) or path == a:
            return True
    return False


def https(edge_ip: str, sni: str, method: str, path: str, headers: dict | None = None, body: bytes | None = None,
          port: int = 443, timeout: float = 8.0):
    """One HTTPS request to edge_ip with the given SNI; returns (status, headers, body) or (None, error, b"")."""
    ctx = ssl.create_default_context()
    try:
        raw = socket.create_connection((edge_ip, port), timeout=timeout)
        tls = ctx.wrap_socket(raw, server_hostname=sni)
    except (OSError, ssl.SSLError, ValueError) as e:   # ValueError: SNI that is not a valid IDNA host name
        return None, f"{type(e).__name__}: {e}", b""
    conn = http.client.HTTPConnection(edge_ip, port, timeout=timeout)
    conn.sock = tls
    try:
        conn.request(method, path, body=body, headers={"Host": sni, **(headers or {})})
        r = conn.getresponse()
        return r.status, dict(r.getheaders()), r.read()
    except (OSError, http.client.HTTPException) as e:
        return None, f"{type(e).__name__}: {e}", b""
    finally:
        conn.close()


def plain(addr: str, method: str, path: str, headers: dict | None = None, timeout: float = 8.0):
    host, port = addr.rsplit(":", 1)
    conn = http.client.HTTPConnection(host, int(port), timeout=timeout)
    try:
        conn.request(method, path, headers=headers or {})
        r = conn.getresponse()
        return r.status, dict(r.getheaders()), r.read()
    except (OSError, http.client.HTTPException) as e:
        return None, f"{type(e).__name__}: {e}", b""
    finally:
        conn.close()


def read_secret(path: str) -> str:
    with open(path, encoding="ascii") as f:
        return f.read().strip()


# ---------------------------------------------------------------------------------------------------------- public
def cmd_public(a) -> int:
    res, log = Result(), EchoLog(a.log)
    echo = f"{a.echo}.{a.mesh_domain}"
    hosts = [echo] + [f"{t}.{a.mesh_domain}" for t in a.tenants] + [f"{a.missing}.{a.mesh_domain}"]

    def no_upstream(name: str) -> None:
        entries = log.new()
        if entries is None:
            return
        bad = [e["path"] for e in entries if not allowed_public(normalized(e["path"]))]
        res.check(not bad, f"{name}: no forbidden path reached upstream", f"upstream received {bad}")

    for host in hosts:
        for path in FORBIDDEN_PUBLIC:
            for method in (("GET", "POST") if path == "/verify" else ("GET",)):
                st, _, body = https(a.edge, host, method, path)
                res.check(st == 404 and MARKER.encode() not in body, f"{host} {method} {path}", f"status {st}")
                no_upstream(f"{host} {method} {path}")
        for path in TRAVERSAL:
            st, _, body = https(a.edge, host, "GET", path)
            # A dot-segment path whose clean form is allowed (e.g. /derp/./probe) may be proxied — the edge matches
            # on the cleaned path; everything else must stop at the edge. The upstream check is the real criterion.
            if not allowed_public(normalized(path)):
                res.check(st is None or (st >= 400 and MARKER.encode() not in body), f"{host} traversal {path}",
                          f"status {st}")
            no_upstream(f"{host} traversal {path}")
    # allowed paths reach the (fake) tenant upstream and only it
    for path in ALLOWED_SAMPLES:
        st, _, body = https(a.edge, echo, "GET", path)
        res.check(st == 200 and MARKER.encode() in body, f"{echo} allowed {path} reaches upstream", f"status {st}")
        entries = log.new()
        if entries is not None:
            res.check(len(entries) == 1 and entries[0]["port"] == 8080 and entries[0]["path"] == path,
                      f"{echo} allowed {path}: exactly this request upstream on :8080", str(entries))
    # client-supplied forwarding headers are overwritten (Headscale trusts them from the edge — trusted_proxies)
    spoof = {"True-Client-IP": "6.6.6.6", "X-Real-IP": "6.6.6.6", "X-Forwarded-For": "6.6.6.6"}
    st, _, _ = https(a.edge, echo, "GET", "/key?v=113", headers=spoof)
    entries = log.new()
    if entries is not None and entries:
        h = {k.lower(): v for k, v in entries[0]["headers"].items()}
        res.check(h.get("true-client-ip") not in (None, "6.6.6.6") and h.get("x-real-ip") == h.get("true-client-ip"),
                  "spoofed True-Client-IP/X-Real-IP overwritten", str({k: h.get(k) for k in ("true-client-ip", "x-real-ip")}))
        res.check("6.6.6.6" not in h.get("x-forwarded-for", ""), "spoofed X-Forwarded-For not trusted",
                  h.get("x-forwarded-for", ""))
    # static /bootstrap-dns and /robots.txt, never proxied
    for host in hosts:
        st, hdr, body = https(a.edge, host, "GET", f"/bootstrap-dns?q={host}")
        try:
            doc = json.loads(body)
        except ValueError:
            doc = None
        res.check(st == 200 and doc == {host: [a.entry_ip]}, f"{host} /bootstrap-dns static", f"{st} {body[:80]!r}")
        st, _, body = https(a.edge, host, "GET", "/robots.txt")
        res.check(st == 200 and b"Disallow: /" in body, f"{host} /robots.txt")
    no_upstream("bootstrap-dns/robots")
    # SNI and Host must agree (strict_sni_host) — no domain fronting between tenants
    if a.tenants:
        st, _, body = https(a.edge, echo, "GET", "/key?v=113", headers={"Host": f"{a.tenants[0]}.{a.mesh_domain}"})
        res.check(st == 421, "SNI echo / Host other tenant ⇒ 421", f"status {st}")
        no_upstream("SNI/Host mismatch")
    # host label fuzz: invalid labels never reach any upstream
    rnd = random.Random(20261116)
    labels = ["Echo", "e", "ec", "-echo", "echo-", "echo_x", "1echo", "a" * 33, "xn--echo", "echo.echo",
              "*", "localhost", "hs-echo"] + ["".join(rnd.choices(string.ascii_lowercase + "-_", k=rnd.randint(1, 40)))
                                                for _ in range(20)]
    for lab in labels:
        host = f"{lab}.{a.mesh_domain}"
        st, _, body = https(a.edge, host, "GET", "/key?v=113")
        res.check(st in (None, 404, 421) and MARKER.encode() not in body, f"fuzz host {host!r}", f"status {st}")
    entries = log.new()
    if entries is not None:
        res.check(not entries, "fuzzed hosts: nothing reached the echo upstream", str(entries[:3]))
    # :80 — captive portal answer and HTTPS redirect only
    st, hdr, _ = plain(f"{a.edge}:80", "GET", "/generate_204", {"Host": echo, "X-Tailscale-Challenge": "ts_conf"})
    res.check(st == 204 and hdr.get("X-Tailscale-Response") == "response ts_conf", ":80 /generate_204", f"{st} {hdr}")
    for method, path in (("GET", "/key?v=113"), ("POST", "/ts2021"), ("GET", "/api/v1/apikey")):
        st, hdr, _ = plain(f"{a.edge}:80", method, path, {"Host": echo})
        res.check(st == 308 and hdr.get("Location") == f"https://{echo}{path}", f":80 {method} {path} ⇒ 308",
                  f"{st} {hdr.get('Location')}")
    no_upstream(":80")
    # tenant that does not exist ⇒ same 404 as a blocked path
    st, _, _ = https(a.edge, f"{a.missing}.{a.mesh_domain}", "GET", "/key?v=113")
    res.check(st == 404, f"missing tenant {a.missing} /key ⇒ 404", f"status {st}")
    return res.done("public listener")


def cmd_stopped(a) -> int:
    res = Result()
    host = f"{a.slug}.{a.mesh_domain}"
    for path in ("/key?v=113", "/ts2021", "/derp/probe"):
        st, _, body = https(a.edge, host, "GET", path)
        res.check(st == 404 and MARKER.encode() not in body, f"stopped tenant {host} {path} ⇒ 404", f"status {st}")
    return res.done("stopped tenant")


# ----------------------------------------------------------------------------------------------- internal listeners
def cmd_admin(a) -> int:
    res, log = Result(), EchoLog(a.log)
    token = read_secret(a.token_file)
    other = read_secret(a.other_token_file) if a.other_token_file else None
    good = {"X-MG-Token": token, "X-MG-Instance": a.echo, "Authorization": "Bearer conformance-test"}

    def reached() -> list[dict] | None:
        return log.new()

    for method, path in (("GET", "/api/v1/user"), ("POST", "/api/v1/user"), ("DELETE", "/api/v1/node/1"),
                         ("GET", "/version")):
        st, _, body = plain(a.edge, method, path, good)
        res.check(st == 200 and MARKER.encode() in body, f"admin {method} {path} reaches instance", f"status {st}")
        e = reached()
        if e is not None:
            h = {k.lower(): v for k, v in (e[0]["headers"] if e else {}).items()}
            res.check(len(e) == 1 and e[0]["path"] == path and e[0]["port"] == 8080, f"admin {method} {path} upstream",
                      str(e))
            res.check("x-mg-token" not in h and "x-mg-instance" not in h, f"admin {method} {path}: internal headers stripped",
                      str(sorted(h)))
            res.check(h.get("authorization") == "Bearer conformance-test", f"admin {method} {path}: API key forwarded")
    for method, path in (("POST", "/version"), ("GET", "/api/v1"), ("GET", "/api/v2/user"), ("GET", "/swagger"),
                         ("GET", "/metrics"), ("GET", "/debug/pprof/"), ("GET", "/key"), ("GET", "/ts2021"),
                         ("POST", "/verify"), ("GET", "/health"), ("GET", "/"), ("GET", "/api/v1/../debug/pprof/"),
                         ("GET", "/api/v1/%2e%2e/swagger"), ("GET", "/api/v1/..%2f..%2fdebug/pprof/"),
                         ("GET", "/api/v1/..\\debug/pprof/"), ("GET", "/api/v1/%5c..%5cswagger")):
        st, _, body = plain(a.edge, method, path, good)
        e = reached() or []
        bad = [x["path"] for x in e if not normalized(x["path"]).startswith("/api/v1/") and normalized(x["path"]) != "/version"]
        res.check(st == 404 and not bad, f"admin {method} {path} ⇒ 404, nothing outside the allow-list upstream",
                  f"status {st}, upstream {bad}")
    wrong = "".join(random.Random(7).choices(string.ascii_letters + string.digits, k=40))
    variants = {"missing token": None, "empty token": "", "wrong token": wrong, "token + space": token + " x",
                "token prefix": token[:39], "wildcard": "*", "case-flipped": token.swapcase()}
    if other:
        variants["metrics token on admin"] = other
    for name, val in variants.items():
        h = {"X-MG-Instance": a.echo}
        if val is not None:
            h["X-MG-Token"] = val
        st, _, _ = plain(a.edge, "GET", "/api/v1/user", h)
        res.check(st == 403, f"admin {name} ⇒ 403", f"status {st}")
    for inst in (None, "", "Echo", "echo.x", "../echo", "e", "nope-tenant", "echo,other", "*"):
        h = {"X-MG-Token": token}
        if inst is not None:
            h["X-MG-Instance"] = inst
        st, _, body = plain(a.edge, "GET", "/api/v1/user", h)
        res.check(st == 404 and MARKER.encode() not in body, f"admin X-MG-Instance={inst!r} ⇒ 404", f"status {st}")
    e = reached()
    if e is not None:
        res.check(not e, "rejected admin requests: nothing reached the upstream", str(e[:3]))
    return res.done("admin listener")


def cmd_metrics(a) -> int:
    res, log = Result(), EchoLog(a.log)
    token = read_secret(a.token_file)
    other = read_secret(a.other_token_file) if a.other_token_file else None
    good = {"Authorization": f"Bearer {token}"}
    st, _, body = plain(a.edge, "GET", f"/instance/{a.echo}/metrics", good)
    res.check(st == 200 and MARKER.encode() in body, "metrics /instance/<slug>/metrics reaches :9090", f"status {st}")
    e = log.new()
    if e is not None:
        h = {k.lower(): v for k, v in (e[0]["headers"] if e else {}).items()}
        res.check(len(e) == 1 and e[0]["port"] == 9090 and e[0]["path"].split("?")[0] == "/metrics",
                  "metrics upstream request is GET :9090/metrics", str(e))
        res.check("authorization" not in h, "metrics token stripped before the instance", str(sorted(h)))
    for path in (f"/instance/{a.echo}/debug/pprof/", f"/instance/{a.echo}/debug/policy",
                 f"/instance/{a.echo}/metrics/../debug/policy", f"/instance/{a.echo}/%2e%2e/debug/policy",
                 "/metrics", "/debug/pprof/", f"/instance/{a.echo.upper()}/metrics", "/instance/nope-tenant/metrics",
                 "/instance//metrics", f"/instance/{a.echo}/metrics/x", "/"):
        st, _, body = plain(a.edge, "GET", path, good)
        res.check(st == 404 and MARKER.encode() not in body, f"metrics {path} ⇒ 404", f"status {st}")
    wrong = "".join(random.Random(9).choices(string.ascii_letters + string.digits, k=40))
    variants = {"missing": None, "wrong": f"Bearer {wrong}", "lowercase scheme": f"bearer {token}",
                "no scheme": token, "basic": f"Basic {token}"}
    if other:
        variants["admin token on metrics"] = f"Bearer {other}"
    for name, val in variants.items():
        st, _, _ = plain(a.edge, "GET", f"/instance/{a.echo}/metrics", {} if val is None else {"Authorization": val})
        res.check(st == 403, f"metrics {name} ⇒ 403", f"status {st}")
    e = log.new()
    if e is not None:
        res.check(not e, "rejected metrics requests: nothing reached the upstream", str(e[:3]))
    return res.done("metrics listener")


def cmd_unreachable(a) -> int:
    res = Result()
    for t in a.targets:
        host, port = t.rsplit(":", 1)
        try:
            s = socket.create_connection((host, int(port)), timeout=3)
            s.close()
            res.check(False, f"{t} unreachable", "TCP connection succeeded")
        except OSError as e:
            res.check(True, f"{t} unreachable ({type(e).__name__})")
            print(f"  ok   {t}: {type(e).__name__} {getattr(e, 'strerror', '') or e}")
    return res.done("unreachable targets")


def cmd_real_api(a) -> int:
    """A real, short-lived Headscale API key: accepted through the admin listener, useless through the public one."""
    res = Result()
    key = read_secret(a.key_file)
    if not key.startswith("hskey-api-"):
        print("FAIL real-api: key file does not hold a Headscale API key")
        return 1
    auth = {"Authorization": f"Bearer {key}"}
    if a.via == "admin":
        token = read_secret(a.token_file)
        st, _, body = plain(a.edge, "GET", "/api/v1/user", {**auth, "X-MG-Token": token, "X-MG-Instance": a.instance})
        res.check(st == 200 and b'"users"' in body, f"real API call via admin listener (instance {a.instance}) ⇒ 200",
                  f"status {st}")
    else:
        st, _, body = https(a.edge, f"{a.instance}.{a.mesh_domain}", "GET", "/api/v1/user", headers=auth)
        res.check(st == 404 and b'"users"' not in body, "valid API key via the public listener ⇒ 404", f"status {st}")
    return res.done(f"real Headscale API key via {a.via} listener")


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("public")
    p.add_argument("--edge", required=True)
    p.add_argument("--mesh-domain", required=True)
    p.add_argument("--echo", required=True)
    p.add_argument("--entry-ip", required=True)
    p.add_argument("--tenants", type=lambda s: [x for x in s.split(",") if x], default=[])
    p.add_argument("--missing", default="nope-tenant")
    p.add_argument("--log")
    p = sub.add_parser("stopped")
    p.add_argument("--edge", required=True)
    p.add_argument("--mesh-domain", required=True)
    p.add_argument("--slug", required=True)
    for name in ("admin", "metrics"):
        p = sub.add_parser(name)
        p.add_argument("--edge", required=True)
        p.add_argument("--token-file", required=True)
        p.add_argument("--other-token-file")
        p.add_argument("--echo", required=True)
        p.add_argument("--log")
    p = sub.add_parser("unreachable")
    p.add_argument("--targets", type=lambda s: s.split(","), required=True)
    p = sub.add_parser("real-api")
    p.add_argument("--via", choices=["admin", "public"], required=True)
    p.add_argument("--edge", required=True)
    p.add_argument("--key-file", required=True)
    p.add_argument("--instance", required=True)
    p.add_argument("--token-file")
    p.add_argument("--mesh-domain")
    a = ap.parse_args()
    return {"public": cmd_public, "stopped": cmd_stopped, "admin": cmd_admin, "metrics": cmd_metrics,
            "unreachable": cmd_unreachable, "real-api": cmd_real_api}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
