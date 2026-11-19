#!/usr/bin/env python3
"""Edge conformance test (P1-T10a; §14.6 of the master plan; edge side of AC-20 and T-05).

Runs against a deployed edge. A fake tenant upstream (echo_upstream.py, alias hs-<echo slug>) records every request
that reaches "Headscale", so the test can prove that forbidden paths never leave the edge and that internal tokens
are stripped. Subcommands (each prints PASS/FAIL lines; exit code 0 = every check passed):

  public      --edge IP --mesh-domain D --echo SLUG --entry-ip IP [--tenants a,b] [--missing SLUG] [--log FILE]
              [--app-host H]  (also the web-auth redirect of /register/<auth_id> — edge template v10, P4-T07; H defaults
              to app.<base domain> with mesh domain = mesh.<base domain>)
  stopped     --edge IP --mesh-domain D --slug SLUG                  (tenant container stopped ⇒ uniform 404)
  admin       --edge IP:PORT --token-file F --echo SLUG [--log FILE] [--other-token-file F]
  metrics     --edge IP:PORT --token-file F --echo SLUG [--log FILE] [--other-token-file F]
  unreachable --targets IP:PORT[,IP:PORT...]                         (every target must refuse or time out)
  tunnel-reject --targets IP:PORT[,...] --sni HOST [--tls-ports 8443] (tunnel-facing listener, from a non-peer source:
              no TLS/HTTP answer with or without a forged PROXY header — V-17)
  real-api    --via admin|public --edge ADDR --key-file F --instance SLUG [--token-file F] [--mesh-domain D]
              (a real, short-lived Headscale API key read from a root-only file; never printed)
  platform    --edge IP --domain D --admin allowed|refused [--realm R] [--port 443] [--cafile F]
              (P2-T16 sites app./admin./auth. with the real api, web and idp behind: api only on /api/*, every other
              path of app./admin. is the SPA's index.html (edge template v9, P4-T01a) — never the api —, dot segments,
              "\" and unknown /api/* ⇒ 404, one set of security headers from the edge, Admin REST API / master realm /
              console of the IdP ⇒ 404 from this source, admin. served only from the allowed management networks; on a
              tunnel-facing port pass --admin refused)

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
import re
import socket
import ssl
import string
import sys
import urllib.parse

ALLOWED_PUBLIC = ["/ts2021", "/key", "/machine/ping-response", "/derp", "/derp/*", "/register/confirm/*", "/auth/*",
                  "/oidc/callback"]
# /register/<auth_id> (ID-05: hskey-authreq- + 24 characters) reaches Headscale only with the query via=portal; without it
# the edge answers 302 to the Portal's claim page (template v10, P4-T07); any other /register/* path is a 404.
SLUG_RE = re.compile(r"[a-z][a-z0-9-]{1,30}[a-z0-9]")                       # §14.5 (fullmatch only)
REGISTER_RE = re.compile(r"/register/(hskey-authreq-[A-Za-z0-9_-]{24})")   # fullmatch only
FORBIDDEN_PUBLIC = ["/", "/api/v1/apikey", "/api/v1/user", "/api/v1/node", "/api/v1/policy", "/swagger",
                    "/swagger/v1/openapiv2.json", "/verify", "/version", "/health", "/metrics", "/debug/pprof/",
                    "/debug/policy", "/apple", "/apple/macos", "/windows", "/windows/tailscale.reg", "/register",
                    "/derpx", "/keys", "/ts2021x"]
TRAVERSAL = ["/derp/../api/v1/apikey", "/derp/%2e%2e/api/v1/apikey", "/derp/..%2fapi/v1/apikey",
             "/derp/%2e%2e%2fapi/v1/apikey", "/key/../api/v1/apikey", "/register/../api/v1/apikey",
             "/auth/..%2f..%2fapi/v1/apikey", "/derp/./../api/v1/apikey", "/derp/probe/../../debug/pprof/",
             "//api/v1/apikey", "/API/v1/apikey", "/%2fapi/v1/apikey", "/derp/..\\api/v1/apikey",
             "/derp/%5c..%5capi/v1/apikey", "/key/.", "/derp/./probe", "/register/..", "/auth/%2e"]
AUTH_ID = "hskey-authreq-" + "Conf0rmance_-Edge-P4T07x"           # a well-formed Auth ID nobody holds (24 characters)
ALLOWED_SAMPLES = ["/key?v=113", "/ts2021", "/derp", "/derp/probe", "/derp/latency-check", "/machine/ping-response",
                   "/register/confirm/abc", f"/register/{AUTH_ID}?via=portal", "/auth/abc", "/oidc/callback"]
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


def register_upstream_ok(raw_path: str) -> bool:
    """An upstream request for /register/<auth_id> is legitimate only with the query via=portal (template v10)."""
    if not REGISTER_RE.fullmatch(normalized(raw_path)):
        return True
    query = raw_path.split("?", 1)[1] if "?" in raw_path else ""
    return "portal" in urllib.parse.parse_qs(query, keep_blank_values=True).get("via", [])


# Auth IDs the edge must refuse (404, nothing upstream) — with and without via=portal; raw, as sent on the request line
BAD_AUTH_IDS = [AUTH_ID[:-1], AUTH_ID + "x", AUTH_ID.replace("authreq", "authrex"), AUTH_ID.upper(),
                AUTH_ID.replace("hskey-", "hskey_"), AUTH_ID[:-1] + "%2F", AUTH_ID[:-1] + "%40", AUTH_ID[:-1] + ".",
                AUTH_ID[:-1] + "%25", AUTH_ID[:-1] + "%20", AUTH_ID[:-3] + "%0d%0a", AUTH_ID[:-1] + "%E2%80%AE",
                AUTH_ID + "/", AUTH_ID + "/x", AUTH_ID + "%2Fx", "hskey-authreq-", "", "x", "%2F%2Fevil.example",
                "https:%2F%2Fevil.example%2F", "%5c%5cevil.example", "..%2f..%2fapi/v1/apikey",
                "%3Cscript%3Ealert(1)%3C%2Fscript%3Exxxxxxxxxxxx"]
# query strings that do NOT opt out of the redirect (the matcher is `query via=portal`, exact and case-sensitive) and
# that must never be reflected into the Location
NOT_VIA_PORTAL = ["", "?via=Portal", "?via=", "?via=portalx", "?VIA=portal", "?via=portal%00",
                  "?tenant=evil&auth_id=x&return_to=https%3A%2F%2Fevil.example&next=//evil.example"]


def allowed_public(path: str) -> bool:
    if REGISTER_RE.fullmatch(path):        # only with via=portal — checked on the raw upstream path by register_upstream_ok
        return True
    for a in ALLOWED_PUBLIC:
        if a.endswith("/*") and path.startswith(a[:-1]) or path == a:
            return True
    return False


CAFILE: str | None = None   # --cafile of `platform` (dev/CI stack: the run's CA); None = system roots


def https(edge_ip: str, sni: str, method: str, path: str, headers: dict | None = None, body: bytes | None = None,
          port: int = 443, timeout: float = 8.0):
    """One HTTPS request to edge_ip with the given SNI; returns (status, headers, body) or (None, error, b"")."""
    ctx = ssl.create_default_context(cafile=CAFILE)
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
        bad = [e["path"] for e in entries if not allowed_public(normalized(e["path"])) or not register_upstream_ok(e["path"])]
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
    # web-auth (template v10, P4-T07; §7.4 flow A step 6, §14.6): /register/<auth_id> without via=portal ⇒ 302 to the
    # Portal's claim page, Location built from the slug and the Auth ID only (no Host / X-Forwarded-* / query reflected),
    # on every tenant hostname — existing or not (the edge does not know; no oracle); malformed Auth ID ⇒ 404
    app_host = a.app_host or "app." + a.mesh_domain.split(".", 1)[1]
    spoof = {"X-Forwarded-Host": "evil.example", "X-Forwarded-Proto": "http", "Forwarded": "host=evil.example"}
    for host in hosts:
        slug = host.split(".", 1)[0]
        want = f"https://{app_host}/enroll/claim?tenant={slug}&auth_id={AUTH_ID}"
        for method in ("GET", "HEAD"):
            for q in NOT_VIA_PORTAL:
                st, hdr, body = https(a.edge, host, method, f"/register/{AUTH_ID}{q}", headers=spoof)
                h = {k.lower(): v for k, v in hdr.items()} if st else {}
                res.check(st == 302 and h.get("location") == want and h.get("cache-control") == "no-store"
                          and MARKER.encode() not in body, f"{host} {method} /register/<auth_id>{q} ⇒ 302 claim of the Portal",
                          f"status {st} location {h.get('location')!r} cache-control {h.get('cache-control')!r}")
        for bad_id in BAD_AUTH_IDS:
            for q in ("", "?via=portal"):
                st, hdr, body = https(a.edge, host, "GET", f"/register/{bad_id}{q}")
                h = {k.lower(): v for k, v in hdr.items()} if st else {}
                res.check(st == 404 and "location" not in h and MARKER.encode() not in body,
                          f"{host} malformed Auth ID /register/{bad_id}{q} ⇒ 404", f"status {st} {h.get('location')!r}")
        no_upstream(f"{host} web-auth redirect / malformed Auth IDs")
    # with via=portal (ALLOWED_SAMPLES) and the native OIDC confirmation form (POST /register/confirm/*): Headscale
    path = f"/register/confirm/{AUTH_ID}"
    st, hdr, body = https(a.edge, echo, "POST", path, body=b"")
    res.check(st == 200 and MARKER.encode() in body and "Location" not in hdr,
              f"{echo} POST {path} reaches Headscale (native OIDC confirmation)", f"status {st}")
    entries = log.new()
    if entries is not None:
        res.check(len(entries) == 1 and entries[0]["path"] == path and entries[0]["method"] == "POST",
                  f"{echo} POST {path}: exactly this request upstream", str(entries))
    st, _, _ = https(a.edge, f"{a.missing}.{a.mesh_domain}", "GET", f"/register/{AUTH_ID}?via=portal")
    res.check(st == 404, f"missing tenant {a.missing} /register/<auth_id>?via=portal ⇒ 404", f"status {st}")
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
        # web-auth link: a label of slug form (tenant or not — the edge cannot know) ⇒ the same 302; any other ⇒ never
        # redirected, and the Location never carries a label that is not of slug form
        st, hdr, body = https(a.edge, host, "GET", f"/register/{AUTH_ID}")
        loc = {k.lower(): v for k, v in hdr.items()}.get("location") if st else None
        if SLUG_RE.fullmatch(lab):
            ok = st == 302 and loc == f"https://{app_host}/enroll/claim?tenant={lab}&auth_id={AUTH_ID}"
        else:
            ok = st in (None, 404, 421) and loc is None
        res.check(ok and MARKER.encode() not in body, f"fuzz host {host!r} /register/<auth_id>", f"status {st} {loc!r}")
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


def no_answer(host: str, port: int, prefix: bytes, sni: str | None, path: str) -> tuple[bool, str]:
    """Connect, send `prefix` (e.g. a PROXY header), then one HTTP request over TLS (sni set) or plain HTTP.
    True when no HTTP response comes back (refused, reset, closed, TLS failure). A completed TLS handshake alone is
    not an answer: the certificate is public; what matters is that no request is served."""
    try:
        raw = socket.create_connection((host, port), timeout=3)
    except OSError as e:
        return True, f"{type(e).__name__} on connect"
    conn = raw
    try:
        raw.settimeout(4)
        if prefix:
            raw.sendall(prefix)
        hs = ""
        if sni:
            try:
                conn = ssl.create_default_context().wrap_socket(raw, server_hostname=sni)
                hs = "TLS ok, "
            except (OSError, ssl.SSLError, ValueError) as e:
                return True, f"TLS handshake failed ({type(e).__name__})"
        req = f"GET {path} HTTP/1.1\r\nHost: {sni or 'conformance.invalid'}\r\nConnection: close\r\n\r\n"
        try:
            conn.sendall(req.encode())
            data = conn.recv(64)
        except (OSError, ssl.SSLError) as e:
            return True, f"{hs}no HTTP answer ({type(e).__name__})"
        if data.startswith(b"HTTP/"):
            return False, f"{hs}answered {data[:20]!r}"
        return True, f"{hs}closed without answer"
    finally:
        conn.close()


def cmd_tunnel_reject(a) -> int:
    """Tunnel-facing listener (P1-T17, GW-02, V-17): proxy_protocol REQUIRE for the tunnel peer, `deny` (REJECT a
    header) for every other source, plus the @direct_tunnel guard for headerless connections. From any source other
    than the peer, no request may be served — without a PROXY header and with a forged one."""
    res = Result()
    for t in a.targets:
        host, port = t.rsplit(":", 1)
        tls = port in a.tls_ports
        forged = f"PROXY TCP4 203.0.113.7 {host} 40000 {port}\r\n".encode()
        paths = ("/key?v=113", "/robots.txt", "/bootstrap-dns") if tls else ("/generate_204", "/key?v=113")
        for label, prefix in (("no PROXY header", b""), ("forged PROXY v1 header", forged)):
            for path in paths:
                ok, detail = no_answer(host, int(port), prefix, a.sni if tls else None, path)
                res.check(ok, f"{t} {label} {path}: not served", detail)
                if ok:
                    print(f"  ok   {t} {label} {path}: {detail}")
    return res.done("tunnel-facing listener from a non-peer source")


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


IDP_REFUSED = ["/realms/master/.well-known/openid-configuration", "/realms/master/protocol/openid-connect/token",
               "/admin/realms/master", "/admin/realms/tenant-a/users", "/admin/master/console/", "/admin/", "/",
               "/realms/tenant-a/../../admin/realms/tenant-a/users", "/realms/tenant-a/%2e%2e/%2e%2e/admin/realms",
               "/resources/..%2f..%2fadmin/realms/tenant-a", "/realms/tenant-a\\..\\..\\admin/realms",
               "/health/ready", "/metrics", "/welcome"]
# app./admin. (edge template v9, P4-T01a): a path outside /api/* is the SPA — index.html, whatever the api has there
# (/healthz, /readyz, /metrics, /internal/* never reach the api); the SPA's router decides (uniform 404 in the page).
SPA_PATHS = ["/", "/healthz", "/readyz", "/metrics", "/internal/prometheus/sd", "/internal/edge/idp-console",
             "/tenants/0190a000-0000-7000-8000-00000000000a/devices", "/platform/tenants", "/login?return_to=%2Fx",
             "/favicon.ico.bak", "/api.v1"]
# never served: dot segments of the raw path (also as %2e/%2f), dotfiles, "\", the bare /api of the web container, a
# missing hashed asset (never index.html in place of JS)
APP_NOT_FOUND = ["/api/../metrics", "/api\\..\\metrics", "/api/%2e%2e/metrics", "/api/..%2fmetrics", "/./metrics",
                 "/t/x/../../metrics", "/.env", "/.git/config", "/assets/.x.js", "/api", "/assets/missing-0000.js",
                 "/%5c..%5cmetrics"]
CSP = "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'"
# one value each, set by the edge only (portal_headers + platform_headers — the web container sets none)
PORTAL_HEADERS = {"content-security-policy": CSP, "x-frame-options": "DENY", "referrer-policy": "no-referrer",
                  "cross-origin-opener-policy": "same-origin", "cross-origin-resource-policy": "same-origin",
                  "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
                  "strict-transport-security": "max-age=31536000", "x-content-type-options": "nosniff"}


def https_all(edge_ip: str, sni: str, path: str, port: int = 443, timeout: float = 8.0):
    """GET over HTTPS; returns (status, [(name, value)...] keeping repeated headers, body) or (None, error, b"")."""
    ctx = ssl.create_default_context(cafile=CAFILE)
    try:
        raw = socket.create_connection((edge_ip, port), timeout=timeout)
        tls = ctx.wrap_socket(raw, server_hostname=sni)
    except (OSError, ssl.SSLError, ValueError) as e:
        return None, f"{type(e).__name__}: {e}", b""
    conn = http.client.HTTPConnection(edge_ip, port, timeout=timeout)
    conn.sock = tls
    try:
        conn.request("GET", path, headers={"Host": sni})
        r = conn.getresponse()
        return r.status, r.getheaders(), r.read()
    except (OSError, http.client.HTTPException) as e:
        return None, f"{type(e).__name__}: {e}", b""
    finally:
        conn.close()


def header_problems(headers) -> list[str]:
    """Differences from the portal's header set: each header exactly once with the expected value, no Server."""
    out = []
    names = [k.lower() for k, _ in headers]
    for name, want in PORTAL_HEADERS.items():
        got = [v for k, v in headers if k.lower() == name]
        if got != [want]:
            out.append(f"{name}={got}")
    if "server" in names:
        out.append("server header present")
    return out


def check_spa(res: Result, edge: str, host: str, port: int) -> None:
    """app./admin. of edge template v9: SPA for every path outside /api/*, 404 for dot segments/dotfiles/"\"."""
    st, hdr, index = https_all(edge, host, "/", port)
    ok = st == 200 and b'id="root"' in index and b'<script type="module"' in index
    res.check(ok, f"{host} GET / ⇒ 200 index.html of the SPA", f"status {st}")
    if not ok:
        return
    bad = header_problems(hdr)
    res.check(not bad, f"{host} /: one CSP and one set of security headers (edge only), no Server", "; ".join(bad))
    ct = [v for k, v in hdr if k.lower() == "content-type"]
    cc = [v for k, v in hdr if k.lower() == "cache-control"]
    res.check(ct == ["text/html; charset=utf-8"] and cc == ["no-cache"], f"{host} /: text/html, Cache-Control no-cache",
              f"{ct} {cc}")
    for path in SPA_PATHS[1:]:
        st, hdr, body = https_all(edge, host, path, port)
        bad = header_problems(hdr) if st else ["no answer"]
        res.check(st == 200 and body == index and not bad, f"{host} GET {path} ⇒ the SPA's index.html (never the api)",
                  f"status {st}, same body {body == index}, {bad}")
    asset = re.search(rb'src="(/assets/index-[A-Za-z0-9_-]+\.js)"', index)
    if asset:
        st, hdr, body = https_all(edge, host, asset.group(1).decode(), port)
        cc = [v for k, v in hdr if k.lower() == "cache-control"] if st else []
        res.check(st == 200 and body[:1] != b"<" and cc == ["public, max-age=31536000, immutable"]
                  and not header_problems(hdr), f"{host} hashed asset: 200, immutable, edge headers", f"status {st} {cc}")
    else:
        res.check(False, f"{host} index.html references a hashed /assets/index-*.js")
    for path in APP_NOT_FOUND:
        st, hdr, body = https_all(edge, host, path, port)
        res.check(st == 404 and body != index, f"{host} GET {path} ⇒ 404 (not the SPA, not the api)", f"status {st}")
    st, hdr, body = https_all(edge, host, "/api/v1/conformance-no-such-route", port)
    ct = [v for k, v in hdr if k.lower() == "content-type"] if st else []
    res.check(st == 404 and ct[:1] and ct[0].startswith("application/problem+json") and not header_problems(hdr),
              f"{host} GET /api/v1/<unknown> ⇒ 404 problem+json of the api, edge headers", f"status {st} {ct}")


def cmd_platform(a) -> int:
    """Sites of the platform (P2-T16, §8.3, §14.6, §15.4): what a client of this source can reach on app./admin./auth."""
    global CAFILE
    CAFILE = a.cafile
    res = Result()
    app, admin, auth = f"app.{a.domain}", f"admin.{a.domain}", f"auth.{a.domain}"
    st, hdr, body = https(a.edge, app, "GET", "/api/v1/auth/session", port=a.port,
                          headers={"X-MG-Token": "x" * 40, "X-Request-Id": "bad id"})
    h = {k.lower(): v for k, v in (hdr.items() if isinstance(hdr, dict) else [])}
    res.check(st == 401 and h.get("content-type", "").startswith("application/problem+json"),
              f"{app} GET /api/v1/auth/session without a session ⇒ 401 problem+json from the api", f"status {st}")
    res.check(h.get("strict-transport-security", "").startswith("max-age=") and h.get("x-content-type-options") == "nosniff"
              and "frame-ancestors 'none'" in h.get("content-security-policy", "") and "server" not in h,
              f"{app}: HSTS, nosniff, CSP, no Server header", str(sorted(h)))
    res.check(h.get("x-request-id", "") not in ("", "bad id"), f"{app}: the request id is the api's, not the client's")
    check_spa(res, a.edge, app, a.port)
    st, _, body = https(a.edge, auth, "GET", f"/realms/{a.realm}/.well-known/openid-configuration", port=a.port)
    try:
        issuer = json.loads(body).get("issuer") if st == 200 else None
    except ValueError:
        issuer = None
    res.check(issuer == f"https://{auth}/realms/{a.realm}", f"{auth} discovery of {a.realm} ⇒ 200, issuer of the realm",
              f"status {st} issuer {issuer}")
    for path in IDP_REFUSED:
        st, _, _ = https(a.edge, auth, "GET", path, port=a.port)
        res.check(st == 404, f"{auth} GET {path} ⇒ 404 from this source", f"status {st}")
    st, detail, _ = https(a.edge, admin, "GET", "/api/v1/auth/session", port=a.port)
    if a.admin == "allowed":
        res.check(st == 401, f"{admin} from an allowed source ⇒ the api (401)", f"status {st} {detail if st is None else ''}")
        check_spa(res, a.edge, admin, a.port)
    else:
        res.check(st is None, f"{admin} from this source ⇒ no answer (aborted or no such site)", f"status {st}")
    return res.done(f"platform sites app./admin./auth. of {a.domain} on {a.edge}:{a.port}")


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
    p.add_argument("--app-host", help="host of the Portal (default app.<base domain> for mesh domain mesh.<base domain>)")
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
    p = sub.add_parser("tunnel-reject")
    p.add_argument("--targets", type=lambda s: s.split(","), required=True)
    p.add_argument("--sni", required=True, help="a real tenant hostname, so a TLS answer would prove acceptance")
    p.add_argument("--tls-ports", type=lambda s: s.split(","), default=["8443"])
    p = sub.add_parser("real-api")
    p.add_argument("--via", choices=["admin", "public"], required=True)
    p.add_argument("--edge", required=True)
    p.add_argument("--key-file", required=True)
    p.add_argument("--instance", required=True)
    p.add_argument("--token-file")
    p.add_argument("--mesh-domain")
    p = sub.add_parser("platform")
    p.add_argument("--edge", required=True)
    p.add_argument("--domain", required=True)
    p.add_argument("--admin", choices=["allowed", "refused"], required=True)
    p.add_argument("--realm", default="tenant-a")
    p.add_argument("--port", type=int, default=443)
    p.add_argument("--cafile")
    a = ap.parse_args()
    return {"public": cmd_public, "stopped": cmd_stopped, "admin": cmd_admin, "metrics": cmd_metrics,
            "unreachable": cmd_unreachable, "tunnel-reject": cmd_tunnel_reject, "real-api": cmd_real_api,
            "platform": cmd_platform}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
