#!/usr/bin/env python3
"""Self-test of the dev/CI stack harness without Docker (P2-T01a): parameters derived from the `ci` environment, render
by the repository's tools, the CI-only TLS change of the Caddyfile (and nothing else), the choice of the Headscale image
from versions.lock, redaction, and compose.yaml taking every image from the lock. Standard library only.

    python3 tests/e2e/harness/test_stack.py
"""
from __future__ import annotations

import difflib
import ipaddress
import os
import pathlib
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import stack  # noqa: E402
from stack import ROOT, Stack, StackError, ci_tls, headscale_lock_key  # noqa: E402

failures = 0
for _s in (sys.stdout, sys.stderr):
    if hasattr(_s, "reconfigure"):
        _s.reconfigure(encoding="utf-8")


def check(ok: bool, name: str, detail: str = "") -> None:
    global failures
    print(f"{'PASS' if ok else 'FAIL'} {name}{'' if ok or not detail else ' — ' + detail}")
    failures += 0 if ok else 1


def raises(fn, name: str) -> None:
    try:
        fn()
    except (StackError, ValueError):
        check(True, name)
    else:
        check(False, name, "no error")


saved = dict(os.environ)
with tempfile.TemporaryDirectory() as d:
    os.environ["E2E_WORK"] = str(pathlib.Path(d) / "work")
    for k in [k for k in os.environ if k.startswith(("MG_", "E2E_HEADSCALE"))]:
        del os.environ[k]
    st = Stack()

    # ---- networks: same layout as infrastructure/host/networks.sh, no overlap, tenant /29 in the tenant pool
    nets = {n: ipaddress.ip_network(s) for n, (s, _, _) in st.networks.items()}
    check(all(not a.overlaps(b) for i, a in enumerate(nets.values()) for b in list(nets.values())[i + 1:]),
          "networks of the stack do not overlap")
    check(not any(n.overlaps(ipaddress.ip_network("10.249.0.0/16")) for n in nets.values()),
          "no network inside 10.249.0.0/16 (platform networks of a real host)")
    check(all(nets[f"t-{t}"].prefixlen == 29 and nets[f"t-{t}"].subnet_of(ipaddress.ip_network("10.250.0.0/16"))
              for t in stack.TENANTS), "tenant networks are /29 inside 10.250.0.0/16")
    check(st.edge_ip == str(next(nets["edge"].hosts()) + 1), "edge at .2 of the edge network", st.edge_ip)
    internal = {n for n, (_, i, _) in st.networks.items() if i}
    check(internal == {"data", "admin", "obs", "sec", "idp-data", "t-tenant-a", "t-tenant-b"},
          "internal networks as on the host (+ tenants)", str(sorted(internal)))

    # ---- render with the repository's tools
    st.work.mkdir(parents=True)
    st.render()
    r = st.work / "render"
    for t, region in (("tenant-a", "901"), ("tenant-b", "902")):
        cfg = (r / t / "config" / "config.yaml").read_text(encoding="utf-8")
        check(f"server_url: https://{t}.{st.mesh}\n" in cfg and f"ipv4: {st.edge_ip}\n" in cfg
              and f"  - {st.networks['t-' + t][0]}\n" in cfg and f"region_id: {region}\n" in cfg,
              f"{t}: server_url, derp ipv4 = edge, trusted_proxies = tenant /29, region {region}")
        comp = (r / t / "compose.yaml").read_text(encoding="utf-8")
        check(f"image: {st.images['headscale']}\n" in comp, f"{t}: Headscale image from versions.lock")
        check("TS_" not in comp.split("services:", 1)[1], f"{t}: no TS_* variable in the tenant compose (PL-15)")
    caddy = (r / "edge" / "caddy" / "Caddyfile").read_text(encoding="utf-8")
    check("dns cloudflare" not in caddy and caddy.count("tls /run/secrets/edge_tls_cert /run/secrets/edge_tls_key") == 1,
          "edge: ACME DNS-01 replaced by the run's certificate")
    # the CI Caddyfile is the plain render of the same params except the header and the tls block
    import json  # noqa: E402
    import mgenv  # noqa: E402
    import render_edge  # noqa: E402
    plain = render_edge.render(mgenv.expand(json.loads((stack.ENV_DIR / "edge.json").read_text(encoding="utf-8")),
                                            st.env))["caddy/Caddyfile"]
    diff = [ln for ln in difflib.unified_diff(plain.splitlines(), caddy.splitlines(), lineterm="", n=0)
            if ln[:1] in "+-" and not ln.startswith(("+++", "---"))]
    changed = [ln for ln in diff if not ln.startswith("+# ")]
    check(sorted(changed) == sorted(["-\ttls {", "-\t\tdns cloudflare {file./run/secrets/cloudflare_dns_token}",
                                     "-\t\tresolvers 1.1.1.1 8.8.8.8", "-\t}",
                                     "+\ttls /run/secrets/edge_tls_cert /run/secrets/edge_tls_key"]),
          "edge: only the tls block differs from the plain render", str(changed))
    for must in (f"default_bind {st.edge_ip}", f"bind {st.admin_ip}", f"remote_ip {st.networks['admin'][0]}",
                 "header_up -X-MG-Token", "path /ts2021 /key /machine/ping-response /derp /derp/*"):
        check(must in caddy, f"edge Caddyfile keeps {must!r}")
    idp = (r / "idp" / "compose.idp.yaml").read_text(encoding="utf-8")
    check(f"KC_PROXY_TRUSTED_ADDRESSES: {st.edge_ip}" in idp, "idp: trusted proxy = edge IP of the stack")
    check(len(list((r / "idp" / "idp" / "realms").glob("*.json"))) == 3, "idp: 3 realms rendered")
    check((st.work / "policies" / "test-allow-intra.hujson").read_text(encoding="utf-8")
          == (ROOT / "infrastructure" / "headscale" / "templates" / "test-allow-intra.hujson").read_text(encoding="utf-8"),
          "policy fixture test-allow-intra copied unchanged")

    # ---- ci_tls refuses a template it does not understand
    raises(lambda: ci_tls("site {\n\ttls internal\n}\n"), "ci_tls: no DNS-01 block ⇒ error")
    raises(lambda: ci_tls(plain + plain), "ci_tls: two DNS-01 blocks ⇒ error")

    # ---- Headscale image: switched by versions.lock only
    dig = "sha256:" + "a" * 64
    official = {"headscale": {"image": "docker.io/headscale/headscale", "index": dig}}
    patched = dict(official, **{"mg-headscale": {"image": "ghcr.io/x/headscale", "index": dig}})
    check(headscale_lock_key(official) == "headscale", "lock without mg-headscale ⇒ official image")
    check(headscale_lock_key(patched) == "mg-headscale", "lock with [images.mg-headscale] ⇒ patched image")
    check(headscale_lock_key(patched, "headscale") == "headscale", "E2E_HEADSCALE_LOCK_KEY=headscale forces official")
    raises(lambda: headscale_lock_key(official, "mg-headscale"), "override to a missing entry ⇒ error")
    raises(lambda: headscale_lock_key({"headscale": {"image": "x", "index": "latest"}}), "entry without digest ⇒ error")

    # ---- parameters are validated
    for var, val, name in (("MG_E2E_NET_BASE", "10.249", "net base 10.249 (host networks) ⇒ error"),
                           ("MG_E2E_NET_BASE", "192.168", "net base outside 10/8 ⇒ error"),
                           ("MG_E2E_TENANT_NET", "10.250.0.0/24", "tenant net not a /28 ⇒ error"),
                           ("MG_E2E_TENANT_NET", "10.251.0.0/28", "tenant net outside the pool ⇒ error")):
        os.environ[var] = val
        raises(Stack, name)
        del os.environ[var]
    os.environ["E2E_PREFIX"] = "Bad_Prefix"
    raises(Stack, "invalid E2E_PREFIX ⇒ error")
    del os.environ["E2E_PREFIX"]

    # ---- redaction
    # sample values are built at run time so that the secret scan of the repository sees no credential-like literal
    value = "".join(chr(65 + (i * 7) % 26) for i in range(40))
    fake_key = "-".join(["hskey", "auth", "abcd1234", "efgh5678ijkl"])
    st.secret_values.add(value)
    red = st.redact(f"a {value} b {fake_key} Authorization: Bearer xyz12345678")
    check(value not in red and fake_key not in red and "xyz12345678" not in red, "redact: values, hskey-, Bearer", red)

os.environ.clear()
os.environ.update(saved)

# ---- compose.yaml takes every image from versions.lock (through the harness) and keeps secrets out of environment
compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
check("@sha256:" not in compose, "compose.yaml: no literal digest (images come from versions.lock via stack.env)")
env_values = re.findall(r"^\s+(TS_AUTHKEY|POSTGRES_PASSWORD\w*|KC_\w*PASSWORD\w*):\s*(\S+)", compose, re.M)
check(all(v.startswith(("file:", "/run/secrets/")) for _, v in env_values) and env_values,
      "compose.yaml: credential variables hold file paths only", str(env_values))
sys.exit(1 if failures else 0)
