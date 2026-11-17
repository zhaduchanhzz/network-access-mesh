#!/usr/bin/env python3
"""Golden test of tools/render_edge.py (P1-T06; first part of the P1-T10a render checks).

    python tools/test_render_edge.py            # compare against tests/golden/edge/*/expected
    python tools/test_render_edge.py --update   # rewrite the golden files after an intentional template change

For every case it also extracts the tenant regex from the rendered Caddyfile and checks that the tenant label is
captured correctly for a mesh domain of 3 and of 4 labels (§14.6 — no hard-coded {labels.N}), and that invalid
parameters are rejected. Standard library only; exit code 0 = pass.
"""
from __future__ import annotations

import ipaddress
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import render_edge as re_  # noqa: E402

GOLDEN = re_.ROOT / "tests" / "golden" / "edge"

BAD = {
    "acme name": {"acme": "prod"},
    "wildcard bind": {"lan_ipv4": "0.0.0.0"},
    "loopback bind": {"lan_ipv4": "127.0.0.1"},
    "ipv6 bind": {"lan_ipv4": "2001:db8::1"},
    "image by tag": {"image": "ghcr.io/zhaduchanhzz/network-access-mesh/edge:latest"},
    "no resolvers": {"dns_resolvers": []},
    "private resolver": {"dns_resolvers": ["192.168.1.1"]},
    "bad domain": {"base_domain": "Example.COM"},
    "no entry ip": {"public_entry_ipv4": ""},
    "wildcard entry ip": {"public_entry_ipv4": "0.0.0.0"},
    "no admin allow-list": {"admin_allow": []},
    "admin allow-list as text": {"admin_allow": "192.0.2.0/24"},
    "admin allow-list open to all": {"admin_allow": ["0.0.0.0/0"]},
    "admin allow-list public": {"admin_allow": ["8.8.8.0/24"]},
    "admin allow-list in the tenant pool": {"admin_allow": ["10.250.0.0/24"]},
    "admin allow-list covering the tenant pool": {"admin_allow": ["10.0.0.0/8"]},
}


def tenant_regex(caddyfile: str) -> re.Pattern:
    m = re.search(r"vars_regexp tenant \{http\.request\.host\} (\S+)", caddyfile)
    if not m:
        raise AssertionError("tenant matcher not found in Caddyfile")
    return re.compile(m.group(1))


def check_regex(caddyfile: str, base_domain: str) -> list[str]:
    rx = tenant_regex(caddyfile)
    mesh = f"mesh.{base_domain}"
    errors = []
    for host, want in [
        (f"tenant-a.{mesh}", "tenant-a"),
        (f"t01.{mesh}", "t01"),
        (f"b2.{mesh}", None),                    # slug needs >= 3 characters (same regex as render_instance)
        (f"tenant-.{mesh}", None),               # must end with a letter or digit
        (f"Tenant-a.{mesh}", None),              # lower case only
        (f"x.tenant-a.{mesh}", None),            # exactly one label before the mesh domain
        (f"tenant-a.{mesh}.evil.test", None),    # anchored at the end
        (f"tenant-a{mesh}", None),               # the dot is literal, not "any character"
        (f"tenant-a.{mesh.replace('.', 'x', 1)}", None),
    ]:
        m = rx.fullmatch(host)
        got = m.group(1) if m else None
        if got != want:
            errors.append(f"{host!r}: captured {got!r}, want {want!r}")
    return errors


def check_structure(caddyfile: str, params: dict) -> list[str]:
    """Invariants of §14.6 that must hold for every rendering."""
    errors = []
    must = [
        "default_bind 10.249.0.2",
        "strict_sni_host on",
        "bind 10.249.2.2",                                  # admin listener only on mg-admin
        "bind 10.249.3.2",                                  # metrics listener only on mg-obs
        "abort @outside",
        "header_up -X-MG-Token",
        "header_up -X-MG-Instance",
        "header_up -Authorization",
        "request>headers>X-Mg-Token delete",
        f'["{params["public_entry_ipv4"]}"]',               # static /bootstrap-dns answer
        "handle_errors 502 503 504",
    ]
    errors += [f"missing {m!r}" for m in must if m not in caddyfile]
    code = "\n".join(line for line in caddyfile.splitlines() if not line.lstrip().startswith("#"))
    block = re.search(r"@tenant \{\n(.*?)\n\t\}", code, re.S)
    tenant_paths = re.search(r"^\s*path (.+)$", block.group(1), re.M) if block else None
    if not tenant_paths:
        errors.append("tenant path allow-list not found")
    else:
        allowed = tenant_paths.group(1).split()
        for forbidden in ("/api/*", "/api/v1/*", "/swagger*", "/verify", "/version", "/health", "/metrics",
                          "/debug/*", "/bootstrap-dns", "/apple*", "/windows", "*"):
            if forbidden in allowed:
                errors.append(f"public allow-list contains {forbidden}")
    if re.search(r"(?m)^\s*(bind|default_bind) .*(0\.0\.0\.0|::)", code):
        errors.append("wildcard bind address")
    if "{labels." in code:
        errors.append("hard-coded {labels.N} (EG-03)")
    tunnel = params.get("tunnel")
    if tunnel:
        peer = tunnel["peer_ipv4"]
        for port in (tunnel["https_port"], tunnel["http_port"]):
            block = re.search(rf"servers 10\.249\.0\.2:{port} \{{(.*?)\n\t\}}", code, re.S)
            if not block:
                errors.append(f"no server options for tunnel port {port}")
                continue
            b = block.group(1)
            if "fallback_policy require" not in b:
                errors.append(f"tunnel port {port}: PROXY header not required")
            deny = re.search(r"deny (.+)", b).group(1).split()
            if any(ipaddress.ip_address(peer) in ipaddress.ip_network(n) for n in deny if ":" not in n):
                errors.append(f"tunnel port {port}: peer {peer} is denied")
            covered = sum(ipaddress.ip_network(n).num_addresses for n in deny if ":" not in n)
            if covered != 2 ** 32 - 1:
                errors.append(f"tunnel port {port}: deny list does not cover every other IPv4 address")
            if port == tunnel["https_port"] and not (0 <= b.find("proxy_protocol") < b.find("\t\t\ttls")):
                errors.append("tunnel TLS port: proxy_protocol must come before tls (GW-02)")
        if code.find(f"servers 10.249.0.2:{tunnel['https_port']}") > code.find("\tservers {"):
            errors.append("generic servers block must come after the tunnel blocks (first match wins)")
        # a headerless connection from a non-peer is closed before any other handler, on both public sites (V-17)
        guard = f"@direct_tunnel vars {{http.request.local.port}} {tunnel['https_port']} {tunnel['http_port']}"
        for name, start in (("TLS site", r"^\*\."), ("HTTP site", r"^http://(?!:)")):
            site = re.search(start + r".*?\n(.*?)\n\}", code, re.S | re.M)
            body = site.group(1) if site else ""
            first_handle = re.search(r"(?m)^\thandle\b.*$", body)
            if guard not in body:
                errors.append(f"{name}: tunnel guard matcher missing")
            elif not first_handle or not first_handle.group(0).startswith("\thandle @direct_tunnel"):
                errors.append(f"{name}: tunnel guard is not the first handle")
            elif "handle @direct_tunnel {\n\t\tabort\n\t}" not in body:
                errors.append(f"{name}: tunnel guard does not abort")
    elif "@direct_tunnel" in code:
        errors.append("tunnel guard rendered without a tunnel")
    return errors


def site_block(code: str, address: str) -> str:
    """Body of the site block whose address line is exactly `address` ("" when absent)."""
    m = re.search(r"(?m)^" + re.escape(address) + r" \{\n(.*?)\n\}\n", code, re.S)
    return m.group(1) if m else ""


def check_platform_sites(caddyfile: str, params: dict) -> list[str]:
    """Invariants of the platform sites (P2-T16, §8.3, §14.6, §15.4, P2-T05a)."""
    errors = []
    code = "\n".join(line for line in caddyfile.splitlines() if not line.lstrip().startswith("#")) + "\n"
    d = params["base_domain"]
    tunnel = params.get("tunnel")
    tport = tunnel["https_port"] if tunnel else None
    app_addr = f"app.{d}" + (f", app.{d}:{tport}" if tunnel else "")
    app, admin, auth = site_block(code, app_addr), site_block(code, f"admin.{d}"), site_block(code, f"auth.{d}")
    auth_tunnel = site_block(code, f"auth.{d}:{tport}") if tunnel else ""
    for name, body in (("app", app), ("admin", admin), ("auth", auth)):
        if not body:
            errors.append(f"site {name}.{d} not found (or its address line changed)")
            continue
        for must in ("import tls_acme", "import platform_site", "import access_log", "abort @from_tenant_pool",
                     "respond @unsafe_path 404"):
            if must not in body:
                errors.append(f"{name}: missing {must!r}")
        route = body[body.find("\troute {"):]
        if "\troute {" not in body or not route.rstrip().endswith("respond 404\n\t}") and "\t\trespond 404\n\t}" not in route:
            errors.append(f"{name}: the route does not end with respond 404")
        if re.search(r"(?m)^\thandle\b", body):
            errors.append(f"{name}: handle blocks (sorted by Caddy) instead of one explicit route")
        for proxy in re.findall(r"reverse_proxy [^\n]*\{\n((?:\t\t\t[^\n]*\n)*)", body):
            if "import upstream_headers" not in proxy:
                errors.append(f"{name}: a reverse_proxy without the upstream header rules")
    for addr in re.findall(r"(?m)^(\S[^\n{]*) \{$", code):
        if f"admin.{d}" in addr and addr != f"admin.{d}":
            errors.append(f"admin.{d} is served on another listener: {addr!r}")
        if tunnel and f":{tport}" in addr and f"admin.{d}" in addr:
            errors.append("admin.<domain> on the tunnel-facing listener")
    if tunnel:   # host without a site on the TLS tunnel-facing server ⇒ abort, never Caddy's default empty 200 (G2)
        catch_all = site_block(code, f"https://:{tport}")
        if catch_all.strip() != "abort":
            errors.append(f"tunnel-facing catch-all site https://:{tport} missing or not a bare abort: {catch_all!r}")
        if code.find(f"https://:{tport} {{") < code.find(f"auth.{d}:{tport} {{"):
            errors.append("tunnel-facing catch-all is not after the tunnel-facing sites")
    if "abort @outside_admin" not in admin or "@outside_admin not remote_ip " + " ".join(params["admin_allow"]) not in admin:
        errors.append("admin: the IP allow-list is not enforced")
    if admin.find("abort @outside_admin") > admin.find("reverse_proxy"):
        errors.append("admin: the allow-list is checked after the proxy")
    for name, body in (("app", app), ("admin", admin)):
        if "reverse_proxy /api/* api.:8080 {" not in body or "import portal_headers" not in body:
            errors.append(f"{name}: /api/* is not proxied to api.:8080 with the portal headers")
    if "remote_ip " + re_.APP_IPS["worker_edge_ip"] not in auth or "reverse_proxy @idp_worker idp.:8080" not in auth:
        errors.append("auth: the Admin REST API / master realm are not restricted to the worker")
    worker = re.search(r"@idp_worker \{\n(.*?)\n\t\}", auth, re.S)
    if not worker or set(re.search(r"path (.+)", worker.group(1)).group(1).split()) != {
            "/admin/realms", "/admin/realms/*", "/realms/master", "/realms/master/*"}:
        errors.append("auth: @idp_worker paths differ from the Admin REST API + master realm")
    for name, body in (("auth", auth), ("auth (tunnel)", auth_tunnel if tunnel else auth)):
        public = re.search(r"@idp_public \{\n(.*?)\n\t\}", body, re.S)
        if not public or "path /realms/* /resources/*" not in public.group(1) or \
                "not path /realms/master /realms/master/*" not in public.group(1):
            errors.append(f"{name}: public paths are not /realms/* + /resources/* without the master realm")
        if "/admin/" in (public.group(1) if public else "") or ":9000" in body:
            errors.append(f"{name}: the console or the management port is routed")
    if tunnel:
        if not auth_tunnel:
            errors.append("auth.<domain> has no block on the tunnel-facing listener")
        elif "@idp_worker" in auth_tunnel or "/admin/realms" in auth_tunnel or \
                not auth_tunnel.split("route {", 1)[-1].lstrip().startswith("abort @direct_tunnel"):
            errors.append("auth (tunnel): Admin API reachable or the tunnel guard is not first")
        if not app.split("route {", 1)[-1].lstrip().startswith("abort @direct_tunnel"):
            errors.append("app (tunnel): the tunnel guard is not the first step of the route")
    elif "@direct_tunnel" in app + admin + auth:
        errors.append("platform sites: tunnel guard rendered without a tunnel")
    if "header_up -X-MG-Token" not in code.split("(upstream_headers)", 1)[-1].split("}", 1)[0]:
        errors.append("upstream_headers does not strip X-MG-Token")
    return errors


def main() -> int:
    update = "--update" in sys.argv
    failures = 0
    cases = sorted(p for p in GOLDEN.iterdir() if (p / "params.json").is_file())
    for case in cases:
        params = json.loads((case / "params.json").read_text(encoding="utf-8"))
        files = re_.render(params)
        expected_dir = case / "expected"
        if update:
            re_.write(files, expected_dir)
            print(f"updated {case.name}")
            continue
        want = {p.relative_to(expected_dir).as_posix(): p.read_text(encoding="utf-8")
                for p in expected_dir.rglob("*") if p.is_file()}
        if set(want) != set(files):
            print(f"FAIL {case.name}: file set differs: {sorted(set(want) ^ set(files))}")
            failures += 1
            continue
        diff = [rel for rel in files if files[rel] != want[rel]]
        if diff:
            print(f"FAIL {case.name}: content differs in {diff}")
            failures += 1
        else:
            print(f"PASS {case.name}: {len(files)} files identical to golden")
        errors = check_regex(files["caddy/Caddyfile"], params["base_domain"])
        if errors:
            print(f"FAIL {case.name}: tenant regex: " + "; ".join(errors))
            failures += 1
        else:
            print(f"PASS {case.name}: tenant label captured correctly ({params['base_domain'].count('.') + 2} labels)")
        errors = check_structure(files["caddy/Caddyfile"], params)
        if errors:
            print(f"FAIL {case.name}: structure: " + "; ".join(errors))
            failures += 1
        else:
            print(f"PASS {case.name}: listener/allow-list invariants of §14.6 hold")
        errors = check_platform_sites(files["caddy/Caddyfile"], params)
        if errors:
            print(f"FAIL {case.name}: platform sites: " + "; ".join(errors))
            failures += 1
        else:
            print(f"PASS {case.name}: app./admin./auth. invariants hold (admin LAN-only, Admin API worker-only — P2-T16)")
        for name, override in BAD.items():
            try:
                re_.render({**params, **override})
                print(f"FAIL {case.name}: accepted invalid parameter ({name})")
                failures += 1
            except (re_.ParamError, ValueError):
                pass
        print(f"PASS {case.name}: {len(BAD)} invalid parameter sets rejected")
    if not cases:
        print("FAIL: no golden cases found")
        return 1
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
