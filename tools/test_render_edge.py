#!/usr/bin/env python3
"""Golden test of tools/render_edge.py (P1-T06; first part of the P1-T10a render checks).

    python tools/test_render_edge.py            # compare against tests/golden/edge/*/expected
    python tools/test_render_edge.py --update   # rewrite the golden files after an intentional template change

For every case it also extracts the tenant regex from the rendered Caddyfile and checks that the tenant label is
captured correctly for a mesh domain of 3 and of 4 labels (§14.6 — no hard-coded {labels.N}), and that invalid
parameters are rejected. From template v11 (admin_public — admin.<domain> on the Internet, owner's decision
2026-11-20) the golden cases admin-public (tunnel) and admin-public-lan render that mode, and MUTATIONS — among them
"admin public but the Keycloak console without its forward_auth" — must each be caught by the checks.
Standard library only; exit code 0 = pass.
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
    "admin_public as text": {"admin_public": "true"},
    "admin_public as a number": {"admin_public": 1},
    "admin_public null": {"admin_public": None},
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
    # G2 round 2, A-1: the logout's id_token_hint (an ID token) never reaches the access log CrowdSec reads
    snippet = re.search(r"\(access_log\) \{\n(.*?)\n\}", caddyfile, re.S)
    if not snippet or not re.search(r"format filter \{\s*wrap json\s*request>uri query \{\s*delete id_token_hint\s*\}",
                                    snippet.group(1)):
        errors.append("access_log does not delete id_token_hint from the logged URI")
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


def snippet(code: str, name: str) -> str:
    m = re.search(r"(?m)^\(" + re.escape(name) + r"\) \{\n(.*?)\n\}\n", code, re.S)
    return m.group(1) if m else ""


CSP = "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'"
# path (decoded, not cleaned) → must the edge refuse it before routing (@dot_segment, template v9)?
DOT_SAMPLES = {"/.env": True, "/.git/config": True, "/api/../metrics": True, "/api/./v1/auth/session": True,
               "/t/x/..": True, "/assets/.hidden.js": True, "/..": True, "/": False, "/api/v1/auth/session": False,
               "/assets/index-9lcqj5sB.js": False, "/favicon.svg": False, "/t/0190a000/devices": False,
               "/platform/tenants": False, "/a..b/c.d": False}


def check_portal_route(body: str) -> list[str]:
    """app./admin. (template v9, P4-T01a): the steps of the route, in order — guards, (console), dot segments ⇒ 404,
    /api/* → api, everything else → web."""
    errors = []
    if "\timport portal_site\n" not in body:
        errors.append("portal_site (dot segments, error page) not imported")
    route = body[body.find("\troute {"):]
    steps = [s for s in re.findall(r"(?m)^\t\t(\S[^\n]*)$", route) if s != "}"]
    want = [s for s in ("abort @direct_tunnel", "abort @from_tenant_pool", "abort @outside_admin",
                        "respond @unsafe_path 404", "route @idp_console {", "respond @dot_segment 404",
                        "reverse_proxy /api/* api.:8080 {", "reverse_proxy web.:8080 {") if s in steps]
    tail = ["respond @dot_segment 404", "reverse_proxy /api/* api.:8080 {", "reverse_proxy web.:8080 {"]
    if steps != want or want[-3:] != tail or "abort @from_tenant_pool" not in want:
        errors.append(f"route steps {steps}, want the order {want} ending with dot segments ⇒ 404, api, web")
    return errors


def check_portal_snippets(code: str) -> list[str]:
    """Headers of app./admin. come from one place (portal_headers + platform_headers), also on the edge's own error page;
    @dot_segment matches the raw path's dot segments only."""
    errors = []
    ph, plh, site = snippet(code, "portal_headers"), snippet(code, "platform_headers"), snippet(code, "portal_site")
    for must in (f'Content-Security-Policy "{CSP}"', "X-Frame-Options DENY", "Referrer-Policy no-referrer",
                 "Cross-Origin-Opener-Policy same-origin", "Cross-Origin-Resource-Policy same-origin",
                 'Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=()"', "defer"):
        if must not in ph:
            errors.append(f"portal_headers: missing {must!r}")
    for must in ('Strict-Transport-Security "max-age=31536000"', "X-Content-Type-Options nosniff", "-Server", "defer"):
        if must not in plh:
            errors.append(f"platform_headers: missing {must!r}")
    if "import platform_headers" not in snippet(code, "platform_site"):
        errors.append("platform_site does not import platform_headers")
    if code.count("Content-Security-Policy") != 1:
        errors.append("Content-Security-Policy set in more than one place")
    errs = re.search(r"\thandle_errors 502 503 504 \{\n(.*?)\n\t\}", site, re.S)
    eb = errs.group(1) if errs else ""
    for must in ("import platform_headers", "import portal_headers *", "header Cache-Control no-store",
                 'respond "Service temporarily unavailable" 503'):
        if must not in eb:
            errors.append(f"portal_site handle_errors: missing {must!r}")
    m = re.search(r"@dot_segment vars_regexp dot \{http\.request\.uri\.path\} (\S+)$", site, re.M)
    if not m:
        errors.append("portal_site: @dot_segment on the raw path {http.request.uri.path} not found")
    else:
        rx = re.compile(m.group(1))
        wrong = [p for p, refused in DOT_SAMPLES.items() if bool(rx.search(p)) != refused]
        if wrong:
            errors.append(f"@dot_segment decides wrongly for {wrong}")
    return errors


def admin_address(params: dict) -> str:
    """Address line of the admin. site: LAN-direct only, or — admin_public (template v11) — also the tunnel-facing port."""
    d, tunnel = params["base_domain"], params.get("tunnel")
    if params.get("admin_public") and tunnel:
        return f"admin.{d}, admin.{d}:{tunnel['https_port']}"
    return f"admin.{d}"


def check_platform_sites(caddyfile: str, params: dict) -> list[str]:
    """Invariants of the platform sites (P2-T16, §8.3, §14.6, §15.4, P2-T05a; admin_public — template v11)."""
    errors = []
    code = "\n".join(line for line in caddyfile.splitlines() if not line.lstrip().startswith("#")) + "\n"
    d = params["base_domain"]
    tunnel = params.get("tunnel")
    public = params.get("admin_public", False)
    tport = tunnel["https_port"] if tunnel else None
    app_addr = f"app.{d}" + (f", app.{d}:{tport}" if tunnel else "")
    app, admin, auth = site_block(code, app_addr), site_block(code, admin_address(params)), site_block(code, f"auth.{d}")
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
        # auth. ends with 404; app./admin. end with the SPA (template v9, P4-T01a) — nothing may come after it
        last = ("\t\treverse_proxy web.:8080 {\n\t\t\timport upstream_headers\n\t\t}\n\t}" if name != "auth"
                else "\t\trespond 404\n\t}")
        if "\troute {" not in body or not route.rstrip().endswith(last):
            errors.append(f"{name}: the route does not end with {last.split(chr(10))[0].strip()!r}")
        if re.search(r"(?m)^\thandle\b", body):
            errors.append(f"{name}: handle blocks (sorted by Caddy) instead of one explicit route")
        for proxy in re.findall(r"reverse_proxy [^\n]*\{\n((?:\t\t\t[^\n]*\n)*)", body):
            if "import upstream_headers" not in proxy:
                errors.append(f"{name}: a reverse_proxy without the upstream header rules")
    for addr in re.findall(r"(?m)^(\S[^\n{]*) \{$", code):
        if f"admin.{d}" in addr and addr != admin_address(params):
            errors.append(f"admin.{d} is served on another listener: {addr!r}")
        if tunnel and not public and f":{tport}" in addr and f"admin.{d}" in addr:
            errors.append("admin.<domain> on the tunnel-facing listener")
    if tunnel:   # host without a site on the TLS tunnel-facing server ⇒ abort, never Caddy's default empty 200 (G2)
        catch_all = site_block(code, f"https://:{tport}")
        if catch_all.strip() != "abort":
            errors.append(f"tunnel-facing catch-all site https://:{tport} missing or not a bare abort: {catch_all!r}")
        if code.find(f"https://:{tport} {{") < code.find(f"auth.{d}:{tport} {{"):
            errors.append("tunnel-facing catch-all is not after the tunnel-facing sites")
    if not public:
        if "abort @outside_admin" not in admin or \
                "@outside_admin not remote_ip " + " ".join(params["admin_allow"]) not in admin:
            errors.append("admin: the IP allow-list is not enforced")
        if admin.find("abort @outside_admin") > admin.find("reverse_proxy"):
            errors.append("admin: the allow-list is checked after the proxy")
    else:
        # admin_public (template v11, owner's decision 2026-11-20): no source restriction on admin. — on the tunnel-facing
        # port the tunnel guard comes first, like app.; the tenant pool is still aborted (checked above for every site)
        if "@outside_admin" in admin or re.search(r"(?m)^\t@\S+ (not )?remote_ip ", admin):
            errors.append("admin (public): an IP allow-list is still rendered")
        if tunnel and not admin.split("route {", 1)[-1].lstrip().startswith("abort @direct_tunnel"):
            errors.append("admin (tunnel): the tunnel guard is not the first step of the route")
        if tunnel and f"@direct_tunnel vars {{http.request.local.port}} {tport} {tunnel['http_port']}" not in admin:
            errors.append("admin (tunnel): tunnel guard matcher missing")
    for name, body in (("app", app), ("admin", admin)):
        if "reverse_proxy /api/* api.:8080 {" not in body or "import portal_headers" not in body:
            errors.append(f"{name}: /api/* is not proxied to api.:8080 with the portal headers")
        errors += [f"{name}: {e}" for e in check_portal_route(body)]
    errors += check_portal_snippets(code)
    # the SPA only behind app./admin.: never on auth. (either listener) nor on the tenant wildcard
    for name, body in (("auth", auth), ("auth (tunnel)", auth_tunnel)):
        if "web.:8080" in body or "portal_site" in body:
            errors.append(f"{name}: the SPA or the portal rules are routed on the IdP site")
    if code.count("reverse_proxy web.:8080 {") != 2:
        errors.append(f"web.:8080 proxied {code.count('reverse_proxy web.:8080 {')} times (want app. and admin. only)")
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
    if tunnel and not public and "@direct_tunnel" in admin:
        errors.append("admin: tunnel guard rendered on a LAN-direct-only site")
    if "header_up -X-MG-Token" not in code.split("(upstream_headers)", 1)[-1].split("}", 1)[0]:
        errors.append("upstream_headers does not strip X-MG-Token")
    return errors


CONSOLE_PATHS = {"/admin", "/admin/*", "/realms/master", "/realms/master/*", "/resources/*"}
# the console route of admin. (template v8, P3-T15), byte for byte — in both modes of admin_public (template v11)
CONSOLE_ROUTE = ("\t\troute @idp_console {\n\t\t\tforward_auth api.:8080 {\n\t\t\t\turi /internal/edge/idp-console\n"
                 "\t\t\t\timport upstream_headers\n\t\t\t\theader_up -Authorization\n\t\t\t}\n"
                 "\t\t\trespond @idp_impersonation 403\n\t\t\treverse_proxy idp.:8080 {\n\t\t\t\timport upstream_headers\n"
                 "\t\t\t}\n\t\t}\n")


def check_idp_console(caddyfile: str, params: dict) -> list[str]:
    """P3-T15 (§8.2 (3), template v8): the Keycloak administration console is served on admin.<domain> only, every
    request of it behind the forward_auth of the api (GET /internal/edge/idp-console); impersonation is refused on
    admin. and auth.; the console never on auth. nor on the tunnel-facing listener unless admin. is (admin_public — template
    v11: then the same gated route, byte for byte); /internal/* never on a public site."""
    errors = []
    code = "\n".join(line for line in caddyfile.splitlines() if not line.lstrip().startswith("#")) + "\n"
    d = params["base_domain"]
    tunnel = params.get("tunnel")
    tport = tunnel["https_port"] if tunnel else None
    app = site_block(code, f"app.{d}" + (f", app.{d}:{tport}" if tunnel else ""))
    admin, auth = site_block(code, admin_address(params)), site_block(code, f"auth.{d}")
    if not admin:
        return [f"admin: site {admin_address(params)!r} not found"]
    console = re.search(r"@idp_console path (.+)", admin)
    if not console or set(console.group(1).split()) != CONSOLE_PATHS:
        errors.append(f"admin: @idp_console paths are not exactly {sorted(CONSOLE_PATHS)}")
    portal = re.search(r"@portal not path (.+)", admin)
    if not portal or set(portal.group(1).split()) != CONSOLE_PATHS or "import portal_headers @portal" not in admin:
        errors.append("admin: the portal headers are not limited to the non-console paths")
    if "import portal_headers *" not in app:
        errors.append("app: the portal headers do not apply to every response")
    route = re.search(r"\t\troute @idp_console \{\n(.*?)\n\t\t\}\n", admin, re.S)
    if not route:
        errors.append("admin: no `route @idp_console` block")
    else:
        body = route.group(1)
        steps = re.findall(r"(?m)^\t\t\t(\S+(?: \S+)*)", body)
        want = ["forward_auth api.:8080 {", "respond @idp_impersonation 403", "reverse_proxy idp.:8080 {"]
        if steps[:1] != want[:1] or [x for x in steps if not x.startswith(("import", "header_up", "uri", "}"))] != want:
            errors.append(f"admin: the console route is not forward_auth → impersonation 403 → idp (got {steps})")
        fa = re.search(r"forward_auth api\.:8080 \{\n(.*?)\n\t\t\t\}", body, re.S)
        fab = fa.group(1) if fa else ""
        for must in ("uri /internal/edge/idp-console", "import upstream_headers", "header_up -Authorization"):
            if must not in fab:
                errors.append(f"admin: forward_auth misses {must!r}")
        if "header_up -Cookie" in fab:
            errors.append("admin: forward_auth strips the Cookie the gate needs (Platform Console session)")
    # idp:8080 is reached from admin. ONLY inside the console route (behind forward_auth)
    outside = admin.replace(route.group(0), "") if route else admin
    if "idp.:8080" in outside:
        errors.append("admin: idp.:8080 is proxied outside the forward_auth route")
    if not params.get("admin_public") and admin.find("abort @outside_admin") > admin.find("route @idp_console"):
        errors.append("admin: the console route comes before the IP allow-list")
    # the console route itself is the same whatever admin_public says (template v11: admin. on the Internet does NOT
    # loosen the Keycloak console — the forward_auth 2P gate is its only door, impersonation refused behind it)
    if route and route.group(0) != CONSOLE_ROUTE:
        errors.append("admin: the console route differs from the gated route of template v8")
    imp = "@idp_impersonation path_regexp impersonation (?i)^/admin/realms/[^/]+/users/[^/]+/impersonation/?$"
    for name, body in (("admin", admin), ("auth", auth)):
        if imp not in body:
            errors.append(f"{name}: impersonation matcher missing")
    if auth.find("respond @idp_impersonation 403") < 0 or \
            auth.find("respond @idp_impersonation 403") > auth.find("reverse_proxy @idp_worker"):
        errors.append("auth: impersonation is not refused before the worker's Admin API route")
    # the console is not routed anywhere else: no forward_auth or console paths on app./auth./tunnel, no /internal
    for name, body in (("app", app), ("auth", auth)):
        if "forward_auth" in body or "@idp_console" in body or "/admin/master" in body:
            errors.append(f"{name}: console routing outside admin.")
    if tunnel:
        auth_tunnel = site_block(code, f"auth.{d}:{tport}")
        if "/admin" in auth_tunnel or "forward_auth" in auth_tunnel:
            errors.append("auth (tunnel): the console or the Admin API is reachable through the VPS")
    if code.count("forward_auth ") != 1 or code.count("/internal/edge/idp-console") != 1:
        errors.append("exactly one forward_auth (the console gate) expected")
    if re.search(r"reverse_proxy /internal|path /internal", code):
        errors.append("/internal/* routed by a public site")
    return errors


AUTH_ID = "hskey-authreq-" + "Ab0_-" * 4 + "Zz9_"          # 24 characters after the prefix (ID-05)
# path (decoded and cleaned by Caddy before path_regexp) → is it a web-auth Auth ID path?
REGISTER_SAMPLES = {
    f"/register/{AUTH_ID}": True,
    f"/register/{AUTH_ID[:-1]}": False,                     # 23 characters
    f"/register/{AUTH_ID}x": False,                         # 25 characters
    f"/register/{AUTH_ID}/": False, f"/register/{AUTH_ID}/x": False, f"/register/{AUTH_ID}.": False,
    f"/register/{AUTH_ID.replace('authreq', 'authrex')}": False, f"/register/{AUTH_ID.upper()}": False,
    f"/register/{AUTH_ID[:-1]}.": False, f"/register/{AUTH_ID[:-1]}%": False, f"/register/{AUTH_ID[:-1]}@": False,
    f"/register/{AUTH_ID[:-1]}\n": False, "/register/hskey-authreq-": False, "/register/": False, "/register": False,
    f"/register/confirm/{AUTH_ID}": False, f"/x/register/{AUTH_ID}": False, f"/registerx/{AUTH_ID}": False,
    "/register/hskey-authreq-//evil.example/abcdefghijk": False, "/register/hskey-authreq-ééééééééééééééééééééééé": False,
}


def check_web_auth(caddyfile: str, params: dict) -> list[str]:
    """P4-T07 (§7.4 flow A step 6, §14.6, template v10): on the tenant wildcard site, GET /register/<auth_id> without
    via=portal ⇒ 302 to the Portal's claim page built ONLY from the two regex captures (slug, auth_id); with via=portal ⇒
    the tenant's Headscale; the allow-list keeps /register/confirm/* only — any other /register/* is a 404."""
    errors = []
    code = "\n".join(line for line in caddyfile.splitlines() if not line.lstrip().startswith("#")) + "\n"
    d = params["base_domain"]
    site = re.search(r"(?m)^\*\.[^\n]* \{\n(.*?)\n\}\n", code, re.S)
    body = site.group(1) if site else ""
    tenant = re.search(r"@tenant \{\n(.*?)\n\t\}", body, re.S)
    paths = re.search(r"path (.+)", tenant.group(1)).group(1).split() if tenant else []
    if "/register/confirm/*" not in paths or any(p.startswith("/register") and p != "/register/confirm/*" for p in paths):
        errors.append(f"@tenant: /register/* must be narrowed to /register/confirm/* (got {paths})")
    host_rx = tenant_regex(caddyfile).pattern
    blocks = {}
    for name, last in (("register_portal", "not query via=portal"), ("register_native", "query via=portal")):
        m = re.search(r"@" + name + r" \{\n(.*?)\n\t\}", body, re.S)
        lines = [ln.strip() for ln in m.group(1).splitlines()] if m else []
        rx = re.match(r"path_regexp authid (\S+)$", lines[1]) if len(lines) == 3 else None
        if not rx or lines[0] != f"vars_regexp tenant {{http.request.host}} {host_rx}" or lines[2] != last:
            errors.append(f"@{name}: want the tenant host regex, path_regexp authid and {last!r} (got {lines})")
            continue
        blocks[name] = rx.group(1)
        wrong = [p for p, ok in REGISTER_SAMPLES.items() if bool(re.search(rx.group(1), p)) != ok]
        if wrong:
            errors.append(f"@{name}: the Auth ID regex decides wrongly for {wrong}")
        if re.search(rx.group(1), f"/register/{AUTH_ID}").group(1) != AUTH_ID:
            errors.append(f"@{name}: capture group 1 is not the Auth ID")
    if len(set(blocks.values())) > 1:
        errors.append("@register_portal and @register_native use different Auth ID regexes")
    redirect = re.search(r"\thandle @register_portal \{\n(.*?)\n\t\}", body, re.S)
    want = [f"redir https://app.{d}/enroll/claim?tenant={{re.tenant.1}}&auth_id={{re.authid.1}} 302",
            "header Cache-Control no-store"]
    if not redirect or sorted(ln.strip() for ln in redirect.group(1).splitlines()) != sorted(want):
        errors.append(f"handle @register_portal: want exactly {want}")
    native = re.search(r"\thandle @register_native \{\n(.*?)\n\t\}", body, re.S)
    if not native or "reverse_proxy hs-{re.tenant.1}.:8080 {" not in native.group(1) or \
            "header_up True-Client-IP {remote_host}" not in native.group(1):
        errors.append("handle @register_native: not a proxy to hs-<slug>:8080 with the client IP overwritten")
    # the only redirect of the tenant site, never built from request data other than the two captures
    redirs = re.findall(r"(?m)^\s*redir (.+)$", body)
    if len(redirs) != 1 or re.search(r"\{(?!re\.(tenant|authid)\.1\})", redirs[0]):
        errors.append(f"tenant site: redirects {redirs} (want one, with no placeholder but the two captures)")
    order = [body.find(h) for h in ("\thandle @unsafe_path {", "\thandle @register_portal {",
                                    "\thandle @register_native {", "\thandle @tenant {")]
    if -1 in order or order != sorted(order):
        errors.append("tenant site: handle order is not @unsafe_path, @register_portal, @register_native, @tenant")
    if "/enroll/claim" in code.replace(body, ""):
        errors.append("the claim redirect appears outside the tenant site")
    return errors


# Mutations of a rendered Caddyfile that the checks above must catch (template v11): (golden case, description, old,
# new). "admin public but the Keycloak console lost its forward_auth" is the one the owner's decision hinges on.
FWD = ("\t\t\tforward_auth api.:8080 {\n\t\t\t\turi /internal/edge/idp-console\n\t\t\t\timport upstream_headers\n"
       "\t\t\t\theader_up -Authorization\n\t\t\t}\n")
GUARDS = "\t\tabort @direct_tunnel\n\t\tabort @from_tenant_pool\n\t\trespond @unsafe_path 404\n\t\troute @idp_console"
MUTATIONS = [
    ("admin-public", "admin public, console without forward_auth", FWD, ""),
    ("admin-public", "admin public, console forward_auth to another uri", "uri /internal/edge/idp-console",
     "uri /internal/edge/ask"),
    ("admin-public", "admin public, forward_auth sends the console token to the api",
     "\t\t\t\theader_up -Authorization\n", ""),
    ("admin-public", "admin public, impersonation no longer refused on admin.", "\t\t\trespond @idp_impersonation 403\n", ""),
    ("admin-public", "admin public, idp proxied before the gate", "\t\troute @idp_console {\n",
     "\t\treverse_proxy /admin/* idp.:8080 {\n\t\t\timport upstream_headers\n\t\t}\n\t\troute @idp_console {\n"),
    ("admin-public", "admin public, tunnel guard dropped from admin.", GUARDS, GUARDS.replace("\t\tabort @direct_tunnel\n", "")),
    ("admin-public", "admin public, tenant pool no longer aborted on admin.", GUARDS,
     GUARDS.replace("\t\tabort @from_tenant_pool\n", "")),
    ("admin-public", "admin public, an allow-list left on admin.", GUARDS,
     GUARDS.replace("\t\tabort @from_tenant_pool\n", "\t\tabort @from_tenant_pool\n\t\tabort @outside_admin\n")),
    ("admin-public-lan", "admin public (LAN), console without forward_auth", FWD, ""),
    ("tunnel", "admin LAN-only, admin. added to the tunnel-facing listener", "admin.example.com {",
     "admin.example.com, admin.example.com:8443 {"),
    ("tunnel", "admin LAN-only, allow-list dropped", "\t\tabort @outside_admin\n", ""),
    ("tunnel", "admin LAN-only, console without forward_auth", FWD, ""),
]


def check_mutations() -> list[str]:
    """Every mutation of MUTATIONS must be caught by at least one check (a check that cannot fail proves nothing)."""
    missed = []
    for case, name, old, new in MUTATIONS:
        params = json.loads((GOLDEN / case / "params.json").read_text(encoding="utf-8"))
        caddy = re_.render(params)["caddy/Caddyfile"]
        if old not in caddy:
            missed.append(f"{name}: the text to mutate is not in the render of {case}")
            continue
        mutated = caddy.replace(old, new)
        errors = (check_structure(mutated, params) + check_platform_sites(mutated, params)
                  + check_idp_console(mutated, params) + check_web_auth(mutated, params))
        if not errors:
            missed.append(f"{name} ({case}): not caught")
    return missed


def check_admin_allow_optional() -> list[str]:
    """admin_allow is required for admin. LAN-only and optional with admin_public (template v11)."""
    base = json.loads((GOLDEN / "tunnel" / "params.json").read_text(encoding="utf-8"))
    no_allow = {k: v for k, v in base.items() if k != "admin_allow"}
    errors = []
    for params, want_ok in ((no_allow, False), ({**no_allow, "admin_public": False}, False),
                            ({**no_allow, "admin_public": True}, True)):
        try:
            caddy = re_.render(params)["caddy/Caddyfile"]
            if not want_ok:
                errors.append(f"accepted without admin_allow: admin_public={params.get('admin_public')!r}")
            elif "@outside_admin" in caddy:
                errors.append("admin_public without admin_allow still renders an allow-list")
        except (re_.ParamError, ValueError) as e:
            if want_ok:
                errors.append(f"refused admin_public without admin_allow: {e}")
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
            mode = "admin public — template v11" if params.get("admin_public") else "admin LAN-only"
            print(f"PASS {case.name}: app./admin./auth. invariants hold ({mode}, Admin API worker-only — P2-T16)")
        errors = check_idp_console(files["caddy/Caddyfile"], params)
        if errors:
            print(f"FAIL {case.name}: idp console: " + "; ".join(errors))
            failures += 1
        else:
            print(f"PASS {case.name}: Keycloak console only on admin. behind forward_auth, impersonation refused (P3-T15)")
        errors = check_web_auth(files["caddy/Caddyfile"], params)
        if errors:
            print(f"FAIL {case.name}: web-auth: " + "; ".join(errors))
            failures += 1
        else:
            print(f"PASS {case.name}: /register/<auth_id> ⇒ 302 claim of the Portal, via=portal ⇒ Headscale (P4-T07)")
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
    if not update:
        missed = check_mutations()
        if missed:
            print("FAIL mutations: " + "; ".join(missed))
            failures += 1
        else:
            print(f"PASS mutations: {len(MUTATIONS)}/{len(MUTATIONS)} caught (incl. admin public + console without "
                  "forward_auth)")
        errors = check_admin_allow_optional()
        if errors:
            print("FAIL admin_allow/admin_public: " + "; ".join(errors))
            failures += 1
        else:
            print("PASS admin_allow required unless admin_public (template v11)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
