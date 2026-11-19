"""admin.<domain> on the Internet — edge template v11, parameter admin_public (owner's decision 2026-11-20, §15.4) — on
the dev/CI stack. FUNCTIONAL only (§22.1).

The stack's edge has no tunnel-facing listener (infrastructure/environments/ci/edge.json). These cases render the stack's
Caddyfile again with `admin_public: true` and a tunnel whose peer is THIS host (its address on the edge network,
st.host_ip): the host plays the VPS's l4proxy — every connection to <edge>:8443 starts with a PROXY v2 header claiming an
Internet client's address. The edge validates the file (a temporary file next to the Caddyfile — the edge's rootfs and
/etc/caddy are read-only) and reloads it; the stack's own Caddyfile is reloaded again afterwards, whatever happened.

  E2E-121 admin. public through the tunnel-facing listener: the render (admin. on :8443, no allow-list, the Keycloak
          console route byte for byte the one of the LAN-only render); conformance `platform --admin public --proxy-v2`
          (SPA, /api/* to the api, every console path — /admin/*, master realm, /resources/*, impersonation — 401 of the
          api's forward_auth gate, never Keycloak; auth. and app. unchanged) through :8443 from an "Internet" address; on
          LAN-direct a container outside admin_allow is served (401 from the api) while admin_public is on; after the
          restore: :8443 refused, the same container closed again, this host still served
  E2E-122 the api sees the client's real address through PROXY v2: a Super Admin signs in through the tunnel from
          address X (Keycloak on auth.:8443 + TOTP) ⇒ sessions.ip = X; the console without an approved console session
          ⇒ 403; impersonation ⇒ 403 of the gate + critical security event; a console session requested from X ⇒
          source_cidr X/32 (default /32 of the request — §8.2 (3)); approved by the other Super Admin ⇒ the console
          loads from X; the same cookies from another Internet address Y (also with spoofed X-Forwarded-For/X-Real-IP/
          True-Client-IP/Forwarded = X) and from LAN-direct ⇒ 403 source_ip_not_allowed
Needs the two Super Admins of E2E-24 and E2E-42 (st.platform_sa, st.platform_sa2). Standard library only; cookies,
passwords and TOTP keys stay in this process (and its redaction set).
"""
from __future__ import annotations

import copy
import json
import random
import re
import secrets
import socket
import subprocess
import sys

from backend import Browser, portal_login, psql
from dualcontrol import psql_one
from idpadmin import approve, request_session
from stack import ROOT, Stack, StackError

sys.path.insert(0, str(ROOT / "tests" / "security" / "edge"))
import conformance  # noqa: E402 — the PROXY v2 header of the conformance suite (one implementation)

TUNNEL_PORT, TUNNEL_HTTP_PORT = 8443, 8080
ADDR_SESSION = "198.51.100.23"     # "Internet" client of E2E-122 (documentation range, never on the stack)
ADDR_OTHER = "203.0.113.77"        # another Internet address, same cookies
ADDR_CONFORMANCE = "203.0.113.50"  # source claimed by the conformance run of E2E-121
TMP_NAME = "Caddyfile.adminpub"
CONSOLE_ROUTE = re.compile(r"(?ms)^\t\troute @idp_console \{\n.*?\n\t\t\}\n")


class TunnelBrowser(Browser):
    """This host as the VPS's l4proxy: every connection goes to the edge's tunnel-facing port and starts with a PROXY v2
    header claiming `src` (destination port 443, as l4proxy forwards it)."""

    port = TUNNEL_PORT

    def __init__(self, st: Stack, src: str):
        super().__init__(st)
        self.src = src

    def dial(self) -> socket.socket:
        raw = super().dial()
        raw.sendall(conformance.proxy_v2(self.src, self.st.edge_ip, random.randint(20000, 60000)))
        return raw


def public_params(st: Stack) -> dict:
    """Overrides of the ci edge.json for E2E-121: admin_public + a tunnel whose peer is this host."""
    return {"admin_public": True, "tunnel": {"edge_tunnel_ipv4": st.edge_ip, "peer_ipv4": st.host_ip,
                                             "http_port": TUNNEL_HTTP_PORT, "https_port": TUNNEL_PORT}}


def render_public(st: Stack) -> str:
    return st.edge_files(**public_params(st))["caddy/Caddyfile"]


def render_issues(st: Stack, public: str, plain: str) -> list[str]:
    """The public render differs from the stack's where it must, and only there for the Keycloak console."""
    out = []
    d = re.escape(st.domain)
    if not re.search(rf"(?m)^admin\.{d}, admin\.{d}:{TUNNEL_PORT} \{{$", public):
        out.append("admin. not on the tunnel-facing port")
    if "@outside_admin" in public:
        out.append("allow-list still rendered")
    if "@outside_admin" not in plain:
        out.append("the stack's own render lost its allow-list")
    routes = (CONSOLE_ROUTE.findall(public), CONSOLE_ROUTE.findall(plain))
    if len(routes[0]) != 1 or routes[0] != routes[1]:
        out.append("console route differs from the LAN-only render")
    return out


def caddy(st: Stack, *args: str):
    return st.docker("exec", st.name("edge"), "caddy", *args, "--adapter", "caddyfile", check=False, timeout=120)


def reload(st: Stack, path: str) -> None:
    p = caddy(st, "reload", "--config", path, "--address", "unix//run/caddy/admin.sock")
    if p.returncode != 0:
        raise StackError(f"caddy reload {path}: {st.redact(p.stderr + p.stdout)[-600:]}")


def container_admin(st: Stack) -> str:
    """GET https://admin.<domain>/api/v1/auth/session from a container on the edge network (outside admin_allow, which
    is this host only): the HTTP status line, or "closed" when the edge closed the connection."""
    host = "admin." + st.domain
    p = st.docker("run", "--rm", "--name", st.name("pubprobe"), "--network", st.name("edge"), "--add-host",
                  f"{host}:{st.edge_ip}", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                  st.images["alpine"], "sh", "-c",
                  f"o=$(wget -q -S -O /dev/null --no-check-certificate https://{host}/api/v1/auth/session 2>&1); "
                  'printf %s "$o" | grep -m1 "HTTP/" || echo closed', check=False, timeout=60)
    return (p.stdout.strip().splitlines() or ["?"])[-1].strip()


def port_refused(st: Stack, port: int) -> bool:
    try:
        socket.create_connection((st.edge_ip, port), timeout=5).close()
        return False
    except OSError:
        return True


def conformance_run(st: Stack) -> tuple[bool, str]:
    try:
        p = subprocess.run([sys.executable, "-I", str(ROOT / "tests" / "security" / "edge" / "conformance.py"),
                            "platform", "--edge", st.edge_ip, "--port", str(TUNNEL_PORT), "--proxy-v2", ADDR_CONFORMANCE,
                            "--domain", st.domain, "--admin", "public", "--cafile", str(st.work / "ca" / "ca.crt")],
                           capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300)
    except subprocess.TimeoutExpired as e:
        raise StackError("conformance.py platform --admin public: timeout") from e
    lines = p.stdout.strip().splitlines()
    ok = p.returncode == 0 and bool(lines) and lines[-1].startswith("PASS platform sites") and "via PROXY v2" in lines[-1]
    fails = [ln for ln in lines if ln.startswith("FAIL")][:6]
    return ok, f"rc={p.returncode} {lines[-1] if lines else p.stderr[-200:]} {fails}"


def reasons_since(st: Stack, identity: str, t0: str) -> set[str]:
    """Reasons of the gate's refusals of `identity` audited since t0 (the gate audits one refusal per person, reason and
    minute — so a reason, not every request)."""
    rows = psql(st, "SELECT DISTINCT details ->> 'reason' FROM audit_events WHERE action = 'idp.console.access' AND "
                    f"actor_identity_id = '{identity}' AND occurred_at >= '{t0}'::timestamptz")
    return {x[0] for x in rows}


def sessions_part(st: Stack) -> tuple[bool, str]:
    """E2E-122 — runs while the public Caddyfile is loaded."""
    sa1, sa2 = getattr(st, "platform_sa", None), getattr(st, "platform_sa2", None)
    if not sa1 or not sa2:
        raise StackError("no Super Admins of E2E-24 / E2E-42 (st.platform_sa, st.platform_sa2)")
    admin_host = f"admin.{st.domain}"
    admin = f"https://{admin_host}"
    console = f"{admin}/admin/master/console/"
    # the requester: the second Super Admin (its only earlier console session — E2E-42 — is bound to 192.0.2.0/24)
    t0 = psql_one(st, "SELECT now()")
    bx = TunnelBrowser(st, ADDR_SESSION)
    s2, steps = portal_login(st, bx, admin_host, "scope=platform", sa2, sa2.get("otp"))
    sa2_id = psql_one(st, f"SELECT id FROM identities WHERE subject = '{sa2['sub']}'")
    sess_ip = psql_one(st, "SELECT host(ip) FROM sessions WHERE identity_id = "
                           f"'{sa2_id}' AND origin = 'admin' AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1")
    before = bx.get(console)
    target = "00000000-0000-4000-8000-0000000e2121"
    imp = bx.request("POST", f"{admin}/admin/realms/tenant-a/users/{target}/impersonation", b"", {"Origin": admin})
    imp_sec = psql_one(st, "SELECT severity FROM security_events WHERE kind = 'idp.console_impersonation_attempt' "
                           f"AND details ->> 'identity_id' = '{sa2_id}' AND details ->> 'ip' = '{ADDR_SESSION}' "
                           "ORDER BY occurred_at DESC LIMIT 1")
    req = request_session(st, bx, s2, {"reason": "E2E-122 admin public", "duration_minutes": 10},
                          "e2e-adminpub-" + secrets.token_hex(6))
    appr = req.json()
    cidr = (appr.get("payload") or {}).get("source_cidr")
    # the approver signs in through the tunnel too, from another Internet address
    b1 = TunnelBrowser(st, ADDR_OTHER)
    s1, _ = portal_login(st, b1, admin_host, "scope=platform", sa1, sa1.get("otp"))
    seen = b1.get(f"{admin}/api/v1/platform/approvals/{appr.get('id')}").json()
    done = approve(st, b1, s1, seen)
    executed = done.json().get("status")
    page = bx.get(console)
    html = page.body.decode("utf-8", "replace")
    env = re.search(r'<script id="environment" type="application/json">(.*?)</script>', html, re.S)
    envj = json.loads(env.group(1)) if env else {}
    # the same cookies elsewhere: another Internet address (spoofed forwarding headers too), then LAN-direct
    by = TunnelBrowser(st, ADDR_OTHER)
    by.jar = copy.deepcopy(bx.jar)
    other = by.get(console).status
    spoof = by.get(console, {"X-Forwarded-For": ADDR_SESSION, "X-Real-IP": ADDR_SESSION,
                             "True-Client-IP": ADDR_SESSION, "Forwarded": f"for={ADDR_SESSION}"}).status
    lan = Browser(st)
    lan.jar = copy.deepcopy(bx.jar)
    lan_status = lan.get(console).status
    reasons = reasons_since(st, sa2_id, t0)
    # decisive: the SAME cookies are let through from X and refused from Y and from LAN-direct — the only difference is the
    # address the edge took from the PROXY v2 header (or from the TCP peer on LAN-direct)
    ok = (sess_ip == ADDR_SESSION and before.status == 403 and "source_ip_not_allowed" in reasons
          and imp.status == 403 and imp.body.startswith(b"The Keycloak administration console") and imp_sec == "critical"
          and req.status == 202 and cidr == f"{ADDR_SESSION}/32" and executed == "executed"
          and page.status == 200 and envj.get("authUrl") == admin
          and other == 403 and spoof == 403 and lan_status == 403)
    return ok, (f"đăng nhập qua tunnel {steps} ⇒ sessions.ip {sess_ip}; console chưa duyệt {before.status}; "
                f"impersonation {imp.status} {imp.body[:40]!r} ({imp_sec}); xin {req.status} CIDR "
                f"{cidr}; duyệt {done.status} {executed}; console từ X {page.status} ({envj.get('authUrl')}); từ Y "
                f"{other}, Y + header giả {spoof}; LAN-direct {lan_status}; lý do từ chối đã audit {sorted(reasons)}")


def check_admin_public(r, st: Stack) -> None:
    caddy_dir = st.work / "render" / "edge" / "caddy"
    plain = (caddy_dir / "Caddyfile").read_text(encoding="utf-8")
    public = render_public(st)
    issues = render_issues(st, public, plain)
    tmp = caddy_dir / TMP_NAME
    tmp.write_text(public, encoding="utf-8", newline="\n")
    tmp.chmod(0o644)
    results: dict[str, tuple[bool, str]] = {}
    try:
        v = caddy(st, "validate", "--config", f"/etc/caddy/{TMP_NAME}")
        if v.returncode != 0:
            raise StackError(f"caddy validate {TMP_NAME}: {st.redact(v.stderr + v.stdout)[-600:]}")
        reload(st, f"/etc/caddy/{TMP_NAME}")
        conf_ok, conf = conformance_run(st)
        lan_public = container_admin(st)
        results["E2E-121"] = (conf_ok and lan_public.startswith("HTTP/") and " 401" in lan_public,
                              f"conformance {conf}; LAN-direct từ container ngoài admin_allow: {lan_public!r}")
        try:
            results["E2E-122"] = sessions_part(st)
        except (StackError, OSError, ValueError, KeyError) as e:
            results["E2E-122"] = (False, f"{type(e).__name__}: {e}")
    finally:
        reload(st, "/etc/caddy/Caddyfile")
        tmp.unlink(missing_ok=True)
    refused = port_refused(st, TUNNEL_PORT)
    lan_after = container_admin(st)
    host_after = Browser(st).get(f"https://admin.{st.domain}/api/v1/auth/session").status
    ok121, d121 = results.get("E2E-121", (False, "không chạy"))
    ok121 = ok121 and not issues and refused and lan_after == "closed" and host_after == 401
    r.add("E2E-121", "edge v11 admin_public: render (admin. trên :8443, không allow-list, route console Keycloak giống hệt "
          "bản LAN-only); conformance `platform --admin public --proxy-v2` qua listener tunnel-facing từ địa chỉ "
          "Internet (SPA, /api/* ⇒ api, mọi path console — /admin/*, realm master, /resources/*, impersonation — 401 "
          "của cổng forward_auth, không bao giờ Keycloak); LAN-direct: container ngoài admin_allow được phục vụ (401); "
          "trả Caddyfile của stack ⇒ :8443 bị từ chối, container lại bị đóng, host vẫn 401", ok121,
          f"render {issues or 'ok'}; {d121}; sau khi trả: :8443 refused {refused}, container {lan_after!r}, host "
          f"{host_after}", limit=1400)
    ok122, d122 = results.get("E2E-122", (False, "không chạy"))
    r.add("E2E-122", "edge v11 admin_public: api thấy đúng IP client qua PROXY v2 — Super Admin đăng nhập qua tunnel từ X "
          "(sessions.ip = X); console chưa duyệt ⇒ 403; impersonation ⇒ 403 của cổng + security event critical; phiên "
          "console xin từ X ⇒ source_cidr X/32, Super Admin kia (cũng qua tunnel) duyệt ⇒ console tải được từ X; cùng "
          "cookie từ Y (kể cả header chuyển tiếp giả = X) và từ LAN-direct ⇒ 403 source_ip_not_allowed", ok122, d122,
          limit=1400)


def run_all(r, st: Stack, guarded) -> None:
    guarded(r, "E2E-121", check_admin_public, st)
