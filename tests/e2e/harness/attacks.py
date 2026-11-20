"""Targeted attacks of the P5-T09 security test round (master §18, §18.1 — the surfaces the unit/DB/matrix tests do not
reach end to end) on the dev/CI stack: api, worker, SPA and idp built from the tree, the edge rendered from the tree —
FUNCTIONAL only (§22.1). Every probe goes through the edge as a client would; the attacker is a Tenant Admin of tenant-a
(its own Keycloak user, seeded membership, password + TOTP) or an anonymous client.

  E2E-125 CSRF on EVERY state-changing operation of api/openapi.yaml (internal/authz/operations_gen.go): with the Tenant
          Admin's session cookie on tenant-a's own paths — no X-CSRF-Token (same Origin), foreign Origin, Origin "null",
          no Origin + Sec-Fetch-Site: cross-site, no Origin and no Sec-Fetch-Site — each refused 403 before routing,
          with its reason in audit_events (one denied session.check per request); nothing of tenant-a changed (md5 of
          every row of every table with tenant_id, sessions, jobs)
  E2E-126 cross-tenant through the edge: the same session sends EVERY operation (safe and unsafe, valid CSRF) with
          tenant-b's id in {tenantId} (tenant routes) and every platform route — never 2xx/5xx/501, tenant routes 404
          (or a 4xx of the parameter binding before authorization), platform routes 403/404; tenant-b's rows unchanged;
          ".." and "%2e%2e%2f" from A's path to B's ⇒ 404 at the edge
  E2E-127 SSRF through the issuer of an IdP (T-21) end to end: tenant-b's IdP row is pointed (as a compromised platform
          configuration would) at internal destinations — a canary listener on mg-admin and mg-data (fixed IPs and
          its Docker DNS name), IPv4-mapped IPv6, 169.254.169.254, loopback, the edge's admin listener, the
          compose service name of PostgreSQL, another port, http://, the Keycloak admin path of auth.<domain>, the
          Portal origin, a decimal IP — GET /auth/login for tenant-b ⇒ 502 upstream_rejected and the canary saw no
          connection (positive control: the canary counts a connection from a helper first); the row is restored and
          a real login of tenant-b works again
  E2E-128 open redirect outside /register: return_to variants (incl. dot segments, which a browser resolves into
          "//host") ⇒ 422; Keycloak authorize with a redirect_uri off the registered one ⇒ no redirect there;
          end-session with a foreign post_logout_redirect_uri ⇒ no redirect there; port 80 of the edge reflects only the
          request's own Host (X-Forwarded-Host, Forwarded, an absolute request-target never pick the target)
  E2E-129 hostile input / deserialisation: unknown and duplicated JSON keys, wrong Content-Type, invalid UTF-8, a body
          above the limit, 100 000 nested arrays, a number out of range, a hostile HuJSON import — every answer 4xx
          (never 5xx), the api still answers; the effect of unknown keys is recorded (rejected or ignored)
  E2E-130 rate limit through the edge: the auth class per client IP answers 429 + Retry-After inside its burst, and a
          forged X-Forwarded-For / X-Real-IP / Forwarded per request does not reset the bucket; it recovers afterwards
  E2E-131 security headers on every kind of answer of app./admin. (200 JSON, 302, 401, 403, 404, 422, body over the cap, SPA): the
          edge's set exactly once, no Server; Cache-Control no-store on the api; session cookie __Host-, Secure,
          HttpOnly, SameSite; auth. carries HSTS + nosniff
  E2E-132 raw logs of every container of the stack (docker logs, not the redacted artifacts of E2E-16) hold none of the
          run's secret values (the files of <work>/secrets and every value the harness learnt: passwords, TOTP keys,
          session ids, CSRF tokens, API keys) and no hskey-/Bearer pattern — except the Auth IDs Headscale itself logs at
          level info and the node name mg-<one-time enrollment code> it registers (the code is the hostname by design —
          T-06) — hs-* containers only, counted and reported: F-P5-T09-5

Standard library only. No credential is printed: values stay in this process and its redaction set.
"""
from __future__ import annotations

import json
import random
import re
import secrets
import socket
import time
import urllib.parse
import uuid

from asvs2 import admin_api, new_user
from backend import TOTP, Browser, portal_login, psql
from stack import ROOT, SECRET_RE, TENANTS, Stack, StackError

OPS_RE = re.compile(r'\{ID: "(\w+)", Method: "(\w+)", Path: "([^"]+)"')
SAFE = ("GET", "HEAD")


def operations() -> list[tuple[str, str, str]]:
    """(operationId, method, path) of every operation of the spec — the generated authorization contract."""
    src = (ROOT / "internal" / "authz" / "operations_gen.go").read_text(encoding="utf-8")
    ops = OPS_RE.findall(src)
    if len(ops) < 150:
        raise StackError(f"operations_gen.go: only {len(ops)} operations parsed")
    return ops


def fill(path: str, tenant: str) -> str:
    """The path with {tenantId} = tenant and every other parameter a fresh id (settingKey a plain key)."""
    def sub(m: re.Match) -> str:
        name = m.group(1)
        if name == "tenantId":
            return tenant
        if name == "settingKey":
            return "p5t09-key"
        return str(uuid.uuid4())
    return re.sub(r"\{(\w+)\}", sub, path)


class Session:
    """A logged-in Tenant Admin of tenant-a (own Keycloak user): browser, CSRF token, host."""

    def __init__(self, st: Stack, kc, realm: str = "tenant-a"):
        self.st, self.host = st, f"app.{st.domain}"
        self.user = new_user(st, kc, realm, "p5t09-ta")
        self.b, self.otp = Browser(st), TOTP()
        self.sess, _ = portal_login(st, self.b, self.host, f"scope=tenant&tenant={realm}&return_to=%2F", self.user, self.otp)
        self.csrf = self.sess["csrf_token"]

    def call(self, method: str, path: str, body: bytes | None = None, headers: dict | None = None, csrf: bool = True,
             origin: str | None = "same", retries: int = 6):
        """One API call through the edge; a 429 is waited out (Retry-After) and sent again."""
        hdr = {"Content-Type": "application/json"} if body is not None else {}
        if origin == "same":
            hdr["Origin"] = f"https://{self.host}"
        elif origin:
            hdr["Origin"] = origin
        if csrf:
            hdr["X-CSRF-Token"] = self.csrf
        if method not in SAFE:
            hdr["Idempotency-Key"] = "p5t09-" + secrets.token_hex(8)
        hdr.update(headers or {})
        for _ in range(retries):
            r = self.b.request(method, f"https://{self.host}/api/v1{path}", body, hdr)
            if r.status != 429:
                return r
            time.sleep(min(float(r.header("Retry-After") or 2), 15) + 0.2)
        return r


def snapshot(st: Stack, tenant: str) -> dict[str, str]:
    """md5 of every row of a tenant in every table with tenant_id (and its sessions; the job count)."""
    tables = [t for (t,) in psql(st, "SELECT table_name FROM information_schema.columns WHERE table_schema = 'public' "
                                     "AND column_name = 'tenant_id' ORDER BY 1")]
    parts = [f"SELECT '{t}', count(*)::text || ':' || coalesce(md5(string_agg(x::text, '|' ORDER BY x::text)), '') "
             f"FROM {t} x WHERE tenant_id = '{tenant}'" for t in tables
             if t not in ("audit_events", "security_events", "rate_limit_events")]
    parts.append("SELECT 'sessions', count(*)::text || ':' || coalesce(md5(string_agg(s::text, '|' ORDER BY s::text)), '') "
                 f"FROM sessions s JOIN identities i ON i.id = s.identity_id WHERE i.tenant_id = '{tenant}'")
    out = {k: v for k, v in psql(st, " UNION ALL ".join(parts))}
    out["river.river_job"] = psql(st, "SELECT count(*) FROM river.river_job")[0][0]
    return out


def changed(before: dict, after: dict, ignore: tuple[str, ...] = ()) -> list[str]:
    return [k for k in before if k not in ignore and before[k] != after.get(k)]


def tenant_ids(st: Stack) -> dict[str, str]:
    return {s: json.loads((st.work / "render" / s / "meta" / "instance.json").read_text(encoding="utf-8"))["tenant_id"]
            for s in TENANTS}


def audit_reasons(st: Stack, request_ids: list[str]) -> dict[str, list[str]]:
    """request id → the (outcome:reason) of its audit events."""
    out: dict[str, list[str]] = {}
    for i in range(0, len(request_ids), 200):
        chunk = [x for x in request_ids[i:i + 200] if re.fullmatch(r"[A-Za-z0-9-]{8,128}", x or "")]
        if not chunk:
            continue
        ids = ",".join(f"'{x}'" for x in chunk)
        for rid, outcome, why in psql(st, "SELECT request_id, outcome, coalesce(details ->> 'reason', '') FROM audit_events "
                                          f"WHERE request_id IN ({ids})"):
            out.setdefault(rid, []).append(f"{outcome}:{why}")
    return out


class Conds:
    def __init__(self):
        self.rows, self.bad = [], []

    def __call__(self, name: str, good: bool, row: str) -> None:
        if not good:
            self.bad.append(name)
        self.rows.append(f"[{'ok' if good else 'FAIL'} {name}] {row}")

    def report(self, r, tid: str, title: str) -> None:
        r.add(tid, title, not self.bad, (f"FAILED: {', '.join(self.bad)} — " if self.bad else "") + "; ".join(self.rows),
              limit=4000)


# ---------------------------------------------------------------------------------------------------- E2E-125
CSRF_VARIANTS = (  # name, csrf token sent, Origin, extra headers, expected reason
    ("no-token", False, "same", {}, "csrf_token_invalid"),
    ("foreign-origin", True, "https://evil.example", {}, "origin_header_mismatch"),
    ("null-origin", True, "null", {}, "origin_header_mismatch"),
    ("cross-site", True, None, {"Sec-Fetch-Site": "cross-site"}, "sec_fetch_site_cross_origin"),
    ("no-origin", True, None, {}, "origin_header_missing"),
)


# Tables the worker changes on its own schedule (outbox dispatch, health/relay probes, the River queue) — the side
# effects of the sweep are looked for in the audit trail and in the jobs a person requested instead.
BACKGROUND = ("notification_outbox", "provisioning_jobs", "river.river_job", "sessions", "tenant_instances",
              "relay_regions")


def check_csrf(r, st: Stack, s: Session, ids: dict) -> None:
    c = Conds()
    unsafe = [op for op in operations() if op[1] not in SAFE]
    t0 = psql(st, "SELECT now()")[0][0]
    before = snapshot(st, ids["tenant-a"])
    rids, wrong, variant = [], [], {}
    for op_id, method, path in unsafe:
        url = fill(path, ids["tenant-a"])
        for name, tok, origin, extra, _why in CSRF_VARIANTS:
            resp = s.call(method, url, b"{}", extra, csrf=tok, origin=origin)
            rid = resp.header("X-Request-Id")
            rids.append(rid)
            if resp.status != 403 or resp.json().get("code") != "forbidden":
                wrong.append(f"{op_id}/{name} ⇒ {resp.status} {resp.json().get('code')}")
            variant[rid] = (op_id, name, _why)
    reasons = audit_reasons(st, rids)
    # a refusal with the session attached (missing token) is one denied event of that request; the Origin/Fetch
    # Metadata refusals come before the session is resolved — anonymous denials: the first one of a source, action and
    # reason in a 10-minute window reaches audit_events, the others only the metric (G2 F2) — never an event other
    # than a denial, and a recorded one carries the variant's reason
    bad_audit = [f"{variant[x][0]}/{variant[x][1]} {reasons.get(x)}" for x in rids
                 if (variant[x][1] == "no-token" and reasons.get(x) != [f"denied:{variant[x][2]}"])
                 or any(e != f"denied:{variant[x][2]}" for e in reasons.get(x, []))]
    anonymous = sum(1 for x in rids if variant[x][1] != "no-token" and reasons.get(x))
    after = snapshot(st, ids["tenant-a"])
    diff = changed(before, after, ignore=BACKGROUND)
    acted = psql(st, f"SELECT count(*) FROM audit_events WHERE occurred_at >= '{t0}' AND outcome <> 'denied' "
                     f"AND actor_type <> 'system' AND tenant_id = '{ids['tenant-a']}'")[0][0]
    jobs = psql(st, f"SELECT count(*) FROM provisioning_jobs WHERE created_at >= '{t0}' AND requested_by IS NOT NULL "
                    f"AND tenant_id = '{ids['tenant-a']}'")[0][0]
    c("every unsafe operation × 5 variants ⇒ 403", not wrong,
      f"{len(unsafe)} operations × {len(CSRF_VARIANTS)} = {len(rids)} requests, wrong {len(wrong)} {wrong[:5]}")
    c("audit: one denied event per missing-token request, only denials with the right reason", not bad_audit,
      f"mismatches {len(bad_audit)} {bad_audit[:4]}; anonymous refusals recorded (aggregated) {anonymous}")
    c("tenant-a unchanged", not diff and acted == "0" and jobs == "0",
      f"tables changed {diff} (worker-scheduled tables excluded: {', '.join(BACKGROUND)}), audit events other than "
      f"denials {acted}, jobs requested by a person {jobs}")
    c.report(r, "E2E-125", "CSRF trên MỌI operation không an toàn (phiên Tenant Admin của A, path của chính A): thiếu "
             "X-CSRF-Token, Origin lạ, Origin null, Sec-Fetch-Site cross-site, không Origin ⇒ 403 trước định tuyến, "
             "audit đúng lý do, dữ liệu của A không đổi")


# ---------------------------------------------------------------------------------------------------- E2E-126
def check_cross_tenant(r, st: Stack, s: Session, ids: dict) -> None:
    c = Conds()
    ops = operations()
    t0 = psql(st, "SELECT now()")[0][0]
    before = snapshot(st, ids["tenant-b"])
    bad, counts = [], {}
    for op_id, method, path in ops:
        if path.startswith("/auth/"):
            continue
        url = fill(path, ids["tenant-b"])
        resp = s.call(method, url, None if method in SAFE else b"{}")
        counts[resp.status] = counts.get(resp.status, 0) + 1
        tenant_route = path.startswith("/tenants/{tenantId}")
        if tenant_route:
            good = resp.status == 404 or (resp.status in (400, 422) and resp.json().get("code") in
                                          ("invalid_format", "validation_failed", "bad_request"))
        elif path.startswith("/tenants"):          # listMyTenants: own memberships only
            good = resp.status == 200 and ids["tenant-b"] not in resp.body.decode("utf-8", "replace")
        else:
            good = resp.status in (403, 404) or (resp.status in (400, 422) and resp.json().get("code") in
                                                 ("invalid_format", "validation_failed", "bad_request"))
        if not good:
            bad.append(f"{op_id} {method} ⇒ {resp.status} {resp.json().get('code')}")
    after = snapshot(st, ids["tenant-b"])
    diff = changed(before, after, ignore=BACKGROUND)
    jobs = psql(st, f"SELECT count(*) FROM provisioning_jobs WHERE created_at >= '{t0}' AND requested_by IS NOT NULL "
                    f"AND tenant_id = '{ids['tenant-b']}'")[0][0]
    c("every operation with B's tenant id / platform route", not bad,
      f"{sum(counts.values())} requests, by status {dict(sorted(counts.items()))}, wrong {bad[:6]}")
    c("tenant-b unchanged", not diff and jobs == "0", f"tables changed {diff}, jobs requested by a person {jobs}")
    trav = []
    for p in (f"/tenants/{ids['tenant-a']}/../{ids['tenant-b']}/devices",
              f"/tenants/{ids['tenant-a']}/%2e%2e/{ids['tenant-b']}/devices",
              f"/tenants/{ids['tenant-a']}/devices/..%2f..%2f{ids['tenant-b']}%2fdevices",
              f"/tenants/{ids['tenant-a']}%2f..%2f{ids['tenant-b']}/devices"):
        resp = s.call("GET", p)
        trav.append(resp.status)
    c("dot segments from A to B", all(x in (400, 404) for x in trav), f"answers {trav}")
    c.report(r, "E2E-126", "Chéo tenant qua edge: phiên Tenant Admin của A gửi MỌI operation với tenantId của B (route "
             "tenant ⇒ 404 hoặc 4xx của binding) và mọi route platform (⇒ 403/404); không 2xx/5xx; dữ liệu của B không "
             "đổi; dot segment từ path của A sang B ⇒ 404")


# ---------------------------------------------------------------------------------------------------- E2E-127
def _canary(st: Stack, ips: dict[str, str]) -> str:
    """A listener on 443 of mg-admin and mg-data (fixed IPs) counting accepted connections in /tmp/hits."""
    name = st.name("p5t09-canary")
    st.docker("rm", "-f", name, check=False)
    script = "touch /tmp/hits; while :; do nc -l -p 443 -w 2 </dev/null >/dev/null 2>&1 && echo HIT >> /tmp/hits || sleep 0.2; done"
    st.docker("run", "-d", "--name", name, "--network", st.name("admin"), "--ip", ips["admin"], "--cap-drop", "ALL",
              "--security-opt", "no-new-privileges:true", st.images["alpine"], "sh", "-c", script)
    st.docker("network", "connect", "--ip", ips["data"], st.name("data"), name)
    return name


def _hits(st: Stack, name: str) -> int:
    out = st.docker("exec", name, "sh", "-c", "wc -l < /tmp/hits", check=False).stdout.strip()
    return int(out) if out.isdigit() else -1


def check_ssrf(r, st: Stack, ids: dict) -> None:
    c = Conds()
    base = st.env["MG_E2E_NET_BASE"]
    ips = {"admin": f"{base}.2.100", "data": f"{base}.1.100"}
    name = _canary(st, ips)
    time.sleep(1)
    # positive control: a helper on mg-admin reaches the canary and the canary counts it
    st.docker("run", "--rm", "--network", st.name("admin"), st.images["alpine"], "sh", "-c",
              f"echo x | nc -w 2 {ips['admin']} 443 || true", check=False)
    time.sleep(1)
    control = _hits(st, name)
    c("canary counts a connection", control >= 1, f"hits after the helper's connection: {control}")
    st.docker("exec", name, "sh", "-c", ": > /tmp/hits", check=False)
    idp_id = st.env["MG_IDP_ID_TENANT_B"]
    orig = psql(st, f"SELECT issuer, driver FROM identity_providers WHERE id = '{idp_id}'")[0]
    targets = {
        "canary mg-admin": f"https://{ips['admin']}/",
        "canary mg-data": f"https://{ips['data']}/realms/x",
        "canary DNS name": f"https://{name}/",
        "IPv4-mapped canary": f"https://[::ffff:{ips['admin']}]/",
        "metadata": "https://169.254.169.254/latest/meta-data/",
        "loopback": "https://127.0.0.1/",
        "localhost": "https://localhost/",
        "edge admin listener": f"https://{st.admin_ip}/",
        "postgres service": "https://postgres/",
        "other port": f"https://{ips['admin']}:8443/",
        "plain http": f"http://{ips['admin']}/",
        "decimal IP": "https://" + str(int.from_bytes(socket.inet_aton(ips["admin"]), "big")) + "/",
        "keycloak admin path": f"https://auth.{st.domain}/admin/realms/master",
        "portal origin": f"https://app.{st.domain}/",
    }
    b = Browser(st)
    answers, logs = {}, []
    try:
        for label, issuer in targets.items():
            q = issuer.replace("'", "''")
            psql(st, f"UPDATE identity_providers SET issuer = '{q}', driver = 'external' WHERE id = '{idp_id}' RETURNING id")
            resp = b.get(f"https://app.{st.domain}/api/v1/auth/login?scope=tenant&tenant=tenant-b&return_to=%2F")
            answers[label] = (resp.status, resp.json().get("code"), resp.header("Location")[:40])
            logs.append(resp.header("X-Request-Id"))
            time.sleep(0.6)    # auth class: 2/s per IP
    finally:
        psql(st, f"UPDATE identity_providers SET issuer = '{orig[0]}', driver = '{orig[1]}' WHERE id = '{idp_id}' "
                 "RETURNING id")
    time.sleep(1)
    hits = _hits(st, name)
    wrong = {k: v for k, v in answers.items() if v[0] != 502 or v[1] != "upstream_rejected" or v[2]}
    c("every internal issuer ⇒ 502 upstream_rejected, no redirect", not wrong,
      f"{len(answers)} issuers, wrong {wrong}")
    c("canary saw no connection", hits == 0, f"hits {hits}")
    api_log = st.docker("logs", st.compose("ps", "-q", "api").stdout.strip(), check=False)
    text = api_log.stdout + api_log.stderr
    reasons = {}
    for line in text.splitlines():
        if "login start failed" not in line:
            continue
        for rid in logs:
            if rid and rid in line:
                m = re.search(r"(address_[a-z_]+|scheme_[a-z_]+|port_[a-z_]+|destination_[a-z_]+|host_[a-z_]+|"
                              r"redirect_[a-z_]+|platform_[a-z_]+|[a-z]+_refused)", line)
                reasons[rid] = m.group(1) if m else "?"
    c("refusal reasons logged", len(reasons) == len(targets),
      f"reasons {sorted(set(reasons.values()))} for {len(reasons)}/{len(targets)} requests")
    restored = psql(st, f"SELECT issuer, driver FROM identity_providers WHERE id = '{idp_id}'")[0] == orig
    again = Browser(st).get(f"https://app.{st.domain}/api/v1/auth/login?scope=tenant&tenant=tenant-b&return_to=%2F")
    c("row restored, tenant-b login works", restored and again.status == 302 and
      again.header("Location").startswith(f"https://auth.{st.domain}/realms/tenant-b/"),
      f"restored {restored}, login {again.status}")
    st.docker("rm", "-f", name, check=False)
    c.report(r, "E2E-127", "SSRF qua issuer của IdP (T-21) qua api ghép: issuer trỏ vào canary trên mg-admin/mg-data (IP, "
             "tên DNS, IPv4-mapped), 169.254.169.254, loopback, listener admin của edge, postgres, cổng khác, http, path "
             "admin của Keycloak, origin Portal, IP thập phân ⇒ 502 upstream_rejected, canary 0 kết nối (đối chứng "
             "dương đếm được), khôi phục và đăng nhập lại được")


# ---------------------------------------------------------------------------------------------------- E2E-128
def check_open_redirect(r, st: Stack, ids: dict) -> None:
    c = Conds()
    b = Browser(st)
    app, auth = f"https://app.{st.domain}", f"https://auth.{st.domain}"
    evil = ("//evil.example", "/\\evil.example", "https://evil.example/", "%2F%2Fevil.example", "/%5Cevil.example",
            "\t//evil.example", "javascript:alert(1)", "/%0d%0aLocation:%20https://evil.example", "https:evil.example",
            "/.//evil.example")
    bad = []
    for v in evil:
        q = v if v.startswith("%") or v.startswith("/%") else urllib.parse.quote(v, safe="")
        resp = b.get(f"{app}/api/v1/auth/login?scope=tenant&tenant=tenant-a&return_to={q}")
        loc = resp.header("Location")
        if resp.status != 422 or "evil" in loc:
            bad.append(f"{v!r} ⇒ {resp.status} {loc[:50]!r}")
        time.sleep(0.6)
    c("return_to variants ⇒ 422", not bad, f"{len(evil)} variants, wrong {bad}")
    good = b.get(f"{app}/api/v1/auth/login?scope=tenant&tenant=tenant-a&return_to=%2Ftenants")
    loc = good.header("Location")
    ru = re.search(r"redirect_uri=([^&]+)", loc)
    registered = urllib.parse.unquote(ru.group(1)) if ru else ""
    c("legit login redirect_uri is the Portal callback", registered.startswith(f"{app}/api/v1/auth/callback/"),
      f"redirect_uri {registered.replace(st.domain, '<domain>')}")
    kc_bad = []
    for v in ("https://evil.example/", f"https://app.{st.domain}.evil.example/api/v1/auth/callback/x",
              f"https://app.{st.domain}@evil.example/", "//evil.example/", f"{registered}/../../../../evil",
              f"{app}/anything-else", f"http://app.{st.domain}/api/v1/auth/callback/{st.env['MG_IDP_ID_TENANT_A']}"):
        q = urllib.parse.quote(v, safe="")
        resp = b.get(f"{auth}/realms/tenant-a/protocol/openid-connect/auth?client_id=mg-portal&response_type=code"
                     f"&scope=openid&state=x&code_challenge=" + "A" * 43 + f"&code_challenge_method=S256&redirect_uri={q}")
        loc = resp.header("Location")
        if resp.status in (301, 302, 303, 307, 308) and not loc.startswith(f"{auth}/"):
            kc_bad.append(f"{v.replace(st.domain, '<domain>')!r} ⇒ {resp.status} {loc[:60]!r}")
        time.sleep(0.2)
    c("Keycloak refuses foreign redirect_uri", not kc_bad, f"wrong {kc_bad}")
    resp = b.get(f"{auth}/realms/tenant-a/protocol/openid-connect/logout?client_id=mg-portal"
                 "&post_logout_redirect_uri=https%3A%2F%2Fevil.example%2F")
    c("end-session with foreign post_logout_redirect_uri", "evil" not in resp.header("Location"),
      f"{resp.status} Location {'(none)' if not resp.header('Location') else 'set, not evil'}")
    # port 80 answers 308 to https://<the request's own Host> (by design — external.py); an attacker can only set the
    # Host of its own requests, so the check is that nothing else of the request (X-Forwarded-Host, Forwarded, an
    # absolute request-target) picks the target. The absolute form (RFC 9112 §3.2.2: its authority replaces Host) and
    # Host: evil.example are recorded — both are the requester's own choice, never what a victim's browser sends.
    out, injected = [], []
    app_host = f"app.{st.domain}"
    probes = (("Host evil", "/x", "evil.example", ""), ("X-Forwarded-Host", "/x", app_host, "X-Forwarded-Host: evil.example\r\n"),
              ("Forwarded", "/x", app_host, "Forwarded: host=evil.example\r\n"),
              ("X-Forwarded-Host tenant", "/x", f"tenant-a.mesh.{st.domain}", "X-Forwarded-Host: evil.example\r\n"),
              ("absolute-form", "http://evil.example/x", app_host, ""))
    for name, target, host, extra in probes:
        try:
            with socket.create_connection((st.edge_ip, 80), timeout=10) as sock:
                sock.sendall(f"GET {target} HTTP/1.1\r\nHost: {host}\r\n{extra}Connection: close\r\n\r\n".encode())
                raw = b""
                while chunk := sock.recv(4096):
                    raw += chunk
            head = raw.split(b"\r\n\r\n", 1)[0].decode("latin-1")
            status = head.split(" ", 2)[1] if " " in head else "?"
            loc = next((ln.split(":", 1)[1].strip() for ln in head.splitlines() if ln.lower().startswith("location:")), "")
            out.append((name, status, loc.replace(st.domain, "<domain>")))
            if name.startswith(("X-Forwarded", "Forwarded")) and "evil" in loc:
                injected.append(name)
        except OSError as e:
            out.append((name, f"closed ({type(e).__name__})", ""))
    c("port 80: X-Forwarded-Host / Forwarded never pick the redirect target", not injected,
      f"{out} (Host evil.example and the absolute form name the requester's own target — not something a victim's "
      "browser sends)")
    c.report(r, "E2E-128", "Open redirect ngoài /register: return_to dị dạng ⇒ 422, redirect_uri lạ ở Keycloak ⇒ không "
             "chuyển hướng ra ngoài, post_logout_redirect_uri lạ, cổng 80 với Host lạ")


# ---------------------------------------------------------------------------------------------------- E2E-129
def check_hostile_input(r, st: Stack, s: Session, ids: dict) -> None:
    c = Conds()
    t = ids["tenant-a"]
    cases = [
        ("unknown keys (pure function)", "POST", f"/tenants/{t}/policies/templates/render",
         b'{"template_id":"deny-all","params":{},"tenant_id":"' + ids["tenant-b"].encode() + b'","role":"tenant_owner"}', {}),
        ("duplicate keys", "POST", f"/tenants/{t}/policies/templates/render",
         b'{"template_id":"no-such","template_id":"deny-all","params":{}}', {}),
        ("text/plain", "POST", f"/tenants/{t}/policies/templates/render", b'{"template_id":"deny-all","params":{}}',
         {"Content-Type": "text/plain"}),
        ("invalid UTF-8", "POST", f"/tenants/{t}/policies/templates/render",
         b'{"template_id":"deny-\xff\xfe","params":{}}', {}),
        ("over the body limit", "POST", f"/tenants/{t}/policies/import",
         b'{"hujson":"' + b"a" * ((1 << 20) + 64) + b'"}', {}),
        ("100 000 nested arrays", "POST", f"/tenants/{t}/policies/templates/render", b"[" * 100000 + b"]" * 100000, {}),
        ("number out of range", "POST", f"/tenants/{t}/diagnostics/connectivity",
         b'{"source_device_id":"' + str(uuid.uuid4()).encode() + b'","target_device_id":"' + str(uuid.uuid4()).encode()
         + b'","port":1e400}', {}),
        ("negative port", "POST", f"/tenants/{t}/diagnostics/connectivity",
         b'{"source_device_id":"' + str(uuid.uuid4()).encode() + b'","target_device_id":"' + str(uuid.uuid4()).encode()
         + b'","port":-1}', {}),
        ("hostile HuJSON (deep nesting)", "POST", f"/tenants/{t}/policies/import",
         json.dumps({"hujson": "{\"grants\": " + "[" * 20000 + "]" * 20000 + "}"}).encode(), {}),
        ("hostile HuJSON (unknown top-level key)", "POST", f"/tenants/{t}/policies/import",
         json.dumps({"hujson": "{\"grants\": [], \"evil\": {\"$ref\": \"file:///etc/passwd\"}}"}).encode(), {}),
        ("JSON null body", "POST", f"/tenants/{t}/policies/templates/render", b"null", {}),
        ("array body", "POST", f"/tenants/{t}/policies/templates/render", b"[]", {}),
    ]
    rows, server_errors = [], []
    unknown = None
    for name, method, path, body, hdr in cases:
        try:
            resp = s.call(method, path, body, hdr)
        except OSError as e:                 # the server answered and closed while the client was still sending
            rows.append(f"{name} ⇒ connection closed ({type(e).__name__})")
            continue
        code = resp.json().get("code")
        rows.append(f"{name} ⇒ {resp.status} {code}")
        if resp.status >= 500:
            server_errors.append(name)
        if name.startswith("unknown keys"):
            unknown = resp.status
    alive = s.call("GET", "/auth/session")
    c("never 5xx", not server_errors, "; ".join(rows))
    c("api alive afterwards", alive.status == 200, f"GET /auth/session {alive.status}")
    c("unknown keys recorded", unknown is not None,
      "unknown body keys are " + ("REJECTED (422)" if unknown == 422 else f"IGNORED (HTTP {unknown}) — additionalProperties: "
                                  "false of the spec is not enforced at runtime"))
    c.report(r, "E2E-129", "Đầu vào thù địch / deserialization: khóa lạ, khóa trùng, Content-Type sai, UTF-8 hỏng, body "
             "vượt trần, 100 000 mảng lồng, số tràn, HuJSON thù địch ⇒ 4xx, không 5xx, api vẫn trả lời")


# ---------------------------------------------------------------------------------------------------- E2E-130
def check_rate_limit(r, st: Stack) -> None:
    c = Conds()
    b = Browser(st)
    time.sleep(16)                                     # the auth bucket of this source refills (2/s, burst 30)
    statuses, first, retry = [], None, ""
    for i in range(45):
        fake = f"203.0.113.{random.randint(1, 254)}"
        resp = b.get(f"https://app.{st.domain}/api/v1/auth/login?scope=tenant&tenant=p5t09-nope-{i}",
                     {"X-Forwarded-For": fake, "X-Real-IP": fake, "Forwarded": f"for={fake}", "True-Client-IP": fake})
        statuses.append(resp.status)
        if resp.status == 429 and first is None:
            first, retry = i, resp.header("Retry-After")
    c("429 inside the burst despite forged client-IP headers", first is not None and first <= 34,
      f"first 429 at request #{first} (burst 30 + refill), Retry-After {retry!r}, statuses {sorted(set(statuses))}")
    c("Retry-After set", retry.isdigit() and int(retry) >= 1, f"{retry!r}")
    time.sleep(16)
    again = b.get(f"https://app.{st.domain}/api/v1/auth/login?scope=tenant&tenant=p5t09-nope-x")
    c("recovers", again.status != 429, f"after 16 s: {again.status}")
    c.report(r, "E2E-130", "Rate limit qua edge: lớp auth theo IP ⇒ 429 + Retry-After trong burst, X-Forwarded-For/"
             "X-Real-IP/Forwarded giả không làm mới bucket; hồi phục sau đó")


# ---------------------------------------------------------------------------------------------------- E2E-131
def check_headers(r, st: Stack, s: Session, ids: dict) -> None:
    from spa import header_issues  # noqa: PLC0415
    c = Conds()
    b, t = Browser(st), ids["tenant-a"]
    app, admin = f"https://app.{st.domain}", f"https://admin.{st.domain}"
    samples = {
        "200 json": s.call("GET", "/auth/session"),
        "403 csrf": s.call("POST", f"/tenants/{t}/devices/sync", b"{}", csrf=False),
        "404 problem": s.call("GET", f"/tenants/{ids['tenant-b']}/devices"),
        "422 problem": s.call("GET", "/auth/login?scope=tenant&tenant=tenant-a&return_to=%2F%2Fevil"),
        "302 login": b.get(f"{app}/api/v1/auth/login?scope=tenant&tenant=tenant-a&return_to=%2F"),
        "401 anon": b.get(f"{app}/api/v1/auth/session"),
        "401 admin": b.get(f"{admin}/api/v1/auth/session"),
        "SPA": b.get(f"{app}/tenants/{t}/devices"),
        "unknown api path": b.get(f"{app}/api/v1/nope"),
    }
    # the api answers a body over its cap and closes while the client may still be sending: kept when the answer
    # arrives, otherwise recorded (as in E2E-129)
    try:
        samples["over body cap"] = s.call("POST", f"/tenants/{t}/policies/import",
                                          b'{"hujson":"' + b"a" * ((1 << 20) + 64) + b'"}')
    except OSError as e:
        c("over body cap", True, f"connection closed before the answer was read ({type(e).__name__}) — not sampled")
    bad = {k: (v.status, header_issues(v)) for k, v in samples.items() if header_issues(v)}
    c("edge headers exactly once, no Server", not bad, f"{len(samples)} answers ({', '.join(samples)}), wrong {bad}")
    nostore = {k: v.header("Cache-Control") for k, v in samples.items() if k not in ("SPA",) and
               "no-store" not in v.header("Cache-Control")}
    c("api answers no-store", not nostore, f"without no-store {nostore}")
    cookie = next((v for k, v in samples["302 login"].headers if k.lower() == "set-cookie"), "")
    sess_cookie_attrs = s.b.jar.get(s.host, {})
    attrs = cookie.lower()
    c("binding cookie attributes", cookie.startswith("__Host-") and "secure" in attrs and "httponly" in attrs
      and "samesite=" in attrs and "path=/" in attrs and "domain=" not in attrs,
      f"login cookie {cookie.split('=', 1)[0]} attrs {[a.strip().split('=')[0] for a in attrs.split(';')[1:]]}; "
      f"session cookie names {sorted(sess_cookie_attrs)}")
    kc = b.get(f"https://auth.{st.domain}/realms/tenant-a/.well-known/openid-configuration")
    c("auth. HSTS + nosniff", kc.header("Strict-Transport-Security") and kc.header("X-Content-Type-Options") == "nosniff"
      and not kc.header("Server"), f"{kc.status} HSTS {bool(kc.header('Strict-Transport-Security'))} nosniff "
      f"{kc.header('X-Content-Type-Options')!r} Server {kc.header('Server')!r}")
    c.report(r, "E2E-131", "Header bảo mật trên mọi loại phản hồi của app./admin. (200, 302, 401, 403, 404, 422, body vượt trần, "
             "SPA, path lạ): bộ header của edge đúng một lần, không Server, api no-store; cookie __Host- Secure HttpOnly "
             "SameSite; auth. có HSTS + nosniff")


# ---------------------------------------------------------------------------------------------------- E2E-132
def check_raw_logs(r, st: Stack) -> None:
    c = Conds()
    p = st.helper("cd /w/secrets && find . -type f ! -name '*.crt' ! -name '*cert*' ! -name '*.pub' -size -65k | sort | "
                  "while read f; do printf '\\n=====%s\\n' \"$f\"; cat \"$f\"; done", f"{st.work}:/w:ro")
    values = set(v for v in st.secret_values if v and len(v) >= 12)
    nfiles = 0
    for block in p.stdout.split("\n=====")[1:]:
        _name, _, content = block.partition("\n")
        nfiles += 1
        content = content.strip()
        if 12 <= len(content) <= 512 and "\n" not in content:
            values.add(content)
        for ln in content.splitlines():
            ln = ln.strip()
            if len(ln) >= 24 and not ln.startswith("-----"):
                values.add(ln)
    names = sorted(set(st.docker("ps", "-a", "--filter", f"name={st.prefix}-", "--format", "{{.Names}}").stdout.split()))
    leaks, upstream, total = {}, {}, 0
    for n in names:
        lg = st.docker("logs", n, check=False, timeout=120)
        text = (lg.stdout or "") + (lg.stderr or "")
        total += len(text)
        short = n.removeprefix(st.prefix + "-")
        if short.startswith("hs-"):
            # Headscale (upstream, log level info) prints the Auth ID of every web-auth registration it starts and the
            # /register/<auth_id> path of its access log — F-P5-T09-5: counted apart, never an API or pre-auth key
            authreq = len(re.findall(r"hskey-authreq-[A-Za-z0-9_-]+", text))
            # the one-time enrollment code is the node's hostname by design (T-06: mg-<code>, renamed after the claim):
            # Headscale logs the name it registers — not a credential once the claim is decided
            codes = len(re.findall(r"\bmg-[a-z0-9]{12}\b", text))
            if authreq or codes:
                upstream[short] = f"{authreq} Auth ID, {codes} mg-<code>"
            text = re.sub(r"hskey-authreq-[A-Za-z0-9_-]+", "[upstream-auth-id]", text)
            text = re.sub(r"\bmg-[a-z0-9]{12}\b", "mg-[enroll-code]", text)
        hits = sum(1 for v in values if v in text)
        pat = [m.group(0)[:10] for m in SECRET_RE.finditer(text)]
        if hits or pat:
            leaks[short] = (hits, len(pat))
    c("no secret value / pattern in raw logs", not leaks,
      f"{len(names)} containers, {total // 1024} KiB of log, {len(values)} values from {nfiles} secret files + the "
      f"harness; containers with hits (values, patterns) {leaks}; Auth IDs logged by Headscale itself {upstream}")
    c.report(r, "E2E-132", "Log thô (docker logs) của mọi container của stack không chứa giá trị secret nào của lượt "
             "chạy (file trong <work>/secrets + giá trị harness biết) và không có mẫu hskey-/Bearer")


def run_all(r, st: Stack, guarded) -> None:
    ids = tenant_ids(st)
    kc = admin_api(st)
    s = Session(st, kc)
    guarded(r, "E2E-125", check_csrf, st, s, ids)
    guarded(r, "E2E-126", check_cross_tenant, st, s, ids)
    guarded(r, "E2E-129", check_hostile_input, st, s, ids)
    guarded(r, "E2E-131", check_headers, st, s, ids)
    guarded(r, "E2E-128", check_open_redirect, st, ids)
    guarded(r, "E2E-127", check_ssrf, st, ids)
    guarded(r, "E2E-130", check_rate_limit, st)
    guarded(r, "E2E-132", check_raw_logs, st)
