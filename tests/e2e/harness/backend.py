"""Backend checks of the dev/CI stack (P2-T16) — FUNCTIONAL only (§22.1): api and worker built from the tree, wired
against the stack's PostgreSQL, Keycloak, edge and two Headscale, reached as a client would — through the edge, with the
run's internal CA.

  E2E-17  api/worker healthy: /readyz green (postgres, secretstore, edge_admin); hardened containers
  E2E-18  edge → api: unauthenticated GET /api/v1/auth/session ⇒ 401 problem+json, security headers; the api refuses
          any peer but the edge (403)
  E2E-19  edge → idp: public OIDC endpoints only; Admin REST API, master realm, console ⇒ 404 from any source but the
          worker; admin. only from the allowed source
  E2E-20  worker `admin idp-bootstrap` (stdin = break-glass password) through the edge from the worker's address; the
          worker restarted with its keycloak driver provisioned
  E2E-21  admin commands of the api: register-platform-idp, adopt-instance A and B (API key from stdin), client
          secrets (stdin) — their audit events in audit_events (actor_type system)
  E2E-22  OIDC login with TOTP through the edge on app. (Tenant Owner of A seeded by sub): session, own tenant only,
          tenant B ⇒ 404
  E2E-23  device sync through the API (CSRF + Idempotency-Key) run by the worker; job read back (tenant view);
          devices a1/a2; dashboard with real figures
  E2E-24  Super Admin login (TOTP) on admin.: platform health, tenants, jobs (raw detail only on the platform view);
          tenant routes ⇒ 403 without a support grant
  E2E-25  audit_events rows of the whole flow (login, adopt, sync, denials) and no security event raised
Standard library only. No credential is printed or put on a command line: passwords, API keys, client secrets, TOTP
keys and cookies live in this process (and its redaction set) and reach commands only through stdin.
"""
from __future__ import annotations

import hashlib
import hmac
import html
import http.client
import json
import os
import re
import secrets
import socket
import ssl
import struct
import subprocess
import time
import urllib.parse
import urllib.request

from stack import ROOT, TENANTS, Stack, StackError

UA = "mg-e2e-backend/1.0"


# ---------------------------------------------------------------------------------------------------- browser
class Resp:
    def __init__(self, status: int, headers: list[tuple[str, str]], body: bytes):
        self.status, self.headers, self.body = status, headers, body

    def header(self, name: str) -> str:
        return next((v for k, v in self.headers if k.lower() == name.lower()), "")

    def json(self) -> dict:
        try:
            return json.loads(self.body or b"{}")
        except ValueError:
            return {}


class Browser:
    """A minimal user agent through the edge: every host is dialled at the edge's address with its own SNI, TLS is
    verified against the run's CA only, cookies are kept per host, redirects are never followed."""

    def __init__(self, st: Stack):
        self.st = st
        self.ctx = ssl.create_default_context(cafile=str(st.work / "ca" / "ca.crt"))
        self.jar: dict[str, dict[str, str]] = {}

    def request(self, method: str, url: str, body: bytes | None = None, headers: dict | None = None) -> Resp:
        u = urllib.parse.urlsplit(url)
        host = u.hostname or ""
        path = (u.path or "/") + (f"?{u.query}" if u.query else "")
        hdr = {"Host": host, "User-Agent": UA, **(headers or {})}
        if self.jar.get(host):
            hdr["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.jar[host].items())
        raw = socket.create_connection((self.st.edge_ip, 443), timeout=20)
        conn = http.client.HTTPConnection(self.st.edge_ip, 443, timeout=20)
        conn.sock = self.ctx.wrap_socket(raw, server_hostname=host)
        try:
            conn.request(method, path, body=body, headers=hdr)
            r = conn.getresponse()
            resp = Resp(r.status, r.getheaders(), r.read())
        finally:
            conn.close()
        for k, v in resp.headers:
            if k.lower() != "set-cookie":
                continue
            name, _, rest = v.partition("=")
            value = rest.split(";", 1)[0]
            attrs = v.lower()
            if len(value) >= 16:                     # session ids, binding cookies, Keycloak state
                self.st.secret_values.add(value)
            if "max-age=0" in attrs or "expires=thu, 01 jan 1970" in attrs or "max-age=-" in attrs:
                self.jar.get(host, {}).pop(name.strip(), None)
            else:
                self.jar.setdefault(host, {})[name.strip()] = value
        return resp

    def get(self, url: str, headers: dict | None = None) -> Resp:
        return self.request("GET", url, headers=headers)


FORM_RE = re.compile(r"(?is)<form\b([^>]*)>|</form>|<input\b([^>]*)>")
ATTR_RE = re.compile(r'(?is)([a-z_:][-a-z0-9_:.]*)\s*=\s*"([^"]*)"')


def forms(page: str) -> list[dict]:
    """The forms of a Keycloak page: action and named inputs (submit/unchecked boxes excluded)."""
    out: list[dict] = []
    cur = None
    for m in FORM_RE.finditer(page):
        if m.group(0).lower().startswith("<form"):
            a = {k.lower(): html.unescape(v) for k, v in ATTR_RE.findall(m.group(1))}
            out.append({"action": a.get("action", ""), "inputs": {}})
            cur = out[-1]
        elif m.group(0).startswith("</"):
            cur = None
        elif cur is not None:
            a = {k.lower(): html.unescape(v) for k, v in ATTR_RE.findall(m.group(2))}
            t = a.get("type", "").lower()
            if not a.get("name") or t in ("submit", "button", "image", "reset") or \
                    (t in ("checkbox", "radio") and "checked" not in m.group(2).lower()):
                continue
            cur["inputs"][a["name"]] = a.get("value", "")
    return out


class TOTP:
    """RFC 6238 (SHA-1, 6 digits, 30 s), strictly increasing counter (Keycloak refuses a code twice)."""

    def __init__(self) -> None:
        self.key = b""
        self.last = 0

    def code(self) -> str:
        while True:
            now = int(time.time()) // 30
            for c in (now, now + 1):
                if c > self.last:
                    self.last = c
                    mac = hmac.new(self.key, struct.pack(">Q", c), hashlib.sha1).digest()
                    o = mac[-1] & 0x0F
                    return f"{(struct.unpack('>I', mac[o:o + 4])[0] & 0x7FFFFFFF) % 1000000:06d}"
            time.sleep((now + 1) * 30 - time.time() + 0.5)


def keycloak_login(st: Stack, b: Browser, auth_url: str, user: dict, otp: TOTP, portal_host: str) -> tuple[str, list[str]]:
    """Drive Keycloak from the authorization URL to its redirect to the Portal; returns that URL and the steps."""
    steps: list[str] = []
    r = b.get(auth_url)
    for _ in range(12):
        if r.status in (302, 303):
            loc = r.header("Location")
            if urllib.parse.urlsplit(loc).hostname == portal_host:
                return loc, steps
            r = b.get(loc)
            continue
        if r.status != 200:
            raise StackError(f"Keycloak HTTP {r.status} after {steps}")
        fs = forms(r.body.decode("utf-8", "replace"))

        def post(f: dict, step: str, extra: dict) -> Resp:
            v = {**f["inputs"], **extra}
            steps.append(step)
            return b.request("POST", f["action"], urllib.parse.urlencode(v).encode(),
                             {"Content-Type": "application/x-www-form-urlencoded"})

        f = next((x for x in fs if "password" in x["inputs"] and "totp" not in x["inputs"]), None)
        if f:
            r = post(f, "password", {"username": user["username"], "password": user["password"]}
                     if "username" in f["inputs"] else {"password": user["password"]})
            continue
        f = next((x for x in fs if "totp" in x["inputs"] and "totpSecret" in x["inputs"]), None)
        if f:
            otp.key = f["inputs"]["totpSecret"].encode()
            st.secret_values.add(f["inputs"]["totpSecret"])
            r = post(f, "configure_totp", {"totp": otp.code(), "userLabel": "e2e"})
            continue
        f = next((x for x in fs if "otp" in x["inputs"]), None)
        if f:
            r = post(f, "otp", {"otp": otp.code()})
            continue
        raise StackError(f"unexpected Keycloak page after {steps} ({len(fs)} forms)")
    raise StackError(f"too many Keycloak steps: {steps}")


def portal_login(st: Stack, b: Browser, host: str, query: str, user: dict, otp: TOTP | None = None) -> tuple[dict, list[str]]:
    """GET /auth/login on the Portal host → Keycloak (password + TOTP) → callback → GET /auth/session. Pass the user's
    TOTP to log in again later (its key is learnt at the first login). A platform login that enrolled the TOTP carries
    no `otp` in amr and is answered 401 reauth_required (G2 round 2, A-6): the Portal signs in again with reauth=true —
    password + OTP — as done here (the steps then show both passes)."""
    api = f"https://{host}/api/v1"
    otp = otp or TOTP()
    r = b.get(f"{api}/auth/login?{query}")
    if r.status != 302:
        raise StackError(f"GET /auth/login on {host}: HTTP {r.status} {r.body[:200]!r}")
    cb, steps = keycloak_login(st, b, r.header("Location"), user, otp, host)
    r = b.get(cb)
    if r.status == 401 and r.json().get("code") == "reauth_required" and "configure_totp" in steps:
        r = b.get(f"{api}/auth/login?{query}&reauth=true")
        cb, again = keycloak_login(st, b, r.header("Location"), user, otp, host)
        steps += again
        r = b.get(cb)
    if r.status != 302 or not any(k == "__Host-mg_session" for k in b.jar.get(host, {})):
        raise StackError(f"callback on {host}: HTTP {r.status} {r.body[:200]!r}")
    s = b.get(f"{api}/auth/session")
    if s.status != 200:
        raise StackError(f"GET /auth/session on {host}: HTTP {s.status}")
    sess = s.json()
    st.secret_values.add(sess.get("csrf_token", ""))
    return sess, steps


# ---------------------------------------------------------------------------------------------------- Keycloak admin
class KeycloakAdmin:
    """Keycloak's Admin REST API straight on the idp container (the edge never routes it from here — E2E-19), with the
    stack's bootstrap admin (password from the harness's 0600 copy)."""

    def __init__(self, st: Stack):
        cid = st.compose("ps", "-q", "idp").stdout.strip()
        ip = st.docker("inspect", "-f", f'{{{{(index .NetworkSettings.Networks "{st.name("idp")}").IPAddress}}}}',
                       cid).stdout.strip()
        self.base = f"http://{ip}:8080"
        pw = (st.work / "secrets" / "harness" / "kc_admin_password").read_text(encoding="utf-8")
        tok = self._call("POST", "/realms/master/protocol/openid-connect/token", form={
            "grant_type": "password", "client_id": "admin-cli", "username": "mg-bootstrap-admin", "password": pw})
        self.token = tok["access_token"]
        st.secret_values.add(self.token)

    def _call(self, method: str, path: str, body=None, form=None, headers=None):
        data, hdr = None, dict(headers or {})
        if form is not None:
            data, hdr["Content-Type"] = urllib.parse.urlencode(form).encode(), "application/x-www-form-urlencoded"
        elif body is not None:
            data, hdr["Content-Type"] = json.dumps(body).encode(), "application/json"
        if getattr(self, "token", None):
            hdr["Authorization"] = "Bearer " + self.token
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=hdr)
        with urllib.request.urlopen(req, timeout=20) as r:
            raw = r.read()
            loc = r.headers.get("Location", "")
        return json.loads(raw) if raw else {"location": loc}

    def client_secret(self, realm: str) -> str:
        c = self._call("GET", f"/admin/realms/{realm}/clients?clientId=mg-portal")
        return self._call("GET", f"/admin/realms/{realm}/clients/{c[0]['id']}/client-secret")["value"]

    def create_user(self, realm: str, username: str, password: str) -> str:
        r = self._call("POST", f"/admin/realms/{realm}/users", body={
            "username": username, "email": f"{username}@example.invalid", "emailVerified": True, "enabled": True,
            "firstName": "E2E", "lastName": username,
            "credentials": [{"type": "password", "value": password, "temporary": False}]})
        return r["location"].rsplit("/", 1)[1]


# ---------------------------------------------------------------------------------------------------- helpers
def psql(st: Stack, sql: str) -> list[list[str]]:
    """A read-only query as the cluster superuser inside the postgres container (unix socket); '|'-separated rows."""
    out = st.exec("postgres", "psql", "-U", "postgres", "-d", "meshguard", "-tAF", "|", "-v", "ON_ERROR_STOP=1",
                  "-c", sql).stdout
    return [ln.split("|") for ln in out.splitlines() if ln.strip()]


def admin_cmd(st: Stack, args: list[str], stdin: str | None = None, env: dict | None = None, mounts: list[str] = ()):
    """`meshguard admin …` in a one-off api container of mg-app (as on the host: compose run --rm --no-deps -T)."""
    extra = [x for k, v in (env or {}).items() for x in ("-e", f"{k}={v}")] + [x for m in mounts for x in ("-v", m)]
    return st.compose("run", "--rm", "--no-deps", "-T", *extra, "api", "admin", *args, check=False, timeout=180,
                      input=stdin)


def client_secret_via_script(st: Stack, realm: str) -> str:
    """infrastructure/host/idp-client-secret.sh with stdout a pipe (this process) — and refused towards a file."""
    env = {**os.environ, "MG_IDP_PROJECT": st.prefix, "DOCKER": " ".join(st.docker_cmd)}
    script = str(ROOT / "infrastructure" / "host" / "idp-client-secret.sh")
    p = subprocess.run(["bash", script, realm], capture_output=True, text=True, env=env, timeout=120, encoding="utf-8")
    if p.returncode != 0 or not p.stdout.strip():
        raise StackError(f"idp-client-secret.sh {realm}: exit {p.returncode} {st.redact(p.stderr)[-300:]}")
    value = p.stdout.strip()
    st.secret_values.add(value)
    sink = st.work / "state" / "must-stay-empty"
    with open(sink, "w", encoding="utf-8") as f:
        q = subprocess.run(["bash", script, realm], stdout=f, stderr=subprocess.PIPE, text=True, env=env, timeout=120)
    if q.returncode == 0 or sink.read_text(encoding="utf-8"):
        raise StackError("idp-client-secret.sh wrote the secret to a file")
    sink.unlink()
    return value


def container(st: Stack, service: str) -> str:
    return st.compose("ps", "-q", service).stdout.strip()


def wait_healthy(st: Stack, service: str, timeout: float = 180) -> str:
    end, state = time.time() + timeout, ""
    while time.time() < end:
        state = st.docker("inspect", "-f", "{{.State.Health.Status}}", container(st, service), check=False).stdout.strip()
        if state == "healthy":
            return state
        time.sleep(2)
    return state


# ---------------------------------------------------------------------------------------------------- checks
def check_ready(r, st: Stack, state: dict) -> None:
    detail, ok = [], True
    for svc in ("api", "worker"):
        cid = container(st, svc)
        health = st.docker("inspect", "-f", "{{.State.Health.Status}}", cid, check=False).stdout.strip()
        hc = st.docker("exec", cid, "/usr/local/bin/meshguard", "healthcheck", check=False)
        fmt = "{{.Config.User}} {{.HostConfig.ReadonlyRootfs}} {{.HostConfig.CapDrop}} {{.HostConfig.SecurityOpt}} " \
              "{{.HostConfig.GroupAdd}} {{.HostConfig.PortBindings}}"
        ins = st.docker("inspect", "-f", fmt, cid).stdout.strip()
        good = (health == "healthy" and hc.returncode == 0 and '"ready":true' in hc.stdout and "65532:65532 true [ALL]"
                in ins and "no-new-privileges:true" in ins and "map[]" in ins)
        ok &= good
        detail.append(f"{svc}: {health}, {hc.stdout.strip()[:80]}, {ins}")
    for job in ("bootstrap", "migrate"):
        res = state.get(job, {})
        ok &= bool(res.get("passwords_set"))
        detail.append(f"{job}: {json.dumps(res)[:200]}")
    ok &= state.get("migrate", {}).get("current") is True
    r.add("E2E-17", "Backend (image build từ cây): db-bootstrap + migrate (mg_migrator, mật khẩu role từ file) xong; "
          "api, worker healthy — /readyz xanh (postgres, secretstore, edge_admin); 65532, rootfs chỉ đọc, cap_drop ALL, "
          "no-new-privileges, không publish cổng", ok, "; ".join(detail))


def check_edge_api(r, st: Stack) -> None:
    b = Browser(st)
    s = b.get(f"https://app.{st.domain}/api/v1/auth/session", {"X-MG-Token": "x" * 40, "X-Request-Id": "bad id"})
    p = s.json()
    hdr_ok = (s.header("Strict-Transport-Security").startswith("max-age=") and s.header("X-Content-Type-Options") == "nosniff"
              and "frame-ancestors 'none'" in s.header("Content-Security-Policy") and not s.header("Server"))
    rid_ok = s.header("X-Request-Id") not in ("", "bad id") and p.get("request_id") == s.header("X-Request-Id")
    root = b.get(f"https://app.{st.domain}/")
    adm = b.get(f"https://admin.{st.domain}/api/v1/auth/session")
    # another member of mg-edge calling the api directly (not through the edge) ⇒ 403 from the api itself; the same
    # container asking for admin. with the real SNI (its address is outside admin_allow) ⇒ the edge closes the
    # connection: wget fails and no HTTP status line comes back. Decided on the exit code and the absence of a status
    # line — never on a substring of the error text (OpenSSL prefixes its errors with a random hex thread id).
    admin_host = "admin." + st.domain
    direct = st.docker("run", "--rm", "--name", st.name("direct"), "--network", st.name("edge"), "--add-host",
                       f"{admin_host}:{st.edge_ip}", "--read-only", "--cap-drop", "ALL", "--security-opt",
                       "no-new-privileges:true", st.images["alpine"], "sh", "-c",
                       "wget -q -S -O /dev/null http://api:8080/api/v1/auth/session 2>&1 | head -1; "
                       f"o=$(wget -q -S -O /dev/null --no-check-certificate https://{admin_host}/api/v1/auth/session 2>&1); "
                       'echo "admin rc=$? $(printf %s "$o" | grep -m1 "HTTP/" || printf %s "$o" | head -1)"',
                       check=False, timeout=60)
    lines = direct.stdout.strip().splitlines()
    admin_refused = (len(lines) == 2 and lines[1].startswith("admin rc=") and not lines[1].startswith("admin rc=0 ")
                     and "HTTP/" not in lines[1])
    ok = (s.status == 401 and p.get("code") == "unauthenticated" and s.header("Content-Type").startswith("application/problem+json")
          and hdr_ok and rid_ok and root.status == 404 and adm.status == 401 and lines and "403" in lines[0]
          and admin_refused)
    r.add("E2E-18", "Edge → api: GET https://app./api/v1/auth/session không session ⇒ 401 problem+json (HSTS, nosniff, "
          "CSP, không Server, X-Request-Id sinh mới — không lặp giá trị client); admin. từ nguồn được phép ⇒ 401; "
          "container khác trên mg-edge gọi thẳng api:8080 ⇒ 403 (chỉ edge); admin. từ nguồn khác ⇒ đóng kết nối", ok,
          f"app {s.status} {p.get('code')}, headers {hdr_ok}, request id {rid_ok}, / {root.status}, admin {adm.status}, "
          f"trực tiếp {lines}")


def check_edge_idp(r, st: Stack) -> None:
    b = Browser(st)
    a = f"https://auth.{st.domain}"
    disc = b.get(f"{a}/realms/tenant-a/.well-known/openid-configuration")
    issuer_ok = disc.status == 200 and disc.json().get("issuer") == f"{a}/realms/tenant-a"
    refused = {}
    for path in ("/realms/master/.well-known/openid-configuration", "/realms/master/protocol/openid-connect/token",
                 "/admin/realms/master", "/admin/realms/tenant-a/users", "/admin/master/console/", "/admin/",
                 "/realms/tenant-a/../../admin/realms/tenant-a/users", "/realms/tenant-a/%2e%2e/%2e%2e/admin/realms/tenant-a",
                 "/resources/..%2f..%2fadmin/realms/tenant-a", "/realms/tenant-a\\..\\..\\admin/realms", "/health/ready",
                 "/metrics", "/", "/welcome"):
        refused[path] = b.get(a + path).status
    ok = issuer_ok and all(v == 404 for v in refused.values())
    r.add("E2E-19", "Edge → idp: endpoint OIDC công khai của realm (issuer đúng); Admin REST API, realm master, console, "
          "health/metrics, traversal ⇒ 404 từ mọi nguồn trừ worker", ok,
          f"discovery {disc.status} issuer {issuer_ok}; " + ", ".join(f"{k} ⇒ {v}" for k, v in refused.items()))


def check_idp_bootstrap(r, st: Stack) -> None:
    pw = (st.work / "secrets" / "harness" / "kc_admin_password").read_text(encoding="utf-8")
    p = st.docker("exec", "-i", container(st, "worker"), "/usr/local/bin/meshguard", "admin", "idp-bootstrap",
                  "--admin-username", "mg-bootstrap-admin", "--adopt-realm", "tenant-a", "--adopt-realm", "tenant-b",
                  "--audit-realm", "platform", check=False, timeout=180, input=pw + "\n")
    out = st.redact(p.stdout + p.stderr)
    st.compose("restart", "worker", timeout=120)
    health = wait_healthy(st, "worker")
    logs = st.docker("logs", "--since", "3m", container(st, "worker"), check=False).stdout
    provisioned = '"keycloak_provisioner_bootstrapped":true' in logs
    secret_ref = re.search(r"secret: (mgsec://platform/\S+)", out)
    audited = "events read (view-events only): master, platform" in out   # P3-T15: idp.audit_sync reads them
    ok = p.returncode == 0 and p.stdout.strip().splitlines()[-1:] == ["OK"] and secret_ref is not None and \
        health == "healthy" and provisioned and audited
    r.add("E2E-20", "worker `admin idp-bootstrap` (mật khẩu break-glass qua stdin): danh tính provisioning của driver "
          "keycloak qua edge từ IP tĩnh của worker (/admin/realms, realm master), secret vào SecretStore platform_ops, "
          "đọc được event của realm master và platform (view-events — P3-T15); worker khởi động lại với driver đã có "
          "danh tính", ok,
          f"exit {p.returncode}, {secret_ref.group(1) if secret_ref else 'no secret ref'}, worker {health}, "
          f"provisioned {provisioned}, audited {audited}; {out[-300:]}")


def check_registry(r, st: Stack, state: dict) -> None:
    kc = KeycloakAdmin(st)
    ids = {k: st.env[k] for k in ("MG_IDP_ID_PLATFORM", "MG_IDP_ID_TENANT_A", "MG_IDP_ID_TENANT_B")}
    res: list[str] = []
    ok = True
    p = admin_cmd(st, ["register-platform-idp"], env={"MG_IDP_ID_PLATFORM": ids["MG_IDP_ID_PLATFORM"]})
    ok &= p.returncode == 0
    res.append(f"register-platform-idp {p.returncode}")
    for slug in TENANTS:
        key = json.loads(st.headscale(slug, "apikeys", "create", "-e", "2160h", "-o", "json").stdout)
        st.secret_values.add(key)
        meta = st.work / "render" / slug / "meta" / "instance.json"
        p = admin_cmd(st, ["adopt-instance", "--host", "e2e-host", "--host-region", "lab", "--run-uid-range", "30000-39999",
                           "--tenant-net-pool", "10.250.0.0/16", "--name", f"E2E {slug}", "/run/mg-adopt/instance.json"],
                      stdin=json.dumps(key, indent="\t") + "\n", env={k: v for k, v in ids.items() if k != "MG_IDP_ID_PLATFORM"},
                      mounts=[f"{meta}:/run/mg-adopt/instance.json:ro"])
        out = st.redact(p.stdout + p.stderr)
        ok &= p.returncode == 0 and "valid keys now: 1" in out
        res.append(f"adopt {slug} {p.returncode} ({'1 key' if 'valid keys now: 1' in out else out[-200:]})")
    for realm, var in (("platform", "MG_IDP_ID_PLATFORM"), ("tenant-a", "MG_IDP_ID_TENANT_A"), ("tenant-b", "MG_IDP_ID_TENANT_B")):
        # the runbook's way (infrastructure/host/idp-client-secret.sh: kcadm inside the idp container, stdout only to a
        # pipe), checked against the Admin API
        secret = client_secret_via_script(st, realm)
        st.secret_values.add(secret)
        same = secret == kc.client_secret(realm)
        p = admin_cmd(st, ["set-idp-client-secret", ids[var]], stdin=secret + "\n")
        ok &= p.returncode == 0 and same
        res.append(f"client secret {realm} {p.returncode} (script = Admin API: {same})")
    rows = psql(st, "SELECT action, actor_type, count(*) FROM audit_events WHERE action LIKE 'platform.instance.adopt%' "
                    "OR action LIKE 'platform.idp%' OR action LIKE 'tenant.idp%' GROUP BY 1, 2 ORDER BY 1")
    actions = {a: (t, int(n)) for a, t, n in rows}
    audit_ok = (actions.get("platform.instance.adopt.requested", ("", 0))[1] == 2
                and actions.get("platform.instance.adopt.succeeded", ("", 0))[1] == 2
                and all(t == "system" for t, _ in actions.values()))
    ok &= audit_ok
    tenants = psql(st, "SELECT slug, status FROM tenants ORDER BY slug")
    ok &= tenants == [["tenant-a", "active"], ["tenant-b", "active"]]
    state["tenant_ids"] = {s: json.loads((st.work / "render" / s / "meta" / "instance.json").read_text(encoding="utf-8"))["tenant_id"]
                           for s in TENANTS}
    state["kc"] = kc
    r.add("E2E-21", "Lệnh quản trị của api (compose run, credential qua stdin): register-platform-idp, adopt-instance "
          "A và B (pre-flight qua listener admin của edge, key cũ bị expire), client secret mg-portal — sự kiện audit "
          "vào audit_events (actor_type system)", ok,
          "; ".join(res) + f"; audit {actions}; tenants {tenants}")


def check_tenant_login(r, st: Stack, state: dict) -> None:
    kc = state["kc"]
    user = {"username": "e2e-owner-a-" + secrets.token_hex(3), "password": secrets.token_urlsafe(18)}
    st.secret_values.add(user["password"])
    sub = kc.create_user("tenant-a", user["username"], user["password"])
    p = admin_cmd(st, ["seed-membership", "--tenant", "tenant-a", "--role", "tenant_owner", "--subject", sub,
                       "--display-name", "E2E Owner A"])
    b = Browser(st)
    sess, steps = portal_login(st, b, f"app.{st.domain}", "scope=tenant&tenant=tenant-a&return_to=%2F", user)
    a_id, b_id = state["tenant_ids"]["tenant-a"], state["tenant_ids"]["tenant-b"]
    api = f"https://app.{st.domain}/api/v1"
    mine = b.get(f"{api}/tenants").json()
    other = b.get(f"{api}/tenants/{b_id}/devices")
    admin_cookie = Browser(st)
    admin_cookie.jar[f"admin.{st.domain}"] = dict(b.jar.get(f"app.{st.domain}", {}))
    cross_origin = admin_cookie.get(f"https://admin.{st.domain}/api/v1/auth/session")
    m = sess.get("memberships") or [{}]
    ok = (p.returncode == 0 and steps[:1] == ["password"] and "configure_totp" in steps and sess.get("origin") == "app"
          and m[0].get("role") == "tenant_owner" and m[0].get("tenant_id") == a_id
          and [t.get("slug") for t in mine.get("items", [])] == ["tenant-a"] and other.status == 404
          and cross_origin.status == 401)
    state.update(browser=b, session=sess)
    r.add("E2E-22", "Đăng nhập OIDC thật có TOTP qua edge trên app. (Keycloak realm tenant-a, Tenant Owner seed theo "
          "sub): session BFF origin app, membership đúng tenant; GET /tenants chỉ thấy A; thiết bị của B ⇒ 404; cùng "
          "cookie trên admin. ⇒ 401", ok,
          f"seed {p.returncode}, steps {steps}, origin {sess.get('origin')}, membership {m[0].get('role')}, tenants "
          f"{[t.get('slug') for t in mine.get('items', [])]}, B {other.status}, admin {cross_origin.status}")


def check_devices(r, st: Stack, state: dict) -> None:
    b, sess = state["browser"], state["session"]
    a_id = state["tenant_ids"]["tenant-a"]
    api = f"https://app.{st.domain}/api/v1"
    unsafe = {"Origin": f"https://app.{st.domain}", "X-CSRF-Token": sess["csrf_token"],
              "Idempotency-Key": "e2e-sync-" + secrets.token_hex(6)}
    sync = b.request("POST", f"{api}/tenants/{a_id}/devices/sync", None, unsafe)
    job = sync.json()
    status, waited = job.get("status"), 0.0
    t0 = time.time()
    while status not in ("succeeded", "failed", "cancelled") and time.time() - t0 < 120:
        time.sleep(2)
        j = b.get(f"{api}/tenants/{a_id}/jobs/{job.get('id')}")
        status = j.json().get("status") if j.status == 200 else f"HTTP {j.status}"
    waited = time.time() - t0
    jobs = b.get(f"{api}/tenants/{a_id}/jobs?limit=5").json()
    devices = b.get(f"{api}/tenants/{a_id}/devices").json()
    names = sorted(d.get("name") for d in devices.get("items", []))
    dash = b.get(f"{api}/tenants/{a_id}/dashboard")
    d = dash.json().get("devices", {})
    nocsrf = b.request("POST", f"{api}/tenants/{a_id}/devices/sync", None,
                       {"Origin": f"https://app.{st.domain}", "Idempotency-Key": "e2e-nocsrf"})
    state["sync_job"] = job.get("id")
    ok = (sync.status == 202 and status == "succeeded" and any(x.get("id") == job.get("id") for x in jobs.get("items", []))
          and names == ["a1", "a2"] and dash.status == 200 and d.get("total") == 2 and d.get("synced_at")
          and nocsrf.status == 403)
    r.add("E2E-23", "Thiết bị qua API: POST …/devices/sync (CSRF + Idempotency-Key) ⇒ 202 job; worker chạy "
          "inventory.sync qua listener admin của edge ⇒ job succeeded (GET /tenants/{t}/jobs[/{id}]); thiết bị a1, a2; "
          "dashboard có số liệu thật; thiếu CSRF ⇒ 403", ok,
          f"sync {sync.status}, job {status} sau {waited:.0f} s, devices {names}, dashboard {dash.status} {d}, "
          f"không CSRF {nocsrf.status}")


def check_platform(r, st: Stack, state: dict) -> None:
    kc = state["kc"]
    user = {"username": "e2e-super-admin-" + secrets.token_hex(3), "password": secrets.token_urlsafe(18)}
    st.secret_values.add(user["password"])
    sub = kc.create_user("platform", user["username"], user["password"])
    p = admin_cmd(st, ["bootstrap-super-admin", "--subject", sub, "--display-name", "E2E SA"],
                  env={"MG_IDP_ID_PLATFORM": st.env["MG_IDP_ID_PLATFORM"]})
    b, otp = Browser(st), TOTP()
    sess, steps = portal_login(st, b, f"admin.{st.domain}", "scope=platform", user, otp)
    st.platform_sa = {**user, "sub": sub, "otp": otp}   # P3-T15 (idpadmin.py): the first Super Admin of the dual control
    api = f"https://admin.{st.domain}/api/v1"
    health = b.get(f"{api}/platform/health")
    h = health.json()
    tenants = b.get(f"{api}/platform/tenants").json()
    jobs = b.get(f"{api}/platform/jobs?kind=inventory.sync")
    pj = b.get(f"{api}/platform/jobs/{state.get('sync_job')}")
    tenant_route = b.get(f"{api}/tenants/{state['tenant_ids']['tenant-a']}/devices")
    state["sa"] = {"browser": b, "session": sess}   # the Super Admin session of the Phase 3 platform cases (E2E-46, 47)
    ok = (p.returncode == 0 and sess.get("origin") == "admin" and health.status == 200
          and h.get("tenants", {}).get("total") == 2 and h.get("instances", {}).get("total") == 2
          and sorted(t.get("slug") for t in tenants.get("items", [])) == ["tenant-a", "tenant-b"]
          and jobs.status == 200 and pj.status == 200 and "steps" in pj.json() and tenant_route.status == 403)
    r.add("E2E-24", "Super Admin (bootstrap-super-admin theo sub) đăng nhập có TOTP trên admin.: platform health, "
          "tenants, jobs (chi tiết thô chỉ ở GET /platform/jobs/{id}) có dữ liệu thật; route tenant ⇒ 403 khi chưa có "
          "Support Access Grant", ok,
          f"bootstrap {p.returncode}, steps {steps}, health {health.status} tenants {h.get('tenants')} instances "
          f"{h.get('instances')}, platform tenants {sorted(t.get('slug') for t in tenants.get('items', []))}, jobs "
          f"{jobs.status}, job {pj.status}, tenant route {tenant_route.status}")


def check_audit(r, st: Stack) -> None:
    rows = psql(st, "SELECT action, outcome, count(*) FROM audit_events GROUP BY 1, 2 ORDER BY 1, 2")
    got = {(a, o): int(n) for a, o, n in rows}
    sec = psql(st, "SELECT kind, count(*) FROM security_events GROUP BY 1")

    def has(prefix: str, outcome: str) -> bool:
        return any(a.startswith(prefix) and o == outcome for a, o in got)
    ok = (has("platform.instance.adopt", "success") and has("auth.login", "success") and has("device.sync", "success")
          and has("platform.super_admin.bootstrap", "success") and has("tenant.membership.seed", "success")
          and any(o == "denied" for _, o in got) and not any(k == "secrets.integrity_failure" for k, _ in sec))
    r.add("E2E-25", "audit_events của cả luồng (adopt, seed/bootstrap, đăng nhập, sync thiết bị, từ chối) được ghi; "
          "không security event toàn vẹn SecretStore", ok,
          f"{sum(got.values())} sự kiện: " + ", ".join(f"{a}/{o}={n}" for (a, o), n in sorted(got.items()))[:600]
          + f"; security_events {sec}")


def run_all(r, st: Stack, guarded) -> None:
    """Run E2E-17 … E2E-31 in order (each later check builds on the state of the earlier ones)."""
    import asvs2  # noqa: PLC0415 — imports this module
    import orchestrator  # noqa: PLC0415 — imports this module
    import reconfigure  # noqa: PLC0415 — imports this module
    import relayread  # noqa: PLC0415 — imports this module
    state = json.loads((st.work / "state" / "backend.json").read_text(encoding="utf-8")) \
        if (st.work / "state" / "backend.json").exists() else {}
    guarded(r, "E2E-17", check_ready, st, state)
    guarded(r, "E2E-18", check_edge_api, st)
    guarded(r, "E2E-19", check_edge_idp, st)
    guarded(r, "E2E-20", check_idp_bootstrap, st)
    if guarded(r, "E2E-21", check_registry, st, state) is None and "kc" in state:
        if guarded(r, "E2E-22", check_tenant_login, st, state) is None and "browser" in state:
            guarded(r, "E2E-23", check_devices, st, state)
        guarded(r, "E2E-24", check_platform, st, state)
        orchestrator.run_all(r, st, guarded, state)   # E2E-46, E2E-47: Tenant Orchestrator API (P3-T05)
        relayread.run_all(r, st, guarded, state)      # E2E-65, E2E-66: relay read model + relay probe (P3-T05c)
        reconfigure.run_all(r, st, guarded, state)    # E2E-63, E2E-64: instance.reconfigure API (P3-T13)
        asvs2.run_all(r, st, guarded)        # E2E-26 … E2E-31: fixes of the G2 review, round 2 (OWASP ASVS)
    guarded(r, "E2E-25", check_audit, st)

