#!/usr/bin/env python3
"""G4a (P4-T10a) — kiểm chứng sau nâng lô Phase 4 trên staging, tenant thử g4a-<hex>.

  python -B g4a.py <bước> [...]
  provision   SA1 tạo tenant g4a-<hex> (Owner owner@<slug>.example.invalid) ⇒ user Keycloak (create-user.sh) ⇒ Owner
              đăng nhập lần đầu (TOTP) ⇒ ~/.meshguard/g4a-creds.json (mật khẩu + TOTP, chỉ máy này)
  apicheck    SA + Owner đăng nhập thật; route Platform/tenant ⇒ 200; route của tenant-a/b bằng Owner ⇒ 404
  enroll      D1 = tailscaled của VM 105 (web-auth, claim qua API chỉ bằng tham số của Location), D2 = container
              client chính thức (pre-auth key) ⇒ consumed + liên kết sổ thiết bị
  policy      allow → TCP D1→D2:8000; deny → chặn; rollback về allow → thông
  lifecycle   suspend ⇒ chặn + ghi 403; resume ⇒ thông
  devices     rename D2, expire D2 (pending → applied), D2 mất kết nối
  audit       audit của tenant thử có đủ hành động; chéo tenant 404
  ui          Chromium thật (playwright-core 1.65.0, ui.mjs): Owner đăng nhập, Devices/Policies/Audit, Add device web-auth
              ⇒ D3 (container client) ⇒ mở link trong cùng trình duyệt ⇒ trang claim ⇒ verified (G4A_PAUSE_MS: chờ trước
              khi mở link, như người dùng chạy lệnh)
  cleanup     logout D1, gỡ D2/D3, deprovision 2P, kiểm host không còn tài nguyên
  after       ≥ 15 phút sau triển khai: sha policy A/B, policy.drift_check, log ERROR, TCP a1→a2 / b1→b2 (8000 vs 8001)
Chạy trên máy vận hành (G4a: 2026-11-19), theo thứ tự trên. Môi trường (không ghi IP vào file): G4A_CLIENT, G4A_LAB_A1,
G4A_LAB_B1 = mgdeploy@<địa chỉ>; IP/domain của staging đọc từ staging.env qua tools/mgenv.py; 2 Super Admin thử từ
~/.meshguard/g3-creds.json (tests/g3). Mật khẩu/TOTP/cookie/CSRF/mã/Auth ID/key chỉ trong tiến trình (tập che) và file
0600 trong ~/.meshguard (xóa sau cleanup); log + results.json đã che trong G4A_OUT.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import pathlib
import re
import secrets
import shlex
import ssl
import string
import subprocess
import sys
import time
import urllib.parse

sys.stdout.reconfigure(encoding="utf-8")
ROOT = pathlib.Path(__file__).resolve().parents[4]   # docs/planning/evidence/G4a → gốc repo
sys.path[:0] = [str(ROOT / "tests" / "g3"), str(ROOT / "tests" / "e2e" / "harness"), str(ROOT / "tools")]
import backend  # noqa: E402
from g3platform import Platform, TargetBrowser, STEP_UP_S  # noqa: E402
from g3target import Target, load_creds  # noqa: E402

HOME = pathlib.Path(os.path.expanduser("~/.meshguard"))
STATE = HOME / "g4a-state.json"
CREDS = HOME / "g4a-creds.json"
OUT = pathlib.Path(os.environ.get("G4A_OUT") or os.path.expanduser("~/.meshguard/g4a-out"))
OUT.mkdir(parents=True, exist_ok=True)
KEY = str(pathlib.Path.home() / ".ssh" / "id_ed25519_meshguard")
SSH = ["ssh", "-i", KEY, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "ConnectTimeout=30",
       "-o", "ServerAliveInterval=10"]
CLIENT_HOST = os.environ.get("G4A_CLIENT", "")      # mgdeploy@<máy client, khác host Headscale — HS-24>
AUTH_RE = re.compile(r"https://([a-z0-9.-]+)/register/(hskey-authreq-[A-Za-z0-9_-]{24})")
D2 = "g4a-d2"
PORT = 8000

t = Target(ROOT / "infrastructure/environments/staging/staging.env",
           {"host_docker": " ".join(SSH) + " mgdeploy@${MG_LAN_IPV4} sudo -n docker",
            "client_docker": " ".join(SSH) + f" {CLIENT_HOST} sudo -n docker"})
HOSTSSH = SSH + [f"mgdeploy@{t.env['MG_LAN_IPV4']}"]
CLISSH = SSH + [CLIENT_HOST]
RESULTS = OUT / "results.json"
LOG = open(OUT / "run.log", "a", encoding="utf-8")


def log(*a) -> None:
    line = time.strftime("%H:%M:%S", time.gmtime()) + " " + " ".join(str(x) for x in a)
    line = t.redact(line)
    print(line, flush=True)
    LOG.write(line + "\n")
    LOG.flush()


def result(step: str, name: str, ok: bool, detail: str) -> bool:
    doc = json.loads(RESULTS.read_text(encoding="utf-8")) if RESULTS.exists() else {}
    doc.setdefault(step, []).append({"name": name, "ok": ok, "detail": t.redact(detail),
                                     "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
    RESULTS.write_text(json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")
    log(f"{'PASS' if ok else 'FAIL'} [{step}] {name} — {detail}")
    return ok


def run(cmd: list[str], stdin: bytes | None = None, timeout: float = 300) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, input=stdin if stdin is not None else b"", capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    return p.returncode, (p.stdout.decode("utf-8", "replace") + p.stderr.decode("utf-8", "replace")).strip()


def host(cmd: str, stdin: bytes | None = None, timeout: float = 300) -> str:
    return run(HOSTSSH + [cmd], stdin, timeout)[1]


def cli(cmd: str, stdin: bytes | None = None, timeout: float = 300) -> tuple[int, str]:
    return run(CLISSH + [cmd], stdin, timeout)


def sql(q: str) -> str:
    return host("sudo -n docker exec -i mg-core-postgres-1 psql -X -At -U postgres -d meshguard", q.encode())


def hs(slug: str, *args: str) -> str:
    return host("sudo -n docker exec mg-hs-" + slug + " headscale " + " ".join(args))


def hs_nodes(slug: str) -> list[dict]:
    try:
        return json.loads(hs(slug, "nodes", "list", "-o", "json") or "[]") or []
    except ValueError:
        return []


def hs_policy_sha(slug: str) -> str:
    out = host(f"sudo -n docker exec mg-hs-{slug} headscale policy get | head -c -1 | sha256sum | cut -c1-64")
    return out.strip()


def load_state() -> dict:
    return json.loads(STATE.read_text(encoding="utf-8")) if STATE.exists() else {}


def save_state(st: dict) -> None:
    STATE.write_text(json.dumps(st, indent=1), encoding="utf-8")


def wait(fn, timeout: float, every: float = 2.0):
    end = time.time() + timeout
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(every)
    return None


# ------------------------------------------------------------------------------------------------ người dùng tenant
class Owner:
    def __init__(self, slug: str, creds: dict):
        self.slug = slug
        self.user = {"username": creds["username"], "password": creds["password"]}
        t.secret_values.add(creds["password"])
        self.otp = backend.TOTP()
        self.otp.key = creds.get("totp_raw", "").encode()
        self.otp.last = int(creds.get("totp_last", 0))
        if creds.get("totp_raw"):
            t.secret_values.add(creds["totp_raw"])
        self.host = f"app.{t.domain}"
        self.b = TargetBrowser(t)
        self.sess: dict = {}
        self.at = 0.0

    def login(self) -> list[str]:
        self.b = TargetBrowser(t)
        self.sess, steps = backend.portal_login(t, self.b, self.host, f"scope=tenant&tenant={self.slug}", self.user, self.otp)
        self.at = time.time()
        c = json.loads(CREDS.read_text(encoding="utf-8"))
        c.update(totp_raw=self.otp.key.decode(), totp_last=self.otp.last)
        CREDS.write_text(json.dumps(c), encoding="utf-8")
        t.secret_values.add(self.otp.key.decode())
        return steps

    def call(self, method: str, path: str, body=None, idem: str | None = None, if_match: str | None = None,
             tries: int = 8, relogin: bool = True) -> backend.Resp:
        if not self.sess:
            self.login()
        data = json.dumps(body).encode() if body is not None else None
        h = None
        if method != "GET":
            h = {"Origin": f"https://{self.host}", "X-CSRF-Token": self.sess.get("csrf_token", ""),
                 "Content-Type": "application/json"}
            if idem:
                h["Idempotency-Key"] = idem
            if if_match:
                h["If-Match"] = if_match
        r = None
        for _ in range(tries):
            r = self.b.request(method, f"https://{self.host}/api/v1{path}", data if data is not None else
                               (b"" if method != "GET" else None), h)
            if r.status == 429:
                try:
                    w = min(30.0, float(r.header("Retry-After") or 5))
                except ValueError:
                    w = 5.0
                time.sleep(w + 0.5)
                continue
            if r.status == 401 and relogin and r.json().get("code") in ("reauth_required", "unauthenticated"):
                log(f"  {method} {path}: 401 {r.json().get('code')} ⇒ đăng nhập lại")
                self.login()
                if h:
                    h["X-CSRF-Token"] = self.sess.get("csrf_token", "")
                continue
            return r
        return r

    def tenant_id(self) -> str:
        s = self.call("GET", "/auth/session").json()
        return next((m.get("tenant_id") for m in s.get("memberships") or [] if m.get("tenant_slug") == self.slug), "")


def owner(st: dict) -> Owner:
    return Owner(st["slug"], json.loads(CREDS.read_text(encoding="utf-8")))


TOTPF = HOME / "g4a-totp-last.json"


def platform() -> Platform:
    pf = Platform(t, load_creds(HOME / "g3-creds.json", t))
    last = json.loads(TOTPF.read_text()) if TOTPF.exists() else {}
    for s_ in (pf.a, pf.b):
        s_.otp.last = int(last.get(s_.user["username"], 0))
        orig = s_.login

        def wrapped(orig=orig, s_=s_):
            orig()
            d = json.loads(TOTPF.read_text()) if TOTPF.exists() else {}
            d[s_.user["username"]] = s_.otp.last
            TOTPF.write_text(json.dumps(d))
        s_.login = wrapped
    return pf


def tenant_job(o: Owner, tid: str, jid: str, timeout: float = 300) -> dict:
    end, doc = time.time() + timeout, {}
    while time.time() < end:
        r = o.call("GET", f"/tenants/{tid}/jobs/{jid}")
        doc = r.json() if r.status == 200 else {"status": f"HTTP {r.status}"}
        if doc.get("status") in ("succeeded", "failed", "cancelled", "rolled_back", "failed_resumable"):
            return doc
        time.sleep(2)
    return doc


# ------------------------------------------------------------------------------------------------ provision
def cmd_provision() -> None:
    st = load_state()
    pf = platform()
    pf.a.fresh()
    slug = st.get("slug") or f"g4a-{secrets.token_hex(2)}"
    email = f"owner@{slug}.example.invalid"
    st.update(slug=slug, owner_email_domain=f"{slug}.example.invalid", started=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    save_state(st)
    t0 = time.time()
    r, job = pf.create_tenant(slug, email)
    log("POST /platform/tenants", slug, "HTTP", r.status, job.get("code", ""), job.get("id", ""))
    done = pf.wait_job(job.get("id", ""), timeout=600)
    tid = done.get("tenant_id") or next((x["id"] for x in pf.get("/platform/tenants").get("items", []) if x.get("slug") == slug), "")
    steps = done.get("steps") or []
    result("provision", "SA1 POST /platform/tenants ⇒ job tenant.provision", r.status == 202 and done.get("status") == "succeeded",
           f"HTTP {r.status}; job {done.get('status')} {time.time() - t0:.1f} s; {len(steps)} bước; "
           f"bước lỗi {[s.get('name') for s in steps if s.get('status') != 'succeeded']}")
    inst = next((x for x in pf.get("/platform/instances").get("items", []) if x.get("tenant_id") == tid), {})
    st.update(tenant_id=tid, instance_id=inst.get("id", ""), provision_job=job.get("id", ""))
    save_state(st)
    health = host(f"sudo -n docker inspect -f '{{{{.State.Health.Status}}}}' mg-hs-{slug}")
    sub = sql(f"SELECT s.status || ' ' || p.key FROM subscriptions s JOIN subscription_plans p ON p.id = s.plan_id WHERE s.tenant_id = '{tid}'")
    result("provision", "instance healthy, subscription", health == "healthy", f"mg-hs-{slug} {health}; subscription {sub or 'không có'}")
    # Owner: user Keycloak của realm <slug> (create-user.sh), mật khẩu sinh tại chỗ, chỉ qua stdin
    pw = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
    t.secret_values.add(pw)
    CREDS.write_text(json.dumps({"username": "g4a-owner", "password": pw, "email": email}), encoding="utf-8")
    try:
        os.chmod(CREDS, 0o600)
    except OSError:
        pass
    out = host(f"cd ~/mg && sudo -n bash infrastructure/idp/create-user.sh {slug} g4a-owner {email} G4a Owner", (pw + "\n").encode())
    result("provision", "user Keycloak của Owner (create-user.sh)", "created" in out or "exists" in out, out.splitlines()[-1][:80] if out else "")
    o = owner(st)
    steps = o.login()
    ms = [(m.get("tenant_slug"), m.get("role")) for m in o.sess.get("memberships") or []]
    result("provision", "Owner đăng nhập lần đầu (Keycloak mật khẩu + đăng ký TOTP)", (slug, "tenant_owner") in ms,
           f"bước {steps}; memberships {ms}")
    st["owner_membership_id"] = next((m.get("membership_id") or m.get("id") for m in o.sess.get("memberships") or []
                                      if m.get("tenant_slug") == slug), "")
    save_state(st)
    log("session keys:", sorted(o.sess.keys()), "membership keys:", sorted((o.sess.get("memberships") or [{}])[0].keys()))


# ------------------------------------------------------------------------------------------------ apicheck
def cmd_apicheck() -> None:
    st = load_state()
    pf = platform()
    pf.a.fresh()
    o = owner(st)
    o.login()
    st["tenant_a"] = sql("SELECT id FROM tenants WHERE slug = 'tenant-a'")
    st["tenant_b"] = sql("SELECT id FROM tenants WHERE slug = 'tenant-b'")
    save_state(st)
    g, a, b = st["tenant_id"], st["tenant_a"], st["tenant_b"]
    rows = []
    for p in ("tenants", "health", "instances", "hosts", "jobs", "approvals", "users", "plans", "settings",
              "identity-providers", "support-grants", "relay-regions", "backups", "audit"):
        r = pf.call(pf.a, "GET", f"/platform/{p}")
        rows.append((f"SA GET /platform/{p}", r.status, r.status == 200))
    sa_tenant = pf.call(pf.a, "GET", f"/platform/tenants/{g}")
    rows.append(("SA GET /platform/tenants/{g4a}", sa_tenant.status, sa_tenant.status == 200))
    routes = ["devices", "policies", "policies/current", "tags", "users", "groups", "dns", "dns/records", "routes",
              "resources", "enrollment/requests", "enrollment/instructions?os=linux", "audit", "support-grants",
              "approvals", "settings", "dashboard", "jobs", "notifications", "relay", "invitations"]
    r = o.call("GET", f"/tenants/{g}")
    rows.append(("TO-g4a GET /tenants/{g4a}", r.status, r.status == 200))
    for p in routes:
        r = o.call("GET", f"/tenants/{g}/{p}")
        rows.append((f"TO-g4a GET /tenants/{{g4a}}/{p}", r.status, r.status == 200))
        time.sleep(0.3)
    for label, other in (("tenant-a", a), ("tenant-b", b)):
        r = o.call("GET", f"/tenants/{other}")
        rows.append((f"TO-g4a GET /tenants/{{{label}}} (chéo)", r.status, r.status == 404))
        for p in routes:
            r = o.call("GET", f"/tenants/{other}/{p}")
            rows.append((f"TO-g4a GET /tenants/{{{label}}}/{p} (chéo)", r.status, r.status == 404))
            time.sleep(0.3)
    for name, status, ok in rows:
        log(f"  {'PASS' if ok else 'FAIL'} {name}: HTTP {status}")
    npass = sum(1 for _, _, ok in rows if ok)
    st["apicheck"] = {"total": len(rows), "pass": npass, "rows": rows}
    save_state(st)
    groups = {"SA platform": [x for x in rows if x[0].startswith("SA")],
              "TO own": [x for x in rows if x[0].startswith("TO-g4a") and "chéo" not in x[0]],
              "chéo A": [x for x in rows if "tenant-a" in x[0]], "chéo B": [x for x in rows if "tenant-b" in x[0]]}
    result("apicheck", "route sau nâng", npass == len(rows),
           f"{npass}/{len(rows)} PASS — " + "; ".join(f"{k} {sum(1 for x in v if x[2])}/{len(v)}" for k, v in groups.items())
           + "; FAIL: " + str([(n, s) for n, s, ok in rows if not ok]))


# ------------------------------------------------------------------------------------------------ enroll
def d1_status() -> dict:
    rc, out = cli("tailscale status --json 2>/dev/null")
    try:
        return json.loads(out)
    except ValueError:
        return {}


def d2_exec(cmd: str, stdin: bytes | None = None, timeout: float = 120) -> tuple[int, str]:
    return cli(f"sudo -n docker exec {'-i ' if stdin is not None else ''}{D2} sh -c {shlex.quote(cmd)}", stdin, timeout)


def d2_status() -> dict:
    rc, out = d2_exec("tailscale --socket=/tmp/ts.sock status --json")
    try:
        return json.loads(out[out.index("{"):]) if "{" in out else {}
    except ValueError:
        return {}


def ip4(status: dict) -> str:
    return next((x for x in (status.get("Self") or {}).get("TailscaleIPs") or [] if "." in x), "")


def tcp_d1_to_d2(ip: str, wait_s: int = 6) -> str:
    """TCP thật từ tailscaled kernel của VM 105 (D1) tới listener của D2 qua tailnet."""
    code = ("import socket,sys\ntry:\n s=socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=float(sys.argv[3]))\n"
            " s.settimeout(float(sys.argv[3])); print('ANS', s.recv(200).decode().strip())\nexcept Exception as e: print('ERR', type(e).__name__)\n")
    rc, out = cli(f"python3 - {ip} {PORT} {wait_s}", code.encode(), timeout=wait_s + 40)
    return out.strip().splitlines()[-1] if out.strip() else "ERR none"


def cmd_enroll() -> None:
    st = load_state()
    slug, g = st["slug"], st["tenant_id"]
    login = f"https://{slug}.mesh.{t.domain}"
    o = owner(st)
    o.login()
    mid = st.get("owner_membership_id", "") or sql(f"SELECT id FROM tenant_memberships WHERE tenant_id = '{g}' AND status = 'active'")
    st["owner_membership_id"] = mid
    save_state(st)
    # ---------------------------------------------------------------- D1: web-auth (VM 105, tailscaled của hệ thống)
    ins = o.call("GET", f"/tenants/{g}/enrollment/instructions?os=linux")
    ij = ins.json()
    result("enroll", "GET /enrollment/instructions?os=linux", ins.status == 200 and ij.get("login_server") == login,
           f"HTTP {ins.status}; login_server đúng tenant {ij.get('login_server') == login}")
    req = o.call("POST", f"/tenants/{g}/enrollment/requests", {"method": "web_auth", "device_label": "g4a-vm105"},
                 idem="g4a-wa-" + secrets.token_hex(6))
    rj = req.json()
    cred, rid = rj.get("credential") or {}, (rj.get("request") or {}).get("id", "")
    code = cred.get("enroll_code", "")
    if code:
        t.secret_values.add(code)
    st["d1_request"] = rid
    save_state(st)
    result("enroll", "D1 POST /enrollment/requests {web_auth, device_label}", req.status == 201 and len(code) == 12
           and cred.get("hostname") == f"mg-{code}" and (rj.get("request") or {}).get("status") == "issued",
           f"HTTP {req.status}; status {(rj.get('request') or {}).get('status')}; hostname mg-<12 ký tự>; "
           f"lệnh có --hostname {f'--hostname=mg-{code}' in cred.get('command', '') or f'--hostname mg-{code}' in cred.get('command', '')}; "
           f"hết hạn {cred.get('expires_at')}")
    # tailscale login trên VM 105 (profile mới), chạy nền, link vào ~/g4a/up.log (0700)
    script = ("#!/bin/sh\nset -u\nexec sudo -n tailscale login --login-server=\"$1\" --hostname=\"$2\" --accept-dns=false "
              "--timeout=600s >\"$HOME/g4a/up.log\" 2>&1\n")
    rc, out = cli("mkdir -p ~/g4a && chmod 0700 ~/g4a && cat > ~/g4a/up.sh && chmod 0700 ~/g4a/up.sh && md5sum ~/g4a/up.sh",
                  script.encode())
    want = hashlib.md5(script.encode()).hexdigest()
    log("  up.sh md5", "khớp" if want in out else f"LỆCH {out}")
    t_up = time.time()
    rc, out = cli(f"rm -f ~/g4a/up.log; setsid nohup ~/g4a/up.sh {login} mg-{code} </dev/null >/dev/null 2>&1 & disown; echo started")
    link = wait(lambda: (lambda m: m.groups() if m else None)(AUTH_RE.search(cli("cat ~/g4a/up.log 2>/dev/null")[1])), 60, 1.0)
    hostp, auth = link or ("", "")
    if auth:
        t.secret_values.add(auth)
    st0 = d1_status()
    result("enroll", "D1 tailscale login --login-server <tenant> --hostname mg-<mã> ⇒ link /register/<auth_id>",
           hostp == f"{slug}.mesh.{t.domain}" and bool(auth),
           f"link sau {time.time() - t_up:.1f} s; host = <slug>.mesh.<domain> {hostp == f'{slug}.mesh.{t.domain}'}; "
           f"BackendState {st0.get('BackendState')}")
    if not auth:
        log(cli("cat ~/g4a/up.log")[1][-500:])
        return
    # edge v10: 302 về trang claim (LAN-direct và qua DNS công khai → VPS)
    link_url = f"https://{hostp}/register/{auth}"
    want_loc = f"https://app.{t.domain}/enroll/claim?tenant={slug}&auth_id={auth}"
    lb = TargetBrowser(t)
    lan = lb.get(link_url)
    pub_status, pub_loc, pub_cc = public_get(hostp, f"/register/{auth}")
    result("enroll", "edge v10: GET link ⇒ 302 trang claim (LAN-direct + DNS công khai/VPS)",
           lan.status == 302 and lan.header("Location") == want_loc and lan.header("Cache-Control") == "no-store"
           and pub_status == 302 and pub_loc == want_loc and pub_cc == "no-store",
           f"LAN {lan.status} Location đúng {lan.header('Location') == want_loc} Cache-Control {lan.header('Cache-Control')}; "
           f"công khai {pub_status} Location đúng {pub_loc == want_loc} Cache-Control {pub_cc}")
    page = lb.get(want_loc)
    body = page.body.decode("utf-8", "replace")
    native = lb.get(link_url + "?via=portal")
    result("enroll", "Location ⇒ index.html của SPA; ?via=portal ⇒ trang Headscale", page.status == 200
           and "text/html" in page.header("Content-Type") and '<div id="root"' in body and native.status == 200
           and auth in native.body.decode("utf-8", "replace"),
           f"claim page {page.status} {page.header('Content-Type')} root div {'<div id=\"root\"' in body} CSP "
           f"{bool(page.header('Content-Security-Policy'))}; via=portal {native.status} có Auth ID "
           f"{auth in native.body.decode('utf-8', 'replace')}")
    # claim chỉ bằng hai tham số của Location (như trang claim P4-T08)
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(lan.header("Location")).query))
    tid_from_slug = o.tenant_id() if q.get("tenant") == slug else ""
    t_claim = time.time()
    claim = o.call("POST", f"/tenants/{tid_from_slug}/enrollment/web-auth/claim", {"auth_id": q.get("auth_id", "")})
    cj = claim.json()
    running = wait(lambda: d1_status().get("BackendState") == "Running", 90, 1.5)
    t_run = time.time() - t_claim
    s1 = d1_status()
    nodes = hs_nodes(slug)
    node = next((n for n in nodes if str(n.get("id")) == str(cj.get("node_id"))), {})
    st.update(d1_node=str(cj.get("node_id", "")), d1_ip=ip4(s1))
    save_state(st)
    result("enroll", "V-07: claim qua API ⇒ verified, client Running, node đổi tên theo nhãn, chủ mg-<membership>",
           claim.status == 200 and cj.get("status") == "verified" and bool(running) and node.get("given_name") == "g4a-vm105"
           and (node.get("user") or {}).get("name") == f"mg-{mid}",
           f"tenant từ slug qua /auth/session {tid_from_slug == g}; claim {claim.status} {cj.get('status')} "
           f"{cj.get('failure_code') or ''}; Running sau {t_run:.1f} s; node #{node.get('id')} name mg-<mã> "
           f"{node.get('name') == f'mg-{code}'} given_name {node.get('given_name')} user mg-<membership Owner> "
           f"{(node.get('user') or {}).get('name') == f'mg-{mid}'} register_method {node.get('register_method')}; "
           f"IP D1 {ip4(s1)}; DNSName {(s1.get('Self') or {}).get('DNSName', '')[:20]}…")
    up_rc = cli("sleep 2; cat ~/g4a/up.log | tail -3; rm -f ~/g4a/up.log")[1]
    log("  up.log (cuối):", up_rc.replace(auth, "[AUTH]")[-200:])
    # sổ thiết bị, audit, device.new
    inv = wait(lambda: sql(f"SELECT id || ' ' || coalesce(given_name,'') FROM device_inventory_cache WHERE tenant_id = '{g}' "
                           f"AND enrollment_request_id = '{rid}' AND removed_at IS NULL"), 60, 3) or ""
    devs = o.call("GET", f"/tenants/{g}/devices").json().get("items") or []
    dv = next((d for d in devs if d.get("given_name") == "g4a-vm105"), {})
    st["d1_device"] = dv.get("id", "")
    save_state(st)
    audit = sql(f"SELECT string_agg(action || ':' || outcome, ',' ORDER BY occurred_at, id) FROM audit_events WHERE tenant_id = '{g}' AND resource_id = '{rid}'")
    newdev = wait(lambda: sql(f"SELECT count(*) || ' ' || string_agg(DISTINCT status, '/') FROM notification_outbox WHERE tenant_id = '{g}' "
                              f"AND kind = 'device.new' AND payload->>'device_id' = '{dv.get('id', '00000000-0000-0000-0000-000000000000')}' "
                              "GROUP BY kind") if dv else None, 60, 3) or ""
    result("enroll", "D1 trong sổ thiết bị (enrollment_request_id), audit cặp claim, device.new",
           bool(inv) and bool(dv) and "enrollment.claim.requested" in (audit or "") and "enrollment.claim.succeeded" in (audit or "")
           and newdev.startswith(("1", "2")),
           f"inventory có liên kết {bool(inv)}; GET /devices thấy g4a-vm105 {bool(dv)} owner {(dv.get('owner') or {}).get('membership_id') == mid} "
           f"online {dv.get('online')}; audit {audit}; device.new outbox {newdev}")
    rq = o.call("GET", f"/tenants/{g}/enrollment/requests/{rid}").json()
    log("  yêu cầu D1:", rq.get("status"), "node", rq.get("node_id"), "claimed_at", rq.get("claimed_at"))
    # profile cũ của tenant-c (đã gỡ 2026-11-18) — không phải profile hiện tại nữa ⇒ gỡ
    rc, out = cli("sudo -n tailscale switch --list")
    old = [ln.split()[0] for ln in out.splitlines()[1:] if "tenant-c." in ln and not ln.rstrip().endswith("*")]
    for pid in old:
        rc2, out2 = cli(f"sudo -n tailscale switch remove {pid}")
        log("  gỡ profile tenant-c cũ", pid, rc2, out2[-120:])
    log("  profiles:", cli("sudo -n tailscale switch --list")[1].replace(t.domain, "<domain>"))

    # ---------------------------------------------------------------- D2: pre-auth key (container client chính thức)
    req2 = o.call("POST", f"/tenants/{g}/enrollment/requests", {"method": "preauth_key", "device_label": "g4a-d2",
                                                                 "ttl_minutes": 10}, idem="g4a-pk-" + secrets.token_hex(6))
    r2 = req2.json()
    key = (r2.get("credential") or {}).get("preauth_key", "")
    if key:
        t.secret_values.add(key)
    rid2 = (r2.get("request") or {}).get("id", "")
    st["d2_request"] = rid2
    save_state(st)
    result("enroll", "D2 POST /enrollment/requests {preauth_key, 10 phút}", req2.status == 201 and key.startswith("hskey-auth-")
           and key not in (r2.get("credential") or {}).get("command", ""),
           f"HTTP {req2.status}; status {(r2.get('request') or {}).get('status')}; key hiển thị một lần, lệnh không chứa key; "
           f"hết hạn {(r2.get('credential') or {}).get('expires_at')}")
    img = f"{t.images['tailscale']}"
    run_sh = ("tailscaled --tun=userspace-networking --state=mem: --socket=/tmp/ts.sock --statedir=/tmp/st "
              ">/tmp/tsd.log 2>&1 & exec sleep infinity")
    cli(f"sudo -n docker rm -f {D2} >/dev/null 2>&1; true")
    rc, out = cli(f"sudo -n docker run -d --name {D2} --hostname g4a-d2 --network bridge --read-only "
                  "--tmpfs /tmp:size=16m,mode=1777 --tmpfs /run/g4a:size=1m,mode=0700 --cap-drop ALL "
                  "--security-opt no-new-privileges:true --memory 256m --pids-limit 128 --label meshguard.role=g4a-client "
                  f"-e TS_NO_LOGS_NO_SUPPORT=true --entrypoint sh {img} -c {shlex.quote(run_sh)}")
    log("  docker run D2:", rc, out[-80:])
    rc, out = d2_exec("umask 077; cat > /run/g4a/authkey", stdin=key.encode())
    rc, out = d2_exec(f"i=0; while [ ! -S /tmp/ts.sock ] && [ $i -lt 50 ]; do sleep 0.2; i=$((i+1)); done; "
                      f"timeout 90 tailscale --socket=/tmp/ts.sock up --login-server={login} --auth-key=file:/run/g4a/authkey "
                      f"--hostname=g4a-d2 --accept-dns=false --timeout=80s; rc=$?; rm -f /run/g4a/authkey; exit $rc", timeout=150)
    s2 = d2_status()
    st["d2_ip"] = ip4(s2)
    save_state(st)
    nodes = hs_nodes(slug)
    n2 = next((n for n in nodes if n.get("name") == "g4a-d2"), {})
    result("enroll", "D2 tailscale up --auth-key=file: ⇒ Running, node authkey của mg-<membership>",
           rc == 0 and s2.get("BackendState") == "Running" and n2.get("register_method") in (1, "REGISTER_METHOD_AUTH_KEY", "authkey")
           and (n2.get("user") or {}).get("name") == f"mg-{mid}",
           f"up rc {rc}; BackendState {s2.get('BackendState')}; node #{n2.get('id')} {n2.get('register_method')} user mg-<membership Owner> "
           f"{(n2.get('user') or {}).get('name') == f'mg-{mid}'}; IP {ip4(s2)}; key xóa khỏi tmpfs")
    st["d2_node"] = str(n2.get("id", ""))
    save_state(st)
    # reconcile ⇒ consumed + liên kết sổ thiết bị + device.new
    t_rc = time.time()
    s = wait(lambda: (lambda x: x if x.startswith("consumed") else None)(sql(f"SELECT status || ' ' || coalesce(consumed_node_id::text,'') FROM enrollment_requests WHERE id = '{rid2}'")), 360, 5) or \
        sql(f"SELECT status FROM enrollment_requests WHERE id = '{rid2}'")
    linked = sql(f"SELECT d.id || ' ' || coalesce(d.given_name,'') FROM device_inventory_cache d WHERE d.tenant_id = '{g}' AND d.enrollment_request_id = '{rid2}' AND d.removed_at IS NULL")
    nd2 = sql(f"SELECT count(*) FROM notification_outbox n JOIN device_inventory_cache d ON n.payload->>'device_id' = d.id::text "
              f"WHERE n.tenant_id = '{g}' AND n.kind = 'device.new' AND d.enrollment_request_id = '{rid2}'")
    hk = hs(slug, "preauthkeys", "list", "-o", "json")
    try:
        keys = json.loads(hk or "[]") or []
    except ValueError:
        keys = []
    rq2 = o.call("GET", f"/tenants/{g}/enrollment/requests/{rid2}").json()
    result("enroll", "D2 enrollment.reconcile ⇒ consumed + node trong sổ thiết bị + device.new",
           s.startswith("consumed") and s.endswith(st["d2_node"]) and bool(linked) and nd2 not in ("", "0")
           and rq2.get("status") == "consumed",
           f"{s.split()[0] if s else '?'} sau {time.time() - t_rc:.0f} s, consumed_node_id = node D2 {s.endswith(st['d2_node'])}; "
           f"sổ thiết bị có liên kết {bool(linked)}; device.new {nd2}; API status {rq2.get('status')} node {rq2.get('node_id')}; "
           f"key ở Headscale: {[(k.get('used'), k.get('reusable'), k.get('ephemeral')) for k in keys]}")
    dv2 = next((d for d in o.call("GET", f"/tenants/{g}/devices").json().get("items") or [] if d.get("name") == "g4a-d2"), {})
    st["d2_device"] = dv2.get("id", "")
    save_state(st)
    leaked = sql("SELECT (SELECT count(*) FROM enrollment_requests x WHERE x::text LIKE '%hskey-%') + "
                 "(SELECT count(*) FROM idempotency_keys x WHERE x::text LIKE '%hskey-%') + "
                 "(SELECT count(*) FROM audit_events x WHERE x::text LIKE '%hskey-%')")
    code_leak = sql(f"SELECT (SELECT count(*) FROM idempotency_keys x WHERE x::text LIKE '%{code}%') + "
                    f"(SELECT count(*) FROM audit_events x WHERE x::text LIKE '%{code}%')") if code else "?"
    result("enroll", "không có key/mã trong DB", leaked == "0" and code_leak == "0",
           f"hàng chứa hskey- (enrollment_requests/idempotency_keys/audit_events): {leaked}; mã web-auth trong idempotency/audit: {code_leak}")


def public_get(hostname: str, path: str) -> tuple[int, str, str]:
    """GET qua DNS công khai (máy vận hành → VPS → tunnel → edge), không theo chuyển hướng."""
    try:
        c = http.client.HTTPSConnection(hostname, 443, timeout=20, context=ssl.create_default_context())
        c.request("GET", path, headers={"User-Agent": "g4a-check"})
        r = c.getresponse()
        r.read()
        return r.status, r.getheader("Location") or "", r.getheader("Cache-Control") or ""
    except Exception as e:  # noqa: BLE001
        return 0, type(e).__name__, ""


# ------------------------------------------------------------------------------------------------ policy
def P(typ: str, ref: str) -> dict:
    return {"type": typ, "ref": ref}


ALLOW = {"grants": [{"src": [P("autogroup", "member")], "dst": [P("autogroup", "member")], "ip": [f"tcp:{PORT}"]}]}
DENY = {"grants": []}


def d2_listen() -> None:
    cli(f"sudo -n docker exec -d {D2} nc -lk -p {PORT} -e echo g4a d2 tcp/{PORT}")


def tcp_until(want_open: bool, timeout: float = 90) -> tuple[str, float]:
    t0 = time.time()
    ip = load_state().get("d2_ip", "")
    last = ""
    while time.time() - t0 < timeout:
        last = tcp_d1_to_d2(ip, 4)
        if last.startswith("ANS") == want_open:
            return last, time.time() - t0
        time.sleep(2)
    return last, time.time() - t0


def policy_version(o: Owner, g: str, source: dict, label: str) -> dict:
    c = o.call("POST", f"/tenants/{g}/policies", {"source": source}, idem="g4a-pol-" + secrets.token_hex(6))
    v = c.json() if c.status == 201 else {}
    val = o.call("POST", f"/tenants/{g}/policies/{v.get('id')}/validate", None, if_match=v.get("etag")) if v else None
    vv = val.json() if val is not None and val.status == 200 else {}
    rep = vv.get("validation_report") or {}
    ap = o.call("POST", f"/tenants/{g}/policies/{vv.get('id')}/approve", {"content_sha256": vv.get("content_sha256")},
                if_match=vv.get("etag")) if vv else None
    va = ap.json() if ap is not None and ap.status == 200 else {}
    result("policy", f"{label}: draft → validate → approve", c.status == 201 and v.get("state") == "draft"
           and vv.get("state") == "validated" and rep.get("result") == "passed" and va.get("state") == "approved",
           f"POST {c.status} {v.get('state')} v{v.get('version')}; validate {val.status if val else '-'} {vv.get('state')} "
           f"result {rep.get('result')} CheckPolicy {rep.get('check')} rendered_sha256 {str(rep.get('rendered_sha256', ''))[:12]}…; "
           f"approve {ap.status if ap else '-'} {va.get('state')} review_mode {va.get('review_mode')}")
    return va


def apply_version(o: Owner, g: str, slug: str, v: dict, label: str, action: str = "apply") -> dict:
    t0 = time.time()
    r = o.call("POST", f"/tenants/{g}/policies/{v.get('id')}/{action}", None, idem="g4a-ap-" + secrets.token_hex(6))
    acc = r.json() if r.status == 202 else {}
    jid = (acc.get("job") or {}).get("id", "")
    j = tenant_job(o, g, jid) if jid else {}
    stored = hs_policy_sha(slug)
    app = sql(f"SELECT trigger || ' ' || state || ' ' || applied_sha256 || ' ' || policy_version_id FROM policy_applications "
              f"WHERE tenant_id = '{g}' ORDER BY created_at DESC, id DESC LIMIT 1").split()
    cur = o.call("GET", f"/tenants/{g}/policies/current").json()
    vid = (acc.get("version") or {}).get("id") or v.get("id")
    ok = r.status == 202 and j.get("status") == "succeeded" and len(app) == 4 and app[1] == "applied" and app[2] == stored \
        and app[3] == vid
    result("policy", f"{label}: {action} ⇒ job policy.apply, read-back sha khớp", ok,
           f"{action} {r.status} Location job {(r.header('Location') or '').endswith(jid)}; job {j.get('status')} {time.time() - t0:.1f} s; "
           f"application {app[:2]} sha {app[2][:16] if len(app) > 2 else '?'}… = Headscale {stored[:16]}… {len(app) > 2 and app[2] == stored}; "
           f"version {vid == (app[3] if len(app) > 3 else '')}; current.desired {((cur.get('desired') or {}).get('id') == vid)}")
    return acc.get("version") or v


def cmd_policy() -> None:
    st = load_state()
    slug, g = st["slug"], st["tenant_id"]
    o = owner(st)
    o.login()
    d2_listen()
    cur = o.call("GET", f"/tenants/{g}/policies/current").json()
    local = d2_exec(f"echo | nc -w 3 127.0.0.1 {PORT}")[1]
    base, _ = tcp_until(False, 12)
    result("policy", "trước khi áp: policy ban đầu của tenant", not base.startswith("ANS"),
           f"current: desired v{(cur.get('desired') or {}).get('version')} applied {(cur.get('applied') or {}).get('state', '') or list(cur.keys())}; "
           f"TCP D1→D2:{PORT} {base}; listener cục bộ trên D2 '{local.strip()}'; sha Headscale {hs_policy_sha(slug)[:16]}…")
    va = policy_version(o, g, ALLOW, "allow (autogroup:member → autogroup:member tcp:8000)")
    apply_version(o, g, slug, va, "allow")
    ans, dt = tcp_until(True, 90)
    result("policy", "allow ⇒ TCP thật D1→D2:8000 thông", ans.startswith("ANS"), f"{ans} sau {dt:.1f} s")
    st["policy_allow"] = va.get("id")
    save_state(st)
    vd = policy_version(o, g, DENY, "deny-all (grants: [])")
    apply_version(o, g, slug, vd, "deny")
    ans, dt = tcp_until(False, 90)
    peers = len((d1_status().get("Peer") or {}))
    result("policy", "deny ⇒ TCP bị chặn (listener vẫn trả lời cục bộ)", not ans.startswith("ANS"),
           f"{ans} sau {dt:.1f} s; D1 còn {peers} peer; cục bộ D2 '{d2_exec(f'echo | nc -w 3 127.0.0.1 {PORT}')[1].strip()}'")
    rv = apply_version(o, g, slug, va, "rollback về allow", action="rollback")
    ans, dt = tcp_until(True, 90)
    result("policy", "rollback ⇒ TCP thông lại", ans.startswith("ANS"), f"{ans} sau {dt:.1f} s; version mới v{rv.get('version')} rollback_of allow {rv.get('rollback_of') == va.get('id')}")


# ------------------------------------------------------------------------------------------------ lifecycle
def cmd_lifecycle() -> None:
    st = load_state()
    g = st["tenant_id"]
    pf = platform()
    o = owner(st)
    o.login()
    d2_listen()
    r, j = pf.lifecycle(g, "suspend")
    d = pf.wait_job(j.get("id", ""), 300) if r.status == 202 else {}
    tst = pf.tenant(g).get("status")
    ans, dt = tcp_until(False, 90)
    w = o.call("POST", f"/tenants/{g}/enrollment/requests", {"method": "preauth_key"}, idem="g4a-susp-" + secrets.token_hex(6), tries=3)
    rd = o.call("GET", f"/tenants/{g}/devices")
    result("lifecycle", "suspend ⇒ job, TCP bị chặn, ghi ⇒ 403 tenant_suspended, đọc vẫn được",
           r.status == 202 and d.get("status") == "succeeded" and tst == "suspended" and not ans.startswith("ANS")
           and w.status == 403 and rd.status == 200,
           f"HTTP {r.status} job {d.get('status')}; tenant {tst}; TCP {ans} sau {dt:.1f} s; POST enrollment {w.status} "
           f"{w.json().get('code')}; GET devices {rd.status}")
    r, j = pf.lifecycle(g, "resume")
    d = pf.wait_job(j.get("id", ""), 300) if r.status == 202 else {}
    tst = pf.tenant(g).get("status")
    ans, dt = tcp_until(True, 120)
    result("lifecycle", "resume ⇒ job, TCP thông lại", r.status == 202 and d.get("status") == "succeeded" and tst == "active"
           and ans.startswith("ANS"), f"HTTP {r.status} job {d.get('status')}; tenant {tst}; TCP {ans} sau {dt:.1f} s")


# ------------------------------------------------------------------------------------------------ devices
def cmd_devices() -> None:
    st = load_state()
    slug, g = st["slug"], st["tenant_id"]
    o = owner(st)
    o.login()
    d2_listen()
    dev = st.get("d2_device") or next((d["id"] for d in o.call("GET", f"/tenants/{g}/devices").json().get("items") or []
                                       if d.get("name") == "g4a-d2"), "")
    ans0, _ = tcp_until(True, 30)
    r = o.call("PATCH", f"/tenants/{g}/devices/{dev}", {"given_name": "g4a-d2-renamed"})
    rj = r.json()
    node = next((n for n in hs_nodes(slug) if str(n.get("id")) == st.get("d2_node")), {})
    result("devices", "rename D2 (PATCH given_name) ⇒ Headscale đọc lại", r.status == 200 and rj.get("given_name") == "g4a-d2-renamed"
           and node.get("given_name") == "g4a-d2-renamed", f"PATCH {r.status} given_name {rj.get('given_name')}; Headscale {node.get('given_name')}")
    t0 = time.time()
    e = o.call("POST", f"/tenants/{g}/devices/{dev}/expire", None, idem="g4a-exp-" + secrets.token_hex(6))
    ej = e.json()
    first = (ej.get("revocation") or {}).get("state")
    seen = [first]

    def applied():
        s = (o.call("GET", f"/tenants/{g}/devices/{dev}").json().get("revocation") or {})
        if s.get("state") != seen[-1]:
            seen.append(s.get("state"))
        return s if s.get("state") in ("applied", "failed") else None
    rev = wait(applied, 120, 2) or {}
    node = next((n for n in hs_nodes(slug) if str(n.get("id")) == st.get("d2_node")), {})
    result("devices", "expire D2 ⇒ 202 pending → applied (đọc lại Headscale)", e.status == 202 and first == "pending"
           and rev.get("state") == "applied",
           f"POST expire {e.status} Location job {bool(e.header('Location'))}; trạng thái {seen} sau {time.time() - t0:.1f} s; "
           f"verified_at {rev.get('verified_at')}; Headscale expiry {str(node.get('expiry'))[:25]}")
    ans, dt = tcp_until(False, 120)
    s2 = wait(lambda: (lambda s: s if s.get("BackendState") != "Running" or (s.get("Self") or {}).get("Expired") else None)(d2_status()), 90, 3) or d2_status()
    result("devices", "D2 mất kết nối sau expire", not ans.startswith("ANS") and ans0.startswith("ANS"),
           f"TCP trước {ans0}; sau {ans} ({dt:.1f} s); D2 BackendState {s2.get('BackendState')} Self.Expired {(s2.get('Self') or {}).get('Expired')}")


# ------------------------------------------------------------------------------------------------ audit
def cmd_audit() -> None:
    st = load_state()
    g, a, b = st["tenant_id"], st["tenant_a"], st["tenant_b"]
    o = owner(st)
    o.login()
    items, cur = [], ""
    for _ in range(20):
        r = o.call("GET", f"/tenants/{g}/audit?limit=100" + (f"&cursor={urllib.parse.quote(cur)}" if cur else ""))
        j = r.json()
        items += j.get("items") or []
        cur = j.get("next_cursor") or ""
        if not cur:
            break
    acts = {}
    for x in items:
        acts[f"{x.get('action')}:{x.get('outcome')}"] = acts.get(f"{x.get('action')}:{x.get('outcome')}", 0) + 1
    (OUT / "audit-actions.json").write_text(json.dumps(acts, indent=1, ensure_ascii=False), encoding="utf-8")
    need = ["enrollment.request", "enrollment.claim.requested", "enrollment.claim.succeeded", "policy.create", "policy.validate",
            "policy.approved", "policy.desired_set", "policy.rollback", "device.rename.requested", "device.rename.succeeded",
            "device.expire"]
    have = {n: [k for k in acts if k.startswith(n)] for n in need}
    missing = [n for n, v in have.items() if not v]
    result("audit", "GET /tenants/{g4a}/audit có đủ hành động", r.status == 200 and not missing,
           f"{len(items)} sự kiện, {len(acts)} loại; thiếu {missing}; " + ", ".join(f"{k}×{v}" for k, v in sorted(acts.items())))
    ca, cb = o.call("GET", f"/tenants/{a}/audit"), o.call("GET", f"/tenants/{b}/audit")
    leak = sql(f"SELECT count(*) FROM audit_events WHERE tenant_id IN ('{a}','{b}') AND occurred_at >= '{st['started']}' AND "
               f"(details::text LIKE '%{g}%' OR details::text LIKE '%{st['slug']}%' OR resource_id = '{g}')")
    ab = sql(f"SELECT t.slug || ':' || count(e.id) FROM tenants t LEFT JOIN audit_events e ON e.tenant_id = t.id AND e.occurred_at >= '{st['started']}' "
             f"WHERE t.id IN ('{a}','{b}') GROUP BY t.slug ORDER BY 1")
    result("audit", "cách ly: Owner g4a đọc audit A/B ⇒ 404; audit của A/B không chứa gì của tenant thử", ca.status == 404 and cb.status == 404
           and leak == "0", f"GET audit A {ca.status}, B {cb.status}; hàng audit của A/B nhắc tới tenant thử (id/slug) từ lúc bắt đầu: {leak}; "
           f"sự kiện A/B trong cửa sổ: {ab.replace(chr(10), ', ')}")


# ------------------------------------------------------------------------------------------------ cleanup
def cmd_cleanup() -> None:
    st = load_state()
    slug, g = st["slug"], st["tenant_id"]
    rc, out = cli("sudo -n timeout 60 tailscale logout; echo rc=$?; sudo -n tailscale switch --list; tailscale status 2>&1 | head -2")
    log("  D1 logout:", out.replace(t.domain, "<domain>")[-300:])
    rc, out = cli(f"sudo -n docker rm -f {D2} g4a-d3; rm -rf ~/g4a; echo done")
    log("  D2 rm + ~/g4a:", out[-80:])
    pf = platform()
    d = pf.deprovision(g, slug, "G4a (P4-T10a): dọn tenant thử sau kiểm chứng")
    j = pf.wait_job(d.get("job_id", ""), 600) if d.get("job_id") else {}
    tst = pf.tenant(g).get("status")
    result("cleanup", "deprovision 2P (SA1 yêu cầu, SA1 tự duyệt ⇒ 403, SA2 duyệt)", d.get("request_status") == 202
           and d.get("self_approval_status") == 403 and d.get("approve_status") == 200 and j.get("status") == "succeeded" and tst == "deleted",
           f"DELETE {d.get('request_status')}, tự duyệt {d.get('self_approval_status')}, SA2 duyệt {d.get('approve_status')}, "
           f"job {j.get('status')} {len(j.get('steps') or [])} bước; tenant {tst}; {d.get('error', '')}")
    inst = st.get("instance_id", "")
    chk = host(f"echo containers=$(sudo -n docker ps -a --format '{{{{.Names}}}}' | grep -c -- '{slug}'); "
               f"echo networks=$(sudo -n docker network ls --format '{{{{.Name}}}}' | grep -c -- '{slug}'); "
               f"echo volumes=$(sudo -n docker volume ls --format '{{{{.Name}}}}' | grep -c -- '{slug}'); "
               f"echo dir=$(sudo -n ls /opt/meshguard/tenants | grep -c -- '{inst or 'none'}'); "
               f"echo secrets=$(sudo -n find /opt/meshguard/secrets -maxdepth 3 -name '*{inst or 'none'}*' 2>/dev/null | wc -l); "
               f"echo edge_nets=$(sudo -n docker inspect -f '{{{{range $k,$v := .NetworkSettings.Networks}}}}{{{{$k}}}} {{{{end}}}}' mg-edge)")
    vals = dict(x.split("=", 1) for x in chk.splitlines() if "=" in x)
    result("cleanup", "host không còn tài nguyên của tenant thử", all(vals.get(k) == "0" for k in ("containers", "networks", "volumes", "dir", "secrets"))
           and slug not in vals.get("edge_nets", ""),
           f"container {vals.get('containers')}, network {vals.get('networks')}, volume {vals.get('volumes')}, thư mục instance {vals.get('dir')}, "
           f"secret {vals.get('secrets')}; network của edge: {vals.get('edge_nets')}")
    rc, out = cli("sudo -n tailscale switch --list; tailscale status --json 2>/dev/null | python3 -c \"import json,sys; d=json.load(sys.stdin); print(d.get('BackendState'), d.get('CurrentTailnet'))\"; "
                  "ip -br addr show tailscale0; sudo -n docker ps -a --filter label=meshguard.role=g4a-client --format '{{.Names}}' | wc -l")
    result("cleanup", "VM 105 không thuộc tailnet nào, không còn container g4a", "tenant-" not in out and "g4a-" not in out.split("ID")[-1],
           out.replace(t.domain, "<domain>").replace("\n", " | ")[-300:])

# ------------------------------------------------------------------------------------------------ ui (Chromium thật)
PW = pathlib.Path(os.environ.get("G4A_PW_DIR") or pathlib.Path(__file__).resolve().parent)   # ui.mjs + node_modules/playwright-core
D3 = "g4a-d3"


def cmd_ui() -> None:
    import threading
    st = load_state()
    slug, g = st["slug"], st["tenant_id"]
    c = json.loads(CREDS.read_text(encoding="utf-8"))
    hand = HOME / "g4a-ui"
    hand.mkdir(mode=0o700, exist_ok=True)
    for f in hand.iterdir():
        f.unlink()
    shots = OUT / "shots"
    shots.mkdir(exist_ok=True)
    cfgf = HOME / "g4a-ui.json"
    cfgf.write_text(json.dumps({"app": f"https://app.{t.domain}", "auth_host": f"auth.{t.domain}", "slug": slug, "tenant_id": g,
                                "username": c["username"], "password": c["password"], "totp_raw": c["totp_raw"],
                                "totp_last": c.get("totp_last", 0), "handoff": str(hand), "shots": str(shots),
                                "pause_ms": int(os.environ.get("G4A_PAUSE_MS", "0"))}), encoding="utf-8")
    try:
        os.chmod(cfgf, 0o600)
    except OSError:
        pass
    t.secret_values.update({c["password"], c["totp_raw"]})
    proc = subprocess.Popen(["node", str(PW / "ui.mjs"), str(cfgf)], cwd=str(PW), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    def pump():
        for raw in proc.stdout:
            log("  [node]", raw.decode("utf-8", "replace").rstrip())
    th = threading.Thread(target=pump, daemon=True)
    th.start()
    try:
        hf = hand / "hostname"
        hn = wait(lambda: hf.exists() and hf.read_text().strip(), 240, 1.0) or ""
        if hf.exists():
            hf.unlink()
        if not hn:
            log("  không nhận được hostname từ SPA")
            return
        t.secret_values.add(hn)
        login = f"https://{slug}.mesh.{t.domain}"
        run_sh = ("tailscaled --tun=userspace-networking --state=mem: --socket=/tmp/ts.sock --statedir=/tmp/st "
                  ">/tmp/tsd.log 2>&1 & exec sleep infinity")
        cli(f"sudo -n docker rm -f {D3} >/dev/null 2>&1; true")
        rc, out = cli(f"sudo -n docker run -d --name {D3} --hostname g4a-d3 --network bridge --read-only "
                      "--tmpfs /tmp:size=16m,mode=1777 --cap-drop ALL --security-opt no-new-privileges:true --memory 256m "
                      f"--pids-limit 128 --label meshguard.role=g4a-client -e TS_NO_LOGS_NO_SUPPORT=true --entrypoint sh "
                      f"{t.images['tailscale']} -c {shlex.quote(run_sh)}")
        up = (f"i=0; while [ ! -S /tmp/ts.sock ] && [ $i -lt 50 ]; do sleep 0.2; i=$((i+1)); done; "
              f"timeout 300 tailscale --socket=/tmp/ts.sock up --login-server={login} --hostname={hn} --accept-dns=false "
              "--timeout=280s >/tmp/up.log 2>&1")
        cli(f"sudo -n docker exec -d {D3} sh -c {shlex.quote(up)}")
        got = wait(lambda: (lambda m: m.group(0) if m else None)(AUTH_RE.search(cli(f"sudo -n docker exec {D3} cat /tmp/up.log")[1])), 60, 1.0)
        if not got:
            log("  D3 không in link")
            return
        t.secret_values.add(got.rsplit("/", 1)[-1])
        (hand / "link").write_text(got)
        result("ui", "D3 (container client chính thức, không key) chạy lệnh của SPA ⇒ link", True, f"docker run rc {rc}; link của <slug>.mesh.<domain>")
        cf = hand / "claimed"
        wait(lambda: cf.exists(), 180, 1.0)
        def d3s():
            rc_, o_ = cli(f"sudo -n docker exec {D3} tailscale --socket=/tmp/ts.sock status --json")
            try:
                return json.loads(o_[o_.index("{"):]) if "{" in o_ else {}
            except ValueError:
                return {}
        running = wait(lambda: d3s().get("BackendState") == "Running", 90, 2)
        n3 = next((n for n in hs_nodes(slug) if n.get("given_name") == "g4a-ui"), {})
        inv = sql(f"SELECT count(*) FROM device_inventory_cache d JOIN enrollment_requests r ON r.id = d.enrollment_request_id "
                  f"WHERE d.tenant_id = '{g}' AND r.device_label = 'g4a-ui' AND r.status = 'verified' AND d.removed_at IS NULL")
        result("ui", "V-07 qua trình duyệt: D3 Running sau claim trong SPA, node đổi tên g4a-ui, sổ thiết bị có liên kết",
               bool(running) and bool(n3) and (n3.get("user") or {}).get("name") == f"mg-{st['owner_membership_id']}" and inv == "1",
               f"D3 Running {bool(running)}; node #{n3.get('id')} given_name {n3.get('given_name')} register_method {n3.get('register_method')} "
               f"user mg-<membership Owner> {(n3.get('user') or {}).get('name') == f'mg-' + st['owner_membership_id']}; inventory verified + liên kết {inv}")
        st["d3_node"] = str(n3.get("id", ""))
        save_state(st)
    finally:
        try:
            proc.wait(timeout=240)
        except subprocess.TimeoutExpired:
            proc.kill()
        th.join(timeout=5)
        tl = hand / "totp_last"
        if tl.exists():
            c = json.loads(CREDS.read_text(encoding="utf-8"))
            c["totp_last"] = max(int(c.get("totp_last", 0)), int(tl.read_text().strip() or 0))
            CREDS.write_text(json.dumps(c), encoding="utf-8")
        res = hand / "ui-result.json"
        if res.exists():
            for s_ in json.loads(res.read_text(encoding="utf-8")).get("steps", []):
                result("ui", s_["name"], s_["ok"], s_["detail"])
        cfgf.unlink(missing_ok=True)
        for f in hand.iterdir():
            f.unlink()

# ------------------------------------------------------------------------------------------------ after (≥ 15 phút sau 16:03)
LAB = {"a1": os.environ.get("G4A_LAB_A1", ""), "b1": os.environ.get("G4A_LAB_B1", "")}   # mgdeploy@<client lab>


def cmd_after() -> None:
    since = os.environ.get("G4A_SINCE", "2026-11-19 16:03:00+00")   # giờ xong triển khai
    rows = {}
    for slug in ("tenant-a", "tenant-b"):
        live = hs_policy_sha(slug)
        app = sql(f"SELECT a.applied_sha256 || ' ' || a.trigger || ' ' || a.created_at::timestamptz(0) FROM policy_applications a JOIN tenants t ON t.id = a.tenant_id "
                  f"WHERE t.slug = '{slug}' AND a.state = 'applied' AND a.superseded_at IS NULL ORDER BY a.created_at DESC LIMIT 1")
        jobs = sql(f"SELECT j.kind || ':' || j.status || '×' || count(*) FROM provisioning_jobs j JOIN tenants t ON t.id = j.tenant_id WHERE t.slug = '{slug}' "
                   f"AND j.created_at >= '{since}' AND j.kind IN ('policy.drift_check', 'policy.apply') GROUP BY j.kind, j.status ORDER BY 1")
        sec = sql(f"SELECT count(*) FROM security_events e JOIN tenants t ON t.id = e.tenant_id WHERE t.slug = '{slug}' AND e.occurred_at >= '{since}' "
                  "AND e.kind LIKE 'instance.policy%'")
        nodes = hs_nodes(slug)
        rows[slug] = (live, app, jobs, sec, nodes)
        result("after", f"{slug}: policy sha + drift_check", live.startswith("46206234ae7c6484") and app.startswith(live)
               and "policy.apply" not in jobs and sec == "0" and "policy.drift_check:succeeded" in jobs,
               f"Headscale {live[:16]}…; applied (chưa bị thay) {app[:16]}… {' '.join(app.split()[1:])}; job từ 16:03: {jobs.replace(chr(10), ', ')}; "
               f"security_event instance.policy* {sec}; node online {[(n.get('given_name'), n.get('online')) for n in nodes]}")
    werr = host(f"sudo -n docker logs --since {since[:10]}T{since[11:16]}:00Z mg-app-worker-1 2>&1 | grep '\"level\":\"ERROR\"' | "
                "python3 -c \"import sys,json,collections; c=collections.Counter(); [c.update([json.loads(l).get('msg','?')+' | '+str(json.loads(l).get('kind') or json.loads(l).get('job_kind') or '')]) for l in sys.stdin if l.strip().startswith('{')]; print(dict(c))\"")
    aerr = host(f"sudo -n docker logs --since {since[:10]}T{since[11:16]}:00Z mg-app-api-1 2>&1 | grep -c '\"level\":\"ERROR\"'")
    merr = host(f"sudo -n docker logs --since {since[:10]}T{since[11:16]}:00Z mg-app-mail-bridge-1 2>&1 | grep -c '\"level\":\"ERROR\"'")
    aerr2 = host(f"sudo -n docker logs --since {since[:10]}T{since[11:16]}:00Z mg-agent 2>&1 | grep -c '\"level\":\"ERROR\"'")
    result("after", "log ERROR từ 16:00 UTC (worker, api, mail-bridge, agent)", werr in ("{}", "") and aerr.strip() == "0",
           f"worker {werr}; api {aerr}; mail-bridge {merr}; agent {aerr2}")
    for name, ssh_host in LAB.items():
        code = ("import json,socket,subprocess,time\n"
                "st=json.loads(subprocess.run(['tailscale','status','--json'],capture_output=True,text=True).stdout)\n"
                "peer=[p for p in (st.get('Peer') or {}).values()][0]\n"
                "ip=[a for a in peer['TailscaleIPs'] if '.' in a][0]\n"
                "def tcp(port):\n"
                " t=time.time()\n"
                " try:\n  s=socket.create_connection((ip,port),timeout=5); s.close(); return 'connected %.2fs'%(time.time()-t)\n"
                " except ConnectionRefusedError: return 'RST (refused) %.2fs'%(time.time()-t)\n"
                " except Exception as e: return type(e).__name__+' %.1fs'%(time.time()-t)\n"
                "print(json.dumps({'self':st['Self']['HostName'],'state':st['BackendState'],'peer':peer['HostName'],'peer_online':peer.get('Online'),"
                "'tcp8000':tcp(8000),'tcp8001':tcp(8001)}))\n")
        rc, out = run(SSH + [ssh_host, "python3 -"], code.encode(), 60)
        ping = run(SSH + [ssh_host, "ping -c 3 -W 2 100.64.0.2 | tail -2 | head -1"], None, 60)[1]
        try:
            j = json.loads(out.strip().splitlines()[-1])
        except (ValueError, IndexError):
            j = {}
        result("after", f"{name}→{j.get('peer', '?')}: TCP 8000 qua tailnet (grant tcp:8000), 8001 (không có grant)",
               j.get("state") == "Running" and j.get("peer_online") is True and j.get("tcp8000", "").startswith(("connected", "RST")) and "Timeout" in j.get("tcp8001", ""),
               f"{j}; ping: {ping}")


if __name__ == "__main__":
    step = sys.argv[1]
    log(f"===== {step} =====")
    {"provision": cmd_provision, "apicheck": cmd_apicheck, "enroll": cmd_enroll, "policy": cmd_policy,
     "lifecycle": cmd_lifecycle, "devices": cmd_devices, "audit": cmd_audit, "cleanup": cmd_cleanup, "ui": cmd_ui, "after": cmd_after}[step]()
