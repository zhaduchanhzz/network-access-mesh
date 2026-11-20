#!/usr/bin/env python3
"""G4b — kiểm trên staging sau đợt nâng 4 (G4b-E1 SMTP realm + lời mời Owner qua IdP, G4b-E14 i18n, E3/E12), tenant thử
g4bv-<hex>. Chế độ "Chỉ kiểm tự động": mọi e-mail là <x>@<slug>.example.invalid — relay nhận và chuyển, thư không tới ai.

  python -B g4bv.py <bước>
  provision  SA1 tạo tenant g4bv-<hex> (Console API, IdP do nền tảng host, Owner owner@<slug>.example.invalid) ⇒ job
             tenant.provision; rồi bước realm
  realm      realm mới: smtpServer + i18n (kcadm trong container idp — như user-id.sh); chạy lại riêng được
  invite     job member.idp_invite của lời mời Owner (bước 16) ⇒ succeeded; user Owner trong realm + required actions;
             log Keycloak (KC-SERVICES0088 / lỗi gửi thư) và log mail-bridge (message relayed — không in địa chỉ/nội dung)
  owner      đặt mật khẩu cho chính user Owner qua admin API (kcadm reset-password, mật khẩu chỉ qua stdin; required
             actions còn CONFIGURE_TOTP) ⇒ Owner đăng nhập (mật khẩu + đăng ký TOTP) ⇒ tenant_owner ⇒ Owner mời End User
             (POST /invitations) ⇒ job member.idp_invite succeeded ⇒ GET /invitations + cột IdP (GET /jobs)
  locale     GET /auth/login?scope=tenant&tenant=<slug>&ui_locales=vi|en ⇒ trang Keycloak <html lang="vi"|"en">
  e3e12      End User (mật khẩu đặt như Owner) đăng nhập ⇒ end_user; GET /enrollment/instructions ⇒ self_enroll=false;
             Console GET /platform/tenants có plan + name; nhãn tenant ở instance/job
  cleanup    deprovision 2P (SA1 yêu cầu, SA1 tự duyệt ⇒ 403, SA2 duyệt) ⇒ deleted; host không còn tài nguyên
Chạy trên máy vận hành, theo thứ tự trên. IP/domain đọc từ staging.env (tools/mgenv.py); 2 Super Admin thử từ
~/.meshguard/g3-creds.json. Mật khẩu/TOTP/cookie/CSRF chỉ trong tiến trình (tập che) và file 0600 ~/.meshguard/g4bv-*
(xóa sau cleanup); log + results.json đã che (thêm: domain ⇒ <domain>, IP ⇒ <ip>) trong G4BV_OUT.
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import secrets
import shlex
import string
import subprocess
import sys
import time
import urllib.parse

sys.stdout.reconfigure(encoding="utf-8")
ROOT = pathlib.Path(__file__).resolve().parents[4]   # docs/planning/evidence/G4b → gốc repo
sys.path[:0] = [str(ROOT / "tests" / "g3"), str(ROOT / "tests" / "e2e" / "harness"), str(ROOT / "tools")]
import backend  # noqa: E402
from g3platform import Platform, TargetBrowser, STEP_UP_S  # noqa: E402,F401
from g3target import Target, load_creds  # noqa: E402

HOME = pathlib.Path(os.path.expanduser("~/.meshguard"))
STATE = HOME / "g4bv-state.json"
CREDS = HOME / "g4bv-creds.json"
TOTPF = HOME / "g4bv-totp-last.json"
OUT = pathlib.Path(os.environ.get("G4BV_OUT") or os.path.expanduser("~/.meshguard/g4bv-out"))
OUT.mkdir(parents=True, exist_ok=True)
KEY = str(pathlib.Path.home() / ".ssh" / "id_ed25519_meshguard")
SSH = ["ssh", "-i", KEY, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "ConnectTimeout=30",
       "-o", "ServerAliveInterval=10"]
IDP = "mg-idp-idp-1"
BRIDGE = "mg-app-mail-bridge-1"

t = Target(ROOT / "infrastructure/environments/staging/staging.env",
           {"host_docker": " ".join(SSH) + " mgdeploy@${MG_LAN_IPV4} sudo -n docker"})
HOSTSSH = SSH + [f"mgdeploy@{t.env['MG_LAN_IPV4']}"]
RESULTS = OUT / "results.json"
LOG = open(OUT / "run.log", "a", encoding="utf-8")
PLAIN = {t.domain: "<domain>", t.env["MG_LAN_IPV4"]: "<ip>"}
if t.env.get("MG_PUBLIC_IPV4"):
    PLAIN[t.env["MG_PUBLIC_IPV4"]] = "<pub>"


def clean(text: str) -> str:
    text = t.redact(text)
    for k, v in PLAIN.items():
        text = text.replace(k, v)
    return text


def log(*a) -> None:
    line = clean(time.strftime("%H:%M:%S", time.gmtime()) + " " + " ".join(str(x) for x in a))
    print(line, flush=True)
    LOG.write(line + "\n")
    LOG.flush()


def result(step: str, name: str, ok: bool, detail: str) -> bool:
    doc = json.loads(RESULTS.read_text(encoding="utf-8")) if RESULTS.exists() else {}
    doc.setdefault(step, []).append({"name": name, "ok": ok, "detail": clean(detail),
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


def sql(q: str) -> str:
    return host("sudo -n docker exec -i mg-core-postgres-1 psql -X -At -U postgres -d meshguard", q.encode())


def host_now() -> str:
    return host("date -u +%Y-%m-%dT%H:%M:%SZ").strip()


# Keycloak admin API: kcadm TRONG container idp với admin khởi tạo của realm master (đọc từ secret đã mount — như
# infrastructure/idp/user-id.sh / create-user.sh); không secret trong argv; mật khẩu người dùng chỉ qua stdin.
KC_SCRIPT = r"""
set -euo pipefail
cfg=$(mktemp /tmp/kcadm.XXXXXX)
trap 'rm -f "$cfg"' EXIT
conf=/run/secrets/keycloak.conf
admin=$(sed -n 's/^bootstrap-admin-username=//p' "$conf")
KC_CLI_PASSWORD=$(sed -n 's/^bootstrap-admin-password=//p' "$conf") \
  /opt/keycloak/bin/kcadm.sh config credentials --config "$cfg" --server http://localhost:8080 --realm master \
  --user "$admin" >/dev/null
kc() { /opt/keycloak/bin/kcadm.sh "$@" --config "$cfg"; }
[[ $2 =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]] || { echo "realm?" >&2; exit 2; }
case "$1" in
  realm) kc get "realms/$2" --fields 'realm,enabled,smtpServer(*),internationalizationEnabled,supportedLocales,defaultLocale' ;;
  users) kc get users -r "$2" --fields id,username,email,enabled,emailVerified,requiredActions,firstName,lastName,createdTimestamp ;;
  setpw)
    [[ $3 =~ ^[0-9a-f-]{36}$ ]] || { echo "id?" >&2; exit 2; }
    IFS= read -r pw || true
    pw=${pw%$'\r'}
    [[ $pw =~ ^[A-Za-z0-9]{16,128}$ ]] || { echo "pw?" >&2; exit 2; }
    printf '{"type":"password","value":"%s","temporary":false}' "$pw" | kc update "users/$3/reset-password" -r "$2" -f -
    printf '{"firstName":"G4bv","lastName":"%s","emailVerified":true,"requiredActions":["CONFIGURE_TOTP"]}' "$4" \
      | kc update "users/$3" -r "$2" -f -
    echo "setpw ok" ;;
  *) exit 2 ;;
esac
"""


def kc(op: str, realm: str, *args: str, stdin: bytes | None = None) -> str:
    inner = ["sudo", "-n", "docker", "exec", "-i", IDP, "bash", "-c", KC_SCRIPT, "kc", op, realm, *args]
    return host(" ".join(shlex.quote(x) for x in inner), stdin, timeout=120)


def kc_json(op: str, realm: str):
    out = kc(op, realm)
    try:
        return json.JSONDecoder().raw_decode(out[out.index("[") if op == "users" else out.index("{"):])[0]
    except ValueError:
        log(f"  kcadm {op} {realm}: không đọc được JSON: {out[-300:]}")
        return None


def load_state() -> dict:
    return json.loads(STATE.read_text(encoding="utf-8")) if STATE.exists() else {}


def save_state(st: dict) -> None:
    STATE.write_text(json.dumps(st, indent=1), encoding="utf-8")
    try:
        os.chmod(STATE, 0o600)
    except OSError:
        pass


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


# ------------------------------------------------------------------------------------------------ người dùng tenant
class Member:
    """Một người dùng của tenant thử (Owner / End User) — creds trong CREDS[who]."""

    def __init__(self, slug: str, who: str):
        self.slug, self.who = slug, who
        c = json.loads(CREDS.read_text(encoding="utf-8"))[who]
        self.user = {"username": c["username"], "password": c["password"]}
        t.secret_values.add(c["password"])
        self.otp = backend.TOTP()
        self.otp.key = c.get("totp_raw", "").encode()
        self.otp.last = int(c.get("totp_last", 0))
        if c.get("totp_raw"):
            t.secret_values.add(c["totp_raw"])
        self.host = f"app.{t.domain}"
        self.b = TargetBrowser(t)
        self.sess: dict = {}

    def login(self) -> list[str]:
        self.b = TargetBrowser(t)
        self.sess, steps = backend.portal_login(t, self.b, self.host, f"scope=tenant&tenant={self.slug}", self.user, self.otp)
        c = json.loads(CREDS.read_text(encoding="utf-8"))
        c[self.who].update(totp_raw=self.otp.key.decode(), totp_last=self.otp.last)
        CREDS.write_text(json.dumps(c), encoding="utf-8")
        t.secret_values.add(self.otp.key.decode())
        return steps

    def call(self, method: str, path: str, body=None, idem: str | None = None, tries: int = 8) -> backend.Resp:
        if not self.sess:
            self.login()
        data = json.dumps(body).encode() if body is not None else None
        h = None
        if method != "GET":
            h = {"Origin": f"https://{self.host}", "X-CSRF-Token": self.sess.get("csrf_token", ""),
                 "Content-Type": "application/json"}
            if idem:
                h["Idempotency-Key"] = idem
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
            if r.status == 401 and r.json().get("code") in ("reauth_required", "unauthenticated"):
                self.login()
                if h:
                    h["X-CSRF-Token"] = self.sess.get("csrf_token", "")
                continue
            return r
        return r


def put_creds(who: str, username: str, password: str) -> None:
    c = json.loads(CREDS.read_text(encoding="utf-8")) if CREDS.exists() else {}
    c[who] = {"username": username, "password": password}
    CREDS.write_text(json.dumps(c), encoding="utf-8")
    try:
        os.chmod(CREDS, 0o600)
    except OSError:
        pass


def idp_jobs(slug_tid: str) -> list[list[str]]:
    rows = sql("SELECT id, status, coalesce(error->>'code',''), coalesce(resource_type,''), coalesce(resource_id,''), "
               "to_char(created_at,'HH24:MI:SS'), coalesce(extract(epoch from finished_at-started_at)::numeric(8,2)::text,''), "
               "coalesce(output::text,'') FROM provisioning_jobs "
               f"WHERE tenant_id = '{slug_tid}' AND kind = 'member.idp_invite' ORDER BY created_at")
    return [r.split("|") for r in rows.splitlines() if r.strip()]


def wait_idp_job(tid: str, inv: str, timeout: float = 180) -> list[str]:
    end = time.time() + timeout
    while time.time() < end:
        js = [j for j in idp_jobs(tid) if j[4] == inv]
        if js and js[-1][1] in ("succeeded", "failed", "cancelled", "rolled_back"):
            return js[-1]
        time.sleep(2)
    js = [j for j in idp_jobs(tid) if j[4] == inv]
    return js[-1] if js else []


def mail_and_kc_logs(since: str, slug: str) -> tuple[dict, dict]:
    """Log mail-bridge (dòng 'mailrelay: message …': kết quả, số người nhận — không địa chỉ) và log Keycloak (lỗi gửi thư)."""
    out = host(f"sudo -n docker logs --since {since} {BRIDGE} 2>&1 | grep 'mailrelay: ' || true")
    msgs = []
    for ln in out.splitlines():
        try:
            d = json.loads(ln[ln.index("{"):])
        except ValueError:
            continue
        msgs.append({k: d.get(k) for k in ("time", "msg", "result", "code", "status", "rcpt", "sent", "failed", "attempts",
                                           "duration_ms", "bytes")})
    kcl = host(f"sudo -n docker logs --since {since} {IDP} 2>&1 | grep -E 'KC-SERVICES0088|Failed to send|EmailException|"
               f"SendFailedException|MessagingException' || true")
    lines = [x for x in kcl.splitlines() if x.strip()]
    return ({"messages": msgs}, {"errors": len(lines), "errors_realm": sum(1 for x in lines if slug in x),
                                 "sample": [clean(x)[:200] for x in lines[:3]]})


# ------------------------------------------------------------------------------------------------ provision
def cmd_provision() -> None:
    st = load_state()
    pf = platform()
    pf.a.fresh()
    slug = st.get("slug") or f"g4bv-{secrets.token_hex(2)}"
    email = f"owner@{slug}.example.invalid"
    st.update(slug=slug, owner_email=email, since=host_now(), started=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    save_state(st)
    t0 = time.time()
    body = {"slug": slug, "name": f"G4b verify {slug}", "plan_key": "standard", "owner_email": email,
            "identity_provider": {"driver": "keycloak"}, "settings": {"dns": {"magic_dns": True}}}
    r = pf.call(pf.a, "POST", "/platform/tenants", body, key=f"g4bv-create-{slug}")
    job = r.json()
    log("POST /platform/tenants", slug, "HTTP", r.status, job.get("code", ""), job.get("id", ""))
    done = pf.wait_job(job.get("id", ""), timeout=600)
    tid = done.get("tenant_id") or next((x["id"] for x in pf.get("/platform/tenants?limit=100").get("items", [])
                                         if x.get("slug") == slug), "")
    steps = done.get("steps") or []
    slow = sorted(((s.get("name"), s.get("duration_ms") or 0) for s in steps), key=lambda x: -(x[1] or 0))[:2]
    st.update(tenant_id=tid, provision_job=job.get("id", ""))
    save_state(st)
    result("provision", "SA1 POST /platform/tenants (driver keycloak) ⇒ job tenant.provision",
           r.status == 202 and done.get("status") == "succeeded",
           f"HTTP {r.status}; job {done.get('status')} {time.time() - t0:.1f} s; {len(steps)} bước, "
           f"bước lỗi {[s.get('name') for s in steps if s.get('status') != 'succeeded']}; lâu nhất {slow}")
    inst = next((x for x in pf.get("/platform/instances?limit=100").get("items", []) if x.get("tenant_id") == tid), {})
    st["instance_id"] = inst.get("id", "")
    save_state(st)
    health = host(f"sudo -n docker inspect -f '{{{{.State.Health.Status}}}}' mg-hs-{slug}")
    result("provision", "instance healthy", health.strip() == "healthy", f"mg-hs-{slug} {health.strip()}")
    cmd_realm()


def cmd_realm() -> None:
    st = load_state()
    slug = st["slug"]
    rl = kc_json("realm", slug) or {}
    smtp = rl.get("smtpServer") or {}
    safe = {k: smtp.get(k) for k in ("host", "port", "starttls", "ssl", "auth", "from", "fromDisplayName")}
    safe["password_field"] = "password" in smtp
    if safe.get("from"):
        safe["from"] = re.sub(r"@.*", "@<domain>", safe["from"])
    i18n = (rl.get("internationalizationEnabled"), sorted(rl.get("supportedLocales") or []), rl.get("defaultLocale"))
    st["realm"] = {"smtp": safe, "i18n": i18n}
    save_state(st)
    result("provision", "realm mới: smtpServer = mailrelay:587 STARTTLS, không AUTH",
           safe.get("host") == "mailrelay" and str(safe.get("port")) == "587" and str(safe.get("starttls")) == "true"
           and str(safe.get("auth") or "false") == "false" and not safe["password_field"],
           f"realm {rl.get('realm')} enabled {rl.get('enabled')}; smtpServer {safe}")
    result("provision", "realm mới: i18n bật, vi+en, mặc định vi",
           i18n[0] is True and i18n[1] == ["en", "vi"] and i18n[2] == "vi", f"(internationalizationEnabled, supportedLocales, "
           f"defaultLocale) = {i18n}")


# ------------------------------------------------------------------------------------------------ invite (Owner)
def cmd_invite() -> None:
    st = load_state()
    slug, tid = st["slug"], st["tenant_id"]
    inv = sql(f"SELECT id || '|' || status || '|' || coalesce(invited_by_identity_id::text,'') FROM tenant_invitations "
              f"WHERE tenant_id = '{tid}' ORDER BY created_at").splitlines()
    owner_inv = inv[0].split("|")[0] if inv else ""
    st["owner_invitation"] = owner_inv
    save_state(st)
    j = wait_idp_job(tid, owner_inv)
    st["owner_idp_job"] = j[0] if j else ""
    save_state(st)
    result("invite", "lời mời Owner (bước 16) ⇒ job member.idp_invite",
           bool(j) and j[1] == "succeeded",
           f"{len(inv)} lời mời của tenant ({[x.split('|')[1] + (' (không người mời)' if not x.split('|')[2] else '') for x in inv]}); "
           f"job {j[1] if j else 'không có'} lỗi '{j[2] if j else ''}' resource {j[3] if j else ''} = lời mời Owner "
           f"{bool(j) and j[4] == owner_inv}; tạo {j[5] if j else ''}, chạy {j[6] if j else ''} s; output {j[7][:160] if j else ''}")
    users = kc_json("users", slug) or []
    u = next((x for x in users if x.get("email") == st["owner_email"]), {})
    st["owner_kc_id"] = u.get("id", "")
    save_state(st)
    result("invite", "user Owner trong realm + required actions",
           bool(u) and u.get("enabled") is True and set(u.get("requiredActions") or []) >= {"UPDATE_PASSWORD", "CONFIGURE_TOTP"},
           f"{len(users)} user trong realm; username = e-mail {u.get('username') == st['owner_email']}; enabled {u.get('enabled')}; "
           f"emailVerified {u.get('emailVerified')}; requiredActions {sorted(u.get('requiredActions') or [])}")
    ml, kl = mail_and_kc_logs(st["since"], slug)
    relayed = [m for m in ml["messages"] if m.get("msg") == "mailrelay: message relayed"]
    result("invite", "log Keycloak không có lỗi gửi thư (KC-SERVICES0088 …) kể từ lúc provision",
           kl["errors"] == 0, f"dòng lỗi {kl['errors']} (của realm thử {kl['errors_realm']}) {kl['sample']}")
    result("invite", "log mail-bridge: thư thiết lập đã nhận + chuyển tới Worker",
           len(relayed) >= 1 and all(m.get("result") == "delivered" or m.get("sent") for m in relayed),
           f"{len(ml['messages'])} dòng 'mailrelay: message …' kể từ {st['since']}: "
           + "; ".join(f"{m.get('time', '')[11:19]} {m.get('msg')} result={m.get('result')} code={m.get('code')} "
                       f"status={m.get('status')} rcpt={m.get('rcpt')} sent={m.get('sent')} failed={m.get('failed')} "
                       f"{m.get('duration_ms')} ms" for m in ml["messages"]))


# ------------------------------------------------------------------------------------------------ owner
def set_password(slug: str, kc_id: str, who: str, username: str, last: str) -> bool:
    pw = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
    t.secret_values.add(pw)
    put_creds(who, username, pw)
    out = kc("setpw", slug, kc_id, last, stdin=(pw + "\n").encode())
    return result(who, f"đặt mật khẩu cho user {who} qua admin API (kcadm reset-password, stdin; requiredActions = CONFIGURE_TOTP)",
                  "setpw ok" in out, "setpw ok" if "setpw ok" in out else out[-120:])


def cmd_owner() -> None:
    st = load_state()
    slug, tid = st["slug"], st["tenant_id"]
    if not set_password(slug, st["owner_kc_id"], "owner", st["owner_email"], "Owner"):
        return
    o = Member(slug, "owner")
    steps = o.login()
    ms = [(m.get("tenant_slug"), m.get("role")) for m in o.sess.get("memberships") or []]
    inv = sql(f"SELECT status FROM tenant_invitations WHERE id = '{st['owner_invitation']}'")
    result("owner", "Owner đăng nhập lần đầu (mật khẩu + đăng ký TOTP) ⇒ tenant_owner", (slug, "tenant_owner") in ms,
           f"bước {steps}; memberships {ms}; lời mời Owner {inv}")
    email = f"user@{slug}.example.invalid"
    st["user_email"] = email
    save_state(st)
    r = o.call("POST", f"/tenants/{tid}/invitations", {"email": email, "role": "end_user"}, idem="g4bv-inv-" + secrets.token_hex(6))
    ij = r.json()
    st["user_invitation"] = ij.get("id", "")
    save_state(st)
    result("owner", "Owner POST /invitations (end_user)", r.status == 201, f"HTTP {r.status}; status {ij.get('status')} role {ij.get('role')}")
    j = wait_idp_job(tid, st["user_invitation"])
    result("owner", "job member.idp_invite của lời mời End User", bool(j) and j[1] == "succeeded",
           f"job {j[1] if j else 'không có'} lỗi '{j[2] if j else ''}' chạy {j[6] if j else ''} s; output {j[7][:160] if j else ''}")
    lst = o.call("GET", f"/tenants/{tid}/invitations")
    jobs = o.call("GET", f"/tenants/{tid}/jobs?kind=member.idp_invite&limit=100")
    by = {}
    for x in (jobs.json().get("items") or []):
        rid = (x.get("resource") or {}).get("id")
        if (x.get("resource") or {}).get("type") == "invitation" and rid not in by:
            by[rid] = x
    rows = [(i.get("role"), i.get("status"), (by.get(i.get("id")) or {}).get("status", "chưa có job"),
             ((by.get(i.get("id")) or {}).get("error") or {}).get("code", "")) for i in lst.json().get("items") or []]
    result("owner", "GET /invitations + cột IdP (GET /jobs?kind=member.idp_invite, ghép theo resource — như InvitationsPage)",
           lst.status == 200 and jobs.status == 200 and any(r_[0] == "end_user" and r_[2] == "succeeded" for r_ in rows),
           f"HTTP {lst.status}/{jobs.status}; (role, trạng thái lời mời, job IdP, mã lỗi) = {rows}")
    users = kc_json("users", slug) or []
    u = next((x for x in users if x.get("email") == email), {})
    st["user_kc_id"] = u.get("id", "")
    save_state(st)
    ml, kl = mail_and_kc_logs(st["since"], slug)
    relayed = [m for m in ml["messages"] if m.get("msg") == "mailrelay: message relayed"]
    result("owner", "user End User trong realm; log Keycloak/mail-bridge sau lời mời thứ hai",
           bool(u) and kl["errors"] == 0 and len(relayed) >= 2,
           f"user có {bool(u)} requiredActions {sorted(u.get('requiredActions') or [])}; lỗi gửi thư Keycloak {kl['errors']}; "
           f"mail-bridge relayed {len(relayed)}/{len(ml['messages'])} dòng (result {[m.get('result') for m in ml['messages']]})")


# ------------------------------------------------------------------------------------------------ locale
def kc_page_lang(query: str) -> tuple[str, str, int]:
    b = TargetBrowser(t)
    r = b.get(f"https://app.{t.domain}/api/v1/auth/login?{query}")
    hops = 0
    auth_q = ""
    while r.status in (302, 303) and hops < 6:
        loc = r.header("Location")
        if "/protocol/openid-connect/auth" in loc:
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(loc).query)
            auth_q = ",".join(q.get("ui_locales", ["-"]))
        r = b.get(loc)
        hops += 1
    m = re.search(r'<html[^>]*\blang="([^"]*)"', r.body.decode("utf-8", "replace"))
    return (m.group(1) if m else "?"), auth_q, r.status


def cmd_locale() -> None:
    st = load_state()
    slug = st["slug"]
    for lang in ("vi", "en"):
        got, q, status = kc_page_lang(f"scope=tenant&tenant={slug}&ui_locales={lang}")
        result("locale", f"GET /auth/login?scope=tenant&tenant=<slug>&ui_locales={lang} ⇒ trang Keycloak lang={lang}",
               got == lang and status == 200, f"authorization request ui_locales={q}; trang HTTP {status} <html lang=\"{got}\">")
    got, q, status = kc_page_lang(f"scope=tenant&tenant={slug}")
    log(f"  (không ui_locales) authorization request ui_locales={q}; trang HTTP {status} lang={got} (mặc định realm)")


# ------------------------------------------------------------------------------------------------ E3 / E12
def cmd_e3e12() -> None:
    st = load_state()
    slug, tid = st["slug"], st["tenant_id"]
    if st.get("user_kc_id") and set_password(slug, st["user_kc_id"], "user", st["user_email"], "User"):
        u = Member(slug, "user")
        steps = u.login()
        ms = [(m.get("tenant_slug"), m.get("role")) for m in u.sess.get("memberships") or []]
        result("e3e12", "End User đăng nhập lần đầu ⇒ end_user (lời mời gắn)", (slug, "end_user") in ms, f"bước {steps}; memberships {ms}")
        ins = u.call("GET", f"/tenants/{tid}/enrollment/instructions?os=linux")
        req = u.call("POST", f"/tenants/{tid}/enrollment/requests", {"method": "web_auth", "device_label": "g4bv"},
                     idem="g4bv-e3-" + secrets.token_hex(6))
        result("e3e12", "E3: End User — GET /enrollment/instructions ⇒ self_enroll=false (menu ẩn \"Thêm thiết bị\"); POST ⇒ 403",
               ins.status == 200 and ins.json().get("self_enroll") is False and req.status == 403,
               f"HTTP {ins.status} self_enroll={ins.json().get('self_enroll')}; POST /enrollment/requests HTTP {req.status} "
               f"{req.json().get('code', '')}")
    pf = platform()
    pf.a.fresh()
    items = pf.get("/platform/tenants?limit=100").get("items", [])
    me = next((x for x in items if x.get("id") == tid), {})
    with_plan = sum(1 for x in items if x.get("plan"))
    result("e3e12", "E12: Console GET /platform/tenants có name + plan", bool(me.get("name")) and bool(me.get("plan")),
           f"tenant thử: name '{me.get('name')}', plan {json.dumps(me.get('plan'))[:80]}; {with_plan}/{len(items)} tenant có plan")
    inst = next((x for x in pf.get("/platform/instances?limit=100").get("items", []) if x.get("tenant_id") == tid), {})
    jobs = [x for x in pf.get("/platform/jobs?kind=tenant.provision&limit=50").get("items", []) if x.get("tenant_id") == tid]
    result("e3e12", "E12: nhãn tenant/host ở instance và job của Console",
           inst.get("tenant_slug") == slug and bool(inst.get("tenant_name")) and bool(inst.get("host_name"))
           and any(j.get("tenant_slug") == slug for j in jobs),
           f"instance tenant_slug={inst.get('tenant_slug') == slug} tenant_name={bool(inst.get('tenant_name'))} "
           f"host_name={bool(inst.get('host_name'))}; job có tenant_slug {sum(1 for j in jobs if j.get('tenant_slug') == slug)}/{len(jobs)}")


# ------------------------------------------------------------------------------------------------ cleanup
def cmd_cleanup() -> None:
    st = load_state()
    slug, g = st["slug"], st["tenant_id"]
    pf = platform()
    d = pf.deprovision(g, slug, "G4b: dọn tenant thử sau kiểm trên staging (đợt 4)")
    j = pf.wait_job(d.get("job_id", ""), 600) if d.get("job_id") else {}
    tst = pf.tenant(g).get("status")
    result("cleanup", "deprovision 2P (SA1 yêu cầu, SA1 tự duyệt ⇒ 403, SA2 duyệt)", d.get("request_status") == 202
           and d.get("self_approval_status") == 403 and d.get("approve_status") == 200 and j.get("status") == "succeeded"
           and tst == "deleted",
           f"DELETE {d.get('request_status')}, tự duyệt {d.get('self_approval_status')}, SA2 duyệt {d.get('approve_status')}, "
           f"job {j.get('status')} {len(j.get('steps') or [])} bước; tenant {tst}; {d.get('error', '')}")
    inst = st.get("instance_id", "")
    chk = host(f"echo containers=$(sudo -n docker ps -a --format '{{{{.Names}}}}' | grep -c -- '{slug}'); "
               f"echo networks=$(sudo -n docker network ls --format '{{{{.Name}}}}' | grep -c -- '{slug}'); "
               f"echo volumes=$(sudo -n docker volume ls --format '{{{{.Name}}}}' | grep -c -- '{slug}'); "
               f"echo dir=$(sudo -n ls /opt/meshguard/tenants | grep -c -- '{inst or 'none'}'); "
               f"echo dirslug=$(sudo -n ls /opt/meshguard/tenants | grep -c -- '{slug}'); "
               f"echo secrets=$(sudo -n find /opt/meshguard/secrets -maxdepth 3 -name '*{inst or 'none'}*' 2>/dev/null | wc -l); "
               f"echo edge_nets=$(sudo -n docker inspect -f '{{{{range $k,$v := .NetworkSettings.Networks}}}}{{{{$k}}}} {{{{end}}}}' mg-edge); "
               f"echo hs=$(sudo -n docker ps --format '{{{{.Names}}}}' | grep -c '^mg-hs-')")
    vals = dict(x.split("=", 1) for x in chk.splitlines() if "=" in x)
    result("cleanup", "host không còn tài nguyên của tenant thử",
           all(vals.get(k) == "0" for k in ("containers", "networks", "volumes", "dir", "dirslug", "secrets"))
           and slug not in vals.get("edge_nets", ""),
           f"container {vals.get('containers')}, network {vals.get('networks')}, volume {vals.get('volumes')}, thư mục instance "
           f"{vals.get('dir')}/{vals.get('dirslug')}, secret {vals.get('secrets')}; network của edge: {vals.get('edge_nets')}; "
           f"mg-hs-* đang chạy {vals.get('hs')}")
    rl = kc_json("realm", slug) or {}
    log(f"  realm {slug}: enabled {rl.get('enabled')} (idp.disable)")


if __name__ == "__main__":
    cmds = {"provision": cmd_provision, "realm": cmd_realm, "invite": cmd_invite, "owner": cmd_owner, "locale": cmd_locale,
            "e3e12": cmd_e3e12, "cleanup": cmd_cleanup}
    if len(sys.argv) != 2 or sys.argv[1] not in cmds:
        sys.exit(__doc__)
    cmds[sys.argv[1]]()
