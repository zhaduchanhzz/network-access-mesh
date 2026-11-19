#!/usr/bin/env python3
"""dep4 — đăng nhập thật (Keycloak mật khẩu + TOTP, qua edge, như người dùng trong LAN) và gọi API cho diễn tập.
Dùng harness của repo (tests/e2e/harness/backend.py: Browser, portal_login, TOTP) và Platform của tests/g3.
Chạy trên VM 110 (ngoài host lồng) bằng cây nguồn mới: python3 -B api.py <lệnh> [tham số]   (cây nguồn: $DEP4_TREE, mặc định ~/dep4/root/rootdir/src/new)
  login   lần đầu: SA1, SA2 (admin.), TO A, TO B (app.) — đăng ký TOTP ở lần đăng nhập đầu, ghi ~/dep4/creds.json (0600)
  p3data  dữ liệu mẫu Phase 3 qua API: lời mời (thư tới .invalid — không gửi được), suspend→resume tenant-b
  check   kiểm sau nâng/rollback: session, platform tenants, cách ly chéo tenant, các route Phase 4 (nếu có)
Mật khẩu đọc từ host lồng (docker exec cat — không in), TOTP/cookie/CSRF chỉ trong tiến trình và tập che.
"""
from __future__ import annotations

import json
import os
import pathlib
import secrets
import subprocess
import sys
import time

TREE = pathlib.Path(os.environ.get("DEP4_TREE") or os.path.expanduser("~/dep4/root/rootdir/src/new"))
sys.path.insert(0, str(TREE / "tests" / "g3"))
sys.path.insert(0, str(TREE / "tests" / "e2e" / "harness"))
import backend  # noqa: E402
from g3target import Target  # noqa: E402
import g3platform  # noqa: E402

W = pathlib.Path(os.path.expanduser("~/dep4"))
CREDS = W / "creds.json"
USERS = {"sa1": ("platform", "dep4-sa1"), "sa2": ("platform", "dep4-sa2"),
         "toa": ("tenant-a", "dep4-a-owner"), "tob": ("tenant-b", "dep4-b-owner")}


def target() -> Target:
    return Target(W / "dep4.env", {"connect": "10.77.4.10", "ca_file": str(W / "ca.crt"),
                                   "host_docker": "sudo -n docker exec -i dep4-host docker", "client_docker": "sudo -n docker",
                                   "client_network": "dep4-lan", "client_add_host": "10.77.4.10",
                                   "client_ca_dir": str(W / "cadir"), "resource_prefix": "dep4g3"})


def password(realm: str, user: str) -> str:
    return subprocess.run(["sudo", "-n", "docker", "exec", "dep4-host", "cat", f"/root/dep4x/creds/{realm}-{user}.pw"],
                          capture_output=True, text=True, check=True).stdout.strip()


class Who:
    def __init__(self, t: Target, key: str, totp: bytes | None):
        realm, user = USERS[key]
        self.t, self.key, self.realm = t, key, realm
        self.user = {"username": user, "password": password(realm, user)}
        t.secret_values.add(self.user["password"])
        self.otp = backend.TOTP()
        if totp:
            self.otp.key = totp
        self.host = f"admin.{t.domain}" if realm == "platform" else f"app.{t.domain}"
        self.query = "scope=platform" if realm == "platform" else f"scope=tenant&tenant={realm}"
        self.b = g3platform.TargetBrowser(t)
        self.session: dict = {}

    def login(self) -> list[str]:
        self.b = g3platform.TargetBrowser(self.t)
        self.session, steps = backend.portal_login(self.t, self.b, self.host, self.query, self.user, self.otp)
        return steps

    def call(self, method: str, path: str, body: dict | None = None) -> backend.Resp:
        h = None
        if method != "GET":
            h = {"Origin": f"https://{self.host}", "X-CSRF-Token": self.session.get("csrf_token", ""),
                 "Content-Type": "application/json", "Idempotency-Key": "dep4-" + secrets.token_hex(8)}
        return self.b.request(method, f"https://{self.host}/api/v1{path}",
                              json.dumps(body).encode() if body is not None else None, h)


def load(t: Target) -> dict[str, Who]:
    doc = json.loads(CREDS.read_text(encoding="utf-8")) if CREDS.exists() else {}
    out = {}
    for k in USERS:
        raw = doc.get("totp", {}).get(k)
        out[k] = Who(t, k, raw.encode() if raw else None)
        if raw:
            t.secret_values.add(raw)
    return out


def save(ws: dict[str, Who]) -> None:
    sas = [{"username": ws[k].user["username"], "password": ws[k].user["password"], "totp_raw": ws[k].otp.key.decode()}
           for k in ("sa1", "sa2")]
    CREDS.write_text(json.dumps({"super_admins": sas, "totp": {k: w.otp.key.decode() for k, w in ws.items()}}),
                     encoding="utf-8")
    os.chmod(CREDS, 0o600)


def cmd_login(t: Target) -> None:
    ws = load(t)
    for k, w in ws.items():
        steps = w.login()
        print(f"login {k}: OK steps={steps} role={w.session.get('platform_role') or [m.get('role') for m in w.session.get('memberships', [])]}")
        save(ws)
        time.sleep(31)          # TOTP: lần sau không dùng lại cửa sổ 30 s


def ids(t: Target, w: Who) -> dict[str, str]:
    r = w.call("GET", "/platform/tenants")
    items = r.json().get("items") or r.json().get("tenants") or []
    return {x["slug"]: x["id"] for x in items}


def cmd_p3data(t: Target) -> None:
    ws = load(t)
    sa, toa = ws["sa1"], ws["toa"]
    sa.login(); toa.login()
    tid = ids(t, sa)
    print("tenants:", sorted(tid))
    r = toa.call("POST", f"/tenants/{tid['tenant-a']}/invitations",
                 {"email": "dep4-invitee@example.invalid", "role": "tenant_admin"})
    print("invitation tenant-a:", r.status, r.json().get("status", r.json().get("code")))
    for action in ("suspend", "resume"):
        r = sa.call("POST", f"/platform/tenants/{tid['tenant-b']}/{action}")
        job = r.json().get("job_id") or r.json().get("id")
        print(f"{action} tenant-b:", r.status, job)
        for _ in range(60):
            j = sa.call("GET", f"/platform/jobs/{job}").json()
            if j.get("status") in ("succeeded", "failed", "rolled_back", "failed_resumable", "cancelled"):
                break
            time.sleep(1)
        print(f"  job {action}:", j.get("status"))


def show(label: str, r: backend.Resp, want) -> bool:
    ok = r.status in (want if isinstance(want, tuple) else (want,))
    body = r.json()
    info = body.get("code") or (f"{len(body.get('items') or [])} items" if isinstance(body.get("items"), list) else "")
    print(f"{'PASS' if ok else 'FAIL'} {label}: HTTP {r.status} {info}")
    return ok


def cmd_check(t: Target) -> None:
    ws = load(t)
    for w in ws.values():
        w.login()
    sa, toa, tob = ws["sa1"], ws["toa"], ws["tob"]
    tid = ids(t, sa)
    a, b = tid["tenant-a"], tid["tenant-b"]
    res = [show("SA GET /platform/tenants", sa.call("GET", "/platform/tenants"), 200),
           show("SA GET /platform/health", sa.call("GET", "/platform/health"), 200),
           show("TO-A GET /tenants/A", toa.call("GET", f"/tenants/{a}"), 200),
           show("TO-A GET /tenants/B (cách ly)", toa.call("GET", f"/tenants/{b}"), (403, 404)),
           show("TO-B GET /tenants/A/audit (cách ly)", tob.call("GET", f"/tenants/{a}/audit"), (403, 404)),
           show("TO-A GET /tenants/A/audit", toa.call("GET", f"/tenants/{a}/audit"), 200)]
    p4 = [("devices", 200), ("policies", 200), ("tags", 200), ("users", 200), ("groups", 200), ("dns", 200),
          ("routes", 200), ("resources", 200), ("enrollment/requests", 200), ("support-grants", 200),
          ("settings", 200), ("dashboard", 200)]
    for path, want in p4:
        r = toa.call("GET", f"/tenants/{a}/{path}")
        strict = len(sys.argv) > 2 and sys.argv[2] == "p4"      # sau nâng cấp: route Phase 4 phải có
        res.append(show(f"[P4] TO-A GET /tenants/A/{path}", r, want if strict else (want, 404)))
        r = tob.call("GET", f"/tenants/{a}/{path}")
        res.append(show(f"[P4] TO-B GET /tenants/A/{path} (cách ly)", r, (403, 404)))
    for path in ("platform/instances", "platform/users", "platform/plans", "platform/support-grants"):
        res.append(show(f"[P4] SA GET /{path}", sa.call("GET", f"/{path}"), 200 if len(sys.argv) > 2 and sys.argv[2] == "p4" else (200, 404)))
    print(f"TỔNG: {sum(res)}/{len(res)} PASS")



def cmd_dns(t: Target) -> None:
    """P4-T12 qua Host Agent: TO-A thêm một bản ghi A (value = IP tailnet của thiết bị lab-a2), chờ job dns.records_write,
    rồi xóa bản ghi (job ghi lại file). Kết quả job cho biết Agent có WriteDnsRecords hay không."""
    ip = sys.argv[2]
    ws = load(t)
    toa, sa = ws["toa"], ws["sa1"]
    toa.login(); sa.login()
    a = ids(t, sa)["tenant-a"]
    r = toa.call("POST", f"/tenants/{a}/dns/records", {"name": (sys.argv[4] if len(sys.argv) > 4 else "svc") + ".dep4-lab.test", "type": "A", "value": ip})
    print("POST dns/records:", r.status, r.json().get("code", ""))
    if r.status != 201:
        print(r.body[:300]); return
    rec, job = r.json()["record"], r.json()["job"]
    for _ in range(60):
        j = toa.call("GET", f"/tenants/{a}/jobs/{job['id']}").json()
        if j.get("status") in ("succeeded", "failed", "failed_resumable", "rolled_back", "cancelled", "dead"):
            break
        time.sleep(1)
    print("job dns.records_write:", j.get("status"), j.get("error_code") or j.get("error") or "")
    if len(sys.argv) > 3 and sys.argv[3] == "keep":
        return
    lst = toa.call("GET", f"/tenants/{a}/dns/records")
    etag = lst.header("ETag")
    d = toa.b.request("DELETE", f"https://{toa.host}/api/v1/tenants/{a}/dns/records/{rec['id']}", None,
                      {"Origin": f"https://{toa.host}", "X-CSRF-Token": toa.session.get("csrf_token", ""),
                       "If-Match": rec.get("etag") or etag or "*"})
    print("DELETE dns/records:", d.status, d.json().get("code", ""))



def cmd_job(t: Target) -> None:
    """POST /platform/jobs/{id}/{retry|rollback} bằng SA1 rồi chờ trạng thái cuối."""
    jid, action = sys.argv[2], sys.argv[3]
    sa = load(t)["sa1"]
    sa.login()
    r = sa.call("POST", f"/platform/jobs/{jid}/{action}")
    print(f"{action}:", r.status, r.json().get("status") or r.json().get("code"))
    for _ in range(120):
        j = sa.call("GET", f"/platform/jobs/{jid}").json()
        if j.get("status") in ("succeeded", "failed", "rolled_back", "failed_resumable", "cancelled"):
            break
        time.sleep(1)
    print("job:", j.get("status"), j.get("error_code") or "")



def cmd_deprov(t: Target) -> None:
    """Deprovision qua 2P (Platform của tests/g3: A yêu cầu, A tự duyệt ⇒ 403, B duyệt) một tenant theo slug."""
    from g3target import load_creds  # noqa: PLC0415
    slug = sys.argv[2]
    pf = g3platform.Platform(t, load_creds(CREDS, t))
    items = pf.get("/platform/tenants").get("items") or []
    tid = next(x["id"] for x in items if x["slug"] == slug)
    out = pf.deprovision(tid, slug, "dep4 rehearsal cleanup")
    print("deprovision:", {k: out.get(k) for k in ("request_status", "self_approval_status", "approve_status", "error")})
    if out.get("job_id"):
        print("job:", pf.wait_job(out["job_id"], timeout=300).get("status"))


if __name__ == "__main__":
    tt = target()
    {"login": cmd_login, "p3data": cmd_p3data, "check": cmd_check, "dns": cmd_dns, "job": cmd_job, "deprov": cmd_deprov}[sys.argv[1]](tt)
