#!/usr/bin/env python3
"""Platform Console (P4-T02) trên stack dev/CI thật — FUNCTIONAL only (§22.1).

Chạy sau `e2e.py up` trên cùng tham số (E2E_PREFIX, E2E_WORK, MG_E2E_NET_BASE, …), trên host có Docker và python3:

  WEB_NODE_MODULES=<node_modules đã cài của apps/web> [NODE_IMAGE=…] python3 tests/e2e/harness/platformui.py

Stack chưa có trình duyệt (Playwright là P4-T14), nên trình duyệt được thay bằng Vitest + jsdom chạy App thật của
apps/web (router, QueryClient, client openapi-fetch) và mỗi "trình duyệt" là một proxy cục bộ 127.0.0.1 của harness: SPA
gọi /api/v1/* cùng origin như thật, proxy chuyển nguyên văn tới https://admin.<domain> qua edge (TLS theo CA của lượt
chạy, cookie phiên __Host- giữ trong proxy — SPA không thấy cookie, như HttpOnly; header Origin như trình duyệt cho method
ghi). Bản build của SPA do edge phục vụ (service web — P4-T01a) được kiểm riêng (chunk của Platform Console tải được).
Không có Host Agent trong stack này (như E2E-46): job tenant.provision dừng ở queued sau bước 1–2 của API — 19 bước thật
chạy ở `make provisioning-it` (P3-T07) và staging.

Chuẩn bị (không phải ca): E2E-17, E2E-20, E2E-21 của backend.py, Super Admin 1 (check_platform — kết luận E2E-24 cần
E2E-22/23 không chạy ở đây nên không tính), Super Admin 2 (bootstrap-super-admin), version policy mong muốn của tenant-a
(admin policy-apply — resume áp lại nó).

  E2E-89  Tạo tenant qua SPA: danh sách tenant (registry thật) → wizard → POST /platform/tenants (Idempotency-Key do SPA
          sinh — UUID v4, là request_key của job) → timeline 19 bước (2 bước của API succeeded, 17 chưa chạy) → hủy ⇒
          cancelled, tenant failed → chi tiết tenant → xin xóa 2P (gõ lại slug + lý do; người yêu cầu không có nút duyệt)
          → Super Admin 2: hàng chờ, hash tính trong trình duyệt = payload_sha256 → duyệt ⇒ executed, job
          tenant.deprovision; DB: approval do SA1 yêu cầu, SA2 duyệt với đúng hash đã hiển thị; audit
  E2E-90  Vòng đời qua SPA: tenant-a (instance, relay) tạm ngưng → timeline poll tới succeeded → chi tiết làm mới (nút
          khôi phục) → khôi phục ⇒ succeeded; DB tenant-a active; mọi request của SPA là /api/v1/* tới admin., mỗi
          thao tác ghi một Idempotency-Key khác nhau, không 5xx, log không chứa secret; bản build qua edge: index.html
          của /platform/tenants/new + chunk lazy của màn hình (JS cùng origin, có CSP)

P4-T03 (src/live/platform-ops.live.test.tsx — chạy sau hai ca trên; mỗi Super Admin đăng nhập LẠI để step-up còn trong
15 phút; chuẩn bị thêm một user Keycloak của realm platform làm đích của E2E-108):
  E2E-108 Nhân sự nền tảng qua SPA: SA1 thêm platform user theo sub thật (POST /platform/users, Idempotency-Key UUID v4)
          → hàng của chính SA1 không có thao tác → xin gán Super Admin (PUT …/super-admin-role) ⇒ 202 + trang phê duyệt,
          người yêu cầu không có nút → SA2: hàng chờ, hash trình duyệt = server → duyệt ⇒ executed; DB: role super_admin,
          approval platform.user.super_admin do SA1 yêu cầu, SA2 duyệt với đúng hash SPA hiển thị; audit create + execute
  E2E-109 Thiết lập + IdP qua SPA: SA1 mở sửa approval.ttl_hours, SA2 sửa trước (API, ETag đúng) ⇒ SA1 lưu với ETag cũ ⇒
          412, hộp hiện giá trị mới nhất ⇒ dùng bản mới ⇒ 200; DB giá trị cuối, audit hai lần sửa. IdP của tenant-a: sửa
          claim_mapping ⇒ 202 + phê duyệt, CHƯA có hiệu lực → SA2 duyệt ⇒ có hiệu lực; audit của tenant-a ghi
          identity_provider.platform_change.request/.apply
  E2E-110 Instance qua SPA: Platform Health = số của API, Hosts (cổng STUN còn trống), chi tiết instance của tenant-a (health
          có checked_at, digest, version cấu hình) → Restart ⇒ 202 ⇒ timeline job instance.restart (stack không có Host
          Agent: worker không chạy kind này ⇒ job dừng ở queued — kiểm tới mức job được tạo, như E2E-79) → hủy qua UI ⇒
          cancelled; DB: Idempotency-Key của SPA = request_key của job, audit platform.instance.restart.requested

Thư viện chuẩn. Mật khẩu, TOTP, cookie, CSRF token chỉ nằm trong tiến trình này (và tập redaction).
"""
from __future__ import annotations

import http.server
import json
import os
import pathlib
import re
import secrets
import socketserver
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import backend  # noqa: E402
import checks  # noqa: E402
from backend import TOTP, KeycloakAdmin, admin_cmd, psql  # noqa: E402
from idpadmin import platform_session  # noqa: E402
from phase3 import policy_apply  # noqa: E402
from stack import ROOT, Stack, StackError, log  # noqa: E402

NODE_IMAGE = os.environ.get("NODE_IMAGE",
                            "docker.io/library/node@sha256:e6bedef217677b276c591795e169840edd9096dbf13f29df8ef8d1856b8820bc")
PASS_REQ = ("Accept", "Content-Type", "X-CSRF-Token", "Idempotency-Key", "If-Match")
PASS_RESP = ("Content-Type", "Location", "ETag", "Retry-After", "X-Request-Id", "RateLimit-Limit", "RateLimit-Remaining",
             "RateLimit-Reset")
UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
UUID4 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


class Proxy:
    """'Trình duyệt' của một Super Admin: HTTP cục bộ → https://admin.<domain>/api/v1/* qua edge, cookie giữ ở đây."""

    def __init__(self, st: Stack, browser: backend.Browser, name: str):
        self.st, self.b, self.name = st, browser, name
        self.host = f"admin.{st.domain}"
        self.lock = threading.Lock()
        self.seen: list[tuple[str, str, int, str]] = []    # method, path (không query), status, Idempotency-Key
        proxy = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def _forward(self):
                if not self.path.startswith("/api/v1/"):
                    self.send_error(404)
                    return
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else None
                hdr = {k: self.headers[k] for k in PASS_REQ if self.headers.get(k)}
                if self.command not in ("GET", "HEAD"):
                    hdr["Origin"] = f"https://{proxy.host}"
                with proxy.lock:
                    r = proxy.b.request(self.command, f"https://{proxy.host}{self.path}", body, hdr)
                    proxy.seen.append((self.command, self.path.split("?")[0], r.status, hdr.get("Idempotency-Key", "")))
                self.send_response(r.status)
                for k in PASS_RESP:
                    if r.header(k):
                        self.send_header(k, r.header(k))
                self.send_header("Content-Length", str(len(r.body)))
                self.end_headers()
                self.wfile.write(r.body)

            do_GET = do_POST = do_DELETE = do_PATCH = do_PUT = _forward

        class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
            daemon_threads = True

        self.httpd = Server(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def close(self) -> None:
        self.httpd.shutdown()


def prepare(st: Stack) -> dict:
    """Điều kiện của hai ca; lỗi ⇒ StackError (không ca nào chạy)."""
    state = json.loads((st.work / "state" / "backend.json").read_text(encoding="utf-8"))
    pre = checks.Results(st)
    backend.check_ready(pre, st, state)
    backend.check_idp_bootstrap(pre, st)
    backend.check_registry(pre, st, state)
    if pre.failed:
        raise StackError("chuẩn bị (E2E-17/20/21) thất bại: " + "; ".join(x["id"] for x in pre.rows if x["result"] != "PASS"))
    backend.check_platform(checks.Results(st), st, state)     # tạo Super Admin 1 (st.platform_sa)
    kc = KeycloakAdmin(st)
    sa2 = {"username": "ui-sa2-" + secrets.token_hex(3), "password": secrets.token_urlsafe(18), "otp": TOTP()}
    st.secret_values.add(sa2["password"])
    sa2["sub"] = kc.create_user("platform", sa2["username"], sa2["password"])
    target = {"username": "ui-pu-" + secrets.token_hex(3), "password": secrets.token_urlsafe(18)}   # P4-T03: E2E-108
    st.secret_values.add(target["password"])
    target_sub = kc.create_user("platform", target["username"], target["password"])
    p = admin_cmd(st, ["bootstrap-super-admin", "--subject", sa2["sub"], "--display-name", "UI SA2"],
                  env={"MG_IDP_ID_PLATFORM": st.env["MG_IDP_ID_PLATFORM"]})
    b1, s1 = platform_session(st, st.platform_sa)
    b2, s2 = platform_session(st, sa2)
    base = (ROOT / "infrastructure" / "headscale" / "templates" / "bootstrap-policy.hujson").read_text(encoding="utf-8")
    code, out, _ = policy_apply(st, base, "--trigger", "bootstrap")
    desired = psql(st, "SELECT desired_policy_version_id IS NOT NULL FROM tenants WHERE slug = 'tenant-a'")
    roles = (s1.get("principal", {}).get("platform_role"), s2.get("principal", {}).get("platform_role"))
    if p.returncode != 0 or roles != ("super_admin", "super_admin") or code != 0 or desired != [["t"]]:
        raise StackError(f"chuẩn bị: SA2 bootstrap {p.returncode}, roles {roles}, policy-apply {code} {out.get('state')}, "
                         f"desired {desired}")
    log(f"chuẩn bị xong: hai Super Admin, policy-apply {out.get('state')}")
    state.update(b1=b1, b2=b2, sa2_sub=sa2["sub"], sa2=sa2, target_sub=target_sub)
    return state


def run_live(st: Stack, p1: Proxy, p2: Proxy, tenant_a: str, test_file: str = "src/live/platform.live.test.tsx",
             case_ids: tuple[str, ...] = ("UI-01", "UI-04", "UI-05"), name: str = "live",
             extra_env: dict | None = None) -> tuple[dict, dict, str]:
    """Một file src/live/*.live.test.tsx trong Node pin digest ⇒ (facts, {UI-0n: đạt?}, tóm tắt); log riêng theo `name`."""
    nm = os.environ.get("WEB_NODE_MODULES", "")
    if not nm or not pathlib.Path(nm, "vitest").exists():
        raise StackError("WEB_NODE_MODULES phải trỏ tới node_modules đã cài của apps/web (npm ci)")
    out = st.out / "platformui"
    out.mkdir(parents=True, exist_ok=True)
    os.chmod(out, 0o777)
    cmd = [*st.docker_cmd, "run", "--rm", "--network", "host", "-u", f"{os.getuid()}:{os.getgid()}", "-e", "HOME=/tmp",
           "-e", f"MG_LIVE_SA1={p1.url}", "-e", f"MG_LIVE_SA2={p2.url}", "-e", f"MG_LIVE_TENANT_A={tenant_a}",
           "-e", f"MG_LIVE_RUN={secrets.token_hex(3)}", "-e", f"MG_LIVE_OUT=/out/{name}.json",
           *[x for k, v in (extra_env or {}).items() for x in ("-e", f"{k}={v}")],
           "-v", f"{ROOT}:/src", "-v", f"{nm}:/src/apps/web/node_modules", "-v", f"{out}:/out", "-w", "/src/apps/web",
           NODE_IMAGE, "npx", "vitest", "run", "--reporter=verbose", test_file]
    t0 = time.time()
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=1800, check=False)
    text = re.sub(r"\x1b\[[0-9;]*m", "", p.stdout + p.stderr)
    (out / ("vitest.log" if name == "live" else f"{name}.log")).write_text(st.redact(text), encoding="utf-8")
    facts = json.loads((out / f"{name}.json").read_text(encoding="utf-8")) if (out / f"{name}.json").exists() else {}
    cases = {c: bool(re.search(rf"^\s*✓ .*{c} ", text, re.M)) for c in case_ids}
    return facts, cases, f"vitest exit {p.returncode} sau {time.time() - t0:.0f} s, {sum(cases.values())}/{len(case_ids)} ca"


def ok_uuid(x) -> bool:
    return bool(re.fullmatch(UUID, str(x or "")))


def check_create(r: checks.Results, st: Stack, facts: dict, cases: dict, summary: str, proxies: list[Proxy],
                 sa2_sub: str) -> None:
    slug, tid, appr, pj = facts.get("slug", ""), facts.get("tenant_id"), facts.get("approval_id"), facts.get("provision_job")
    if not (re.fullmatch(r"ui-[0-9a-f]{6}", slug) and ok_uuid(tid) and ok_uuid(appr) and ok_uuid(pj)):
        r.add("E2E-89", "Tạo tenant qua SPA", False, f"{summary}; facts thiếu: {facts}")
        return
    one = lambda sql: (psql(st, sql) or [[""]])[0][0]   # noqa: E731
    tenant = psql(st, f"SELECT slug, status FROM tenants WHERE id = '{tid}'")
    jobs = psql(st, f"SELECT kind, status FROM provisioning_jobs WHERE tenant_id = '{tid}' ORDER BY created_at")
    ap = psql(st, "SELECT a.status, a.action, a.payload_sha256, ri.subject, di.subject FROM approval_requests a "
                  "JOIN identities ri ON ri.id = a.requested_by_identity_id LEFT JOIN identities di ON "
                  f"di.id = a.approved_by_identity_id WHERE a.id = '{appr}'")
    create_key = next((k for p in proxies for (m, path, _, k) in p.seen if m == "POST" and path == "/api/v1/platform/tenants"), "")
    job_key = one(f"SELECT request_key FROM provisioning_jobs WHERE id = '{pj}'")
    audit = {a: int(n) for a, n in psql(st, "SELECT action, count(*) FROM audit_events WHERE resource_id IN "
                                            f"('{tid}', '{appr}', '{pj}') AND outcome = 'success' GROUP BY 1")}
    sa1 = st.platform_sa["sub"]
    ok = (cases.get("UI-01") and cases.get("UI-04") and facts.get("provision_status_seen") == "queued"
          and tenant and tenant[0][0] == slug and tenant[0][1] in ("deprovisioning", "deleted")
          and jobs[:1] == [["tenant.provision", "cancelled"]] and any(k == "tenant.deprovision" for k, _ in jobs)
          and ap and ap[0][:3] == ["executed", "platform.tenant.delete", facts.get("payload_sha256")]
          and ap[0][3] == sa1 and ap[0][4] == sa2_sub and bool(UUID4.match(create_key)) and create_key == job_key
          and audit.get("platform.tenant.create.requested") == 1 and audit.get("platform.job.cancel") == 1
          and audit.get("platform.approval.approve", 0) >= 1)
    r.add("E2E-89", "P4-T02: tạo tenant qua SPA (wizard → POST /platform/tenants với Idempotency-Key của SPA = request_key "
          "của job → timeline 19 bước, 2 bước API xong → hủy → chi tiết → xin xóa 2P → Super Admin 2 duyệt với hash "
          "tính trong trình duyệt ⇒ executed + tenant.deprovision); DB: người yêu cầu SA1, người duyệt SA2, đúng hash", ok,
          f"{summary}; tenant {tenant}; jobs {jobs}; approval {[x[:3] for x in ap]} requester=SA1 "
          f"{bool(ap) and ap[0][3] == sa1} decider=SA2 {bool(ap) and ap[0][4] == sa2_sub}; khóa tạo tenant UUIDv4 "
          f"{bool(UUID4.match(create_key))} = request_key {create_key == job_key}; audit {audit}", limit=900)


def check_lifecycle(r: checks.Results, st: Stack, facts: dict, cases: dict, proxies: list[Proxy]) -> None:
    ids = [x for x in (facts.get("suspend_job"), facts.get("resume_job")) if ok_uuid(x)]
    sr = psql(st, "SELECT kind, status FROM provisioning_jobs WHERE id IN (" + ",".join(f"'{x}'" for x in ids)
              + ") ORDER BY created_at") if ids else []
    a_state = (psql(st, "SELECT status FROM tenants WHERE slug = 'tenant-a'") or [[""]])[0][0]
    seen = [x for p in proxies for x in p.seen]
    writes = [x for x in seen if x[0] in ("POST", "DELETE") and "/approvals/" not in x[1] and not x[1].startswith("/api/v1/auth/")]
    keys = [x[3] for x in writes]
    keys_ok = len(keys) >= 5 and all(UUID4.match(k) for k in keys) and len(set(keys)) == len(keys)
    bad = [x for x in seen if x[2] >= 500 or not x[1].startswith("/api/v1/")]
    log_text = (st.out / "platformui" / "vitest.log").read_text(encoding="utf-8")
    leaked = sum(1 for v in st.secret_values if v and len(v) >= 8 and v in log_text)
    (st.out / "platformui" / "requests.txt").write_text(
        "\n".join(f"{p.name} {m} {path} {s}" for p in proxies for (m, path, s, _) in p.seen) + "\n", encoding="utf-8")
    # bản build của SPA do edge phục vụ: index.html của một deep link + chunk lazy của màn hình wizard
    b = backend.Browser(st)
    admin = f"https://admin.{st.domain}"
    page = b.get(f"{admin}/platform/tenants/new")
    html = page.body.decode("utf-8", "replace")
    main_js = re.search(r'<script[^>]+src="(/assets/index-[^"]+\.js)"', html)
    chunk, js = None, None
    if main_js:
        js = b.get(admin + main_js.group(1))
        name = re.search(r"(TenantCreatePage-[A-Za-z0-9_-]+\.js)", js.body.decode("utf-8", "replace"))
        if name:
            chunk = b.get(f"{admin}/assets/{name.group(1)}")
    served = (page.status == 200 and 'id="react-aria-pressable-style"' in html and js is not None and js.status == 200
              and chunk is not None and chunk.status == 200 and "javascript" in chunk.header("Content-Type")
              and "default-src 'self'" in chunk.header("Content-Security-Policy"))
    ok = (cases.get("UI-05") and facts.get("suspend_status") == "succeeded" and facts.get("resume_status") == "succeeded"
          and sr == [["tenant.suspend", "succeeded"], ["tenant.resume", "succeeded"]] and a_state == "active"
          and keys_ok and not bad and leaked == 0 and served)
    r.add("E2E-90", "P4-T02: vòng đời qua SPA — tenant-a tạm ngưng → timeline poll tới succeeded → chi tiết làm mới → "
          "khôi phục ⇒ succeeded, tenant-a active; mọi request của SPA là /api/v1/* tới admin., mỗi thao tác ghi một "
          "Idempotency-Key UUID v4 khác nhau, không 5xx, log không chứa secret; edge phục vụ bản build (deep link + chunk "
          "lazy của wizard, có CSP)", ok,
          f"suspend/resume {sr}; tenant-a {a_state}; {len(seen)} request ({len(writes)} ghi có khóa, khóa ok {keys_ok}); "
          f"lỗi {bad[:3]}; secret lộ {leaked}; edge: index {page.status}, main {js.status if js else None}, chunk "
          f"{chunk.status if chunk else None} {chunk.header('Content-Type') if chunk else ''}", limit=900)


# ---------------------------------------------------------------------------------------------------- P4-T03
def _ident(st: Stack, sub: str) -> str:
    return (psql(st, f"SELECT id FROM identities WHERE subject = '{sub}'") or [[""]])[0][0]


def _seen(p: Proxy, method: str, path_re: str) -> list[tuple[str, str, int, str]]:
    return [x for x in p.seen if x[0] == method and re.fullmatch(path_re, x[1])]


def check_ops_users(r: checks.Results, st: Stack, facts: dict, cases: dict, summary: str, p1: Proxy, sa2_sub: str,
                    target_sub: str) -> None:
    appr = facts.get("sa_approval_id")
    sa1, sa2, target = _ident(st, st.platform_sa["sub"]), _ident(st, sa2_sub), _ident(st, target_sub)
    role = psql(st, f"SELECT r.key, pu.status FROM platform_users pu JOIN roles r ON r.id = pu.role_id "
                    f"WHERE pu.identity_id = '{target}'") if target else []
    ap = psql(st, "SELECT status, action, payload_sha256, requested_by_identity_id, approved_by_identity_id "
                  f"FROM approval_requests WHERE id = '{appr}'") if ok_uuid(appr) else []
    created = _seen(p1, "POST", r"/api/v1/platform/users")
    audit = {a: int(n) for a, n in psql(st, "SELECT action, count(*) FROM audit_events WHERE outcome = 'success' AND action IN "
                                            "('platform.user.create', 'platform.user.super_admin.execute') AND "
                                            f"(resource_id = '{appr}' OR details::text LIKE '%{target}%' OR resource_id IN "
                                            f"(SELECT id::text FROM platform_users WHERE identity_id = '{target}')) GROUP BY 1")} \
        if target and ok_uuid(appr) else {}
    ok = (cases.get("UI-06") and facts.get("target_role_seen") == "super_admin" and role == [["super_admin", "active"]]
          and bool(ap) and ap[0][:3] == ["executed", "platform.user.super_admin", facts.get("sa_payload_sha256")]
          and ap[0][3] == sa1 and ap[0][4] == sa2 and len(created) == 1 and created[0][2] == 201
          and bool(UUID4.match(created[0][3])) and audit.get("platform.user.create", 0) >= 1
          and audit.get("platform.user.super_admin.execute", 0) >= 1)
    r.add("E2E-108", "P4-T03: nhân sự nền tảng qua SPA — SA1 thêm user theo sub thật (POST /platform/users, Idempotency-Key "
          "UUID v4) → không thao tác trên chính mình → xin gán Super Admin ⇒ 202 + phê duyệt (người yêu cầu không có nút) → "
          "SA2 duyệt với hash tính trong trình duyệt ⇒ executed; DB: role super_admin, người yêu cầu SA1, người duyệt SA2, "
          "đúng hash; audit create + execute", ok,
          f"{summary}; role {role}; approval {[x[:3] for x in ap]} requester=SA1 {bool(ap) and ap[0][3] == sa1} "
          f"decider=SA2 {bool(ap) and ap[0][4] == sa2}; POST users {[(x[2], bool(UUID4.match(x[3]))) for x in created]}; "
          f"audit {audit}", limit=900)


def check_ops_settings_idp(r: checks.Results, st: Stack, facts: dict, cases: dict, p1: Proxy, sa2_sub: str,
                           tenant_a: str) -> None:
    puts = [x[2] for x in _seen(p1, "PUT", r"/api/v1/platform/settings/approval\.ttl_hours")]
    value = (psql(st, "SELECT value::text, version FROM system_settings WHERE key = 'approval.ttl_hours'") or [["", ""]])[0]
    upd = int((psql(st, "SELECT count(*) FROM audit_events WHERE action = 'platform.settings.update' AND outcome = 'success' "
                        "AND resource_id = 'approval.ttl_hours'") or [["0"]])[0][0] or 0)
    idp, appr = facts.get("idp_id"), facts.get("idp_approval_id")
    sa1, sa2 = _ident(st, st.platform_sa["sub"]), _ident(st, sa2_sub)
    ap = psql(st, "SELECT status, action, payload_sha256, requested_by_identity_id, approved_by_identity_id "
                  f"FROM approval_requests WHERE id = '{appr}'") if ok_uuid(appr) else []
    mapping = (psql(st, f"SELECT claim_mapping ->> 'name', tenant_id FROM identity_providers WHERE id = '{idp}'")
               or [["", ""]])[0] if ok_uuid(idp) else ["", ""]
    tenant_audit = {a: int(n) for a, n in psql(st, "SELECT action, count(*) FROM audit_events WHERE tenant_id = "
                                                   f"'{tenant_a}' AND action IN ('identity_provider.platform_change.request', "
                                                   "'identity_provider.platform_change.apply') GROUP BY 1")}
    ok = (cases.get("UI-07") and cases.get("UI-08") and facts.get("sa2_put_status") == 200 and facts.get("stale_seen") is True
          and puts == [412, 200] and value[0] == "48" and upd >= 2
          and facts.get("idp_name_before_approval") != "preferred_username" and mapping == ["preferred_username", tenant_a]
          and bool(ap) and ap[0][:3] == ["executed", "platform.idp.update_tenant", facts.get("idp_payload_sha256")]
          and ap[0][3] == sa1 and ap[0][4] == sa2
          and tenant_audit.get("identity_provider.platform_change.request", 0) >= 1
          and tenant_audit.get("identity_provider.platform_change.apply", 0) >= 1)
    r.add("E2E-109", "P4-T03: thiết lập + IdP qua SPA — SA2 sửa approval.ttl_hours trong lúc SA1 đang sửa ⇒ SA1 lưu với ETag "
          "cũ ⇒ 412, hộp hiện giá trị mới nhất ⇒ dùng bản mới ⇒ 200; IdP của tenant-a: sửa claim_mapping ⇒ 202 + phê "
          "duyệt, chưa hiệu lực trước khi duyệt ⇒ SA2 duyệt ⇒ có hiệu lực; audit của tenant ghi request/apply", ok,
          f"PUT của SA1 {puts}; SA2 {facts.get('sa2_put_status')}; DB value {value}; audit update {upd}; IdP name trước "
          f"{facts.get('idp_name_before_approval')!r} sau {mapping[0]!r}; approval {[x[:3] for x in ap]} requester=SA1 "
          f"{bool(ap) and ap[0][3] == sa1} decider=SA2 {bool(ap) and ap[0][4] == sa2}; audit tenant {tenant_audit}", limit=900)


def check_ops_instance(r: checks.Results, st: Stack, facts: dict, cases: dict, p1: Proxy, tenant_a: str) -> None:
    job, inst = facts.get("restart_job"), facts.get("instance_id")
    row = psql(st, "SELECT kind, status, request_key, tenant_id FROM provisioning_jobs "
                   f"WHERE id = '{job}'") if ok_uuid(job) else []
    posts = _seen(p1, "POST", rf"/api/v1/platform/instances/{inst}/restart") if ok_uuid(inst) else []
    audit = int((psql(st, "SELECT count(*) FROM audit_events WHERE action = 'platform.instance.restart.requested' "
                          f"AND resource_id = '{inst}'") or [["0"]])[0][0] or 0) if ok_uuid(inst) else 0
    totals = int((psql(st, "SELECT count(*) FROM tenants") or [["-1"]])[0][0])
    ok = (cases.get("UI-09") and facts.get("restart_status_seen") == "queued" and facts.get("restart_final") == "cancelled"
          and bool(row) and row[0][0] == "instance.restart" and row[0][1] == "cancelled" and row[0][3] == tenant_a
          and len(posts) == 1 and posts[0][2] == 202 and bool(UUID4.match(posts[0][3])) and row[0][2] == posts[0][3]
          and audit >= 1 and facts.get("instance_health") in ("healthy", "unhealthy", "unknown")
          and str(facts.get("image_digest_shown", "")).startswith("sha256:") and facts.get("hosts_seen", 0) >= 1
          and facts.get("health_tenants_total", -2) <= totals)
    (st.out / "platformui" / "requests-ops.txt").write_text(
        "\n".join(f"{p1.name} {m} {path} {s}" for (m, path, s, _) in p1.seen) + "\n", encoding="utf-8")
    r.add("E2E-110", "P4-T03: instance qua SPA — Platform Health = số của API, Hosts (cổng STUN còn trống), chi tiết instance "
          "tenant-a (health có checked_at, digest, version cấu hình) → Restart ⇒ 202 ⇒ timeline job instance.restart "
          "(stack không có Host Agent ⇒ job dừng ở queued — kiểm tới mức job được tạo) → hủy qua UI ⇒ cancelled; "
          "Idempotency-Key của SPA = request_key của job; audit restart.requested", ok,
          f"job {row[:1]}; POST {[(x[2], bool(UUID4.match(x[3]))) for x in posts]} = request_key "
          f"{bool(row) and bool(posts) and row[0][2] == posts[0][3]}; trạng thái thấy {facts.get('restart_status_seen')} → "
          f"{facts.get('restart_final')}; audit {audit}; health {facts.get('instance_health')}; config "
          f"{facts.get('config_current')!r}; hosts {facts.get('hosts_seen')} STUN {facts.get('stun_free_text')!r}; tenants "
          f"(health) {facts.get('health_tenants_total')}", limit=900)


def run_ops(r: checks.Results, st: Stack, state: dict, proxies: list[Proxy]) -> None:
    """Đăng nhập lại hai Super Admin (step-up ≤ 15 phút cho các thao tác ghi), chạy platform-ops.live.test.tsx, 3 ca."""
    b1, s1 = platform_session(st, st.platform_sa)
    b2, s2 = platform_session(st, state["sa2"])
    if (s1.get("principal", {}).get("platform_role"), s2.get("principal", {}).get("platform_role")) != ("super_admin",) * 2:
        raise StackError("đăng nhập lại hai Super Admin thất bại")
    p1, p2 = Proxy(st, b1, "sa1-ops"), Proxy(st, b2, "sa2-ops")
    proxies += [p1, p2]
    tenant_a = state["tenant_ids"]["tenant-a"]
    facts, cases, summary = run_live(st, p1, p2, tenant_a, "src/live/platform-ops.live.test.tsx",
                                     ("UI-06", "UI-07", "UI-08", "UI-09"), "ops", {"MG_LIVE_TARGET_SUB": state["target_sub"]})
    log(f"P4-T03: {summary}")
    check_ops_users(r, st, facts, cases, summary, p1, state["sa2_sub"], state["target_sub"])
    check_ops_settings_idp(r, st, facts, cases, p1, state["sa2_sub"], tenant_a)
    check_ops_instance(r, st, facts, cases, p1, tenant_a)


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    st = Stack()
    st.users = {}
    r = checks.Results(st)
    proxies: list[Proxy] = []
    error = None
    try:
        state = prepare(st)
        p1, p2 = Proxy(st, state["b1"], "sa1"), Proxy(st, state["b2"], "sa2")
        proxies = [p1, p2]
        facts, cases, summary = run_live(st, p1, p2, state["tenant_ids"]["tenant-a"])
        check_create(r, st, facts, cases, summary, proxies, state["sa2_sub"])
        check_lifecycle(r, st, facts, cases, proxies)
        if os.environ.get("PLATFORMUI_SKIP_OPS") != "1":
            run_ops(r, st, state, proxies)
    except (StackError, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as e:
        error = f"{type(e).__name__}: {st.redact(str(e))[-1500:]}"
        log("LỖI: " + error)
    finally:
        for p in proxies:
            p.close()
    lines = [f"{x['result']:4} {x['id']:8} [{x['label']}] {x['name']}\n{'':14}{x['detail']}" for x in r.rows]
    passed = sum(x["result"] == "PASS" for x in r.rows)
    text = "\n".join(lines) + f"\n\n{passed}/{len(r.rows)} ca PASS (functional)" + (f"\nLỖI: {error}" if error else "") + "\n"
    (st.out / "platformui").mkdir(parents=True, exist_ok=True)
    (st.out / "platformui" / "summary.txt").write_text(text, encoding="utf-8")
    print(text, flush=True)
    expected = 2 if os.environ.get("PLATFORMUI_SKIP_OPS") == "1" else 5
    return 1 if error or r.failed or len(r.rows) != expected else 0


if __name__ == "__main__":
    sys.exit(main())
