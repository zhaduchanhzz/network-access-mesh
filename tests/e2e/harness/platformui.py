#!/usr/bin/env python3
"""P4-T02 — Platform Console (SPA apps/web) với stack dev/CI thật — FUNCTIONAL only (§22.1).

Chạy sau `e2e.py up` trên cùng tham số (E2E_PREFIX, E2E_WORK, MG_E2E_NET_BASE, …), trên host có Docker và python3:

  WEB_NODE_MODULES=<node_modules của apps/web> [NODE_IMAGE=…] python3 tests/e2e/harness/platformui.py

Chưa có SPA sau edge (P4-T01a), nên trình duyệt được thay bằng Vitest + jsdom chạy App thật của apps/web, và mỗi
"trình duyệt" là một proxy cục bộ 127.0.0.1 của harness: SPA gọi /api/v1/* cùng origin như thật, proxy chuyển nguyên
văn tới https://admin.<domain> qua edge (TLS theo CA của lượt chạy, cookie phiên __Host- giữ trong proxy — SPA không
thấy cookie, như HttpOnly; header Origin như trình duyệt cho method ghi). Không có Host Agent trong stack này (như E2E-46):
job tenant.provision dừng ở queued sau bước 1–2 của API — 19 bước thật chạy ở `make provisioning-it` (P3-T07) và
staging.

  UI-E2E-01  chuẩn bị: E2E-17…E2E-21, E2E-24 của backend.py (IdP, registry, Super Admin 1) + Super Admin 2
             (bootstrap-super-admin) + version policy mong muốn của tenant-a (admin policy-apply — resume áp lại nó)
  UI-E2E-02  src/live/platform.live.test.tsx: wizard → job timeline 19 bước → hủy → chi tiết tenant → xin xóa 2P (người
             yêu cầu không duyệt được) → Super Admin 2 duyệt với hash tính trong trình duyệt → tenant-a tạm ngưng/khôi
             phục, timeline poll tới khi job xong
  UI-E2E-03  đối chiếu DB: tenant mới `failed` (job cancelled) rồi có job tenant.deprovision; approval `executed` do
             người thứ hai quyết định với đúng payload_sha256; Idempotency-Key của POST/DELETE do SPA sinh (UUID v4, mỗi
             thao tác một khóa; khóa tạo tenant = request_key của job); audit .requested/.cancel/.approve; tenant-a
             `active` lại, job suspend/resume succeeded
  UI-E2E-04  proxy: mọi request của SPA là /api/v1/* tới admin.; không 5xx; không secret của lượt chạy trong log

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
            def log_message(self, *_):  # noqa: D401 — im lặng
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


def prepare(r: checks.Results, st: Stack) -> dict:
    state = json.loads((st.work / "state" / "backend.json").read_text(encoding="utf-8"))
    for tid, fn, *args in (("E2E-17", backend.check_ready, st, state), ("E2E-20", backend.check_idp_bootstrap, st),
                           ("E2E-21", backend.check_registry, st, state)):
        fn(r, *args)
    # E2E-24 chỉ để tạo Super Admin 1 (st.platform_sa): kết luận của nó cần E2E-22/23 (không chạy ở đây) ⇒ không tính
    backend.check_platform(checks.Results(st), st, state)
    kc = KeycloakAdmin(st)
    sa2 = {"username": "ui-sa2-" + secrets.token_hex(3), "password": secrets.token_urlsafe(18)}
    st.secret_values.add(sa2["password"])
    sa2["sub"] = kc.create_user("platform", sa2["username"], sa2["password"])
    p = admin_cmd(st, ["bootstrap-super-admin", "--subject", sa2["sub"], "--display-name", "UI SA2"],
                  env={"MG_IDP_ID_PLATFORM": st.env["MG_IDP_ID_PLATFORM"]})
    b1, s1 = platform_session(st, st.platform_sa)
    b2, s2 = platform_session(st, sa2, TOTP())
    base = (ROOT / "infrastructure" / "headscale" / "templates" / "bootstrap-policy.hujson").read_text(encoding="utf-8")
    code, out, _ = policy_apply(st, base, "--trigger", "bootstrap")
    desired = psql(st, "SELECT desired_policy_version_id IS NOT NULL FROM tenants WHERE slug = 'tenant-a'")
    ok = (p.returncode == 0 and s1.get("principal", {}).get("platform_role") == "super_admin"
          and s2.get("principal", {}).get("platform_role") == "super_admin" and code == 0 and desired == [["t"]])
    r.add("UI-E2E-01", "Chuẩn bị: IdP, registry (tenant-a/b adopt), hai Super Admin đăng nhập Keycloak + TOTP trên admin., "
          "version policy mong muốn của tenant-a", ok,
          f"SA2 bootstrap {p.returncode}; SA1 {s1.get('principal', {}).get('platform_role')}, SA2 "
          f"{s2.get('principal', {}).get('platform_role')}; policy-apply {code} {out.get('state')}; desired {desired}")
    state.update(b1=b1, b2=b2, s1=s1, s2=s2, sa2_sub=sa2["sub"])
    return state


def run_live(r: checks.Results, st: Stack, p1: Proxy, p2: Proxy, tenant_a: str) -> dict:
    nm = os.environ.get("WEB_NODE_MODULES", "")
    if not nm or not pathlib.Path(nm, "vitest").exists():
        raise StackError("WEB_NODE_MODULES phải trỏ tới node_modules đã cài của apps/web (npm ci)")
    out = st.out / "platformui"
    out.mkdir(parents=True, exist_ok=True)
    os.chmod(out, 0o777)
    run = secrets.token_hex(3)
    cmd = [*st.docker_cmd, "run", "--rm", "--network", "host", "-u", f"{os.getuid()}:{os.getgid()}", "-e", "HOME=/tmp",
           "-e", f"MG_LIVE_SA1={p1.url}", "-e", f"MG_LIVE_SA2={p2.url}", "-e", f"MG_LIVE_TENANT_A={tenant_a}",
           "-e", f"MG_LIVE_RUN={run}", "-e", "MG_LIVE_OUT=/out/live.json",
           "-v", f"{ROOT}:/src", "-v", f"{nm}:/src/apps/web/node_modules", "-v", f"{out}:/out", "-w", "/src/apps/web",
           NODE_IMAGE, "npx", "vitest", "run", "--reporter=verbose", "src/live/platform.live.test.tsx"]
    t0 = time.time()
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=1800, check=False)
    text = re.sub(r"\x1b\[[0-9;]*m", "", p.stdout + p.stderr)
    (out / "vitest.log").write_text(st.redact(text), encoding="utf-8")
    facts = json.loads((out / "live.json").read_text(encoding="utf-8")) if (out / "live.json").exists() else {}
    passed = re.findall(r"^\s*✓ .*UI-0\d", text, re.M)
    failed = re.findall(r"^\s*(?:×|✗|FAIL) .*", text, re.M)
    ok = p.returncode == 0 and len(passed) == 3 and not failed and "skipped" not in text.split("Tests")[-1]
    r.add("UI-E2E-02", "SPA thật (Vitest + jsdom, App + router + client openapi-fetch) qua proxy của hai Super Admin: wizard "
          "→ timeline 19 bước → hủy → chi tiết → xin xóa 2P → người thứ hai duyệt (hash tính trong trình duyệt) → "
          "tenant-a tạm ngưng/khôi phục với timeline poll tới khi xong", ok,
          f"exit {p.returncode} sau {time.time() - t0:.0f} s; {len(passed)}/3 ca đạt; {failed[:3]}; facts {facts}")
    return facts


def verify(r: checks.Results, st: Stack, facts: dict, proxies: list[Proxy], sa2_sub: str) -> None:
    slug, tid, appr = facts.get("slug", ""), facts.get("tenant_id", ""), facts.get("approval_id", "")
    if not (re.fullmatch(r"ui-[0-9a-f]{6}", slug) and re.fullmatch(r"[0-9a-f-]{36}", tid or "") and
            re.fullmatch(r"[0-9a-f-]{36}", appr or "")):
        r.add("UI-E2E-03", "Đối chiếu DB", False, f"facts thiếu: {facts}")
        return
    one = lambda sql: (psql(st, sql) or [[""]])[0][0]   # noqa: E731
    tenant = psql(st, f"SELECT slug, status FROM tenants WHERE id = '{tid}'")
    jobs = psql(st, f"SELECT kind, status FROM provisioning_jobs WHERE tenant_id = '{tid}' ORDER BY created_at")
    ap = psql(st, "SELECT a.status, a.action, a.payload_sha256, ri.subject, di.subject FROM approval_requests a "
                  "JOIN identities ri ON ri.id = a.requested_by_identity_id LEFT JOIN identities di ON "
                  f"di.id = a.approved_by_identity_id WHERE a.id = '{appr}'")
    sa1_sub = st.platform_sa["sub"]
    # POST/DELETE của SPA mang Idempotency-Key (duyệt/từ chối không có trong spec)
    writes = [(m, path, k) for p in proxies for (m, path, _, k) in p.seen
              if m in ("POST", "DELETE") and "/approvals/" not in path and not path.startswith("/api/v1/auth/")]
    keys = [k for _, _, k in writes]
    uuid4 = bool(keys) and all(UUID4.match(k) for k in keys)
    create_key = next((k for m, path, k in writes if path == "/api/v1/platform/tenants"), "")
    pj = str(facts.get("provision_job", ""))
    job_key = one(f"SELECT request_key FROM provisioning_jobs WHERE id = '{pj}'") if re.fullmatch(r"[0-9a-f-]{36}", pj) else ""
    stored = int(one("SELECT count(*) FROM (SELECT key AS k FROM idempotency_keys UNION SELECT request_key FROM "
                     "provisioning_jobs) x WHERE k IN (" + ",".join(f"'{k}'" for k in keys) + ")")) if uuid4 else -1
    audit = {a: int(n) for a, n in psql(st, "SELECT action, count(*) FROM audit_events WHERE (resource_id = "
                                            f"'{tid}' OR resource_id = '{appr}' OR resource_id = '{facts.get('provision_job', '')}') "
                                            "AND outcome = 'success' GROUP BY 1")}
    a_state = one("SELECT status FROM tenants WHERE slug = 'tenant-a'")
    ids = [x for x in (facts.get("suspend_job"), facts.get("resume_job")) if re.fullmatch(r"[0-9a-f-]{36}", str(x or ""))]
    sr = psql(st, "SELECT kind, status FROM provisioning_jobs WHERE id IN ("
                  + ",".join(f"'{x}'" for x in ids) + ") ORDER BY created_at") if ids else []
    ok = (tenant and tenant[0][0] == slug and tenant[0][1] in ("failed", "deprovisioning", "deleted")
          and jobs[:1] == [["tenant.provision", "cancelled"]] and any(k == "tenant.deprovision" for k, _ in jobs)
          and ap and ap[0][0] == "executed" and ap[0][1] == "platform.tenant.delete"
          and ap[0][2] == facts.get("payload_sha256") and ap[0][3] == sa1_sub and ap[0][4] == sa2_sub
          and uuid4 and len(keys) >= 5 and len(set(keys)) == len(keys) and create_key == job_key != ""
          and audit.get("platform.tenant.create.requested") == 1 and audit.get("platform.job.cancel") == 1
          and audit.get("platform.approval.approve", 0) >= 1
          and a_state == "active" and sr == [["tenant.suspend", "succeeded"], ["tenant.resume", "succeeded"]])
    r.add("UI-E2E-03", "DB sau luồng UI: tenant mới (job provision cancelled, rồi tenant.deprovision), approval executed — "
          "người yêu cầu SA1, người duyệt SA2, đúng payload_sha256 đã hiển thị; Idempotency-Key do SPA sinh: UUID v4, mỗi "
          "thao tác một khóa, khóa của POST /platform/tenants là request_key của job; audit; tenant-a active lại, "
          "suspend/resume succeeded", ok,
          f"tenant {tenant}; jobs {jobs}; approval {[x[:3] for x in ap]} (requester=SA1 {bool(ap) and ap[0][3] == sa1_sub}, "
          f"decider=SA2 {bool(ap) and ap[0][4] == sa2_sub}); {len(keys)} khóa, UUIDv4 {uuid4}, khóa tạo tenant = request_key "
          f"của job {create_key == job_key != ''}, {stored} khóa có trong idempotency_keys/provisioning_jobs; audit {audit}; "
          f"tenant-a {a_state}; suspend/resume {sr}", limit=900)


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
        state = prepare(r, st)
        p1, p2 = Proxy(st, state["b1"], "sa1"), Proxy(st, state["b2"], "sa2")
        proxies = [p1, p2]
        tenant_a = state["tenant_ids"]["tenant-a"]
        facts = run_live(r, st, p1, p2, tenant_a)
        verify(r, st, facts, proxies, state["sa2_sub"])
        seen = [x for p in proxies for x in p.seen]
        bad = [x for x in seen if x[2] >= 500]
        log_text = (st.out / "platformui" / "vitest.log").read_text(encoding="utf-8") if (st.out / "platformui" / "vitest.log").exists() else ""
        leaked = [v for v in st.secret_values if v and len(v) >= 8 and v in log_text]
        (st.out / "platformui" / "requests.txt").write_text(
            "\n".join(f"{p.name} {m} {path} {s}" for p in proxies for (m, path, s, _) in p.seen) + "\n", encoding="utf-8")
        r.add("UI-E2E-04", "Proxy: mọi request của SPA là /api/v1/* tới admin.; không 5xx; log của lượt chạy không chứa secret",
              bool(seen) and not bad and not leaked,
              f"{len(seen)} request ({sum(1 for x in seen if x[0] != 'GET')} ghi); 5xx {bad[:3]}; secret lộ {len(leaked)}")
    except (StackError, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as e:
        error = f"{type(e).__name__}: {st.redact(str(e))[-1500:]}"
        log("LỖI: " + error)
    finally:
        for p in proxies:
            p.close()
    lines = [f"{x['result']:4} {x['id']:10} {x['name']}\n{'':15}{x['detail']}" for x in r.rows]
    passed = sum(x["result"] == "PASS" for x in r.rows)
    text = "\n".join(lines) + f"\n\n{passed}/{len(r.rows)} ca PASS (functional)" + (f"\nLỖI: {error}" if error else "") + "\n"
    (st.out / "platformui").mkdir(parents=True, exist_ok=True)
    (st.out / "platformui" / "summary.txt").write_text(text, encoding="utf-8")
    print(text, flush=True)
    return 1 if error or r.failed else 0


if __name__ == "__main__":
    sys.exit(main())
