#!/usr/bin/env python3
"""Thêm thiết bị / trang claim / Enrollment key của Tenant Portal (P4-T08) trên stack dev/CI thật — FUNCTIONAL only (§22.1).

Chạy sau `e2e.py up` trên cùng tham số (E2E_PREFIX, E2E_WORK, MG_E2E_NET_BASE, …), trên host có Docker và python3:

  WEB_NODE_MODULES=<node_modules đã cài của apps/web> [NODE_IMAGE=…] python3 tests/e2e/harness/enrollui.py

Như peopleui.py / policyui.py: trình duyệt được thay bằng Vitest + jsdom chạy App thật của apps/web; "trình duyệt" là một
proxy cục bộ 127.0.0.1 giữ phiên (cookie __Host- — SPA không thấy) của một Tenant Admin của tenant-a đã đăng nhập Keycloak
+ TOTP qua edge app.<domain>. Trong lúc src/live/enrollment.live.test.tsx chạy, harness đóng vai THIẾT BỊ qua một thư mục
bí mật 0700 (không phải thư mục kết quả; tệp bị xóa ngay sau khi đọc, giá trị vào tập redaction):
  - tệp `hostname` (mg-<mã> của lệnh SPA hiển thị) ⇒ client Tailscale chính thức `tailscale up --login-server
    https://tenant-a.<mesh> --hostname <đó>` không key ⇒ link /register/<auth_id> client in ra ⇒ GET qua edge v10 ⇒ 302
    ⇒ ghi path + query của Location (chỉ khi Location đúng https://app.<domain>/enroll/claim) vào tệp `claim`;
  - tệp `key` (pre-auth key SPA hiển thị một lần) ⇒ client chính thức dùng key (tệp 0400 trong container).

Chuẩn bị (không phải ca): E2E-17, E2E-20, E2E-21 của backend.py; subscription của tenant-a (quota §7.4 bước 3);
TenantSettings.enrollment.web_auth_enabled = true, requires_approval = false (đặt bằng SQL như E2E-101; giá trị cũ đặt lại
khi xong); Tenant Admin seed-membership + đăng nhập.

  E2E-119 Web-auth qua SPA (§7.4 luồng A, P4-T07 §3): wizard Linux hiển thị login_server của tenant; "Tạo lệnh đăng ký" ⇒
          lệnh --hostname mg-<mã> (mã không ở URL/Storage/cache); client chính thức chạy lệnh; link của client qua edge ⇒
          302 tới trang claim; SPA mở Location: gỡ auth_id khỏi URL, thấy yêu cầu đang chờ, xác nhận tường minh ⇒
          verified; Auth ID không còn dấu vết (DOM/URL/Storage/cache); client Running, node đổi tên theo nhãn dưới
          mg-<membership Admin>; DB: yêu cầu verified, sổ thiết bị có enrollment_request_id; danh sách "Yêu cầu của bạn"
          thấy verified
  E2E-120 Pre-auth key qua SPA (§7.4 phương thức B): Enrollment key → tạo key một lần 5 phút (POST /enrollment/requests,
          Idempotency-Key của SPA) ⇒ hộp hiển thị một lần (lệnh không chứa key); client chính thức dùng key ⇒ Running dưới
          mg-<membership Admin>; đóng hộp ⇒ key không còn ở DOM/URL/Storage/cache; enrollment.reconcile ⇒ yêu cầu
          consumed, bảng của SPA (poll) thấy consumed; bảng idempotency_keys / enrollment_requests không chứa key

Thư viện chuẩn. Mật khẩu, TOTP, cookie, CSRF token, mã enrollment, Auth ID, pre-auth key chỉ nằm trong tiến trình này,
thư mục bí mật (xóa khi xong) và tập redaction.
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import secrets
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import backend  # noqa: E402
import checks  # noqa: E402
import enrollment  # noqa: E402 — _ensure_subscription, _set_enrollment, _key_file, _client (pre-auth key)
import webauth  # noqa: E402 — _client (không key), _link, _follow, _backend_state, _nodes
from backend import Browser, psql  # noqa: E402
from dualcontrol import psql_one, tenant_id  # noqa: E402
from lifecycle import admin_session  # noqa: E402
from platformui import NODE_IMAGE, UUID4, Proxy, ok_uuid  # noqa: E402
from stack import ROOT, Stack, StackError, log  # noqa: E402

SLUG = "tenant-a"
WEB_FACTS = ("login_server_shown", "hostname_shape", "code_not_stored", "claim_path_shape", "auth_id_stripped", "pending_seen",
             "claim_result", "auth_id_traces", "row_status")
CLAIM_RE = re.compile(r"^/enroll/claim\?tenant=tenant-a&auth_id=hskey-authreq-[A-Za-z0-9_-]{24}$")


def prepare(st: Stack) -> dict:
    state = json.loads((st.work / "state" / "backend.json").read_text(encoding="utf-8"))
    pre = checks.Results(st)
    backend.check_ready(pre, st, state)
    if not tenant_id(st, SLUG):      # lượt đầu trên stack này (E2E-20/21 không chạy lại được: adopt đã xong)
        backend.check_idp_bootstrap(pre, st)
        backend.check_registry(pre, st, state)
    if pre.failed:
        raise StackError("chuẩn bị (E2E-17/20/21) thất bại: " + "; ".join(x["id"] for x in pre.rows if x["result"] != "PASS"))
    a_id = tenant_id(st, SLUG)
    enrollment._ensure_subscription(st, a_id)
    before = psql_one(st, f"SELECT coalesce(settings -> 'enrollment', 'null'::jsonb)::text FROM tenants WHERE id = '{a_id}'")
    enrollment._set_enrollment(st, a_id, {"web_auth_enabled": True, "requires_approval": False})
    b, sess = admin_session(st)
    st.secret_values.add(sess.get("csrf_token", ""))
    mid = psql_one(st, f"SELECT id FROM tenant_memberships WHERE tenant_id = '{a_id}' AND identity_id = "
                       f"'{sess['principal']['identity_id']}'")
    secret_dir = st.fresh_dir("secrets/enrollui")
    log(f"chuẩn bị xong: tenant-a {a_id}, Tenant Admin membership {mid}, enrollment trước {before}")
    return {"a_id": a_id, "b": b, "sess": sess, "mid": mid, "before": before, "secret_dir": secret_dir}


def restore(st: Stack, a_id: str, before: str) -> None:
    if before == "null":
        psql(st, f"UPDATE tenants SET settings = settings - 'enrollment' WHERE id = '{a_id}'")
    else:
        psql(st, f"UPDATE tenants SET settings = jsonb_set(settings, '{{enrollment}}', '{before}'::jsonb) WHERE id = '{a_id}'")


class Device:
    """Phần "thiết bị" của hai ca — chạy khi thư mục bí mật có tệp tương ứng."""

    def __init__(self, st: Stack, state: dict):
        self.st, self.s = st, state
        self.done: dict[str, str] = {}
        self.clients: list[str] = []
        self.d: pathlib.Path = state["secret_dir"]

    def _take(self, name: str) -> str:
        p = self.d / name
        v = p.read_text(encoding="utf-8").strip()
        p.unlink(missing_ok=True)
        if v:
            self.st.secret_values.add(v)
        return v

    def web(self) -> None:
        hn = self._take("hostname")
        if not re.fullmatch(r"mg-[a-z2-7]{12}", hn):
            self.done["web"] = "hostname sai dạng"
            return
        name = webauth._client(self.st, "ui14", SLUG, hn)
        self.clients.append(name)
        self.s["web_client"] = name
        host, auth = webauth._link(self.st, name)
        summary, slug, t_auth = webauth._follow(self.st, Browser(self.st), host, auth)
        path = f"/enroll/claim?tenant={slug}&auth_id={t_auth}"
        if slug == SLUG and t_auth == auth and CLAIM_RE.match(path):
            self.st.write_private(self.d / "claim", path)
        self.s["redirect"] = summary
        self.done["web"] = f"client {name}: link của tenant {host == f'{SLUG}.{self.st.mesh}'}, edge {summary}"

    def key(self) -> None:
        key = self._take("key")
        if not key.startswith("hskey-auth-"):
            self.done["key"] = "key sai dạng"
            return
        f = enrollment._key_file(self.st, "ui15", key)
        name = enrollment._client(self.st, "ui15", key_file=f, hostname="ui15-key")
        self.clients.append(name)
        self.s["key_client"] = name
        self.done["key"] = f"client {name} với key"

    def poll(self) -> None:
        try:
            if (self.d / "hostname").exists() and "web" not in self.done:
                self.done["web"] = "…"
                self.web()
            if (self.d / "key").exists() and "key" not in self.done:
                self.done["key"] = "…"
                self.key()
        except (StackError, OSError, ValueError, KeyError, subprocess.SubprocessError) as e:
            self.done.setdefault("error", f"{type(e).__name__}: {self.st.redact(str(e))[-400:]}")

    def cleanup(self) -> None:
        for c in self.clients:
            self.st.docker("rm", "-f", c, check=False)


def run_live(st: Stack, admin: Proxy, state: dict) -> tuple[dict, dict, str, Device]:
    nm = os.environ.get("WEB_NODE_MODULES", "")
    if not nm or not pathlib.Path(nm, "vitest").exists():
        raise StackError("WEB_NODE_MODULES phải trỏ tới node_modules đã cài của apps/web (npm ci)")
    out = st.out / "enrollui"
    out.mkdir(parents=True, exist_ok=True)
    os.chmod(out, 0o777)
    facts_file = out / "live.json"
    facts_file.unlink(missing_ok=True)
    env = {"MG_LIVE_ADMIN": admin.url, "MG_LIVE_TENANT_A": state["a_id"], "MG_LIVE_SECRET_DIR": "/secret",
           "MG_LIVE_RUN": secrets.token_hex(3), "MG_LIVE_OUT": "/out/live.json"}
    cmd = [*st.docker_cmd, "run", "--rm", "--network", "host", "-u", f"{os.getuid()}:{os.getgid()}", "-e", "HOME=/tmp",
           *[x for k, v in env.items() for x in ("-e", f"{k}={v}")],
           "-v", f"{ROOT}:/src", "-v", f"{nm}:/src/apps/web/node_modules", "-v", f"{out}:/out",
           "-v", f"{state['secret_dir']}:/secret", "-w", "/src/apps/web",
           NODE_IMAGE, "npx", "vitest", "run", "--reporter=verbose", "src/live/enrollment.live.test.tsx"]
    device = Device(st, state)
    t0 = time.time()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    lines: list[str] = []
    reader = threading.Thread(target=lambda: lines.extend(proc.stdout or []), daemon=True)
    reader.start()
    while proc.poll() is None and time.time() - t0 < 1800:
        device.poll()
        time.sleep(1)
    if proc.poll() is None:
        proc.kill()
    reader.join(timeout=10)
    text = re.sub(r"\x1b\[[0-9;]*m", "", "".join(lines))
    (out / "vitest.log").write_text(st.redact(text), encoding="utf-8")
    facts = json.loads(facts_file.read_text(encoding="utf-8")) if facts_file.exists() else {}
    cases = {c: bool(re.search(rf"^\s*✓ .*{c} ", text, re.M)) for c in ("UI-14", "UI-15")}
    return facts, cases, f"vitest exit {proc.returncode} sau {time.time() - t0:.0f} s, {sum(cases.values())}/2 ca; thiết bị {device.done}", device


def _request(st: Stack, rid: str) -> list:
    return psql(st, "SELECT status, method, coalesce(device_label, ''), coalesce(consumed_node_id::text, ''), "
                    f"requested_by_membership_id::text FROM enrollment_requests WHERE id = '{rid}'") if ok_uuid(rid) else []


def check_web(r: checks.Results, st: Stack, state: dict, facts: dict, cases: dict, summary: str, admin: Proxy) -> None:
    name = state.get("web_client", "")
    running = bool(name) and bool(checks.wait(lambda: webauth._backend_state(st, name) == "Running", 90))
    rid = facts.get("request_id")
    req = _request(st, rid)
    label = f"ui14-{facts.get('run', '')}"
    node = next((n for n in webauth._nodes(st, SLUG) if req and str(n.get("id")) == req[0][3]), {})
    inventory = psql_one(st, f"SELECT count(*) FROM device_inventory_cache WHERE enrollment_request_id = '{rid}'") if ok_uuid(rid) else "0"
    creates = [x for x in admin.seen if x[0] == "POST" and x[1].endswith("/enrollment/requests")]
    claims = [x for x in admin.seen if x[0] == "POST" and x[1].endswith("/enrollment/web-auth/claim")]
    ok = (cases.get("UI-14") and facts.get("login_server_shown") is True and facts.get("command_has_login_server") is True
          and facts.get("hostname_shape") is True and facts.get("code_not_stored") == [] and facts.get("claim_path_shape") is True
          and facts.get("auth_id_stripped") is True and facts.get("pending_seen") is True and facts.get("claim_result") == "verified"
          and facts.get("auth_id_traces") == [] and facts.get("row_status") == "verified" and running
          and bool(req) and req[0][:3] == ["verified", "web_auth", label] and req[0][4] == state["mid"]
          and node.get("given_name") == label and (node.get("user") or {}).get("name") == f"mg-{state['mid']}"
          and inventory == "1" and len(creates) >= 1 and all(UUID4.match(x[3]) for x in creates)
          # 429 của bucket `enrollment` (5 + 1/5 s mỗi danh tính) ⇒ người dùng bấm lại; lần cuối phải 200, đúng một 200
          and bool(claims) and claims[-1][2] == 200 and [x[2] for x in claims].count(200) == 1
          and all(x[2] in (200, 429) for x in claims))
    r.add("E2E-119", "P4-T08 web-auth qua SPA: wizard Linux (login_server của tenant) → lệnh mg-<mã> → client chính thức → "
          "link qua edge v10 ⇒ 302 ⇒ trang claim (gỡ auth_id, yêu cầu đang chờ, xác nhận tường minh) ⇒ verified; client "
          "Running, node đổi tên theo nhãn dưới mg-<membership>; sổ thiết bị có liên kết; không dấu vết mã/Auth ID", ok,
          f"{summary}; edge {state.get('redirect')}; facts {[(k, facts.get(k)) for k in WEB_FACTS]}; "
          f"client Running {running}; DB {[x[:3] for x in req]} người yêu cầu = Admin {bool(req) and req[0][4] == state['mid']}; "
          f"node {node.get('given_name')!r} user {(node.get('user') or {}).get('name') == 'mg-' + state['mid']}; sổ thiết bị {inventory}; "
          f"POST requests {[x[2] for x in creates]} khóa UUIDv4 {all(UUID4.match(x[3]) for x in creates)}; claim {[x[2] for x in claims]}",
          limit=1600)


def check_key(r: checks.Results, st: Stack, state: dict, facts: dict, cases: dict, summary: str, admin: Proxy) -> None:
    name = state.get("key_client", "")
    running = bool(name) and bool(checks.wait(lambda: webauth._backend_state(st, name) == "Running", 90))
    rid = facts.get("key_request_id")
    req = _request(st, rid)
    label = f"ui15-{facts.get('run', '')}"
    st_nodes = webauth._nodes(st, SLUG)
    node = next((n for n in st_nodes if n.get("name") == "ui15-key"), {})
    leaked = psql_one(st, "SELECT (SELECT count(*) FROM enrollment_requests WHERE row_to_json(enrollment_requests)::text LIKE "
                          "'%hskey-auth-%') + (SELECT count(*) FROM idempotency_keys WHERE row_to_json(idempotency_keys)::text "
                          "LIKE '%hskey-auth-%')")
    creates = [x for x in admin.seen if x[0] == "POST" and x[1].endswith("/enrollment/requests")]
    made = [x for x in creates if x[2] == 201]
    ok = (cases.get("UI-15") and facts.get("key_shape") is True and facts.get("key_command_without_key") is True
          and facts.get("key_not_stored") == [] and facts.get("key_traces_after_close") == [] and running
          and (node.get("user") or {}).get("name") == f"mg-{state['mid']}" and facts.get("key_row_status") == "consumed"
          and bool(req) and req[0][:3] == ["consumed", "preauth_key", label] and leaked == "0"
          and len(made) == 2 and all(x[2] in (201, 429) for x in creates) and all(UUID4.match(x[3]) for x in creates)
          and len({x[3] for x in creates}) == 2)    # lần bấm lại sau 429 dùng lại đúng Idempotency-Key của ý định đó
    r.add("E2E-120", "P4-T08 pre-auth key qua SPA: tạo key một lần 5 phút ở Enrollment key ⇒ hiển thị một lần (lệnh không "
          "chứa key) ⇒ client chính thức Running dưới mg-<membership>; đóng hộp ⇒ không dấu vết; reconcile ⇒ consumed (bảng "
          "của SPA thấy); DB không chứa key", ok,
          f"{summary}; facts {[facts.get(k) for k in ('key_shape', 'key_command_without_key', 'key_not_stored', 'key_traces_after_close', 'key_row_status')]}; "
          f"client Running {running}; node user = Admin {(node.get('user') or {}).get('name') == 'mg-' + state['mid']}; DB {[x[:3] for x in req]}; "
          f"hàng chứa hskey-auth- {leaked}; POST requests {[x[2] for x in creates]}", limit=1400)


def cleanup_nodes(st: Stack) -> None:
    """Node của hai ca rời tenant (stack còn dùng cho ca khác)."""
    for n in webauth._nodes(st, SLUG):
        if str(n.get("given_name", "")).startswith(("ui14-", "ui15-")) or n.get("name") == "ui15-key":
            st.headscale(SLUG, "nodes", "delete", "--identifier", str(n["id"]), "--force", check=False)


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    st = Stack()
    st.users = {}
    r = checks.Results(st)
    proxy: Proxy | None = None
    device: Device | None = None
    state: dict = {}
    error = None
    try:
        state = prepare(st)
        proxy = Proxy(st, state["b"], "admin")
        proxy.host = f"app.{st.domain}"
        facts, cases, summary, device = run_live(st, proxy, state)
        check_web(r, st, state, facts, cases, summary, proxy)
        check_key(r, st, state, facts, cases, summary, proxy)
        (st.out / "enrollui" / "requests.txt").write_text(
            "\n".join(f"{m} {path} {s}" for (m, path, s, _) in proxy.seen) + "\n", encoding="utf-8")
        bad = [x for x in proxy.seen if x[2] >= 500 or not x[1].startswith("/api/v1/")]
        log_text = (st.out / "enrollui" / "vitest.log").read_text(encoding="utf-8")
        leaked = sum(1 for v in st.secret_values if v and len(v) >= 8 and v in log_text)
        log(f"{len(proxy.seen)} request của SPA, lỗi 5xx/ngoài /api/v1: {bad[:3]}, secret lộ trong log: {leaked}")
        if bad or leaked:
            error = f"request lỗi {bad[:3]} / secret lộ {leaked}"
    except (StackError, OSError, ValueError, KeyError, subprocess.SubprocessError) as e:
        error = f"{type(e).__name__}: {st.redact(str(e))[-1500:]}"
        log("LỖI: " + error)
    finally:
        if proxy:
            proxy.close()
        if device:
            device.cleanup()
        try:
            cleanup_nodes(st)
            if state.get("a_id"):
                restore(st, state["a_id"], state["before"])
            st.helper("rm -rf /w/secrets/enrollui /w/secrets/e2e-enroll-ui15", f"{st.work}:/w")
        except (StackError, OSError, subprocess.SubprocessError) as e:
            log(f"dọn: {type(e).__name__}")
    lines = [f"{x['result']:4} {x['id']:8} [{x['label']}] {x['name']}\n{'':14}{x['detail']}" for x in r.rows]
    passed = sum(x["result"] == "PASS" for x in r.rows)
    text = "\n".join(lines) + f"\n\n{passed}/{len(r.rows)} ca PASS (functional)" + (f"\nLỖI: {error}" if error else "") + "\n"
    (st.out / "enrollui").mkdir(parents=True, exist_ok=True)
    (st.out / "enrollui" / "summary.txt").write_text(text, encoding="utf-8")
    print(text, flush=True)
    return 1 if error or r.failed or len(r.rows) != 2 else 0


if __name__ == "__main__":
    sys.exit(main())
