#!/usr/bin/env python3
"""Users / Groups / Invitations của Tenant Portal (P4-T09a) trên stack dev/CI thật — FUNCTIONAL only (§22.1).

Chạy sau `e2e.py up` trên cùng tham số (E2E_PREFIX, E2E_WORK, MG_E2E_NET_BASE, …), trên host có Docker và python3:

  WEB_NODE_MODULES=<node_modules đã cài của apps/web> [NODE_IMAGE=…] python3 tests/e2e/harness/peopleui.py

Như platformui.py (P4-T02): trình duyệt được thay bằng Vitest + jsdom chạy App thật của apps/web, mỗi "trình duyệt" là
một proxy cục bộ 127.0.0.1 của harness tới https://app.<domain>/api/v1/* qua edge (cookie phiên __Host- giữ trong proxy,
header Origin như trình duyệt cho method ghi). Trong lúc src/live/people.live.test.tsx chạy, harness đọc tệp facts của
nó và đóng vai "người khác": người được mời đăng nhập lần đầu (Keycloak + TOTP thật) khi thấy `invitation_id`; Tenant
Owner đăng nhập lại (step-up) và duyệt khi thấy `approval_id`.

Chuẩn bị (không phải ca): E2E-17, E2E-20, E2E-21 của backend.py; version policy mong muốn của tenant-a (policy.apply
group_change áp lên nó); Tenant Owner, hai Tenant Admin (seed-membership + đăng nhập), một end user đang hoạt động,
một user Keycloak chưa được mời; một group do Admin tạo qua API rồi được Owner đánh dấu sensitive qua
PUT /settings/security (step-up, khóa bảo mật — P4-T03a). End user được mời qua API rồi đăng nhập lần đầu
(seed-membership chỉ cấp Owner/Admin).

  E2E-111 Owner qua SPA: mời (POST /invitations với Idempotency-Key UUID v4 của SPA) → bảng Lời mời theo dõi job
          member.idp_invite tới succeeded → người được mời đăng nhập lần đầu → chi tiết: đổi role end_user → tenant_viewer
          (PUT /role) → tenant_admin (PUT /admin-role, step-up) → offboard (gõ lại email) ⇒ khung pending → poll tới
          applied + job succeeded; DB: lời mời accepted, audit role/admin_role/offboard đóng cặp, job member.offboard
          {idp: disabled, keys_expired ≥ 1}, Headscale: pre-auth key của mg-<membership> hết hạn, Keycloak enabled=false
  E2E-112 Tenant Admin qua SPA: chi tiết Admin khác và Owner không có nút thao tác; lệnh khóa Admin khác gửi thẳng qua
          client của SPA ⇒ 403 (audit denied target_not_lower); tạo group + thêm thành viên ⇒ 200, policy.apply
          group_change succeeded; group sensitive ⇒ 202 + yêu cầu phê duyệt (thành viên chưa đổi) → Owner (step-up) duyệt
          ⇒ SPA thấy executed và group đọc lại có thành viên; DB: approval executed, người yêu cầu Admin, người duyệt Owner

Thư viện chuẩn. Mật khẩu, TOTP, cookie, CSRF token, pre-auth key chỉ nằm trong tiến trình này (và tập redaction).
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
from backend import Browser, KeycloakAdmin, portal_login, psql  # noqa: E402
from dualcontrol import first_login, new_user, owner_session, psql_one, tenant_id, unsafe  # noqa: E402
from members import QUERY_A, SLUG, invited_member, membership_of, seeded  # noqa: E402
from phase3 import policy_apply  # noqa: E402
from platformui import NODE_IMAGE, UUID4, Proxy, ok_uuid  # noqa: E402
from stack import ROOT, Stack, StackError, log  # noqa: E402


def app(st: Stack) -> str:
    return f"https://app.{st.domain}/api/v1"


def prepare(st: Stack) -> dict:
    """Điều kiện của hai ca; lỗi ⇒ StackError (không ca nào chạy)."""
    state = json.loads((st.work / "state" / "backend.json").read_text(encoding="utf-8"))
    pre = checks.Results(st)
    backend.check_ready(pre, st, state)
    backend.check_idp_bootstrap(pre, st)
    backend.check_registry(pre, st, state)
    if pre.failed:
        raise StackError("chuẩn bị (E2E-17/20/21) thất bại: " + "; ".join(x["id"] for x in pre.rows if x["result"] != "PASS"))
    base = (ROOT / "infrastructure" / "headscale" / "templates" / "bootstrap-policy.hujson").read_text(encoding="utf-8")
    code, out, _ = policy_apply(st, base, "--trigger", "bootstrap")
    a_id = tenant_id(st, SLUG)
    ob, osess, owner = owner_session(st, SLUG)
    tb, tsess, admin = seeded(st, "tenant_admin", "ui-ta")
    _, _, admin2 = seeded(st, "tenant_admin", "ui-ta2")
    # một end user đang hoạt động (seed-membership chỉ cấp Owner/Admin): mời qua API + đăng nhập lần đầu
    mem, _, _, _ = invited_member(st, ob, osess, a_id, "end_user")
    mem_name = psql_one(st, f"SELECT display_name FROM identities WHERE subject = '{mem['sub']}'")
    invitee = new_user(st, SLUG, "ui-inv")
    # group sensitive: Admin tạo (Idempotency-Key), Owner đánh dấu qua PUT /settings/security (siết ⇒ 200, step-up)
    g = tb.request("POST", f"{app(st)}/tenants/{a_id}/groups", json.dumps({"name": "ui-sens-" + secrets.token_hex(3)}).encode(),
                   unsafe(st, tsess, **{"Idempotency-Key": "ui-" + secrets.token_hex(8)}))
    gid = g.json().get("id", "")
    got = ob.get(f"{app(st)}/tenants/{a_id}/settings")
    sec = got.json().get("settings") or {}
    e = sec.get("enrollment") or {}
    body = {"enrollment": {k: e.get(k) for k in ("identity_mode", "web_auth_enabled", "self_enroll", "requires_approval")},
            "node_expiry": sec.get("node_expiry"),
            "policy": {"four_eyes": (sec.get("policy") or {}).get("four_eyes", False),
                       "sensitive_groups": [*(sec.get("policy") or {}).get("sensitive_groups", []), gid]},
            "routes": sec.get("routes") or {"four_eyes": False}}
    put = ob.request("PUT", f"{app(st)}/tenants/{a_id}/settings/security", json.dumps(body).encode(),
                     unsafe(st, osess, **{"If-Match": got.header("ETag")}))
    if code != 0 or not mem_name or g.status != 201 or put.status != 200:
        raise StackError(f"chuẩn bị: policy-apply {code} {out.get('state')}, member {mem_name!r}, group {g.status}, "
                         f"settings/security {put.status} {put.body[:200]!r}")
    log(f"chuẩn bị xong: Owner, 2 Admin, member '{mem_name}', group sensitive {gid}, policy-apply {out.get('state')}")
    state.update(a_id=a_id, ob=ob, owner=owner, tb=tb, admin=admin, admin2=admin2, mem=mem, mem_name=mem_name,
                 invitee=invitee, sensitive=gid)
    return state


class Helper:
    """Phần "người khác" của hai ca — chạy khi tệp facts của vitest có khóa tương ứng."""

    def __init__(self, st: Stack, state: dict):
        self.st, self.s = st, state
        self.done: dict[str, str] = {}

    def invitee_joins(self) -> None:
        u = self.s["invitee"]
        status, code, _ = first_login(self.st, u)
        mid = membership_of(self.st, u["sub"])
        # Headscale user của thành viên + một pre-auth key sống: offboard phải expire nó
        hs_user = f"mg-{mid}"
        uid = str(json.loads(self.st.headscale(SLUG, "users", "create", hs_user, "-o", "json").stdout)["id"])
        key = json.loads(self.st.headscale(SLUG, "preauthkeys", "create", "-u", uid, "--reusable", "-e", "30m", "-o", "json").stdout)["key"]
        self.st.secret_values.add(key)
        self.s.update(invitee_mid=mid, hs_uid=uid)
        self.done["invitee"] = f"first login {status} {code}; membership {mid}; Headscale user {hs_user} ({uid}) + 1 key"

    def owner_approves(self, approval_id: str) -> None:
        owner = self.s["owner"]
        b = Browser(self.st)                                  # đăng nhập mới ⇒ step-up
        sess, _ = portal_login(self.st, b, f"app.{self.st.domain}", QUERY_A, owner, owner["otp"])
        url = f"{app(self.st)}/tenants/{self.s['a_id']}/approvals/{approval_id}"
        a = b.get(url).json()
        r = b.request("POST", url + "/approve", json.dumps({"payload_sha256": a.get("payload_sha256")}).encode(), unsafe(self.st, sess))
        self.done["approval"] = f"approve {r.status} {r.json().get('status')}"

    def poll(self, facts: dict) -> None:
        try:
            if "invitation_id" in facts and "invitee" not in self.done:
                self.done["invitee"] = "…"
                self.invitee_joins()
            if ok_uuid(facts.get("approval_id")) and "approval" not in self.done:
                self.done["approval"] = "…"
                self.owner_approves(facts["approval_id"])
        except (StackError, OSError, ValueError, KeyError, subprocess.SubprocessError) as e:
            self.done.setdefault("error", f"{type(e).__name__}: {self.st.redact(str(e))[-400:]}")


def run_live(st: Stack, owner: Proxy, admin: Proxy, state: dict) -> tuple[dict, dict, str, Helper]:
    nm = os.environ.get("WEB_NODE_MODULES", "")
    if not nm or not pathlib.Path(nm, "vitest").exists():
        raise StackError("WEB_NODE_MODULES phải trỏ tới node_modules đã cài của apps/web (npm ci)")
    out = st.out / "peopleui"
    out.mkdir(parents=True, exist_ok=True)
    os.chmod(out, 0o777)
    facts_file = out / "live.json"
    facts_file.unlink(missing_ok=True)
    env = {"MG_LIVE_OWNER": owner.url, "MG_LIVE_ADMIN": admin.url, "MG_LIVE_TENANT_A": state["a_id"],
           "MG_LIVE_INVITEE_EMAIL": state["invitee"]["email"], "MG_LIVE_ADMIN2": membership_of(st, state["admin2"]["sub"]),
           "MG_LIVE_OWNER_MID": membership_of(st, state["owner"]["sub"]), "MG_LIVE_SENSITIVE_GROUP": state["sensitive"],
           "MG_LIVE_MEMBER_NAME": state["mem_name"], "MG_LIVE_RUN": secrets.token_hex(3), "MG_LIVE_OUT": "/out/live.json"}
    cmd = [*st.docker_cmd, "run", "--rm", "--network", "host", "-u", f"{os.getuid()}:{os.getgid()}", "-e", "HOME=/tmp",
           *[x for k, v in env.items() for x in ("-e", f"{k}={v}")],
           "-v", f"{ROOT}:/src", "-v", f"{nm}:/src/apps/web/node_modules", "-v", f"{out}:/out", "-w", "/src/apps/web",
           NODE_IMAGE, "npx", "vitest", "run", "--reporter=verbose", "src/live/people.live.test.tsx"]
    helper = Helper(st, state)
    t0 = time.time()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    lines: list[str] = []
    reader = threading.Thread(target=lambda: lines.extend(proc.stdout or []), daemon=True)
    reader.start()
    while proc.poll() is None and time.time() - t0 < 1800:
        try:
            facts = json.loads(facts_file.read_text(encoding="utf-8")) if facts_file.exists() else {}
        except ValueError:
            facts = {}
        helper.poll(facts)
        time.sleep(1)
    if proc.poll() is None:
        proc.kill()
    reader.join(timeout=10)
    text = re.sub(r"\x1b\[[0-9;]*m", "", "".join(lines))
    (out / "vitest.log").write_text(st.redact(text), encoding="utf-8")
    facts = json.loads(facts_file.read_text(encoding="utf-8")) if facts_file.exists() else {}
    cases = {c: bool(re.search(rf"^\s*✓ .*{c} ", text, re.M)) for c in ("UI-11", "UI-12")}
    return facts, cases, f"vitest exit {proc.returncode} sau {time.time() - t0:.0f} s, {sum(cases.values())}/2 ca; harness {helper.done}", helper


def check_owner_flow(r: checks.Results, st: Stack, state: dict, facts: dict, cases: dict, summary: str, owner: Proxy) -> None:
    inv, mid = facts.get("invitation_id"), facts.get("membership_id")
    if not (ok_uuid(inv) and ok_uuid(mid)):
        r.add("E2E-111", "P4-T09a Owner qua SPA", False, f"{summary}; facts thiếu: {facts}", limit=900)
        return
    one = lambda sql: psql_one(st, sql)   # noqa: E731
    invitation = psql(st, f"SELECT lower(email), status FROM tenant_invitations WHERE id = '{inv}'")
    idp_job = psql(st, f"SELECT status FROM provisioning_jobs WHERE kind = 'member.idp_invite' AND resource_id = '{inv}'")
    key = next((k for (m, path, _, k) in owner.seen if m == "POST" and path.endswith("/invitations")), "")
    status = one(f"SELECT status FROM tenant_memberships WHERE id = '{mid}'")
    audit = {a: int(n) for a, n in psql(st, "SELECT action, count(*) FROM audit_events WHERE resource_id = "
                                            f"'{mid}' AND outcome = 'success' GROUP BY 1")}
    job = psql(st, "SELECT status, coalesce(output::text, '{}') FROM provisioning_jobs WHERE kind = 'member.offboard' "
                   f"AND resource_id = '{mid}' ORDER BY created_at DESC LIMIT 1")
    jout = json.loads(job[0][1]) if job else {}
    now = time.time() + 5
    keys = [k for k in json.loads(st.headscale(SLUG, "preauthkeys", "list", "-o", "json").stdout or "[]") or []
            if str((k.get("user") or {}).get("id", "")) == state.get("hs_uid")]
    keys_expired = bool(keys) and all(int((k.get("expiration") or {}).get("seconds", 0)) <= now for k in keys)
    kuser = KeycloakAdmin(st)._call("GET", f"/admin/realms/{SLUG}/users/{state['invitee']['sub']}")
    ok = (cases.get("UI-11") and facts.get("idp_job_seen") == "succeeded"
          and invitation == [[state["invitee"]["email"].lower(), "accepted"]] and idp_job == [["succeeded"]]
          and bool(UUID4.match(key)) and status == "offboarded"
          and audit.get("user.role.set") == 1 and audit.get("user.admin_role.set") == 1
          and audit.get("user.offboard.requested") == 1 and audit.get("user.offboard.succeeded") == 1
          and facts.get("offboard_first_state") == "pending" and facts.get("offboard_state") == "applied"
          and facts.get("offboard_job_seen") == "succeeded" and bool(job) and job[0][0] == "succeeded"
          and jout.get("idp") == "disabled" and int(jout.get("keys_expired", 0)) >= 1 and keys_expired
          and kuser.get("enabled") is False)
    r.add("E2E-111", "P4-T09a Owner qua SPA: mời (Idempotency-Key UUID v4 của SPA) → job member.idp_invite succeeded hiện ở "
          "bảng Lời mời → người được mời đăng nhập lần đầu → đổi role end_user → tenant_viewer (PUT /role) → tenant_admin "
          "(PUT /admin-role, step-up) → offboard (gõ lại email) ⇒ pending → poll tới applied; DB/Headscale/Keycloak khớp", ok,
          f"{summary}; lời mời {invitation}, job IdP {idp_job}, khóa UUIDv4 {bool(UUID4.match(key))}; membership {status}; "
          f"audit {audit}; offboard UI {facts.get('offboard_first_state')}→{facts.get('offboard_state')}, job {job[:1] and job[0][0]} "
          f"{jout}; key Headscale hết hạn {keys_expired} ({len(keys)}); Keycloak enabled={kuser.get('enabled')}", limit=1400)


def check_admin_flow(r: checks.Results, st: Stack, state: dict, facts: dict, cases: dict, summary: str) -> None:
    admin_id = psql_one(st, f"SELECT id FROM identities WHERE subject = '{state['admin']['sub']}'")
    owner_id = psql_one(st, f"SELECT id FROM identities WHERE subject = '{state['owner']['sub']}'")
    admin2_mid = membership_of(st, state["admin2"]["sub"])
    denied = psql_one(st, "SELECT coalesce(details ->> 'reason', '') FROM audit_events WHERE action = 'user.update' AND "
                      f"outcome = 'denied' AND actor_identity_id = '{admin_id}' AND resource_id = '{admin2_mid}' "
                      "ORDER BY occurred_at DESC LIMIT 1")
    gid, appr = facts.get("group_id"), facts.get("approval_id")
    g = psql(st, f"SELECT name, (SELECT count(*) FROM group_members m WHERE m.group_id = g.id) FROM groups g WHERE id = '{gid}'") if ok_uuid(gid) else []
    apply = psql(st, f"SELECT status FROM provisioning_jobs WHERE tenant_id = '{state['a_id']}' AND kind = 'policy.apply' "
                     "AND input ->> 'trigger' = 'group_change' ORDER BY created_at DESC LIMIT 1")
    if apply and apply[0][0] not in ("succeeded", "failed", "cancelled"):
        time.sleep(20)
        apply = psql(st, f"SELECT status FROM provisioning_jobs WHERE tenant_id = '{state['a_id']}' AND kind = 'policy.apply' "
                         "AND input ->> 'trigger' = 'group_change' ORDER BY created_at DESC LIMIT 1")
    ap = psql(st, "SELECT status, action, resource_id, requested_by_identity_id, approved_by_identity_id FROM approval_requests "
                  f"WHERE id = '{appr}'") if ok_uuid(appr) else []
    sens = psql_one(st, f"SELECT count(*) FROM group_members WHERE group_id = '{state['sensitive']}'")
    ok = (cases.get("UI-12") and facts.get("admin_ui_hidden") is True and facts.get("direct_lock_admin") == "403 forbidden"
          and denied == "target_not_lower" and bool(g) and g[0][0] == f"ui-{facts.get('run', '')}" and g[0][1] == "1"
          and apply == [["succeeded"]] and facts.get("approval_first_status") == "pending"
          and facts.get("members_before_approval") == "0/0" and facts.get("approval_status") == "executed"
          and bool(ap) and ap[0][:3] == ["executed", "tenant.group.set_members", state["sensitive"]]
          and ap[0][3] == admin_id and ap[0][4] == owner_id and sens == "1")
    r.add("E2E-112", "P4-T09a Tenant Admin qua SPA: Admin khác/Owner không có nút thao tác, lệnh khóa gửi thẳng ⇒ 403 "
          "(audit target_not_lower); tạo group + thêm thành viên ⇒ 200, policy.apply group_change succeeded; group "
          "sensitive ⇒ 202 + phê duyệt (thành viên chưa đổi) → Owner (step-up) duyệt ⇒ SPA thấy executed, group có thành viên",
          ok, f"{summary}; UI ẩn {facts.get('admin_ui_hidden')}; khóa thẳng {facts.get('direct_lock_admin')} audit {denied!r}; "
          f"group {g}; policy.apply {apply}; phê duyệt UI {facts.get('approval_first_status')}→{facts.get('approval_status')} "
          f"(thành viên trước duyệt {facts.get('members_before_approval')}); DB {[x[:3] for x in ap]} người yêu cầu=Admin "
          f"{bool(ap) and ap[0][3] == admin_id} người duyệt=Owner {bool(ap) and ap[0][4] == owner_id}; thành viên sensitive {sens}",
          limit=1400)


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
        p1, p2 = Proxy(st, state["ob"], "owner"), Proxy(st, state["tb"], "admin")
        for p in (p1, p2):
            p.host = f"app.{st.domain}"           # Tenant Portal (Proxy của platformui mặc định admin.)
        proxies = [p1, p2]
        facts, cases, summary, _ = run_live(st, p1, p2, state)
        check_owner_flow(r, st, state, facts, cases, summary, p1)
        check_admin_flow(r, st, state, facts, cases, summary)
        seen = [x for p in proxies for x in p.seen]
        (st.out / "peopleui" / "requests.txt").write_text(
            "\n".join(f"{p.name} {m} {path} {s}" for p in proxies for (m, path, s, _) in p.seen) + "\n", encoding="utf-8")
        bad = [x for x in seen if x[2] >= 500 or not x[1].startswith("/api/v1/")]
        leaked = sum(1 for v in st.secret_values if v and len(v) >= 8 and v in (st.out / "peopleui" / "vitest.log").read_text(encoding="utf-8"))
        log(f"{len(seen)} request của SPA, lỗi 5xx/ngoài /api/v1: {bad[:3]}, secret lộ trong log: {leaked}")
        if bad or leaked:
            error = f"request lỗi {bad[:3]} / secret lộ {leaked}"
    except (StackError, OSError, ValueError, KeyError, subprocess.SubprocessError) as e:
        error = f"{type(e).__name__}: {st.redact(str(e))[-1500:]}"
        log("LỖI: " + error)
    finally:
        for p in proxies:
            p.close()
    lines = [f"{x['result']:4} {x['id']:8} [{x['label']}] {x['name']}\n{'':14}{x['detail']}" for x in r.rows]
    passed = sum(x["result"] == "PASS" for x in r.rows)
    text = "\n".join(lines) + f"\n\n{passed}/{len(r.rows)} ca PASS (functional)" + (f"\nLỖI: {error}" if error else "") + "\n"
    (st.out / "peopleui").mkdir(parents=True, exist_ok=True)
    (st.out / "peopleui" / "summary.txt").write_text(text, encoding="utf-8")
    print(text, flush=True)
    return 1 if error or r.failed or len(r.rows) != 2 else 0


if __name__ == "__main__":
    sys.exit(main())
