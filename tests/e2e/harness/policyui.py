#!/usr/bin/env python3
"""Trang Policies/Tags của Tenant Portal (P4-T11) trên stack dev/CI thật — FUNCTIONAL only (§22.1).

Chạy sau `e2e.py up` trên cùng tham số (E2E_PREFIX, E2E_WORK, MG_E2E_NET_BASE, …), trên host có Docker và python3:

  WEB_NODE_MODULES=<node_modules đã cài của apps/web> [NODE_IMAGE=…] python3 tests/e2e/harness/policyui.py

Như platformui.py (P4-T02): trình duyệt được thay bằng Vitest + jsdom chạy App thật của apps/web; mỗi "trình duyệt" là một
proxy cục bộ 127.0.0.1 giữ phiên (cookie __Host- — SPA không thấy) của một người đã đăng nhập Keycloak + TOTP qua edge
app.<domain>: Tenant Admin và Tenant Owner của tenant-a (seed-membership theo sub). Hai pha của
src/live/policy.live.test.tsx: pha a với TenantSettings.policy.four_eyes = true (đặt bằng SQL như E2E-97 — đường ghi
PUT /settings/security là P4-T03a), pha b với four_eyes = false; giá trị cũ được đặt lại khi xong.

Chuẩn bị (không phải ca): E2E-17, E2E-20, E2E-21 của backend.py; version policy mong muốn của tenant-a (admin
policy-apply — có version desired); group `ui-<run>` chứa Admin (API của P4-T09).

  E2E-114 Soạn → validate → sửa → duyệt → áp dụng qua SPA: tag khai báo ở trang Tags; bản nháp mới; HuJSON thiếu grants
          ⇒ L1 hiện (bộ dịch phía server, không lưu); `*` ở dst ⇒ validate chặn L4 (draft); sửa bằng HuJSON có chú thích
          (group, e-mail của Admin, tag) ⇒ form ⇒ lưu ⇒ validate đạt, CheckPolicy Headscale thật chấp nhận; gửi duyệt;
          Owner duyệt (peer) và áp dụng ⇒ job policy.apply succeeded; DB: version peer, người soạn/gửi = Admin, người
          duyệt = Owner, lần áp manual applied; sha256 SPA hiển thị = applied_sha256 = sha256 của chuỗi Headscale giữ
          (đọc lại khớp); Headscale có group với mg-<membership Admin>@ (không e-mail), tag trong tagOwners owner rỗng;
          TCP a1→a2:8000 thông (grant thực thi); import không tạo version
  E2E-115 4-eyes: người soạn/gửi không có nút Duyệt (SPA) và ép gọi approve ⇒ 403 (server quyết định); audit
          policy.approved review_mode peer; apply của Owner qua step-up (auth_time mới) ⇒ 202
  E2E-116 Đồng thời + rollback (4-eyes tắt): hai bản nháp cùng gốc; B (deny-all) tự xác nhận + áp dụng; C bị "tab khác"
          sửa ⇒ lưu với revision cũ ⇒ 412 (SPA báo, tải lại); C áp dụng ⇒ 409 stale_base (SPA giải thích) ⇒ "tạo bản
          nháp mới từ nội dung này" có cha = B; rollback về A ⇒ version mới rollback_of A, phê duyệt kế thừa, job
          succeeded, sha đọc lại khớp, TCP thông lại; xóa tag còn tham chiếu ⇒ 409 (SPA hiện số lượng)

Thư viện chuẩn. Mật khẩu, TOTP, cookie, CSRF token chỉ nằm trong tiến trình này (và tập redaction).
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import secrets
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import backend  # noqa: E402
import checks  # noqa: E402
from backend import psql  # noqa: E402
from dualcontrol import owner_session, psql_one, tenant_id  # noqa: E402
from lifecycle import _tcp_a1_a2, admin_session  # noqa: E402
from phase3 import policy_apply  # noqa: E402
from platformui import NODE_IMAGE, Proxy  # noqa: E402
from stack import ROOT, Stack, StackError, log  # noqa: E402

SLUG = "tenant-a"
UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"


def _stored(st: Stack) -> str:
    got = st.headscale(SLUG, "policy", "get", check=False).stdout
    return got[:-1] if got.endswith("\n") else got


def prepare(st: Stack, run: str) -> dict:
    state = json.loads((st.work / "state" / "backend.json").read_text(encoding="utf-8"))
    pre = checks.Results(st)
    backend.check_ready(pre, st, state)
    if not tenant_id(st, SLUG):      # lượt đầu trên stack này (E2E-20/21 không chạy lại được: adopt đã xong)
        backend.check_idp_bootstrap(pre, st)
        backend.check_registry(pre, st, state)
    if pre.failed:
        raise StackError("chuẩn bị (E2E-17/20/21) thất bại: " + "; ".join(x["id"] for x in pre.rows if x["result"] != "PASS"))
    base = (ROOT / "infrastructure" / "headscale" / "templates" / "bootstrap-policy.hujson").read_text(encoding="utf-8")
    code, out, _ = policy_apply(st, base, "--trigger", "bootstrap")
    if code != 0:
        raise StackError(f"chuẩn bị: policy-apply {code} {out}")
    a_id = tenant_id(st, SLUG)
    b_admin, s_admin = admin_session(st)
    b_owner, s_owner, _ = owner_session(st, SLUG)
    me = psql_one(st, f"SELECT id FROM tenant_memberships WHERE tenant_id = '{a_id}' AND identity_id = "
                      f"'{s_admin['principal']['identity_id']}'")
    group = f"ui-{run}"
    hdr = {"Origin": f"https://app.{st.domain}", "X-CSRF-Token": s_admin["csrf_token"], "Content-Type": "application/json"}
    api = f"https://app.{st.domain}/api/v1/tenants/{a_id}"
    g = b_admin.request("POST", f"{api}/groups", json.dumps({"name": group}).encode(),
                        {**hdr, "Idempotency-Key": "e2e-ui-" + secrets.token_hex(6)})
    gid = g.json().get("id") if g.status == 201 else None
    gm = b_admin.request("PUT", f"{api}/groups/{gid}/members", json.dumps({"membership_ids": [me]}).encode(),
                         {**hdr, "If-Match": g.header("ETag") or ""})
    if g.status != 201 or gm.status != 200:
        raise StackError(f"chuẩn bị: POST groups {g.status}, PUT members {gm.status}")
    # chờ policy.apply (group_change) của bước dựng bảng xong (debounce §13.5 — như E2E-96)
    end = time.time() + 150
    while time.time() < end and psql_one(st, "SELECT count(*) FROM provisioning_jobs WHERE tenant_id = "
                                             f"'{a_id}' AND kind = 'policy.apply' AND status IN ('queued', 'running')") != "0":
        time.sleep(1)
    four = psql_one(st, f"SELECT coalesce(settings -> 'policy' -> 'four_eyes', 'null'::jsonb)::text FROM tenants WHERE id = '{a_id}'")
    log(f"chuẩn bị xong: tenant-a {a_id}, group {group}, four_eyes trước {four}")
    return {"a_id": a_id, "admin": (b_admin, s_admin), "owner": (b_owner, s_owner), "me": me, "group": group,
            "four_before": four}


def set_four_eyes(st: Stack, a_id: str, value: str) -> None:
    psql(st, f"UPDATE tenants SET settings = jsonb_set(coalesce(settings, '{{}}'::jsonb), '{{policy}}', "
             f"coalesce(settings -> 'policy', '{{}}'::jsonb) || jsonb_build_object('four_eyes', '{value}'::jsonb)) "
             f"WHERE id = '{a_id}'")


def restore_four_eyes(st: Stack, a_id: str, before: str) -> None:
    if before == "null":
        psql(st, f"UPDATE tenants SET settings = settings #- '{{policy,four_eyes}}' WHERE id = '{a_id}'")
    else:
        set_four_eyes(st, a_id, before)


def run_live(st: Stack, admin: Proxy, owner: Proxy, prep: dict, run: str, phase: str) -> tuple[dict, dict, str]:
    nm = os.environ.get("WEB_NODE_MODULES", "")
    if not nm or not pathlib.Path(nm, "vitest").exists():
        raise StackError("WEB_NODE_MODULES phải trỏ tới node_modules đã cài của apps/web (npm ci)")
    out = st.out / "policyui"
    out.mkdir(parents=True, exist_ok=True)
    os.chmod(out, 0o777)
    cmd = [*st.docker_cmd, "run", "--rm", "--network", "host", "-u", f"{os.getuid()}:{os.getgid()}", "-e", "HOME=/tmp",
           "-e", f"MG_LIVE_ADMIN={admin.url}", "-e", f"MG_LIVE_OWNER={owner.url}", "-e", f"MG_LIVE_TENANT_A={prep['a_id']}",
           "-e", f"MG_LIVE_GROUP={prep['group']}", "-e", f"MG_LIVE_RUN={run}", "-e", f"MG_LIVE_PHASE={phase}",
           "-e", "MG_LIVE_OUT=/out/live.json",
           "-v", f"{ROOT}:/src", "-v", f"{nm}:/src/apps/web/node_modules", "-v", f"{out}:/out", "-w", "/src/apps/web",
           NODE_IMAGE, "npx", "vitest", "run", "--reporter=verbose", "src/live/policy.live.test.tsx"]
    t0 = time.time()
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=1800, check=False)
    text = re.sub(r"\x1b\[[0-9;]*m", "", p.stdout + p.stderr)
    (out / f"vitest-{phase}.log").write_text(st.redact(text), encoding="utf-8")
    facts = json.loads((out / "live.json").read_text(encoding="utf-8")) if (out / "live.json").exists() else {}
    names = ("UI-10", "UI-11", "UI-12") if phase == "a" else ("UI-13",)
    cases = {c: bool(re.search(rf"^\s*✓ .*{c} ", text, re.M)) for c in names}
    return facts, cases, f"pha {phase}: vitest exit {p.returncode} sau {time.time() - t0:.0f} s, {sum(cases.values())}/{len(names)} ca"


def _version(st: Stack, vid: str) -> dict:
    rows = psql(st, "SELECT state, kind, coalesce(review_mode, ''), coalesce(created_by::text, ''), "
                    "coalesce(submitted_by::text, ''), coalesce(approved_by::text, ''), coalesce(parent_version_id::text, ''), "
                    f"coalesce(rollback_of::text, ''), revision, content_sha256 FROM policy_versions WHERE id = '{vid}'")
    if not rows:
        return {}
    r = rows[0]
    return {"state": r[0], "kind": r[1], "review_mode": r[2], "created_by": r[3], "submitted_by": r[4], "approved_by": r[5],
            "parent": r[6], "rollback_of": r[7], "revision": int(r[8]), "content_sha256": r[9]}


def _applications(st: Stack, vid: str) -> list:
    return psql(st, "SELECT trigger, state, applied_sha256 FROM policy_applications WHERE "
                    f"policy_version_id = '{vid}' ORDER BY created_at, id")


def ok_uuid(x) -> bool:
    return bool(re.fullmatch(UUID, str(x or "")))


def check_compose(st: Stack, facts: dict, cases: dict, summary: str, prep: dict,
                  admin: Proxy, owner: Proxy) -> None:
    a_id, vid = prep["a_id"], facts.get("version_a")
    admin_ident, owner_ident = prep["admin"][1]["principal"]["identity_id"], prep["owner"][1]["principal"]["identity_id"]
    v = _version(st, vid) if ok_uuid(vid) else {}
    apps = _applications(st, vid) if ok_uuid(vid) else []
    manual = [a for a in apps if a[0] == "manual"]
    seen = admin.seen + owner.seen
    imports = [x for x in seen if x[0] == "POST" and x[1].endswith("/policies/import")]
    creates = [x for x in seen if x[0] == "POST" and x[1].endswith(f"/tenants/{a_id}/policies") and x[2] == 201]
    tag = facts.get("tag", "")
    ok = (cases.get("UI-10") and cases.get("UI-11") and cases.get("UI-12")
          and facts.get("l1_seen") == "missing_grants" and facts.get("l4_seen") == "wildcard_destination_ack_required"
          and v.get("review_mode") == "peer" and v.get("created_by") == admin_ident and v.get("submitted_by") == admin_ident
          and v.get("approved_by") == owner_ident and manual and manual[-1][1] == "applied"
          and manual[-1][2] == facts.get("applied_sha_a") and facts.get("apply_status") == "succeeded"
          and len(imports) >= 3 and all(x[2] == 200 for x in imports) and len(creates) == 1
          and re.fullmatch(r"tag:ui-[0-9a-f]{6}", tag))
    prep["case114"] = {"ok": bool(ok), "detail": f"{summary}; version {v}; lần áp manual {manual}; sha SPA "
                       f"{str(facts.get('applied_sha_a'))[:12]}; import {[(x[2]) for x in imports]}; tạo version {len(creates)}; "
                       f"L1 {facts.get('l1_seen')}, L4 {facts.get('l4_seen')}; tag {tag}"}


def check_after_a(r: checks.Results, st: Stack, facts: dict, prep: dict) -> None:
    """Ngay sau pha a: chuỗi Headscale giữ, read-back, TCP — trước khi pha b đổi policy."""
    stored = _stored(st)
    sha = hashlib.sha256(stored.encode("utf-8")).hexdigest()
    try:
        doc = json.loads(stored)
    except ValueError:
        doc = {}
    me_tok = f"mg-{prep['me']}@"
    group_ok = doc.get("groups", {}).get(f"group:{prep['group']}") == [me_tok]
    tag_ok = doc.get("tagOwners", {}).get(facts.get("tag", "")) == []
    no_email = "@example" not in stored
    a1 = checks.wait_peer_count(st, "a1", 1, 90)
    answer, control = _tcp_a1_a2(st)
    c = prep["case114"]
    ok = (c["ok"] and sha == facts.get("applied_sha_a") and group_ok and tag_ok and no_email and a1 is not None
          and answer.endswith("a2 tcp/8000"))
    r.add("E2E-114", "P4-T11: soạn → validate → sửa → duyệt → áp dụng qua SPA (Tags: khai báo; HuJSON thiếu grants ⇒ L1; * ở "
          "dst ⇒ L4 chặn; sửa bằng HuJSON có chú thích ⇒ form ⇒ lưu ⇒ validate + CheckPolicy đạt; gửi duyệt; Owner duyệt "
          "peer + áp dụng ⇒ job succeeded); sha SPA = applied_sha256 = Headscale (read-back); group mg-<membership>@, tag "
          "owner rỗng, không e-mail; TCP a1→a2:8000; import không tạo version", ok,
          f"{c['detail']}; Headscale sha {sha[:12]} = SPA {sha == facts.get('applied_sha_a')}; group {group_ok}, tagOwners "
          f"{tag_ok}, không e-mail {no_email}; a1 peers {len(checks.peers(a1)) if a1 else '?'}, tcp {answer or 'không'} "
          f"(control {control or 'không listener'})", limit=1200)


def check_four_eyes(r: checks.Results, st: Stack, facts: dict, prep: dict, owner: Proxy) -> None:
    vid = facts.get("version_a", "")
    forced = facts.get("author_forced_approve") or {}
    audit = psql_one(st, "SELECT string_agg(details ->> 'review_mode', ',') FROM audit_events WHERE action = 'policy.approved' "
                         f"AND resource_id = '{vid}' AND outcome = 'success'") if ok_uuid(vid) else ""
    applies = [x for x in owner.seen if x[0] == "POST" and x[1].endswith(f"/policies/{vid}/apply")]
    ok = (facts.get("author_has_approve_button") is False and forced.get("status") == 403 and forced.get("code") == "forbidden"
          and audit == "peer" and applies and applies[-1][2] == 202 and bool(facts.get("approved_by_shown")))
    r.add("E2E-115", "P4-T11: 4-eyes qua SPA — người soạn/gửi không có nút Duyệt, ép gọi approve ⇒ 403 (server quyết "
          "định); Owner duyệt ⇒ audit policy.approved review_mode peer; apply của Owner qua step-up ⇒ 202", bool(ok),
          f"nút Duyệt của người soạn {facts.get('author_has_approve_button')}; ép approve {forced}; audit {audit}; apply "
          f"{[x[2] for x in applies]}; người duyệt hiển thị {str(facts.get('approved_by_shown'))[:60]}", limit=900)


def check_concurrency(r: checks.Results, st: Stack, facts: dict, cases: dict, summary: str, prep: dict, admin: Proxy) -> None:
    b, c, d, rb, a = (facts.get(k, "") for k in ("version_b", "version_c", "version_d", "rollback_version", "version_a"))
    vb, vc, vd, vr = (_version(st, x) if ok_uuid(x) else {} for x in (b, c, d, rb))
    patches_c = [x[2] for x in admin.seen if x[0] == "PATCH" and x[1].endswith(f"/policies/{c}")]
    applies_c = [x[2] for x in admin.seen if x[0] == "POST" and x[1].endswith(f"/policies/{c}/apply")]
    deletes = [x[2] for x in admin.seen if x[0] == "DELETE" and "/tags/" in x[1]]
    app_b = _applications(st, b) if ok_uuid(b) else []
    app_r = _applications(st, rb) if ok_uuid(rb) else []
    stored = _stored(st)
    sha = hashlib.sha256(stored.encode("utf-8")).hexdigest()
    a1 = checks.wait_peer_count(st, "a1", 1, 90)
    answer, _ = _tcp_a1_a2(st)
    problem = str(facts.get("tag_delete_problem", ""))
    ok = (cases.get("UI-13") and vb.get("review_mode") == "self" and app_b and app_b[-1][:2] == ["manual", "applied"]
          and vc.get("parent") == vb.get("parent") and vc.get("revision", 0) >= 2 and 412 in patches_c and 200 in patches_c
          and facts.get("stale_412_seen") is True and applies_c == [409] and facts.get("stale_base_seen") is True
          and vd.get("parent") == b and vd.get("state") == "draft"
          and vr.get("rollback_of") == a and vr.get("state") == "approved" and app_r and app_r[-1][:2] == ["rollback", "applied"]
          and app_r[-1][2] == sha == facts.get("applied_sha_rollback") and facts.get("rollback_status") == "succeeded"
          and a1 is not None and answer.endswith("a2 tcp/8000") and deletes == [409] and re.search(r"\d+ policy version", problem))
    r.add("E2E-116", "P4-T11: đồng thời + rollback qua SPA (4-eyes tắt) — hai bản nháp cùng gốc; B deny-all tự xác nhận + "
          "áp dụng; C sửa với revision cũ ⇒ 412 (tải lại); C áp dụng ⇒ 409 stale_base ⇒ bản nháp mới có cha = B; rollback "
          "về A ⇒ rollback_of A, phê duyệt kế thừa, job succeeded, sha đọc lại khớp, TCP thông lại; xóa tag còn tham chiếu "
          "⇒ 409 kèm số lượng", bool(ok),
          f"{summary}; B {vb.get('review_mode')} {app_b[-1][:2] if app_b else None}; C rev {vc.get('revision')} PATCH {patches_c} "
          f"apply {applies_c}; D cha=B {vd.get('parent') == b}; rollback {vr.get('rollback_of') == a} {vr.get('state')} "
          f"{app_r[-1][:2] if app_r else None}, sha Headscale = applied = SPA {bool(app_r) and app_r[-1][2] == sha == facts.get('applied_sha_rollback')}; "
          f"tcp {answer or 'không'}; DELETE tag {deletes}: {problem[:160]}", limit=1200)


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    st = Stack()
    st.users = {}
    r = checks.Results(st)
    proxies: list[Proxy] = []
    error, prep = None, {}
    run = secrets.token_hex(3)
    try:
        prep = prepare(st, run)
        admin = Proxy(st, prep["admin"][0], "admin")
        owner = Proxy(st, prep["owner"][0], "owner")
        for p in (admin, owner):
            p.host = f"app.{st.domain}"     # Tenant Portal (platformui.Proxy mặc định admin.)
        proxies = [admin, owner]
        (st.out / "policyui").mkdir(parents=True, exist_ok=True)
        (st.out / "policyui" / "live.json").unlink(missing_ok=True)
        set_four_eyes(st, prep["a_id"], "true")
        facts, cases, summary = run_live(st, admin, owner, prep, run, "a")
        check_compose(st, facts, cases, summary, prep, admin, owner)
        check_after_a(r, st, facts, prep)
        check_four_eyes(r, st, facts, prep, owner)
        set_four_eyes(st, prep["a_id"], "false")
        facts, cases, summary = run_live(st, admin, owner, prep, run, "b")
        check_concurrency(r, st, facts, cases, summary, prep, admin)
    except (StackError, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as e:
        error = f"{type(e).__name__}: {st.redact(str(e))[-1500:]}"
        log("LỖI: " + error)
    finally:
        for p in proxies:
            p.close()
        if prep.get("a_id"):
            restore_four_eyes(st, prep["a_id"], prep.get("four_before", "null"))
    log_texts = "".join((st.out / "policyui" / f"vitest-{ph}.log").read_text(encoding="utf-8")
                        for ph in ("a", "b") if (st.out / "policyui" / f"vitest-{ph}.log").exists())
    leaked = sum(1 for v in st.secret_values if v and len(v) >= 8 and v in log_texts)
    (st.out / "policyui" / "requests.txt").write_text(
        "\n".join(f"{p.name} {m} {path} {s}" for p in proxies for (m, path, s, _) in p.seen) + "\n", encoding="utf-8")
    lines = [f"{x['result']:4} {x['id']:8} [{x['label']}] {x['name']}\n{'':14}{x['detail']}" for x in r.rows]
    passed = sum(x["result"] == "PASS" for x in r.rows)
    text = ("\n".join(lines) + f"\n\n{passed}/{len(r.rows)} ca PASS (functional); secret lộ trong log vitest: {leaked}"
            + (f"\nLỖI: {error}" if error else "") + "\n")
    (st.out / "policyui" / "summary.txt").write_text(text, encoding="utf-8")
    print(text, flush=True)
    return 1 if error or r.failed or len(r.rows) != 3 or leaked else 0


if __name__ == "__main__":
    sys.exit(main())
