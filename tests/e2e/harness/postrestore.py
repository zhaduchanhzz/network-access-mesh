"""P3-T17 — maintenance mode and the reconcile after PostgreSQL was restored to an OLDER point, on the dev/CI stack —
FUNCTIONAL only (§22.1): the api and worker built from the tree, real Keycloak logins with TOTP through the edge, the
real Headscale of tenant-a and tenant-b behind the edge admin listener, a real pg_dump / pg_restore of the stack's
PostgreSQL. The stack has no Host Agent (its tenants are compose services, not agent-managed): the inventory of the host
and the re-issue of an API key through BootstrapApiKey are reported incomplete here — E2E-72 runs them with the real
agent (tests/integration/provisioning, make provisioning-it).

  E2E-70  maintenance mode: `meshguard admin maintenance on` (api, compose run) ⇒ within one poll the api answers 503
          maintenance (problem+json, Retry-After) on app. and admin. — a Super Admin's session included — while the
          platform sign-in on admin. is still served; the worker stops its job worker and schedules (log) and runs no job;
          `maintenance off` ⇒ served again, the worker starts them again; audit platform.maintenance.enable/.disable
  E2E-71  the restore runbook (docs/operations/backup-restore.md §6.3, §6.5): sessions, a pending approval request and a
          pending invitation exist ⇒ pg_dump ⇒ in the gap: the session logged out, a new one opened, a tenant created
          (POST /platform/tenants), tenant-b's API key rotated, a newer policy applied to tenant-a ⇒ maintenance on, api
          and worker stopped, the database renamed and the dump restored (pg_restore --create), api and worker started
          with the startup switch MG_MAINTENANCE=1 (compose.app.maintenance.yaml — the restored database holds no flag):
          503 ⇒ `post-restore-reconcile --dry-run` changes nothing ⇒ the run: no session or grant of the dump valid (the
          logged-out session's cookie ⇒ 401, the gap's ⇒ 401), approvals and invitations closed, the gap's tenant absent
          and not adopted, inventory reported unavailable (no agent), tenant-b's key refused ⇒ reported not re-issued
          (agent_not_configured) ⇒ repaired with the documented fallback (adopt-instance with a CLI key) and the command
          run again (key ok), tenant-a's newer policy NOT overwritten (recorded, validated version desired, flagged),
          audit.gap written, inventory.sync queued while in maintenance ⇒ api and worker recreated WITHOUT the switch:
          still 503 (the flag the reconcile persisted) ⇒ `maintenance off` ⇒ served, the queued syncs run

Standard library only. Passwords, TOTP keys, cookies, CSRF tokens and API keys stay in this process (and its
redaction set).
"""
from __future__ import annotations

import hashlib
import json
import secrets
import time

from backend import Browser, admin_cmd, container, psql
from dualcontrol import owner_session, psql_one, tenant_id, unsafe
from idpadmin import admin_unsafe, platform_session, request_session
from phase3 import apikey_rotate, policy_apply, stored_sha
from stack import ROOT, Stack, StackError, log

DUMP = "/tmp/e2e71.dump"


def _maintenance(st: Stack, *args: str) -> tuple[int, dict, str]:
    p = admin_cmd(st, ["maintenance", *args])
    out = {}
    for line in p.stdout.splitlines():
        if line.startswith("{"):
            out = json.loads(line)
    return p.returncode, out, st.redact(p.stderr)


def _wait_status(b: Browser, url: str, want: int, timeout: float = 30) -> int:
    end, got = time.time() + timeout, 0
    while time.time() < end:
        got = b.get(url).status
        if got == want:
            return got
        time.sleep(1)
    return got


def _worker_logs(st: Stack, since: str) -> str:
    return st.docker("logs", "--since", since, container(st, "worker"), check=False).stdout


def _reconcile(st: Stack, restore_point: str, *extra: str) -> tuple[int, dict, str]:
    """`meshguard admin post-restore-reconcile` inside the running worker (the report is the JSON document on stdout)."""
    p = st.docker("exec", container(st, "worker"), "/usr/local/bin/meshguard", "admin", "post-restore-reconcile",
                  "--restore-point", restore_point, *extra, check=False, timeout=600)
    try:
        rep = json.loads(p.stdout or "{}")
    except ValueError:
        rep = {}
    return p.returncode, rep, st.redact(p.stderr)


def _compose_with_override(st: Stack, *args: str):
    """docker compose of the stack plus the startup switch infrastructure/compose/compose.app.maintenance.yaml."""
    override = ROOT / "infrastructure" / "compose" / "compose.app.maintenance.yaml"
    return st.docker("compose", "-p", st.prefix, "--project-directory", str(ROOT), "--env-file", str(st.work / "stack.env"),
                     *st.compose_files(), "-f", str(override), *args, timeout=300)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------------------------------- E2E-70
def check_maintenance(r, st: Stack, state: dict) -> None:
    sa = getattr(st, "platform_sa", None)
    if not sa:
        raise StackError("no Super Admin of E2E-24 (st.platform_sa)")
    rows, conds = [], []

    def cond(name: str, good: bool, row: str) -> None:
        conds.append((name, good))
        rows.append(f"[{'ok' if good else 'FAIL'} {name}] {row}")

    app, admin = f"https://app.{st.domain}/api/v1", f"https://admin.{st.domain}/api/v1"
    b, sess = platform_session(st, sa)
    state["sa_browser"], state["sa_session"] = b, sess
    t0 = psql_one(st, "SELECT now()")
    code, out, err = _maintenance(st, "status")
    cond("status_off", code == 0 and out.get("enabled") is False, f"status: exit {code} {out} {err[-120:]}")
    since = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 1))
    code, out, err = _maintenance(st, "on", "--reason", "e2e-70")
    cond("on", code == 0 and out.get("enabled") is True and out.get("changed") is True and out.get("reason") == "e2e-70",
         f"on: exit {code} {out} {err[-120:]}")
    anon = Browser(st)
    tenants = _wait_status(anon, f"{app}/tenants", 503)
    resp = anon.get(f"{app}/tenants")
    platform = b.get(f"{admin}/platform/tenants")
    session = Browser(st).get(f"{admin}/auth/session").status
    cond("api_503", tenants == 503 and resp.json().get("code") == "maintenance" and resp.header("Retry-After") == "60"
         and platform.status == 503 and platform.json().get("code") == "maintenance",
         f"app GET /tenants {tenants} {resp.json().get('code')} Retry-After {resp.header('Retry-After')}; Super Admin GET "
         f"/platform/tenants {platform.status} {platform.json().get('code')}")
    b2, _ = platform_session(st, sa)          # the platform sign-in still works
    cond("sign_in_served", session == 401 and b2.get(f"{admin}/auth/session").status == 200,
         f"admin GET /auth/session without a session {session}; a new platform sign-in during maintenance ⇒ session 200")
    deadline, logs = time.time() + 30, ""
    while time.time() < deadline:
        logs = _worker_logs(st, since)
        if "stopping the job worker and the schedules" in logs:
            break
        time.sleep(1)
    t_on = psql_one(st, "SELECT now()")
    time.sleep(12)
    started = psql_one(st, f"SELECT count(*) FROM provisioning_jobs WHERE started_at > '{t_on}'")
    cond("worker_idle", "stopping the job worker and the schedules" in logs and started == "0",
         f"worker log stop notice {'present' if 'stopping the job worker' in logs else 'MISSING'}; jobs started in 12 s of "
         f"maintenance: {started}")
    code, out, err = _maintenance(st, "off")
    cond("off", code == 0 and out.get("enabled") is False and out.get("changed") is True, f"off: exit {code} {out}")
    after = _wait_status(anon, f"{app}/tenants", 401)
    served = b.get(f"{admin}/platform/tenants").status
    deadline = time.time() + 30
    while time.time() < deadline and "job worker and schedules started" not in _worker_logs(st, since):
        time.sleep(1)
    cond("served_again", after == 401 and served == 200 and "job worker and schedules started" in _worker_logs(st, since),
         f"after off: app GET /tenants {after} (no session), Super Admin GET /platform/tenants {served}; worker restarted its "
         "job worker")
    audit = psql_one(st, "SELECT string_agg(action || ':' || actor_type, ',' ORDER BY occurred_at) FROM audit_events WHERE "
                         f"resource_id = 'maintenance' AND action LIKE 'platform.maintenance.%' AND occurred_at > '{t0}'")
    cond("audited", audit == "platform.maintenance.enable:system,platform.maintenance.disable:system", f"audit {audit}")
    failed = [n for n, good in conds if not good]
    for row in rows:
        log(f"  E2E-70 {st.redact(row)}")
    r.add("E2E-70", "P3-T17 chế độ bảo trì: `admin maintenance on` ⇒ api 503 maintenance (Retry-After) cả với phiên Super "
          "Admin, đăng nhập platform trên admin. vẫn được phục vụ; worker dừng job worker + lịch, không job nào chạy; `off` "
          "⇒ phục vụ lại, worker chạy lại; audit platform.maintenance.enable/.disable (system)", not failed,
          (f"FAILED: {', '.join(failed)} — " if failed else "") + "; ".join(rows), limit=2500)


# ---------------------------------------------------------------------------------------------------- E2E-71
def check_post_restore(r, st: Stack, state: dict) -> None:
    sa = getattr(st, "platform_sa", None)
    if not sa:
        raise StackError("no Super Admin of E2E-24 (st.platform_sa)")
    rows, conds = [], []

    def cond(name: str, good: bool, row: str) -> None:
        conds.append((name, good))
        rows.append(f"[{'ok' if good else 'FAIL'} {name}] {row}")

    admin = f"https://admin.{st.domain}/api/v1"
    a_id, b_id = tenant_id(st, "tenant-a"), tenant_id(st, "tenant-b")
    # --- what the dump holds: a Super Admin session, a pending console request, a pending invitation of tenant-a
    b1, s1 = platform_session(st, sa)
    pending = request_session(st, b1, s1, {"reason": "E2E-71 pending", "duration_minutes": 10},
                              "e2e71-" + secrets.token_hex(6)).json()
    ob, osess, _ = owner_session(st, "tenant-a")
    inv_email = f"e2e71-{secrets.token_hex(3)}@example.invalid"
    inv = ob.request("POST", f"https://app.{st.domain}/api/v1/tenants/{a_id}/invitations",
                     json.dumps({"email": inv_email, "role": "tenant_viewer"}).encode(),
                     unsafe(st, osess, **{"Idempotency-Key": "e2e71-" + secrets.token_hex(6)})).json()
    grants = psql_one(st, "SELECT count(*) FROM approval_requests WHERE action = 'platform.idp.console_session' AND "
                          "status = 'executed' AND decided_at > now() - interval '61 minutes'")
    live = psql_one(st, "SELECT count(*) FROM sessions WHERE revoked_at IS NULL")
    cond("dump_content", pending.get("status") == "pending" and inv.get("status") == "pending" and int(live or 0) >= 2,
         f"before the dump: console request {pending.get('status')}, invitation {inv.get('status')}, live sessions {live}, "
         f"executed console grants of the last hour {grants}")
    # --- the dump
    rp = psql_one(st, "SELECT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')")
    time.sleep(1)
    st.exec("postgres", "pg_dump", "-U", "postgres", "-Fc", "-d", "meshguard", "-f", DUMP, timeout=300)
    # --- the gap
    out_s1 = b1.request("POST", f"{admin}/auth/logout", b"", {"Origin": f"https://admin.{st.domain}",
                                                               "X-CSRF-Token": s1["csrf_token"]}).status
    b2, s2 = platform_session(st, sa)
    slug = "e2e71-" + secrets.token_hex(3)
    created = b2.request("POST", f"{admin}/platform/tenants", json.dumps({
        "slug": slug, "name": "E2E-71 gap tenant", "plan_key": "standard", "owner_email": f"owner@{slug}.example.test",
        "identity_provider": {"driver": "keycloak"}, "settings": {"dns": {"magic_dns": True}}}).encode(),
        admin_unsafe(st, s2, **{"Idempotency-Key": "e2e71-" + secrets.token_hex(6)})).status
    rcode, rot, _ = apikey_rotate(st, "--force")
    allow = (ROOT / "infrastructure" / "headscale" / "templates" / "test-allow-intra.hujson").read_text(encoding="utf-8")
    pcode, pout, _ = policy_apply(st, allow)
    newer = stored_sha(st)
    cond("gap", out_s1 == 200 and created == 202 and rcode == 0 and rot.get("outcome") == "rotated" and pcode == 0
         and newer == pout.get("applied_sha256"),
         f"in the gap: logout {out_s1}, new session, POST /platform/tenants {created} ({slug}), tenant-b key "
         f"{rot.get('outcome')} → {rot.get('key_prefix')}, tenant-a policy {pout.get('state')} {newer[:12]}…")
    # --- the restore (runbook §6.3/§6.5): maintenance on, stop, rename, pg_restore --create, start with the STARTUP
    #     switch (compose.app.maintenance.yaml — the restored database holds no flag), reconcile, start without it
    _maintenance(st, "on", "--reason", "pg-restore")
    st.compose("stop", "api", "worker", timeout=180)
    st.exec("postgres", "psql", "-U", "postgres", "-d", "postgres", "-v", "ON_ERROR_STOP=1",
            "-c", "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'meshguard' AND pid <> pg_backend_pid()",
            "-c", f"ALTER DATABASE meshguard RENAME TO meshguard_before_e2e71_{int(time.time())}")
    st.exec("postgres", "pg_restore", "-U", "postgres", "-d", "postgres", "--create", "--exit-on-error", DUMP, timeout=300)
    st.exec("postgres", "rm", "-f", DUMP)
    _compose_with_override(st, "up", "-d", "--wait", "--wait-timeout", "240", "api", "worker")
    blocked = Browser(st).get(f"https://app.{st.domain}/api/v1/tenants")
    fcode, fout, _ = _maintenance(st, "status")
    env = st.docker("inspect", "-f", "{{range .Config.Env}}{{println .}}{{end}}", container(st, "api")).stdout
    cond("restored_in_maintenance", blocked.status == 503 and blocked.json().get("code") == "maintenance"
         and fcode == 0 and fout.get("enabled") is False and "MG_MAINTENANCE=1" in env.splitlines()
         and psql_one(st, f"SELECT count(*) FROM tenants WHERE slug = '{slug}'") == "0",
         f"restored and started with MG_MAINTENANCE=1 (override file): api {blocked.status} {blocked.json().get('code')}, "
         f"persisted flag of the restored db enabled={fout.get('enabled')}; the gap's tenant is not in the registry")
    # --- dry run: nothing changes
    digest_sql = ("SELECT (SELECT count(*) FROM sessions WHERE revoked_at IS NULL) || '|' || (SELECT count(*) FROM "
                  "approval_requests WHERE status IN ('pending','approved')) || '|' || (SELECT count(*) FROM tenant_invitations "
                  "WHERE status = 'pending') || '|' || (SELECT count(*) FROM audit_events) || '|' || (SELECT count(*) FROM "
                  "provisioning_jobs)")
    before = psql_one(st, digest_sql)
    dcode, dry, derr = _reconcile(st, rp, "--dry-run")
    keys_dry = {k.get("slug"): k.get("outcome") for k in dry.get("api_keys") or []}
    cond("dry_run", dcode == 3 and dry.get("dry_run") is True and psql_one(st, digest_sql) == before and stored_sha(st) == newer
         and keys_dry.get("tenant-b") == "would_reissue" and keys_dry.get("tenant-a") == "ok",
         f"dry run: exit {dcode}, state {before} → {psql_one(st, digest_sql)}, keys {keys_dry} {derr[-150:]}")
    # --- the run
    code, rep, err = _reconcile(st, rp)
    keys = {k.get("slug"): k for k in rep.get("api_keys") or []}
    pols = {p.get("tenant_id"): p for p in rep.get("policies") or []}
    incomplete = rep.get("incomplete") or []
    cond("incomplete_without_agent", code == 3 and rep.get("status") == "incomplete"
         and "instances:host:agent_not_configured" in incomplete
         and (rep.get("instances") or {}).get("inventory") == "unavailable",
         f"run: exit {code} {rep.get('status')}, incomplete {incomplete} {err[-150:]}")
    sessions = psql_one(st, f"SELECT count(*) FROM sessions WHERE revoked_at IS NULL AND created_at <= '{rep.get('started_at')}'")
    c1 = b1.get(f"{admin}/auth/session").status          # logged out in the gap, alive again in the dump
    c2 = b2.get(f"{admin}/auth/session").status          # opened in the gap: gone with the restore
    cond("no_session_valid", sessions == "0" and c1 == 401 and c2 == 401 and (rep.get("sessions") or {}).get("revoked", 0) >= 2,
         f"sessions of the dump still valid {sessions} (revoked {(rep.get('sessions') or {}).get('revoked')}); cookie of "
         f"the session logged out in the gap ⇒ {c1}, of the gap's session ⇒ {c2}")
    appr = psql_one(st, f"SELECT status FROM approval_requests WHERE id = '{pending.get('id')}'")
    open_n = psql_one(st, "SELECT count(*) FROM approval_requests WHERE status IN ('pending','approved')")
    grants_after = psql_one(st, "SELECT count(*) FROM approval_requests WHERE action = 'platform.idp.console_session' AND "
                                "status = 'executed' AND decided_at > now() - interval '61 minutes'")
    inv_after = psql_one(st, f"SELECT status FROM tenant_invitations WHERE id = '{inv.get('id')}'")
    cond("no_grant_valid", appr == "expired" and open_n == "0" and grants_after == "0" and inv_after == "revoked",
         f"console request {appr}, open approvals {open_n}, console grants in their window {grants} → {grants_after}, "
         f"invitation {inv_after}")
    kb = keys.get("tenant-b") or {}
    ka = keys.get("tenant-a") or {}
    # tenant-a's stored key works: nothing to do ("ok"), or other valid keys were found (left by an earlier case) and
    # expired by a rotation ("rotated", P3-T10 strays) — never a re-issue
    cond("key_refused_reported", kb.get("outcome") == "failed" and kb.get("error_code") == "agent_not_configured"
         and "api_key:tenant-b:agent_not_configured" in incomplete
         and (ka.get("outcome") == "ok" or (ka.get("outcome") == "rotated" and ka.get("expired_keys", 0) >= 1)),
         f"tenant-b's key (rotated in the gap): {kb.get('outcome')} {kb.get('error_code')}; tenant-a {ka.get('outcome')} "
         f"(expired {ka.get('expired_keys', 0)})")
    pa = pols.get(a_id) or {}
    current = psql(st, "SELECT a.trigger, a.applied_sha256, v.state, v.kind FROM policy_applications a JOIN tenants t ON "
                       "t.id = a.tenant_id JOIN policy_versions v ON v.id = t.desired_policy_version_id WHERE "
                       f"a.tenant_id = '{a_id}' AND a.state = 'applied' AND a.superseded_at IS NULL")
    run_id = rep.get("run_id", "")
    flagged = psql_one(st, f"SELECT count(*) FROM security_events WHERE tenant_id = '{a_id}' AND kind = "
                           f"'policy.restore_review_required' AND details ->> 'run_id' = '{run_id}'")
    cond("policy_not_overwritten", stored_sha(st) == newer and pa.get("outcome") == "adopted"
         and current == [["restore", newer, "validated", "user"]] and flagged == "1",
         f"Headscale {stored_sha(st)[:12]}… (newer {newer[:12]}…), step {pa.get('outcome')}, current application "
         f"{current}, review event {flagged}")
    gap = psql_one(st, f"SELECT count(*) FROM audit_events WHERE action = 'audit.gap' AND details ->> 'run_id' = '{run_id}'")
    expected_gap = 1 + int(psql_one(st, "SELECT count(*) FROM tenants WHERE status <> 'deleted'") or 0)
    queued = psql_one(st, "SELECT count(*) FROM provisioning_jobs j JOIN tenant_instances i ON i.id = j.instance_id "
                          "WHERE j.kind = 'inventory.sync' AND j.status = 'queued' AND j.created_at > "
                          f"'{rep.get('started_at')}'")
    cond("gap_and_sync", gap == str(expected_gap) and queued == "2",
         f"audit.gap events {gap} (platform + {expected_gap - 1} tenants); inventory.sync queued during maintenance {queued}")
    # --- the documented fallback without an agent: a CLI key handed over by adopt-instance, then the command again
    key = json.loads(st.headscale("tenant-b", "apikeys", "create", "-e", "2160h", "-o", "json").stdout)
    st.secret_values.add(key)
    meta = st.work / "render" / "tenant-b" / "meta" / "instance.json"
    p = admin_cmd(st, ["adopt-instance", "--host", "e2e-host", "/run/mg-adopt/instance.json"],
                  stdin=json.dumps(key, indent="\t") + "\n", env={"MG_IDP_ID_TENANT_B": st.env["MG_IDP_ID_TENANT_B"]},
                  mounts=[f"{meta}:/run/mg-adopt/instance.json:ro"])
    code2, rep2, _ = _reconcile(st, rp)
    keys2 = {k.get("slug"): k.get("outcome") for k in rep2.get("api_keys") or []}
    cond("rerun", p.returncode == 0 and code2 == 3 and keys2.get("tenant-b") == "ok"
         and (rep2.get("sessions") or {}).get("revoked") == 0 and (rep2.get("audit_gap") or {}).get("written") == 0,
         f"adopt-instance tenant-b exit {p.returncode}; second run exit {code2}: keys {keys2}, sessions revoked "
         f"{(rep2.get('sessions') or {}).get('revoked')}, audit.gap written {(rep2.get('audit_gap') or {}).get('written')}")
    # --- the startup switch dropped (recreated without the override): the flag the reconcile persisted keeps the api
    #     closed until `maintenance off`
    st.compose("up", "-d", "--wait", "--wait-timeout", "240", "api", "worker", timeout=300)
    env = st.docker("inspect", "-f", "{{range .Config.Env}}{{println .}}{{end}}", container(st, "api")).stdout
    still = Browser(st).get(f"https://app.{st.domain}/api/v1/tenants")
    scode, sout, _ = _maintenance(st, "status")
    pr = sout.get("post_restore") or {}
    cond("persisted_by_reconcile", "MG_MAINTENANCE=1" not in env.splitlines() and still.status == 503
         and sout.get("enabled") is True and sout.get("reason") == "post_restore" and pr.get("status") == "reconciled"
         and pr.get("runs") == 2,
         f"recreated without MG_MAINTENANCE: api {still.status}; flag {sout.get('enabled')} ({sout.get('reason')}), "
         f"post_restore {pr.get('status')} runs {pr.get('runs')}")
    # --- maintenance off ⇒ served again, the queued syncs run
    ocode, oout, _ = _maintenance(st, "off")
    served = _wait_status(Browser(st), f"https://app.{st.domain}/api/v1/tenants", 401)
    end, done = time.time() + 180, ""
    while time.time() < end:
        done = psql_one(st, "SELECT count(*) FROM provisioning_jobs WHERE kind = 'inventory.sync' AND status = 'succeeded' "
                            f"AND created_at > '{rep.get('started_at')}'")
        if done == "2":
            break
        time.sleep(3)
    cond("reopened", ocode == 0 and oout.get("enabled") is False and "incomplete" in (oout.get("note") or "")
         and served == 401 and done == "2",
         f"maintenance off: exit {ocode} note «{oout.get('note')}»; api {served}; inventory.sync succeeded {done}")
    base = (ROOT / "infrastructure" / "headscale" / "templates" / "bootstrap-policy.hujson").read_text(encoding="utf-8")
    policy_apply(st, base, "--trigger", "bootstrap")
    failed = [n for n, good in conds if not good]
    for row in rows:
        log(f"  E2E-71 {st.redact(row)}")
    r.add("E2E-71", "P3-T17 restore PostgreSQL về bản dump cũ hơn (runbook §6.3) + `post-restore-reconcile`: dry run không đổi "
          "gì; không session/grant nào của bản dump còn hiệu lực (cookie của phiên đã logout trong khoảng mất ⇒ 401), phê "
          "duyệt + lời mời đóng; tenant tạo sau dump không có trong registry (không adopt); không agent ⇒ inventory + "
          "cấp lại key báo incomplete, sửa bằng adopt-instance rồi chạy lại; policy mới hơn trên Headscale KHÔNG bị ghi "
          "đè (ghi nhận + version validated + cờ rà soát); audit.gap; inventory.sync chạy sau `maintenance off`", not failed,
          (f"FAILED: {', '.join(failed)} — " if failed else "") + "; ".join(rows), limit=4000)


def run_all(r, st: Stack, guarded) -> None:
    """E2E-70, then E2E-71 (it replaces the stack's database: it runs last)."""
    state: dict = {}
    guarded(r, "E2E-70", check_maintenance, st, state)
    guarded(r, "E2E-71", check_post_restore, st, state)
