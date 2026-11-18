"""P3-T08 suspend/resume on the dev/CI stack — FUNCTIONAL only (§22.1): the api and worker built from the tree, real
Keycloak logins with TOTP through the edge, the real Headscale of tenant-a behind the edge admin listener, two official
tailscale clients (a1, a2) and real TCP between them (never `tailscale ping` — HS-25, CL-09).

  E2E-56  allow fixture (§22.1) applied to tenant-a through the policy core (`admin policy-apply` in the worker) ⇒ a1
          sees a2 and TCP a1→a2:8000 connects; a valid reusable pre-auth key exists; then a Super Admin (admin., CSRF +
          Idempotency-Key) POST /platform/tenants/{a}/suspend ⇒ 202 + Location of the platform job; the job tenant.suspend
          succeeds with its 5 steps; the tenant is `suspended` (GET /platform/tenants/{a}); Headscale stores the
          suspension policy (deny-all) — the desired version is kept; the same request again ⇒ the same job; a second
          suspend ⇒ 409; audit platform.tenant.suspend.requested/.succeeded; tenant.suspended to the Owner and Admins
  E2E-57  during the suspension: a1 has no peer and TCP a1→a2:8000 no longer connects (the listener runs — local
          control); the Tenant Admin of tenant-a signed in before the suspension (seeded by sub, Keycloak + TOTP — its
          sync was accepted then) POST /tenants/{a}/devices/sync ⇒ 403 tenant_suspended (layer 1, audited as a denial)
          while GET /tenants/{a}/devices still answers 200; no pre-auth key
          of tenant-a is valid any more (`headscale preauthkeys list`) — the one created before included
  E2E-58  POST /platform/tenants/{a}/resume ⇒ 202; tenant.resume succeeds (4 steps); the tenant is `active`; Headscale
          stores the desired version again (the allow fixture — no new version); a1 sees a2 and TCP a1→a2:8000 connects
          again; the Tenant Admin's sync ⇒ 202; a second resume ⇒ 409; audit .requested/.succeeded; tenant.resumed. The
          case ends with the deny-all baseline applied again (as E2E-36), the pre-auth keys stay expired.

Standard library only. Passwords, TOTP keys, cookies, CSRF tokens and pre-auth keys stay in this process (and its
redaction set).
"""
from __future__ import annotations

import hashlib
import json
import secrets
import time

import checks
from backend import TOTP, Browser, admin_cmd, portal_login, psql
from dualcontrol import new_user, psql_one, tenant_id
from idpadmin import platform_session
from phase3 import policy_apply, stored_sha
from stack import ROOT, Stack, StackError, log

SLUG = "tenant-a"
# the canonical string the policy core sends for the suspension template (comments dropped, re-indented — P3-T08a)
SUSPENSION = '{\n  "grants": [],\n  "ssh": []\n}'


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _platform_headers(st: Stack, sess: dict, key: str) -> dict:
    return {"Origin": f"https://admin.{st.domain}", "X-CSRF-Token": sess["csrf_token"], "Idempotency-Key": key}


def _tenant_headers(st: Stack, sess: dict, key: str) -> dict:
    return {"Origin": f"https://app.{st.domain}", "X-CSRF-Token": sess["csrf_token"], "Idempotency-Key": key}


def _wait_job(b: Browser, api: str, job: str, timeout: float = 180) -> dict:
    """GET /platform/jobs/{id} until the job is finished (or the timeout); returns the last view."""
    end, doc = time.time() + timeout, {}
    while time.time() < end:
        r = b.get(f"{api}/platform/jobs/{job}")
        doc = r.json() if r.status == 200 else {"status": f"HTTP {r.status}"}
        if doc.get("status") in ("succeeded", "failed", "failed_resumable", "rolled_back", "cancelled"):
            return doc
        time.sleep(2)
    return doc


def _steps(doc: dict) -> list[tuple[str, str]]:
    return [(s.get("name"), s.get("status")) for s in doc.get("steps") or []]


def valid_preauth_keys(st: Stack) -> list[int]:
    """IDs of tenant-a's pre-auth keys that can still register a node: not expired (no expiration = valid) and
    reusable or unused — `headscale preauthkeys list -o json` (every user; expiration {seconds, nanos})."""
    now = time.time()
    out = []
    for k in json.loads(st.headscale(SLUG, "preauthkeys", "list", "-o", "json").stdout or "[]") or []:
        exp = (k.get("expiration") or {}).get("seconds")
        if (exp is None or int(exp) > now) and (k.get("reusable") or not k.get("used")):
            out.append(int(k.get("id", 0)))
    return sorted(out)


def _tcp_a1_a2(st: Stack) -> tuple[str, str]:
    """TCP a1 → a2:8000 over the tailnet, and the local control of the listener on a2."""
    a2 = checks.status(st, "a2")
    control = checks.local_tcp(st, "a2", checks.ALLOWED_PORT)
    if not control:
        checks.start_listeners(st, "a2")
        time.sleep(1)
        control = checks.local_tcp(st, "a2", checks.ALLOWED_PORT)
    return checks.tcp(st, "a1", checks.ip4(a2["Self"]), checks.ALLOWED_PORT), control


def _audit(st: Stack, a_id: str, action: str) -> str:
    """The platform audit events of the action on tenant a: the paired operation (operation_id) then the refusals of the
    request (a 409 is audited with the base action, outcome failure, and its reason)."""
    pair = psql_one(st, "SELECT string_agg(action, ',' ORDER BY occurred_at, id) FROM audit_events WHERE "
                    f"resource_id = '{a_id}' AND action LIKE '{action}.%' AND operation_id IS NOT NULL AND tenant_id IS NULL")
    refused = psql_one(st, "SELECT string_agg(outcome || ':' || coalesce(details ->> 'reason', '-'), ',' ORDER BY occurred_at, id) "
                       f"FROM audit_events WHERE resource_id = '{a_id}' AND action = '{action}' AND tenant_id IS NULL")
    return f"{pair}|{refused}"


def admin_session(st: Stack) -> tuple[Browser, dict]:
    """A Tenant Admin of tenant-a seeded by sub (P2-T11a), signed in through Keycloak with TOTP."""
    u = new_user(st, SLUG, "e2e-ta")
    p = admin_cmd(st, ["seed-membership", "--tenant", SLUG, "--role", "tenant_admin", "--subject", u["sub"],
                       "--display-name", "E2E Admin tenant-a"])
    if p.returncode != 0:
        raise StackError(f"seed-membership tenant_admin: {st.redact(p.stdout + p.stderr)[-300:]}")
    b = Browser(st)
    sess, _ = portal_login(st, b, f"app.{st.domain}", f"scope=tenant&tenant={SLUG}", u, TOTP())
    return b, sess


# ---------------------------------------------------------------------------------------------------- E2E-56
def check_suspend(r, st: Stack, state: dict) -> None:
    sa = getattr(st, "platform_sa", None)
    if not sa:
        raise StackError("no Super Admin of E2E-24 (st.platform_sa)")
    a_id = tenant_id(st, SLUG)
    allow = (ROOT / "infrastructure" / "headscale" / "templates" / "test-allow-intra.hujson").read_text(encoding="utf-8")
    rows, conds = [], []

    def cond(name: str, good: bool, row: str) -> None:
        conds.append((name, good))
        rows.append(f"[{'ok' if good else 'FAIL'} {name}] {row}")

    code, out, err = policy_apply(st, allow)
    cond("allow_applied", code == 0 and out.get("state") == "applied" and stored_sha(st) == out.get("applied_sha256"),
         f"policy-apply allow: exit {code} {out.get('state')} version {out.get('version')} {err[-160:] if code else ''}")
    state["allow_sha"], state["desired"] = out.get("applied_sha256", ""), out.get("version_id", "")
    a1 = checks.wait_peer_count(st, "a1", 1, 90)
    answer, control = _tcp_a1_a2(st)
    cond("tcp_before", a1 is not None and answer.endswith("a2 tcp/8000"),
         f"before: a1 peers {len(checks.peers(a1)) if a1 else '?'}, tcp a1→a2:8000 {answer or 'no connection'} "
         f"(control {control or 'no listener'})")
    key = json.loads(st.headscale(SLUG, "preauthkeys", "create", "-u", st.users[SLUG], "--reusable", "-e", "30m",
                                  "-o", "json").stdout)
    st.secret_values.add(key.get("key", ""))
    state["key_id"] = int(key.get("id", 0))
    valid = valid_preauth_keys(st)
    cond("key_valid_before", state["key_id"] in valid, f"valid pre-auth keys before: {valid} (created {state['key_id']})")

    # a Tenant Admin signed in BEFORE the suspension: the same write is accepted now and refused during it (E2E-57)
    tb, tsess = admin_session(st)
    state["ta_browser"], state["ta_session"] = tb, tsess
    m = (tsess.get("memberships") or [{}])[0]
    sync = tb.request("POST", f"https://app.{st.domain}/api/v1/tenants/{a_id}/devices/sync", None,
                      _tenant_headers(st, tsess, "e2e-sync-" + secrets.token_hex(6)))
    cond("ta_write_before", m.get("role") == "tenant_admin" and sync.status == 202,
         f"Tenant Admin ({m.get('role')}) POST devices/sync before: {sync.status}")

    b, sess = platform_session(st, sa)
    state["sa_browser"], state["sa_session"] = b, sess
    api = f"https://admin.{st.domain}/api/v1"
    idem = "e2e-suspend-" + secrets.token_hex(6)
    first = b.request("POST", f"{api}/platform/tenants/{a_id}/suspend", None, _platform_headers(st, sess, idem))
    job = first.json()
    replay = b.request("POST", f"{api}/platform/tenants/{a_id}/suspend", None, _platform_headers(st, sess, idem))
    cond("accepted", first.status == 202 and first.header("Location") == f"/api/v1/platform/jobs/{job.get('id')}"
         and job.get("kind") == "tenant.suspend" and replay.status == 202 and replay.json().get("id") == job.get("id"),
         f"POST suspend {first.status} {first.header('Location')} kind {job.get('kind')} status {job.get('status')}; "
         f"replay {replay.status} same={replay.json().get('id') == job.get('id')}")
    done = _wait_job(b, api, job.get("id", ""))
    want = [("validate", "succeeded"), ("policy.suspend", "succeeded"), ("registry.suspend", "succeeded"),
            ("preauthkeys.expire", "succeeded"), ("notify", "succeeded")]
    cond("job_succeeded", done.get("status") == "succeeded" and _steps(done) == want,
         f"job {done.get('status')} steps {_steps(done)} error {(done.get('error') or {}).get('code')}")
    tenant = b.get(f"{api}/platform/tenants/{a_id}").json()
    cond("tenant_suspended", tenant.get("status") == "suspended", f"GET /platform/tenants/{{a}}: {tenant.get('status')}")
    cond("policy_suspension", stored_sha(st) == _sha(SUSPENSION),
         f"Headscale policy sha {stored_sha(st)[:16]}… = suspension {_sha(SUSPENSION)[:16]}…")
    reg = psql(st, "SELECT t.desired_policy_version_id::text, v.kind, p.trigger FROM tenants t JOIN policy_applications p "
                   "ON p.tenant_id = t.id AND p.state = 'applied' AND p.superseded_at IS NULL JOIN policy_versions v "
                   f"ON v.id = p.policy_version_id WHERE t.id = '{a_id}'")
    cond("desired_kept", reg == [[state["desired"], "suspension", "suspend"]],
         f"desired|current kind|trigger {reg} (desired before {state['desired']})")
    again = b.request("POST", f"{api}/platform/tenants/{a_id}/suspend", None,
                      _platform_headers(st, sess, "e2e-suspend-" + secrets.token_hex(6)))
    cond("second_409", again.status == 409 and again.json().get("code") == "conflict",
         f"second suspend {again.status} {again.json().get('code')}")
    audit = _audit(st, a_id, "platform.tenant.suspend")
    notes = psql_one(st, f"SELECT count(*) FROM notification_outbox WHERE tenant_id = '{a_id}' AND kind = 'tenant.suspended'")
    cond("audit_notified", audit == "platform.tenant.suspend.requested,platform.tenant.suspend.succeeded|failure:already_suspended"
         and int(notes or 0) >= 1,
         f"audit {audit}; tenant.suspended notifications {notes}")
    state["suspended"] = done.get("status") == "succeeded"
    failed = [n for n, good in conds if not good]
    for row in rows:
        log(f"  E2E-56 {st.redact(row)}")
    r.add("E2E-56", "P3-T08: fixture allow ⇒ TCP a1→a2:8000 thông; Super Admin POST /platform/tenants/{a}/suspend (CSRF + "
          "Idempotency-Key) ⇒ 202 + job tenant.suspend succeeded 5 bước; tenant suspended; Headscale giữ policy "
          "suspension (deny-all), desired giữ nguyên; lặp ⇒ cùng job; suspend lần hai ⇒ 409; audit cặp; thông báo",
          not failed, (f"FAILED: {', '.join(failed)} — " if failed else "") + "; ".join(rows), limit=2500)


# ---------------------------------------------------------------------------------------------------- E2E-57
def check_during(r, st: Stack, state: dict) -> None:
    a_id = tenant_id(st, SLUG)
    rows, conds = [], []

    def cond(name: str, good: bool, row: str) -> None:
        conds.append((name, good))
        rows.append(f"[{'ok' if good else 'FAIL'} {name}] {row}")

    a1 = checks.wait_peer_count(st, "a1", 0, 90)
    answer, control = _tcp_a1_a2(st)
    cond("tcp_blocked", a1 is not None and answer == "" and control.endswith("tcp/8000"),
         f"a1 peers {len(checks.peers(a1)) if a1 else '?'}; tcp a1→a2:8000 {answer or 'no connection'} "
         f"(local control on a2: {control or 'no listener'})")
    b, sess = state["ta_browser"], state["ta_session"]
    m = (sess.get("memberships") or [{}])[0]
    api = f"https://app.{st.domain}/api/v1/tenants/{a_id}"
    sync = b.request("POST", f"{api}/devices/sync", None, _tenant_headers(st, sess, "e2e-sync-" + secrets.token_hex(6)))
    devices = b.get(f"{api}/devices")
    cond("ta_write_403", m.get("role") == "tenant_admin" and sync.status == 403
         and sync.json().get("code") == "tenant_suspended",
         f"Tenant Admin ({m.get('role')}) POST devices/sync {sync.status} {sync.json().get('code')}")
    cond("ta_read_200", devices.status == 200, f"GET devices {devices.status} ({len(devices.json().get('items') or [])} devices)")
    denied = psql_one(st, "SELECT count(*) FROM audit_events WHERE action = 'device.sync' AND outcome = 'denied' "
                      f"AND tenant_id = '{a_id}' AND details ->> 'reason' = 'tenant_suspended'")
    cond("denial_audited", int(denied or 0) >= 1, f"device.sync denied (tenant_suspended) events: {denied}")
    valid = valid_preauth_keys(st)
    cond("keys_expired", valid == [] and state.get("key_id"), f"valid pre-auth keys of tenant-a: {valid or 'none'} "
         f"(key {state.get('key_id')} created before the suspension)")
    failed = [n for n, good in conds if not good]
    for row in rows:
        log(f"  E2E-57 {st.redact(row)}")
    r.add("E2E-57", "P3-T08 trong lúc suspend: a1 không còn peer, TCP a1→a2:8000 bị chặn (listener vẫn chạy); Tenant "
          "Admin POST /tenants/{a}/devices/sync ⇒ 403 tenant_suspended (audit denied), GET devices ⇒ 200; không còn "
          "pre-auth key nào còn hiệu lực", not failed, (f"FAILED: {', '.join(failed)} — " if failed else "") + "; ".join(rows),
          limit=2500)


# ---------------------------------------------------------------------------------------------------- E2E-58
def check_resume(r, st: Stack, state: dict) -> None:
    a_id = tenant_id(st, SLUG)
    b, sess = state["sa_browser"], state["sa_session"]
    api = f"https://admin.{st.domain}/api/v1"
    rows, conds = [], []

    def cond(name: str, good: bool, row: str) -> None:
        conds.append((name, good))
        rows.append(f"[{'ok' if good else 'FAIL'} {name}] {row}")

    versions = psql_one(st, f"SELECT count(*) FROM policy_versions WHERE tenant_id = '{a_id}'")
    first = b.request("POST", f"{api}/platform/tenants/{a_id}/resume", None,
                      _platform_headers(st, sess, "e2e-resume-" + secrets.token_hex(6)))
    job = first.json()
    cond("accepted", first.status == 202 and job.get("kind") == "tenant.resume",
         f"POST resume {first.status} kind {job.get('kind')}")
    done = _wait_job(b, api, job.get("id", ""))
    want = [("validate", "succeeded"), ("policy.resume", "succeeded"), ("registry.resume", "succeeded"),
            ("notify", "succeeded")]
    cond("job_succeeded", done.get("status") == "succeeded" and _steps(done) == want,
         f"job {done.get('status')} steps {_steps(done)} error {(done.get('error') or {}).get('code')}")
    tenant = b.get(f"{api}/platform/tenants/{a_id}").json()
    cond("tenant_active", tenant.get("status") == "active", f"tenant {tenant.get('status')}")
    after = psql_one(st, f"SELECT count(*) FROM policy_versions WHERE tenant_id = '{a_id}'")
    cond("desired_again", stored_sha(st) == state.get("allow_sha") and after == versions,
         f"Headscale policy sha {stored_sha(st)[:16]}… = allow {str(state.get('allow_sha'))[:16]}…; versions {versions} → {after}")
    a1 = checks.wait_peer_count(st, "a1", 1, 90)
    answer, control = _tcp_a1_a2(st)
    cond("tcp_after", a1 is not None and answer.endswith("a2 tcp/8000"),
         f"after: a1 peers {len(checks.peers(a1)) if a1 else '?'}, tcp a1→a2:8000 {answer or 'no connection'}")
    tb, tsess = state["ta_browser"], state["ta_session"]
    if tb:
        sync = tb.request("POST", f"https://app.{st.domain}/api/v1/tenants/{a_id}/devices/sync", None,
                          _tenant_headers(st, tsess, "e2e-sync-" + secrets.token_hex(6)))
        cond("ta_write_again", sync.status == 202, f"Tenant Admin POST devices/sync {sync.status}")
    again = b.request("POST", f"{api}/platform/tenants/{a_id}/resume", None,
                      _platform_headers(st, sess, "e2e-resume-" + secrets.token_hex(6)))
    cond("second_409", again.status == 409, f"second resume {again.status} {again.json().get('code')}")
    audit = _audit(st, a_id, "platform.tenant.resume")
    notes = psql_one(st, f"SELECT count(*) FROM notification_outbox WHERE tenant_id = '{a_id}' AND kind = 'tenant.resumed'")
    cond("audit_notified", audit == "platform.tenant.resume.requested,platform.tenant.resume.succeeded|failure:not_suspended"
         and int(notes or 0) >= 1,
         f"audit {audit}; tenant.resumed notifications {notes}")
    cond("keys_stay_expired", valid_preauth_keys(st) == [], "pre-auth keys still expired after resume")
    base = (ROOT / "infrastructure" / "headscale" / "templates" / "bootstrap-policy.hujson").read_text(encoding="utf-8")
    code, out, _ = policy_apply(st, base, "--trigger", "bootstrap")
    cond("baseline_restored", code == 0 and out.get("state") == "applied" and checks.wait_peer_count(st, "a1", 0, 90) is not None,
         f"baseline deny-all again: exit {code} {out.get('state')}")
    failed = [n for n, good in conds if not good]
    for row in rows:
        log(f"  E2E-58 {st.redact(row)}")
    r.add("E2E-58", "P3-T08 resume: POST /platform/tenants/{a}/resume ⇒ 202, job tenant.resume succeeded 4 bước; tenant "
          "active; Headscale áp lại version mong muốn (không version mới); TCP a1→a2:8000 thông lại; Tenant Admin sync ⇒ "
          "202; resume lần hai ⇒ 409; audit cặp; thông báo; pre-auth key vẫn hết hạn", not failed,
          (f"FAILED: {', '.join(failed)} — " if failed else "") + "; ".join(rows), limit=2500)


def run_all(r, st: Stack, guarded) -> None:
    """E2E-56 … E2E-58 in order (each builds on the previous one)."""
    state: dict = {}
    if guarded(r, "E2E-56", check_suspend, st, state) is None and state.get("suspended"):
        guarded(r, "E2E-57", check_during, st, state)
        guarded(r, "E2E-58", check_resume, st, state)
