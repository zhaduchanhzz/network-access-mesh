"""P4-T10 policy module on the dev/CI stack — FUNCTIONAL only (§22.1): the api and worker built from the tree, a real
Keycloak login with TOTP through the edge, the real Headscale of tenant-a / tenant-b behind the edge admin listener,
the real clients a1/a2 of tenant-a.

  E2E-96  lifecycle + full pipeline (Tenant Admin of tenant-a, 4-eyes off): a group (P4-T09 API) holding the Admin's
          membership and a catalog tag (P4-T15 API); POST /policies with a TYPED source (principals by id) ⇒ 201 draft;
          a second draft on the same base; PATCH without If-Match ⇒ 428; validate ⇒ validated with CheckPolicy passed on
          the real Headscale (dry run); approve (self-review, content_sha256) ⇒ approved; apply ⇒ 202 + Location, job
          policy.apply (manual) succeeds and Headscale stores the render — "group:<name>" with mg-<membership>@ (never
          an e-mail), "tagOwners" with the catalog tag and no owner — read back identical (sha256 of the last
          application = Headscale's), the grant enforced (TCP a1→a2:8000); apply of the second draft ⇒ 409 stale_base;
          a group change ⇒ policy.apply group_change renders the new member, no new version; a typed deny-all applied ⇒
          a1 loses its peer; rollback to the first version ⇒ 202, version N+1 rollback_of, approval inherited, TCP again;
          audit policy.create/validate/approved/desired_set/rollback by the Admin.
  E2E-97  4-eyes + step-up (TenantSettings.policy.four_eyes set by SQL — its write path is P4-T03a): the Admin's
          self-review ⇒ 409, submit, the submitter's approval ⇒ 403, a Tenant Owner approves ⇒ peer; the Owner's apply
          with an auth_time older than 15 min ⇒ 401 reauth_required, after a fresh one ⇒ 202, job succeeded.
  E2E-98  drift + incidents (`meshguard admin policy-drift-check`, the worker running policy.drift_check): in sync ⇒
          exit 0; a policy set out of band (CLI) ⇒ drift, High instance.policy_drift, the drift_repair job re-applies
          the desired state (sha256 back to the applied one), in sync again; an EMPTY stored policy (ErrNoPolicy) ⇒
          Critical instance.policy_missing, job failed no_policy (this stack has no Host Agent: the edge detach is
          internal/policies' DB test — reported edge_detached=false), the desired version applied again; tenant-b's
          db.sqlite replaced by an empty database ⇒ the API key is refused, Critical instance.database_replaced, no API
          key created on the new database (no automatic apikey.bootstrap), the database put back; the deny-all of the
          suspension (E2E-56) was a policy.apply job of its own (trigger suspend, mode suspension) — §11.4 split.

Standard library only. Passwords, TOTP keys, cookies and CSRF tokens stay in this process (and its redaction set).
"""
from __future__ import annotations

import hashlib
import json
import secrets
import time

import checks
from backend import psql
from dualcontrol import owner_session, psql_one, tenant_id
from lifecycle import admin_session
from stack import ROOT, Stack, StackError, log

SLUG = "tenant-a"
SLUG_B = "tenant-b"
GROUP = "e2e-pol"
TAG = "tag:e2e-pol"
POLICY_DIR = "/etc/mg-e2e"   # st.work/policies inside the Headscale containers (stack.py)


def _h(st: Stack, sess: dict, idem: str | None = None, if_match: str | None = None) -> dict:
    h = {"Origin": f"https://app.{st.domain}", "X-CSRF-Token": sess["csrf_token"], "Content-Type": "application/json"}
    if idem:
        h["Idempotency-Key"] = idem
    if if_match:
        h["If-Match"] = if_match
    return h


def _key() -> str:
    return "e2e-pol-" + secrets.token_hex(6)


def _job_status(st: Stack, job: str, timeout: float = 150) -> str:
    end, status = time.time() + timeout, ""
    while time.time() < end:
        status = psql_one(st, f"SELECT status FROM provisioning_jobs WHERE id = '{job}'")
        if status in ("succeeded", "failed", "cancelled"):
            return status
        time.sleep(1)
    return status or "none"


def _newest_job(st: Stack, a_id: str, kind: str, since: str, timeout: float = 150) -> tuple[str, str]:
    """(id, final status) of the newest job of a kind created after `since` (DB clock)."""
    end = time.time() + timeout
    while time.time() < end:
        jid = psql_one(st, f"SELECT id FROM provisioning_jobs WHERE kind = '{kind}' AND tenant_id = '{a_id}' "
                       f"AND created_at > '{since}' ORDER BY created_at DESC LIMIT 1")
        if jid:
            return jid, _job_status(st, jid, max(1.0, end - time.time()))
        time.sleep(1)
    return "", "none"


def _stored(st: Stack, slug: str = SLUG) -> str:
    got = st.headscale(slug, "policy", "get", check=False).stdout
    return got[:-1] if got.endswith("\n") else got


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _last_app(st: Stack, a_id: str) -> list:
    rows = psql(st, "SELECT trigger, state, applied_sha256, policy_version_id FROM policy_applications "
                f"WHERE tenant_id = '{a_id}' ORDER BY created_at DESC, id DESC LIMIT 1")
    return rows[0] if rows else ["", "", "", ""]


def _membership(st: Stack, sess: dict, a_id: str) -> str:
    ident = sess["principal"]["identity_id"]
    return psql_one(st, f"SELECT id FROM tenant_memberships WHERE tenant_id = '{a_id}' AND identity_id = '{ident}'")


def _p(typ: str, ref: str) -> dict:
    return {"type": typ, "ref": ref}


def _member_to_member() -> dict:
    return {"src": [_p("autogroup", "member")], "dst": [_p("autogroup", "member")], "ip": [f"tcp:{checks.ALLOWED_PORT}"]}


class Flow:
    """The Admin's (or Owner's) lifecycle calls on tenant-a."""

    def __init__(self, st: Stack, b, sess: dict, a_id: str):
        self.st, self.b, self.sess = st, b, sess
        self.api = f"https://app.{st.domain}/api/v1/tenants/{a_id}"

    def create(self, source: dict):
        return self.b.request("POST", f"{self.api}/policies", json.dumps({"source": source}).encode(),
                              _h(self.st, self.sess, _key()))

    def post(self, vid: str, action: str, etag: str | None = None, body: dict | None = None, idem: bool = False):
        data = json.dumps(body).encode() if body is not None else None
        return self.b.request("POST", f"{self.api}/policies/{vid}/{action}", data,
                              _h(self.st, self.sess, _key() if idem else None, etag))

    def get(self, vid: str) -> dict:
        r = self.b.get(f"{self.api}/policies/{vid}")
        return r.json() if r.status == 200 else {}

    def approved(self, source: dict) -> dict:
        """create → validate → approve (self-review); the version (or {} on a failure)."""
        c = self.create(source)
        v = c.json() if c.status == 201 else {}
        if not v:
            return {}
        val = self.post(v["id"], "validate", v["etag"])
        v = val.json() if val.status == 200 else {}
        if v.get("state") != "validated":
            return {}
        ap = self.post(v["id"], "approve", v["etag"], {"content_sha256": v["content_sha256"]})
        return ap.json() if ap.status == 200 else {}


# ---------------------------------------------------------------------------------------------------- E2E-96
def check_pipeline(r, st: Stack, state: dict) -> None:
    a_id = tenant_id(st, SLUG)
    rows, conds = [], []

    def cond(name: str, good: bool, row: str) -> None:
        conds.append((name, good))
        rows.append(f"[{'ok' if good else 'FAIL'} {name}] {row}")

    b, sess = admin_session(st)
    f = Flow(st, b, sess, a_id)
    state["admin"] = (b, sess)
    me = _membership(st, sess, a_id)
    since_tables = psql_one(st, "SELECT now()::text")
    # a group holding the Admin (P4-T09 API) and a catalog tag (P4-T15 API)
    g = b.request("POST", f"{f.api}/groups", json.dumps({"name": GROUP}).encode(), _h(st, sess, _key()))
    grp = g.json() if g.status == 201 else {}
    gm = b.request("PUT", f"{f.api}/groups/{grp.get('id')}/members", json.dumps({"membership_ids": [me]}).encode(),
                   _h(st, sess, if_match=g.header("ETag") or grp.get("etag", "")))
    t = b.request("POST", f"{f.api}/tags", json.dumps({"name": TAG, "purpose": "server"}).encode(), _h(st, sess, _key()))
    tag = t.json() if t.status == 201 else {}
    state["group"], state["group_etag"] = grp.get("id"), gm.header("ETag") or ""
    # the group/tag changes enqueue policy.apply (group_change, tag_change): let it finish, so the apply below gets a
    # job of its own (an unfinished job of the tenant would carry it — the debounce of §13.5 — with its trigger)
    _, tstatus = _newest_job(st, a_id, "policy.apply", since_tables)
    cond("tables", g.status == 201 and gm.status == 200 and t.status == 201 and tstatus == "succeeded",
         f"POST groups {g.status}, PUT members {gm.status}, POST tags {t.status}; policy.apply {tstatus}")

    allow = {"grants": [_member_to_member(),
                        {"src": [_p("group", grp.get("id", ""))], "dst": [_p("tag", tag.get("id", ""))], "ip": ["tcp:443"]}]}
    c1 = f.create(allow)
    v1 = c1.json() if c1.status == 201 else {}
    c2 = f.create({"grants": [_member_to_member()]})   # the same base: stale once v1 is applied
    v2 = c2.json() if c2.status == 201 else {}
    nomatch = b.request("PATCH", f"{f.api}/policies/{v1.get('id')}", json.dumps({"source": allow}).encode(), _h(st, sess))
    cond("draft", c1.status == 201 and v1.get("state") == "draft" and v1.get("etag") == '"1"' and c2.status == 201
         and nomatch.status == 428 and v1.get("parent_version_id") == v2.get("parent_version_id"),
         f"POST policies {c1.status} {v1.get('state')} etag {v1.get('etag')}; second draft {c2.status}; PATCH without "
         f"If-Match {nomatch.status}")
    val = f.post(v1.get("id"), "validate", v1.get("etag"))
    vv = val.json() if val.status == 200 else {}
    rep = vv.get("validation_report") or {}
    cond("validate", val.status == 200 and vv.get("state") == "validated" and rep.get("result") == "passed"
         and rep.get("check") == "passed" and len(rep.get("rendered_sha256", "")) == 64,
         f"validate {val.status} {vv.get('state')} result {rep.get('result')} CheckPolicy {rep.get('check')} "
         f"errors {[e.get('code') for e in rep.get('errors') or []]}")
    bad = f.post(vv.get("id"), "approve", vv.get("etag"), {"content_sha256": "0" * 64})
    ap = f.post(vv.get("id"), "approve", vv.get("etag"), {"content_sha256": vv.get("content_sha256")})
    v1 = ap.json() if ap.status == 200 else {}
    cond("approve", bad.status == 409 and ap.status == 200 and v1.get("state") == "approved"
         and v1.get("review_mode") == "self",
         f"approve another content {bad.status}; approve {ap.status} {v1.get('state')} review_mode {v1.get('review_mode')}")
    v2 = f.approved({"grants": [_member_to_member()]}) if v2 else {}

    since = psql_one(st, "SELECT now()::text")
    apl = f.post(v1.get("id"), "apply", idem=True)
    acc = apl.json() if apl.status == 202 else {}
    job = (acc.get("job") or {}).get("id", "")
    status = _job_status(st, job) if job else "none"
    stored = _stored(st)
    app = _last_app(st, a_id)
    rendered = (f'"group:{GROUP}"' in stored and f"mg-{me}@" in stored and f'"{TAG}": []' in stored
                and "@example" not in stored)
    cond("apply", apl.status == 202 and (apl.header("Location") or "").endswith(f"/jobs/{job}") and status == "succeeded"
         and rendered and app[:2] == ["manual", "applied"] and app[2] == _sha(stored) and app[3] == v1.get("id"),
         f"apply {apl.status} job {status}; rendered group/mg-<membership>@/tagOwners {rendered}; last application "
         f"{app[:2]} sha = Headscale {app[2] == _sha(stored)}")
    a1 = checks.wait_peer_count(st, "a1", 1, 90)
    a2 = checks.status(st, "a2")
    answer = checks.tcp(st, "a1", checks.ip4(a2["Self"]), checks.ALLOWED_PORT) if a1 else ""
    cond("enforced", a1 is not None and "a2" in answer, f"a1 peers {len(checks.peers(a1)) if a1 else '?'}, "
         f"tcp a1→a2:{checks.ALLOWED_PORT} {answer or 'no connection'}")
    stale = f.post(v2.get("id", "x"), "apply", idem=True)
    cond("stale_base", stale.status == 409 and "stale_base" in (stale.json().get("detail") or ""),
         f"apply of a draft on the old base {stale.status} {stale.json().get('detail', '')[:80]}")

    # a group change: the same version rendered again (group_change), no new version
    other = psql_one(st, f"SELECT id FROM tenant_memberships WHERE tenant_id = '{a_id}' AND status = 'active' "
                     f"AND id <> '{me}' ORDER BY created_at LIMIT 1")
    versions = psql_one(st, f"SELECT count(*) FROM policy_versions WHERE tenant_id = '{a_id}'")
    since = psql_one(st, "SELECT now()::text")
    gm2 = b.request("PUT", f"{f.api}/groups/{grp.get('id')}/members", json.dumps({"membership_ids": [me, other]}).encode(),
                    _h(st, sess, if_match=state["group_etag"]))
    _, gstatus = _newest_job(st, a_id, "policy.apply", since)
    stored = _stored(st)
    app = _last_app(st, a_id)
    cond("group_change", gm2.status == 200 and gstatus == "succeeded" and f"mg-{other}@" in stored
         and app[0] == "group_change" and app[3] == v1.get("id")
         and psql_one(st, f"SELECT count(*) FROM policy_versions WHERE tenant_id = '{a_id}'") == versions,
         f"PUT members {gm2.status}; policy.apply {gstatus}; new member rendered {f'mg-{other}@' in stored}; "
         f"last application {app[0]} on the same version {app[3] == v1.get('id')}")

    # a typed deny-all, then rollback to the first version
    deny = f.approved({"grants": []})
    d = f.post(deny.get("id", "x"), "apply", idem=True)
    dstatus = _job_status(st, (d.json().get("job") or {}).get("id", "")) if d.status == 202 else "none"
    cut = checks.wait_peer_count(st, "a1", 0, 90) is not None
    cond("deny", d.status == 202 and dstatus == "succeeded" and cut and '"grants": []' in _stored(st),
         f"typed deny-all apply {d.status} job {dstatus}; a1 without peer {cut}")
    rb = f.post(v1.get("id"), "rollback", idem=True)
    rbody = rb.json() if rb.status == 202 else {}
    rv = rbody.get("version") or {}
    rstatus = _job_status(st, (rbody.get("job") or {}).get("id", "")) if rbody else "none"
    a1 = checks.wait_peer_count(st, "a1", 1, 90)
    answer = checks.tcp(st, "a1", checks.ip4(a2["Self"]), checks.ALLOWED_PORT) if a1 else ""
    app = _last_app(st, a_id)
    cond("rollback", rb.status == 202 and rv.get("rollback_of") == v1.get("id") and rv.get("state") == "approved"
         and rv.get("approved_by") == v1.get("approved_by") and rv.get("content_sha256") == v1.get("content_sha256")
         and rstatus == "succeeded" and app[0] == "rollback" and "a2" in answer,
         f"rollback {rb.status} v{rv.get('version')} rollback_of v1 {rv.get('rollback_of') == v1.get('id')}, approval "
         f"inherited {rv.get('approved_by') == v1.get('approved_by')}; job {rstatus}; tcp again {answer or 'no connection'}")
    state["desired"] = rv.get("id")
    cur = b.get(f"{f.api}/policies/current")
    cj = cur.json() if cur.status == 200 else {}
    cond("current", cur.status == 200 and (cj.get("desired") or {}).get("id") == rv.get("id")
         and (cj.get("applied") or {}).get("applied_sha256") == _sha(_stored(st)),
         f"GET current {cur.status}: desired = rollback version, applied sha = Headscale")
    ident = sess["principal"]["identity_id"]
    audit = psql_one(st, "SELECT string_agg(DISTINCT action, ',') FROM audit_events WHERE "
                     f"tenant_id = '{a_id}' AND actor_identity_id = '{ident}' AND action LIKE 'policy.%' AND outcome = 'success'")
    cond("audit", all(a in audit for a in ("policy.create", "policy.validate", "policy.approved", "policy.desired_set",
                                           "policy.rollback")), f"audit {audit}")
    _report(r, "E2E-96", "P4-T10 vòng đời policy có kiểu + pipeline đầy đủ với Headscale thật: draft → validate (lint + "
            "CheckPolicy dry-run) → self-review → apply 202 ⇒ job render group/tag/mg-<membership>@ đọc lại khớp, thực thi "
            "TCP; base cũ ⇒ 409 stale_base; đổi group ⇒ group_change; deny-all có kiểu; rollback kế thừa phê duyệt", rows, conds)


# ---------------------------------------------------------------------------------------------------- E2E-97
def check_four_eyes(r, st: Stack, state: dict) -> None:
    a_id = tenant_id(st, SLUG)
    rows, conds = [], []

    def cond(name: str, good: bool, row: str) -> None:
        conds.append((name, good))
        rows.append(f"[{'ok' if good else 'FAIL'} {name}] {row}")

    b, sess = state.get("admin") or admin_session(st)
    f = Flow(st, b, sess, a_id)
    settings = psql_one(st, f"SELECT settings::text FROM tenants WHERE id = '{a_id}'")
    psql(st, f"UPDATE tenants SET settings = jsonb_set(settings, '{{policy}}', "
             f"coalesce(settings->'policy', '{{}}'::jsonb) || '{{\"four_eyes\": true}}') WHERE id = '{a_id}'")
    try:
        c = f.create({"grants": [_member_to_member()]})
        v = c.json() if c.status == 201 else {}
        val = f.post(v.get("id"), "validate", v.get("etag"))
        v = val.json() if val.status == 200 else {}
        selfr = f.post(v.get("id"), "approve", v.get("etag"), {"content_sha256": v.get("content_sha256")})
        sub = f.post(v.get("id"), "submit", v.get("etag"))
        v = sub.json() if sub.status == 200 else {}
        own = f.post(v.get("id"), "approve", v.get("etag"), {"content_sha256": v.get("content_sha256")})
        cond("submitter", c.status == 201 and selfr.status == 409 and sub.status == 200
             and v.get("state") == "pending_approval" and own.status == 403,
             f"self-review with 4-eyes {selfr.status}; submit {sub.status} {v.get('state')}; the submitter approves {own.status}")
        ob, osess, _ = owner_session(st, SLUG)
        of = Flow(st, ob, osess, a_id)
        ok = of.post(v.get("id"), "approve", v.get("etag"), {"content_sha256": v.get("content_sha256")})
        av = ok.json() if ok.status == 200 else {}
        cond("peer", ok.status == 200 and av.get("review_mode") == "peer"
             and av.get("approved_by") == osess["principal"]["identity_id"],
             f"Owner approves {ok.status} review_mode {av.get('review_mode')}")
        cur = b.get(f"{f.api}/policies/current").json()
        oident = osess["principal"]["identity_id"]
        psql(st, f"UPDATE sessions SET auth_time = now() - interval '1 hour' WHERE identity_id = '{oident}'")
        old = of.post(v.get("id"), "apply", idem=True)
        psql(st, f"UPDATE sessions SET auth_time = now() WHERE identity_id = '{oident}'")
        fresh = of.post(v.get("id"), "apply", idem=True)
        jstatus = _job_status(st, (fresh.json().get("job") or {}).get("id", "")) if fresh.status == 202 else "none"
        cond("step_up", cur.get("four_eyes") is True and cur.get("apply_step_up") is True and old.status == 401
             and old.json().get("code") == "reauth_required" and fresh.status == 202 and jstatus == "succeeded",
             f"current four_eyes {cur.get('four_eyes')}; apply with auth_time 1 h old {old.status} {old.json().get('code')}; "
             f"after a fresh one {fresh.status} job {jstatus}")
        state["desired"] = v.get("id")
        mode = psql_one(st, f"SELECT details->>'review_mode' FROM audit_events WHERE tenant_id = '{a_id}' AND "
                        f"action = 'policy.approved' AND resource_id = '{v.get('id')}'")
        cond("audit", mode == "peer", f"policy.approved review_mode {mode}")
    finally:
        psql(st, f"UPDATE tenants SET settings = '{settings}'::jsonb WHERE id = '{a_id}'")
    _report(r, "E2E-97", "P4-T10 4-eyes (TenantSettings.policy.four_eyes): self-review ⇒ 409, người gửi tự duyệt ⇒ 403, Owner "
            "duyệt ⇒ peer; apply cần step-up (auth_time cũ ⇒ 401 reauth_required, mới ⇒ 202)", rows, conds)


# ---------------------------------------------------------------------------------------------------- E2E-98
def drift_check(st: Stack, slug: str) -> tuple[int, dict]:
    worker = st.compose("ps", "-q", "worker").stdout.strip()
    p = st.docker("exec", worker, "/usr/local/bin/meshguard", "admin", "policy-drift-check", "--tenant", slug,
                  check=False, timeout=240)
    out = {}
    for line in p.stdout.splitlines():
        if line.startswith("{"):
            out = json.loads(line)
    return p.returncode, out


def _set_policy(st: Stack, slug: str, name: str, text: str):
    pol = st.work / "policies" / name
    pol.write_text(text, encoding="utf-8")
    pol.chmod(0o644)
    return st.headscale(slug, "policy", "set", "-f", f"{POLICY_DIR}/{name}", check=False)


def _events(st: Stack, t_id: str, kind: str, severity: str, since: str) -> int:
    return int(psql_one(st, f"SELECT count(*) FROM security_events WHERE tenant_id = '{t_id}' AND kind = '{kind}' "
                            f"AND severity = '{severity}' AND occurred_at > '{since}'") or 0)


def check_drift(r, st: Stack, state: dict) -> None:
    a_id, b_id = tenant_id(st, SLUG), tenant_id(st, SLUG_B)
    rows, conds = [], []

    def cond(name: str, good: bool, row: str) -> None:
        conds.append((name, good))
        rows.append(f"[{'ok' if good else 'FAIL'} {name}] {row}")

    code, out = drift_check(st, SLUG)
    cond("in_sync", code == 0 and (out.get("output") or {}).get("state") == "in_sync", f"drift check exit {code} {out.get('output')}")
    applied = _last_app(st, a_id)[2]
    since = psql_one(st, "SELECT now()::text")
    p = _set_policy(st, SLUG, "drift-e2e.hujson", '{"grants": [{"src": ["*"], "dst": ["*"], "ip": ["*"]}]}')
    code, out = drift_check(st, SLUG)
    o = out.get("output") or {}
    repair = o.get("repair_job_id", "")
    rstatus = _job_status(st, repair) if repair else "none"
    cond("drift", p.returncode == 0 and code == 3 and o.get("state") == "drift" and o.get("read_sha256") != applied
         and _events(st, a_id, "instance.policy_drift", "high", since) >= 1 and rstatus == "succeeded"
         and _sha(_stored(st)) == _last_app(st, a_id)[2] and _last_app(st, a_id)[0] == "drift_repair",
         f"out-of-band set {p.returncode}; drift check exit {code} {o.get('state')}; High event; repair job {rstatus}; "
         f"Headscale back to the applied sha {_sha(_stored(st)) == _last_app(st, a_id)[2]}")
    code, out = drift_check(st, SLUG)
    cond("repaired", code == 0 and (out.get("output") or {}).get("state") == "in_sync", f"drift check after repair exit {code}")

    # ErrNoPolicy: an empty stored policy (PL-06 — the instance would start allow-all)
    since = psql_one(st, "SELECT now()::text")
    p = _set_policy(st, SLUG, "empty-e2e.hujson", "")
    empty = _stored(st).strip() == ""
    code, out = drift_check(st, SLUG)
    o = out.get("output") or {}
    # a failed job keeps no output (jobs: the output is stored on success): the error code and the event tell
    cond("no_policy", empty and code == 3 and out.get("error_code") == "no_policy" and out.get("status") == "failed"
         and _events(st, a_id, "instance.policy_missing", "critical", since) >= 1 and o.get("edge_detached") is not True,
         f"empty set {p.returncode} stored empty {empty}; drift check exit {code} {out.get('error_code')}; Critical event; "
         f"edge_detached {o.get('edge_detached')} (no Host Agent on this stack)")
    b, sess = state.get("admin") or admin_session(st)
    desired = state.get("desired") or psql_one(st, f"SELECT desired_policy_version_id FROM tenants WHERE id = '{a_id}'")
    again = b.request("POST", f"https://app.{st.domain}/api/v1/tenants/{a_id}/policies/{desired}/apply", None,
                      _h(st, sess, _key()))
    astatus = _job_status(st, (again.json().get("job") or {}).get("id", "")) if again.status == 202 else "none"
    code, out = drift_check(st, SLUG)
    cond("restored", again.status == 202 and astatus == "succeeded" and code == 0, f"apply the desired version again "
         f"{again.status} job {astatus}; drift check exit {code}")

    # tenant-b: its db.sqlite replaced by an empty database ⇒ the platform's API key is refused (§13.4)
    base = (ROOT / "infrastructure" / "headscale" / "templates" / "bootstrap-policy.hujson").read_text(encoding="utf-8")
    worker = st.compose("ps", "-q", "worker").stdout.strip()
    pa = st.docker("exec", "-i", worker, "/usr/local/bin/meshguard", "admin", "policy-apply", "--tenant", SLUG_B,
                   "--trigger", "bootstrap", "--file", "-", check=False, timeout=180, input=base)
    hs_b = st.name(f"hs-{SLUG_B}")
    mount = f"{st.work}:/w"
    since = psql_one(st, "SELECT now()::text")
    st.docker("stop", "-t", "60", hs_b, timeout=120)
    try:
        st.helper("mkdir -p /w/db98 && mv /w/data/tenant-b/db.sqlite* /w/db98/", mount)
        st.docker("start", hs_b)
        if not checks.wait(lambda: st.headscale(SLUG_B, "nodes", "list", "-o", "json", check=False,
                                                timeout=20).returncode == 0, 120):
            raise StackError("hs-tenant-b không phản hồi với database trống")
        code, out = drift_check(st, SLUG_B)
        keys = st.headscale(SLUG_B, "apikeys", "list", "-o", "json", check=False).stdout.strip()
        no_bootstrap = keys in ("", "null", "[]")
        cond("database_replaced", pa.returncode == 0 and code == 3 and out.get("error_code") == "database_replaced"
             and _events(st, b_id, "instance.database_replaced", "critical", since) >= 1 and no_bootstrap,
             f"baseline on tenant-b exit {pa.returncode}; drift check exit {code} {out.get('error_code')}; Critical event; "
             f"no API key on the new database (no automatic apikey.bootstrap) {no_bootstrap}")
    finally:
        st.docker("stop", "-t", "60", hs_b, timeout=120, check=False)
        st.helper("rm -f /w/data/tenant-b/db.sqlite* && mv /w/db98/db.sqlite* /w/data/tenant-b/ && rmdir /w/db98", mount)
        st.docker("start", hs_b)
        checks.wait(lambda: st.headscale(SLUG_B, "nodes", "list", "-o", "json", check=False, timeout=20).returncode == 0, 120)
    code, out = drift_check(st, SLUG_B)
    cond("database_back", code == 0, f"tenant-b database put back: drift check exit {code} {(out.get('output') or {}).get('state')}")

    # §11.4 split (E2E-56 ran before): the suspension's deny-all was its own policy.apply job
    sus = psql(st, "SELECT status, coalesce(output->>'mode', ''), coalesce(output->>'trigger', '') FROM provisioning_jobs "
                   f"WHERE tenant_id = '{a_id}' AND kind = 'policy.apply' AND input->>'trigger' = 'suspend' "
                   "ORDER BY created_at LIMIT 1")
    cond("suspend_split", bool(sus) and sus[0] == ["succeeded", "suspension", "suspend"],
         f"policy.apply of the suspend request (E2E-56): {sus[0] if sus else 'none'}")
    _report(r, "E2E-98", "P4-T10 drift: policy đặt ngoài luồng ⇒ High + drift_repair áp lại; policy rỗng (ErrNoPolicy) ⇒ "
            "Critical (stack không có Host Agent: gỡ edge kiểm ở test DB); db.sqlite bị thay ⇒ API key bị từ chối, "
            "Critical, không tự apikey.bootstrap; deny-all của suspend là job policy.apply riêng", rows, conds)


def _report(r, case: str, title: str, rows: list, conds: list) -> None:
    failed = [n for n, good in conds if not good]
    for row in rows:
        log(f"  {case} {row}")
    r.add(case, title, not failed, (f"FAILED: {', '.join(failed)} — " if failed else "") + "; ".join(rows), limit=2500)


def run_all(r, st: Stack, guarded) -> None:
    state: dict = {}
    guarded(r, "E2E-96", check_pipeline, st, state)
    guarded(r, "E2E-97", check_four_eyes, st, state)
    guarded(r, "E2E-98", check_drift, st, state)
    # leave tenant-a on the deny-all baseline (as E2E-91 did): the cases after this one start from it
    base = (ROOT / "infrastructure" / "headscale" / "templates" / "bootstrap-policy.hujson").read_text(encoding="utf-8")
    worker = st.compose("ps", "-q", "worker").stdout.strip()
    st.docker("exec", "-i", worker, "/usr/local/bin/meshguard", "admin", "policy-apply", "--tenant", SLUG,
              "--trigger", "bootstrap", "--file", "-", check=False, timeout=180, input=base)
