"""P4-T09 users and groups on the dev/CI stack — FUNCTIONAL only (§22.1): the api and worker built from the tree, real
Keycloak logins with TOTP through the edge on app., the real Headscale of tenant-a and an official client.

  E2E-92  offboarding (§8.2, V-23): an end user invited through the API (the invitation also runs member.idp_invite —
          the IdP driver finds the Keycloak account and e-mails its required actions) signs in, and an official client
          joins tenant-a under the member's Headscale user mg-<membership> with a reusable pre-auth key; a Tenant Admin
          offboards the member ⇒ 202 + Location of member.offboard, the member's Portal session is refused at once; the
          job (worker → edge admin listener → Headscale, Keycloak Admin API) expires the node and every pre-auth key of
          the user, disables the user in Keycloak; the client reports the expired key; the state reads applied; the audit
          pair is closed. Signing in again is refused at Keycloak (disabled account) and — with the account enabled
          again at Keycloak — by the Portal itself (403, identity_disabled)
  E2E-93  rule 3a and groups: a Tenant Admin is refused (403, audited with the guard's reason) locking the Owner,
          offboarding or demoting another Admin, giving the Admin role and inviting an Admin; it locks and unlocks an
          end user. A group change ⇒ policy.apply (trigger group_change) applied on the desired version — no new version;
          a group listed in TenantSettings.policy.sensitive_groups ⇒ 202 + tenant approval, the Admin's own approval ⇒
          403, the Owner (step-up) approves ⇒ executed with the approved members
Standard library only. Passwords, TOTP keys, cookies, CSRF tokens and pre-auth keys stay in this process (and its
redaction set); the pre-auth key reaches the client container through a 0400 file.
"""
from __future__ import annotations

import json
import secrets
import time

import checks
import urllib.parse

from backend import TOTP, Browser, KeycloakAdmin, admin_cmd, forms, keycloak_login, portal_login, psql
from dualcontrol import first_login, invite, new_user, owner_session, psql_one, tenant_id, unsafe
from stack import Stack, StackError

SLUG = "tenant-a"
QUERY_A = "scope=tenant&tenant=tenant-a"


def api(st: Stack) -> str:
    return f"https://app.{st.domain}/api/v1"


def seeded(st: Stack, role: str, prefix: str) -> tuple[Browser, dict, dict]:
    """A Tenant Admin (or Owner) of tenant-a seeded by sub, signed in through Keycloak with TOTP."""
    u = new_user(st, SLUG, prefix)
    p = admin_cmd(st, ["seed-membership", "--tenant", SLUG, "--role", role, "--subject", u["sub"],
                       "--display-name", f"E2E {prefix}"])
    if p.returncode != 0:
        raise StackError(f"seed-membership {role}: {st.redact(p.stdout + p.stderr)[-300:]}")
    b, otp = Browser(st), TOTP()
    sess, _ = portal_login(st, b, f"app.{st.domain}", QUERY_A, u, otp)
    u["otp"] = otp
    return b, sess, u


def membership_of(st: Stack, sub: str) -> str:
    return psql_one(st, "SELECT m.id FROM tenant_memberships m JOIN identities i ON i.id = m.identity_id "
                    f"WHERE i.subject = '{sub}'")


def invited_member(st: Stack, ob: Browser, osess: dict, a_id: str, role: str) -> tuple[dict, Browser, dict, str]:
    """A Keycloak user invited by the Owner with role, then signed in for the first time (the invitation binds)."""
    u = new_user(st, SLUG, "e2e-mem")
    inv = invite(st, ob, osess, a_id, u["email"], role)
    if inv.status != 201:
        raise StackError(f"invitation: HTTP {inv.status} {inv.body[:200]!r}")
    status, code, b = first_login(st, u)
    if status != 302:
        raise StackError(f"first login of the invited member: HTTP {status} {code}")
    s = b.get(f"{api(st)}/auth/session").json()
    st.secret_values.add(s.get("csrf_token", ""))
    return u, b, s, inv.json().get("id", "")


def wait_job(st: Stack, job_id: str, timeout: float = 120) -> tuple[str, dict]:
    """The final status and the output of a job (the database read model)."""
    end, status, out = time.time() + timeout, "", {}
    while time.time() < end:
        rows = psql(st, f"SELECT status, coalesce(output::text, '{{}}') FROM provisioning_jobs WHERE id = '{job_id}'")
        if rows and len(rows[0]) == 2:
            status, out = rows[0][0], json.loads(rows[0][1])
            if status in ("succeeded", "failed", "cancelled"):
                break
        time.sleep(2)
    return status, out


def start_client(st: Stack, key_file: str, host: str) -> str:
    """A long-running official client (userspace, state in memory) joining tenant-a with the key file; its name."""
    name = st.name(f"e2e92-{host}")
    st.docker("rm", "-f", name, check=False)
    script = ('tailscaled --tun=userspace-networking --state=mem: --socket=/tmp/ts.sock --statedir=/tmp/st '
              '>/tmp/tsd.log 2>&1 & i=0; while [ ! -S /tmp/ts.sock ] && [ $i -lt 50 ]; do sleep 0.2; i=$((i+1)); done; '
              'timeout 45 tailscale --socket=/tmp/ts.sock up --login-server="$LOGIN" --auth-key=file:/run/mg-e2e/authkey '
              '--hostname="$HN" --accept-dns=false --timeout=30s >/tmp/up.log 2>&1; exec sleep 900')
    st.docker("run", "-d", "--name", name, "--network", st.name("edge"),
              "--add-host", f"tenant-a.{st.mesh}:{st.edge_ip}", "--read-only", "--tmpfs", "/tmp", "--cap-drop", "ALL",
              "--security-opt", "no-new-privileges:true", "-v", f"{st.work / 'ca'}:/etc/mg-ci-ca:ro",
              "-v", f"{key_file}:/run/mg-e2e/authkey:ro", "-e", "SSL_CERT_FILE=/etc/mg-ci-ca/ca.crt",
              "-e", "SSL_CERT_DIR=/etc/mg-ci-ca", "-e", "TS_NO_LOGS_NO_SUPPORT=true", "-e", f"LOGIN=https://{SLUG}.{st.mesh}",
              "-e", f"HN={host}", "--entrypoint", "sh", st.images["tailscale"], "-c", script)
    return name


def client_status(st: Stack, name: str) -> dict:
    p = st.docker("exec", name, "tailscale", "--socket=/tmp/ts.sock", "status", "--json", check=False)
    try:
        return json.loads(p.stdout or "{}")
    except ValueError:
        return {}


def nodes_of(st: Stack, user: str) -> list[dict]:
    nodes = json.loads(st.headscale(SLUG, "nodes", "list", "-o", "json").stdout or "[]") or []
    return [n for n in nodes if (n.get("user") or {}).get("name") == user]


def keys_of(st: Stack, user_id: str) -> list[dict]:
    keys = json.loads(st.headscale(SLUG, "preauthkeys", "list", "-o", "json").stdout or "[]") or []
    return [k for k in keys if str((k.get("user") or {}).get("id", "")) == user_id]


def password_once(st: Stack, b: Browser, auth_url: str, user: dict) -> str:
    """One password submission at Keycloak (never more: brute-force detection must not lock the account): "accepted"
    when Keycloak goes on (OTP step or the redirect to the Portal), else "refused"."""
    r = b.get(auth_url)
    for _ in range(4):
        if r.status in (302, 303):
            r = b.get(r.header("Location"))
    f = next((x for x in forms(r.body.decode("utf-8", "replace")) if "password" in x["inputs"]), None)
    if r.status != 200 or not f:
        return f"no login form (HTTP {r.status})"
    v = {**f["inputs"], "username": user["username"], "password": user["password"]}
    r = b.request("POST", f["action"], urllib.parse.urlencode(v).encode(), {"Content-Type": "application/x-www-form-urlencoded"})
    page = r.body.decode("utf-8", "replace")
    if r.status in (302, 303) or any("otp" in x["inputs"] for x in forms(page)):
        return "accepted"
    return "refused"


def expired(ts: dict | None, now: float) -> bool:
    return bool(ts) and int(ts.get("seconds", 0)) <= now


# ---------------------------------------------------------------------------------------------------- E2E-92
def check_offboard(r, st: Stack, state: dict) -> None:
    ob, osess, owner = owner_session(st, SLUG)
    a_id = tenant_id(st, SLUG)
    state.update(owner_browser=ob, owner_session=osess, owner=owner, a_id=a_id)
    tb, tsess, admin = seeded(st, "tenant_admin", "e2e92-ta")
    state.update(admin_browser=tb, admin_session=tsess, admin=admin)
    u, ub, usess, inv_id = invited_member(st, ob, osess, a_id, "end_user")
    mid = membership_of(st, u["sub"])
    hs_user = f"mg-{mid}"
    rows, conds = [], []

    def cond(name: str, good: bool, row: str) -> None:
        conds.append((name, good))
        rows.append(f"[{'ok' if good else 'FAIL'} {name}] {row}")

    # the invitation's IdP job (member.idp_invite): the Keycloak account is found and e-mailed its required actions
    inv_job = psql_one(st, f"SELECT id FROM provisioning_jobs WHERE kind = 'member.idp_invite' AND resource_id = '{inv_id}'")
    istatus, iout = wait_job(st, inv_job, 90) if inv_job else ("none", {})
    cond("idp_invite", istatus == "succeeded" and iout.get("idp") == "invited" and iout.get("email_sent") is True
         and iout.get("created") is False, f"member.idp_invite {istatus} {iout}")

    # the member's Headscale user, a node and a spare reusable key
    uid = str(json.loads(st.headscale(SLUG, "users", "create", hs_user, "-o", "json").stdout)["id"])
    key = json.loads(st.headscale(SLUG, "preauthkeys", "create", "-u", uid, "--reusable", "-e", "30m", "-o", "json").stdout)["key"]
    spare = json.loads(st.headscale(SLUG, "preauthkeys", "create", "-u", uid, "--reusable", "-e", "30m", "-o", "json").stdout)["key"]
    st.secret_values.update({key, spare})
    d = st.fresh_dir("secrets/e2e92")
    st.write_private(d / "authkey", key)
    st.helper("chown 0:0 /w/secrets/e2e92/authkey; chmod 0400 /w/secrets/e2e92/authkey", f"{st.work}:/w")
    client = start_client(st, str(d / "authkey"), "e2e92-member")
    state["client"] = client
    running = checks.wait(lambda: client_status(st, client).get("BackendState") == "Running", 60)
    node = (nodes_of(st, hs_user) or [{}])[0]
    cond("enrolled", bool(running) and bool(node), f"client Running {bool(running)}, node {node.get('id')} of {hs_user}")

    # offboard by the Tenant Admin
    off = tb.request("DELETE", f"{api(st)}/tenants/{a_id}/users/{mid}", b"", unsafe(st, tsess))
    body = off.json()
    job_id = ((body.get("offboarding") or {}).get("job_id")) or ""
    cond("accepted", off.status == 202 and body.get("status") == "offboarded"
         and off.header("Location") == f"/api/v1/tenants/{a_id}/jobs/{job_id}"
         and (body.get("offboarding") or {}).get("state") == "pending",
         f"DELETE {off.status} status {body.get('status')} offboarding {body.get('offboarding')}")
    gone = ub.get(f"{api(st)}/auth/session").status
    cond("session_refused", gone == 401, f"GET /auth/session of the member after the offboarding: {gone}")
    status, out = wait_job(st, job_id, 120)
    cond("job", status == "succeeded" and out.get("nodes_expired") == 1 and out.get("keys_expired") == 2
         and out.get("idp") == "disabled", f"member.offboard {status} {out}")
    now = time.time() + 5
    n = (nodes_of(st, hs_user) or [{}])[0]
    ks = keys_of(st, uid)
    cond("headscale", expired(n.get("expiry"), now) and len(ks) == 2 and all(expired(k.get("expiration"), now) for k in ks),
         f"node expiry {n.get('expiry')}, keys {[k.get('expiration') for k in ks]}")
    cs = checks.wait(lambda: (lambda s: s if s.get("BackendState") == "NeedsLogin" or (s.get("Self") or {}).get("Expired")
                                        else None)(client_status(st, client)), 60)
    cond("client_expired", bool(cs), f"client {((cs or {}).get('BackendState'))} expired {((cs or {}).get('Self') or {}).get('Expired')}")
    kc = KeycloakAdmin(st)
    kuser = kc._call("GET", f"/admin/realms/{SLUG}/users/{u['sub']}")
    cond("idp_disabled", kuser.get("enabled") is False, f"Keycloak user enabled={kuser.get('enabled')}")
    view = ob.get(f"{api(st)}/tenants/{a_id}/users/{mid}").json()
    cond("applied", (view.get("offboarding") or {}).get("state") == "applied", f"GET /users/{{id}} {view.get('offboarding')}")
    pair = psql_one(st, "SELECT string_agg(action || '/' || outcome, ',' ORDER BY occurred_at, id) FROM audit_events "
                    f"WHERE resource_id = '{mid}' AND action LIKE 'user.offboard%'")
    cond("audit", pair == "user.offboard.requested/success,user.offboard.succeeded/success", f"audit {pair}")
    ident = psql_one(st, f"SELECT status FROM identities WHERE subject = '{u['sub']}'")

    # signing in again: refused at Keycloak (disabled), then — account enabled again at the IdP — by the Portal
    b2 = Browser(st)
    start = b2.get(f"{api(st)}/auth/login?{QUERY_A}")
    at_idp = password_once(st, b2, start.header("Location"), u)
    kc._call("PUT", f"/admin/realms/{SLUG}/users/{u['sub']}", body={"enabled": True})
    b3 = Browser(st)
    start = b3.get(f"{api(st)}/auth/login?{QUERY_A}")
    cb, _ = keycloak_login(st, b3, start.header("Location"), u, u["otp"], f"app.{st.domain}")
    again = b3.get(cb)
    reason = psql_one(st, "SELECT details ->> 'reason' FROM audit_events WHERE action = 'auth.login' AND outcome = 'denied' "
                      f"AND actor_identity_id = (SELECT id FROM identities WHERE subject = '{u['sub']}') "
                      "ORDER BY occurred_at DESC LIMIT 1")
    kc._call("PUT", f"/admin/realms/{SLUG}/users/{u['sub']}", body={"enabled": False})
    cond("relogin_refused", at_idp == "refused" and again.status == 403 and reason == "identity_disabled"
         and ident == "disabled", f"Keycloak {at_idp}; Portal callback {again.status} reason {reason}; identity {ident}")

    st.docker("rm", "-f", client, check=False)
    for x in nodes_of(st, hs_user):
        st.headscale(SLUG, "nodes", "delete", "--identifier", str(x["id"]), "--force", check=False)
    st.helper("rm -rf /w/secrets/e2e92", f"{st.work}:/w")
    r.add("E2E-92", "P4-T09 offboard (V-23): thành viên được mời qua API (member.idp_invite: tài khoản Keycloak được tìm "
          "thấy, gửi thư required actions) đăng nhập, client chính thức vào tenant-a dưới user mg-<membership>; Tenant "
          "Admin offboard ⇒ 202 + Location job, session Portal bị từ chối ngay; job member.offboard expire node + mọi "
          "pre-auth key, vô hiệu user ở Keycloak; client thấy key hết hạn; trạng thái applied; cặp audit đóng; đăng nhập "
          "lại bị từ chối ở Keycloak và — tài khoản bật lại ở IdP — ở Portal (403 identity_disabled)",
          all(g for _, g in conds), "; ".join(rows), limit=1600)


# ---------------------------------------------------------------------------------------------------- E2E-93
def check_rules_and_groups(r, st: Stack, state: dict) -> None:
    ob, osess, owner, a_id = state["owner_browser"], state["owner_session"], state["owner"], state["a_id"]
    tb, tsess, admin = state["admin_browser"], state["admin_session"], state["admin"]
    _, _, admin2 = seeded(st, "tenant_admin", "e2e93-ta2")
    owner_mid, admin_id = membership_of(st, owner["sub"]), psql_one(st, f"SELECT id FROM identities WHERE subject = '{admin['sub']}'")
    admin2_mid = membership_of(st, admin2["sub"])
    u, _, _, _ = invited_member(st, ob, osess, a_id, "tenant_viewer")
    user_mid = membership_of(st, u["sub"])
    users = f"{api(st)}/tenants/{a_id}/users/"
    rows, conds = [], []

    def cond(name: str, good: bool, row: str) -> None:
        conds.append((name, good))
        rows.append(f"[{'ok' if good else 'FAIL'} {name}] {row}")

    def denied(action: str) -> str:
        return psql_one(st, "SELECT coalesce(details ->> 'reason', '') FROM audit_events WHERE action = "
                        f"'{action}' AND outcome = 'denied' AND actor_identity_id = '{admin_id}' ORDER BY occurred_at DESC LIMIT 1")

    def etag(path: str) -> str:
        return ob.get(path).header("ETag")

    hdr = unsafe(st, tsess, **{"If-Match": '"1"'})
    refusals = []
    for name, method, path, body, action, reason in (
            ("lock Owner", "PATCH", users + owner_mid, {"status": "locked"}, "user.update", "target_not_lower"),
            ("offboard Admin", "DELETE", users + admin2_mid, None, "user.offboard", "target_not_lower"),
            ("demote Admin", "PUT", users + admin2_mid + "/role", {"role": "tenant_viewer"}, "user.role.set", "target_not_lower"),
            ("give Admin", "PUT", users + user_mid + "/admin-role", {"role": "tenant_admin"}, "user.admin_role.set", "no_grant")):
        rec = tb.request(method, path, json.dumps(body).encode() if body else b"", hdr)
        got = denied(action)
        refusals.append(f"{name}: {rec.status} {got}")
        cond(name, rec.status == 403 and got == reason, f"{name} {rec.status} reason {got}")
    inv = invite(st, tb, tsess, a_id, f"e2e93-adm-{secrets.token_hex(3)}@example.invalid", "tenant_admin")
    cond("invite Admin", inv.status == 403, f"invitation tenant_admin by the TA: {inv.status}")
    lock = tb.request("PATCH", users + user_mid, json.dumps({"status": "locked"}).encode(),
                      unsafe(st, tsess, **{"If-Match": etag(users + user_mid)}))
    unlock = tb.request("PATCH", users + user_mid, json.dumps({"status": "active"}).encode(),
                        unsafe(st, tsess, **{"If-Match": etag(users + user_mid)}))
    cond("lock end user", lock.status == 200 and lock.json().get("status") == "locked" and unlock.status == 200
         and unlock.json().get("status") == "active", f"lock {lock.status}, unlock {unlock.status}")

    # a group change ⇒ policy.apply (group_change) on the desired version
    desired = psql_one(st, f"SELECT desired_policy_version_id FROM tenants WHERE id = '{a_id}'")
    versions = psql_one(st, f"SELECT count(*) FROM policy_versions WHERE tenant_id = '{a_id}'")
    groups = f"{api(st)}/tenants/{a_id}/groups"
    g = tb.request("POST", groups, json.dumps({"name": f"e2e93-{secrets.token_hex(2)}"}).encode(),
                   unsafe(st, tsess, **{"Idempotency-Key": "e2e93-" + secrets.token_hex(6)})).json()
    gpath = f"{groups}/{g.get('id')}"
    put = tb.request("PUT", gpath + "/members", json.dumps({"membership_ids": [user_mid]}).encode(),
                     unsafe(st, tsess, **{"If-Match": etag(gpath)}))
    job = psql_one(st, f"SELECT id FROM provisioning_jobs WHERE tenant_id = '{a_id}' AND kind = 'policy.apply' "
                   "AND input ->> 'trigger' = 'group_change' ORDER BY created_at DESC LIMIT 1")
    jstatus, jout = wait_job(st, job, 120)
    app = psql(st, f"SELECT trigger, state, policy_version_id FROM policy_applications WHERE tenant_id = '{a_id}' "
                   "ORDER BY created_at DESC, id DESC LIMIT 1")
    cond("group_change", put.status == 200 and put.json().get("member_count") == 1 and jstatus == "succeeded"
         and bool(app) and app[0][:2] == ["group_change", "applied"] and app[0][2] == desired
         and psql_one(st, f"SELECT count(*) FROM policy_versions WHERE tenant_id = '{a_id}'") == versions,
         f"PUT members {put.status}; policy.apply {jstatus} {jout}; application {app}; desired {desired[:8]}")

    # sensitive: 202 + approval (the Admin signs in again: the request needs a step-up); self-approval 403; the Owner
    # (step-up) approves ⇒ executed with the approved set
    tsess, _ = portal_login(st, tb, f"app.{st.domain}", QUERY_A, admin, admin["otp"])
    psql(st, f"UPDATE tenants SET settings = jsonb_set(settings, '{{policy}}', jsonb_build_object('sensitive_groups', "
             f"jsonb_build_array('{g.get('id')}'))) WHERE id = '{a_id}'")
    req = tb.request("PUT", gpath + "/members", json.dumps({"membership_ids": [user_mid, admin2_mid]}).encode(),
                     unsafe(st, tsess, **{"If-Match": etag(gpath)}))
    a = req.json()
    unchanged = ob.get(gpath).json().get("member_count")
    approvals = f"{api(st)}/tenants/{a_id}/approvals/{a.get('id')}"
    decision = json.dumps({"payload_sha256": a.get("payload_sha256")}).encode()
    self_ = tb.request("POST", approvals + "/approve", decision, unsafe(st, tsess))
    osess, _ = portal_login(st, ob, f"app.{st.domain}", QUERY_A, owner, owner["otp"])     # step-up
    done = ob.request("POST", approvals + "/approve", decision, unsafe(st, osess))
    after = ob.get(gpath).json()
    cond("sensitive", req.status == 202 and req.header("Location") == f"/api/v1/tenants/{a_id}/approvals/{a.get('id')}"
         and a.get("action") == "tenant.group.set_members" and unchanged == 1 and self_.status == 403
         and done.status == 200 and done.json().get("status") == "executed" and after.get("member_count") == 2,
         f"PUT {req.status} {a.get('action')} (members before approval {unchanged}); self {self_.status}; "
         f"Owner {done.status} {done.json().get('status')}; members {after.get('member_count')}")
    psql(st, f"UPDATE tenants SET settings = settings - 'policy' WHERE id = '{a_id}'")
    r.add("E2E-93", "P4-T09 quy tắc 3a + group: Tenant Admin bị từ chối (403, audit lý do của guard) khi khóa Owner, "
          "offboard/hạ Admin khác, gán role Admin, mời Admin; khóa/mở khóa end user được; đổi thành viên group ⇒ "
          "policy.apply trigger group_change applied trên version desired, không version mới; group sensitive ⇒ 202 + "
          "phê duyệt tenant, tự duyệt ⇒ 403, Owner (step-up) duyệt ⇒ executed đúng tập đã duyệt",
          all(g for _, g in conds), "; ".join(rows), limit=1600)


def run_all(r, st: Stack, guarded) -> None:
    """E2E-92, E2E-93 in order (E2E-93 reuses the Owner and Admin of E2E-92)."""
    state: dict = {}
    try:
        if guarded(r, "E2E-92", check_offboard, st, state) is None and "admin_session" in state:
            guarded(r, "E2E-93", check_rules_and_groups, st, state)
    finally:
        if state.get("client"):
            st.docker("rm", "-f", state["client"], check=False)
