"""P3-T05a invitations and P3-T04a dual control on the dev/CI stack — FUNCTIONAL only (§22.1): the api built from the
tree, real Keycloak logins with TOTP through the edge on app., PostgreSQL of the stack.

  E2E-36  P3-T05a invitation accepted at the first login: a Tenant Owner of tenant-a (seeded by sub) invites an e-mail
          as tenant_admin through POST /tenants/{t}/invitations (CSRF, Idempotency-Key — a replay returns the same
          invitation, no token in the answer); the Keycloak user with that verified e-mail signs in for the first time
          ⇒ session with the tenant_admin membership of tenant-a; the invitation is accepted by that identity
          (idp_id of tenant-a), invitation.accept audited, the outbox holds the invitation without its token
  E2E-37  P3-T05a refusals at the first login: another e-mail than the pending invitation ⇒ 403, audited
          no_invitation, the invitation stays pending; an expired invitation ⇒ 403 invitation_expired, the invitation
          becomes expired; neither person gets a session nor a membership
  E2E-38  P3-T04a dual control in the tenant: a request of the Owner (written as the 2P operations of later tasks
          write it) shows its exact payload and hash; the Owner's self-approval ⇒ 403; the invited Admin with a session
          older than 15 min ⇒ 401 reauth_required; after a fresh sign-in (password + OTP) the approval reaches the
          action registry ⇒ 409 (no executor of this action in this build — nothing runs); the Admin's rejection ⇒
          rejected, audited with both persons; an Owner of tenant-b ⇒ 404 on tenant-a's path and on its own
Standard library only. Passwords, TOTP keys, cookies and CSRF tokens stay in this process (and its redaction set).
"""
from __future__ import annotations

import hashlib
import json
import secrets

from backend import TOTP, Browser, KeycloakAdmin, admin_cmd, keycloak_login, portal_login, psql
from stack import Stack, StackError

QUERY_A = "scope=tenant&tenant=tenant-a"


def psql_one(st: Stack, sql: str) -> str:
    """The first column of the first row of a query as the cluster superuser ("" when none)."""
    rows = psql(st, sql)
    return rows[0][0] if rows else ""


def tenant_id(st: Stack, slug: str) -> str:
    return psql_one(st, f"SELECT id FROM tenants WHERE slug = '{slug}'")


def new_user(st: Stack, realm: str, prefix: str) -> dict:
    """A Keycloak user of realm with a verified e-mail <username>@example.invalid (backend.KeycloakAdmin.create_user)."""
    kc = KeycloakAdmin(st)                       # a fresh admin token (the master token lives 60 s)
    u = {"username": f"{prefix}-" + secrets.token_hex(3), "password": secrets.token_urlsafe(18)}
    st.secret_values.add(u["password"])
    u["sub"] = kc.create_user(realm, u["username"], u["password"])
    u["email"] = f"{u['username']}@example.invalid"
    return u


def owner_session(st: Stack, slug: str) -> tuple[Browser, dict, dict]:
    """A Tenant Owner of slug seeded by sub (P2-T11a), signed in through Keycloak with TOTP."""
    u = new_user(st, slug, f"e2e-own-{slug[-1]}")
    p = admin_cmd(st, ["seed-membership", "--tenant", slug, "--role", "tenant_owner", "--subject", u["sub"],
                       "--display-name", f"E2E Owner {slug}"])
    if p.returncode != 0:
        raise StackError(f"seed-membership {slug}: {st.redact(p.stdout + p.stderr)[-300:]}")
    b, otp = Browser(st), TOTP()
    sess, _ = portal_login(st, b, f"app.{st.domain}", f"scope=tenant&tenant={slug}", u, otp)
    u["otp"] = otp
    return b, sess, u


def unsafe(st: Stack, sess: dict, **extra) -> dict:
    return {"Origin": f"https://app.{st.domain}", "X-CSRF-Token": sess["csrf_token"], "Content-Type": "application/json",
            **extra}


def first_login(st: Stack, u: dict) -> tuple[int, str, Browser]:
    """The first login of u on app. for tenant-a; returns the callback status, the problem code and the browser."""
    b, otp = Browser(st), TOTP()
    u["otp"] = otp
    start = b.get(f"https://app.{st.domain}/api/v1/auth/login?{QUERY_A}")
    if start.status != 302:
        raise StackError(f"GET /auth/login: HTTP {start.status}")
    cb, _ = keycloak_login(st, b, start.header("Location"), u, otp, f"app.{st.domain}")
    r = b.get(cb)
    return r.status, r.json().get("code", ""), b


def denied_reason(st: Stack, identity_sub: str) -> str:
    """The reason of the last denied auth.login of the identity of that sub."""
    return psql_one(st, "SELECT details ->> 'reason' FROM audit_events WHERE action = 'auth.login' AND outcome = 'denied' "
                    f"AND actor_identity_id = (SELECT id FROM identities WHERE subject = '{identity_sub}') "
                    "ORDER BY occurred_at DESC LIMIT 1")


def invite(st: Stack, b: Browser, sess: dict, a_id: str, email: str, role: str, key: str | None = None):
    body = json.dumps({"email": email, "role": role}).encode()
    return b.request("POST", f"https://app.{st.domain}/api/v1/tenants/{a_id}/invitations", body,
                     unsafe(st, sess, **{"Idempotency-Key": key or "e2e-inv-" + secrets.token_hex(8)}))


# ---------------------------------------------------------------------------------------------------- E2E-36
def check_invitation_accepted(r, st: Stack, state: dict) -> None:
    b, sess, owner = owner_session(st, "tenant-a")
    a_id = tenant_id(st, "tenant-a")
    state.update(owner_browser=b, owner_session=sess, owner=owner, a_id=a_id)
    invitee = new_user(st, "tenant-a", "e2e-invitee")
    key = "e2e-inv-" + secrets.token_hex(8)
    created = invite(st, b, sess, a_id, invitee["email"].upper(), "tenant_admin", key)
    replay = invite(st, b, sess, a_id, invitee["email"].upper(), "tenant_admin", key)
    inv = created.json()
    no_token = "token" not in created.body.decode("utf-8", "replace").lower()
    status, code, ib = first_login(st, invitee)
    s = ib.get(f"https://app.{st.domain}/api/v1/auth/session").json() if status == 302 else {}
    if s:
        st.secret_values.add(s.get("csrf_token", ""))
    m = (s.get("memberships") or [{}])[0]
    row = psql(st, f"SELECT i.status, i.accepted_identity_id = id2.id, i.idp_id = id2.idp_id FROM tenant_invitations i, "
                    f"identities id2 WHERE i.id = '{inv.get('id')}' AND id2.subject = '{invitee['sub']}'")
    audited = psql_one(st, "SELECT count(*) FROM audit_events WHERE action = 'invitation.accept' AND outcome = 'success' "
                       f"AND resource_id = '{inv.get('id')}'")
    outbox = psql(st, f"SELECT payload::text FROM notification_outbox WHERE kind = 'tenant.invitation' "
                       f"AND recipient_email = '{invitee['email']}'")
    outbox_ok = len(outbox) == 1 and inv.get("id", "?") in outbox[0][0] and "token" not in outbox[0][0]
    state.update(invitee=invitee, invitee_browser=ib, invitee_session=s)
    ok = (created.status == 201 and replay.status == 201 and replay.json().get("id") == inv.get("id") and no_token
          and inv.get("status") == "pending" and status == 302 and m.get("role") == "tenant_admin"
          and m.get("tenant_id") == a_id and row == [["accepted", "t", "t"]] and audited == "1" and outbox_ok)
    r.add("E2E-36", "P3-T05a: lời mời (Owner tenant-a mời tenant_admin qua API, CSRF + Idempotency-Key — lặp lại trả "
          "cùng lời mời, không có token) được gắn ở lần đăng nhập đầu (Keycloak + TOTP) của user có email đã xác minh "
          "trùng (khác hoa thường): session có membership tenant_admin của tenant-a; lời mời accepted bởi đúng identity "
          "của IdP tenant-a; audit invitation.accept; outbox tenant.invitation không chứa token", ok,
          f"tạo {created.status}, lặp {replay.status} (cùng id {replay.json().get('id') == inv.get('id')}), không token "
          f"{no_token}; đăng nhập đầu {status} {code}; membership {m.get('role')}@{m.get('tenant_id') == a_id}; lời mời "
          f"{row}; audit {audited}; outbox {outbox_ok}")


# ---------------------------------------------------------------------------------------------------- E2E-37
def check_invitation_refusals(r, st: Stack, state: dict) -> None:
    b, sess, a_id = state["owner_browser"], state["owner_session"], state["a_id"]
    # another e-mail: an invitation is pending for alice-…, bob-… signs in for the first time
    alice = f"e2e-alice-{secrets.token_hex(3)}@example.invalid"
    pending = invite(st, b, sess, a_id, alice, "tenant_viewer").json()
    bob = new_user(st, "tenant-a", "e2e-bob")
    s1, c1, b1 = first_login(st, bob)
    why1 = denied_reason(st, bob["sub"])
    still = psql_one(st, f"SELECT status FROM tenant_invitations WHERE id = '{pending.get('id')}'")
    # expired: the invitation of carol is moved into the past (created and expiry, as superuser), carol signs in
    carol = new_user(st, "tenant-a", "e2e-carol")
    late = invite(st, b, sess, a_id, carol["email"], "tenant_viewer").json()
    psql(st, f"UPDATE tenant_invitations SET created_at = now() - interval '2 days', expires_at = now() - interval '1 day' "
              f"WHERE id = '{late.get('id')}'")
    s2, c2, b2 = first_login(st, carol)
    why2 = denied_reason(st, carol["sub"])
    expired = psql_one(st, f"SELECT status FROM tenant_invitations WHERE id = '{late.get('id')}'")
    members = psql_one(st, "SELECT count(*) FROM tenant_memberships m JOIN identities i ON i.id = m.identity_id "
                       f"WHERE i.subject IN ('{bob['sub']}', '{carol['sub']}')")
    sessions = [x.get(f"https://app.{st.domain}/api/v1/auth/session").status for x in (b1, b2)]
    ok = (s1 == 403 and c1 == "forbidden" and why1 == "no_invitation" and still == "pending" and s2 == 403
          and c2 == "forbidden" and why2 == "invitation_expired" and expired == "expired" and members == "0"
          and sessions == [401, 401])
    r.add("E2E-37", "P3-T05a: lần đăng nhập đầu bị từ chối khi email khác lời mời đang chờ (403, audit no_invitation, "
          "lời mời vẫn pending) và khi lời mời đã hết hạn (403, audit invitation_expired, lời mời chuyển expired); không "
          "session, không membership", ok,
          f"email khác: {s1} {c1} lý do {why1}, lời mời {still}; hết hạn: {s2} {c2} lý do {why2}, lời mời {expired}; "
          f"membership {members}; GET /auth/session {sessions}")


# ---------------------------------------------------------------------------------------------------- E2E-38
def check_dual_control(r, st: Stack, state: dict) -> None:
    ob, osess, owner, a_id = state["owner_browser"], state["owner_session"], state["owner"], state["a_id"]
    invitee, ib = state["invitee"], state["invitee_browser"]
    api = f"https://app.{st.domain}/api/v1/tenants/{a_id}/approvals"
    payload = {"setting": "policy.four_eyes", "value": False}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    owner_id = psql_one(st, f"SELECT id FROM identities WHERE subject = '{owner['sub']}'")
    req_id = psql_one(st, "INSERT INTO approval_requests (scope, tenant_id, action, resource_type, resource_id, payload, "
                      "payload_sha256, requested_by_identity_id, reason, expires_at) VALUES ('tenant', "
                      f"'{a_id}', 'tenant.settings.disable_four_eyes', 'settings', 'policy', '{canonical}'::jsonb, "
                      f"'{digest}', '{owner_id}', 'E2E', now() + interval '1 day') RETURNING id")
    seen = ob.get(f"{api}/{req_id}")
    view = seen.json()
    view_ok = seen.status == 200 and view.get("payload") == payload and view.get("payload_sha256") == digest
    decision = json.dumps({"payload_sha256": digest}).encode()
    self_ = ob.request("POST", f"{api}/{req_id}/approve", decision, unsafe(st, osess))
    # the invited Admin: a session older than the step-up window, then a fresh sign-in (password + OTP)
    invitee_id = psql_one(st, f"SELECT id FROM identities WHERE subject = '{invitee['sub']}'")
    psql(st, f"UPDATE sessions SET auth_time = now() - interval '20 minutes' WHERE identity_id = '{invitee_id}' "
              "AND revoked_at IS NULL")
    isess = state["invitee_session"]
    stale = ib.request("POST", f"{api}/{req_id}/approve", decision, unsafe(st, isess))
    isess, steps = portal_login(st, ib, f"app.{st.domain}", QUERY_A, invitee, invitee["otp"])
    fresh = ib.request("POST", f"{api}/{req_id}/approve", decision, unsafe(st, isess))
    pending = psql_one(st, f"SELECT status FROM approval_requests WHERE id = '{req_id}'")
    rejected = ib.request("POST", f"{api}/{req_id}/reject", b"", unsafe(st, isess))
    audited = psql_one(st, "SELECT count(*) FROM audit_events WHERE action = 'approval.reject' AND outcome = 'success' "
                       f"AND actor_identity_id = '{invitee_id}' AND details ->> 'requested_by_identity_id' = '{owner_id}'")
    denials = {row[0]: row[1] for row in psql(st, "SELECT details ->> 'reason', count(*) FROM audit_events WHERE "
               f"action = 'approval.approve' AND outcome IN ('denied', 'failure') AND resource_id = '{req_id}' GROUP BY 1")
               if len(row) == 2}
    # an Owner of tenant-b: A's request is invisible on A's path (not a member) and on B's own path (another tenant's)
    bb, bsess, _ = owner_session(st, "tenant-b")
    b_id = tenant_id(st, "tenant-b")
    cross = [bb.get(f"{api}/{req_id}").status, bb.get(f"https://app.{st.domain}/api/v1/tenants/{b_id}/approvals/{req_id}").status,
             bb.request("POST", f"https://app.{st.domain}/api/v1/tenants/{b_id}/approvals/{req_id}/approve", decision,
                        unsafe(st, bsess)).status]
    ok = (view_ok and self_.status == 403 and stale.status == 401 and stale.json().get("code") == "reauth_required"
          and fresh.status == 409 and pending == "pending" and rejected.status == 200
          and rejected.json().get("status") == "rejected" and audited == "1" and cross == [404, 404, 404]
          and denials.get("self_approval") == "1" and denials.get("step_up_required") == "1"
          and denials.get("action_unavailable") == "1")
    r.add("E2E-38", "P3-T04a: yêu cầu phê duyệt phạm vi tenant — người duyệt thấy đúng payload + hash; Owner tự duyệt ⇒ "
          "403; Admin được mời với phiên quá 15 phút ⇒ 401 reauth_required; đăng nhập lại (mật khẩu + OTP) ⇒ duyệt tới "
          "registry ⇒ 409 (bản này không có executor của thao tác — không gì chạy, vẫn pending); Admin từ chối ⇒ rejected, "
          "audit ghi cả hai người; Owner tenant-b ⇒ 404 trên path của A và của chính B", ok,
          f"xem {seen.status} payload/hash {view_ok}; tự duyệt {self_.status}; phiên cũ {stale.status} "
          f"{stale.json().get('code')}; đăng nhập lại {steps}; duyệt {fresh.status} ({pending}); từ chối "
          f"{rejected.status} {rejected.json().get('status')}; audit reject {audited}; lý do từ chối {denials}; "
          f"tenant-b {cross}")


def run_all(r, st: Stack, guarded) -> None:
    """E2E-36 … E2E-38 in order (each builds on the state of the previous one)."""
    state: dict = {}
    if guarded(r, "E2E-36", check_invitation_accepted, st, state) is None and "invitee" in state:
        guarded(r, "E2E-37", check_invitation_refusals, st, state)
        guarded(r, "E2E-38", check_dual_control, st, state)
