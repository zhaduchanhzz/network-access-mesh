"""P4-T03a administration on the dev/CI stack — FUNCTIONAL only (§22.1): the api built from the tree, real Keycloak
logins with TOTP through the edge on admin. (the two Super Admins of E2E-24/E2E-42) and app. (an Owner and an Admin of
tenant-a, an Owner of tenant-b), PostgreSQL of the stack.

  E2E-94  §20 P4-T03a on the platform side: PATCH /platform/identity-providers/{id} naming issuer ⇒ 422; a change of the
          claim constraints of tenant-a's IdP row ⇒ 202 + Location of a platform approval request — NOT in effect (the
          tenant's Owner reads the IdP unchanged), visible to the tenant (its audit lists
          identity_provider.platform_change.request, its Owner is notified idp.config_changed "requested"); the
          requester's own approval ⇒ 403; the second Super Admin approves ⇒ executed, in effect, the tenant's audit
          lists identity_provider.platform_change.apply with both persons. The Super Admin role through 2P only: a new
          platform user (sub of the platform realm, POST /platform/users) gets super_admin when the second Super Admin
          approves (its session then reads platform_role super_admin) and loses it the same way (its session revoked)
  E2E-95  the tenant side: PATCH /settings refuses a security key (422); the Owner (step-up) turns policy 4-eyes on ⇒ 200;
          turning it off ⇒ 202 + Location of a TENANT approval request (the Admin is notified approval.requested), not in
          effect; the Owner's own approval ⇒ 403; the Admin (another person, step-up) approves ⇒ executed, 4-eyes off;
          an Owner of tenant-b reads tenant-a's settings ⇒ 404; POST /request-deletion with another slug ⇒ 422, with
          the slug ⇒ 200 (the platform notified once, a platform audit event), the tenant still active
Standard library only. Passwords, TOTP keys, cookies and CSRF tokens stay in this process (and its redaction set).
"""
from __future__ import annotations

import json
import secrets

from backend import TOTP, Browser, KeycloakAdmin, portal_login
from dualcontrol import owner_session, psql_one, tenant_id, unsafe
from idpadmin import admin_unsafe, platform_session
from members import seeded
from stack import Stack, StackError


def _admin(st: Stack) -> str:
    return f"https://admin.{st.domain}/api/v1"


def _app(st: Stack) -> str:
    return f"https://app.{st.domain}/api/v1"


class _Conds:
    def __init__(self) -> None:
        self.rows: list[str] = []
        self.ok = True

    def __call__(self, name: str, good: bool, row: str) -> None:
        self.ok = self.ok and bool(good)
        self.rows.append(f"[{'ok' if good else 'FAIL'} {name}] {row}")


# ---------------------------------------------------------------------------------------------------- E2E-94
def check_platform_admin(r, st: Stack, state: dict) -> None:
    sa1, sa2 = getattr(st, "platform_sa", None), getattr(st, "platform_sa2", None)
    if not sa1 or not sa2:
        raise StackError("no Super Admins of E2E-24 / E2E-42 (st.platform_sa, st.platform_sa2)")
    b1, s1 = platform_session(st, sa1)
    b2, s2 = platform_session(st, sa2)
    api, a_id = _admin(st), tenant_id(st, "tenant-a")
    c = _Conds()
    lst = b1.get(f"{api}/platform/identity-providers?scope=tenant&limit=200").json().get("items", [])
    idp = next((x for x in lst if x.get("tenant_id") == a_id), {})
    path = f"{api}/platform/identity-providers/{idp.get('id')}"
    tag = b1.get(path).header("ETag")
    issuer = b1.request("PATCH", path, json.dumps({"issuer": "https://evil.example/realms/x"}).encode(),
                        admin_unsafe(st, s1, **{"If-Match": tag}))
    c("issuer 422", issuer.status == 422 and issuer.json().get("code") == "validation_failed", f"issuer {issuer.status}")
    ob, osess, _ = owner_session(st, "tenant-a")
    before = ob.get(f"{_app(st)}/tenants/{a_id}/identity-provider").json().get("claim_mapping")
    req = b1.request("PATCH", path, json.dumps({"claim_mapping": {"name": "name"}}).encode(),
                     admin_unsafe(st, s1, **{"If-Match": tag}))
    appr = req.json()
    c("202 + Location", req.status == 202 and req.header("Location") == f"/api/v1/platform/approvals/{appr.get('id')}"
      and appr.get("action") == "platform.idp.update_tenant", f"PATCH {req.status} {appr.get('action')}")
    pending = ob.get(f"{_app(st)}/tenants/{a_id}/identity-provider").json().get("claim_mapping")
    c("not in effect", pending == before and "name" not in (pending or {}), f"claim_mapping {before} → {pending}")
    aud = ob.get(f"{_app(st)}/tenants/{a_id}/audit?action=identity_provider.platform_change.request&limit=50").json()
    seen = [e for e in aud.get("items", []) if (e.get("details") or {}).get("approval_id") == appr.get("id")]
    notes = [n for n in ob.get(f"{_app(st)}/tenants/{a_id}/notifications?limit=50").json().get("items", [])
             if n.get("kind") == "idp.config_changed" and (n.get("payload") or {}).get("approval_id") == appr.get("id")]
    c("tenant audit + Owner notified", len(seen) == 1 and len(notes) == 1, f"audit {len(seen)}, notifications {len(notes)}")
    decision = json.dumps({"payload_sha256": appr.get("payload_sha256")}).encode()
    self_ = b1.request("POST", f"{api}/platform/approvals/{appr.get('id')}/approve", decision, admin_unsafe(st, s1))
    done = b2.request("POST", f"{api}/platform/approvals/{appr.get('id')}/approve", decision, admin_unsafe(st, s2))
    c("self 403, second SA executes", self_.status == 403 and done.status == 200 and done.json().get("status") == "executed",
      f"self {self_.status}; second {done.status} {done.json().get('status')}")
    after = ob.get(f"{_app(st)}/tenants/{a_id}/identity-provider").json().get("claim_mapping")
    sa1_id = psql_one(st, f"SELECT id FROM identities WHERE subject = '{sa1['sub']}'")
    sa2_id = psql_one(st, f"SELECT id FROM identities WHERE subject = '{sa2['sub']}'")
    applied = psql_one(st, "SELECT count(*) FROM audit_events WHERE action = 'identity_provider.platform_change.apply' "
                       f"AND tenant_id = '{a_id}' AND details ->> 'approval_id' = '{appr.get('id')}' "
                       f"AND details ->> 'requested_by_identity_id' = '{sa1_id}' AND details ->> 'decided_by_identity_id' = '{sa2_id}'")
    c("in effect, audited", after == {"name": "name"} and applied == "1", f"claim_mapping {after}; audit apply {applied}")

    # the Super Admin role: only through 2P
    kc = KeycloakAdmin(st)
    u3 = {"username": "e2e-sa3-" + secrets.token_hex(3), "password": secrets.token_urlsafe(18)}
    st.secret_values.add(u3["password"])
    u3["sub"] = kc.create_user("platform", u3["username"], u3["password"])
    direct = b1.request("POST", f"{api}/platform/users", json.dumps({"subject": u3["sub"], "role": "super_admin"}).encode(),
                        admin_unsafe(st, s1, **{"Idempotency-Key": "e2e94-" + secrets.token_hex(6)}))
    made = b1.request("POST", f"{api}/platform/users", json.dumps({"subject": u3["sub"], "role": "platform_viewer",
                                                                    "display_name": "E2E SA3"}).encode(),
                      admin_unsafe(st, s1, **{"Idempotency-Key": "e2e94-" + secrets.token_hex(6)}))
    pu = made.json()
    c("never SA directly; created as viewer", direct.status == 403 and made.status == 201 and pu.get("role") == "platform_viewer",
      f"SA direct {direct.status}; create {made.status} {pu.get('role')}")
    otp3 = TOTP()
    b3, s3 = platform_session(st, u3, otp3)
    grant = b1.request("PUT", f"{api}/platform/users/{pu.get('id')}/super-admin-role",
                       json.dumps({"super_admin": True, "reason": "E2E-94"}).encode(), admin_unsafe(st, s1))
    g = grant.json()
    role_pending = b1.get(f"{api}/platform/users/{pu.get('id')}").json().get("role")
    granted = b2.request("POST", f"{api}/platform/approvals/{g.get('id')}/approve",
                         json.dumps({"payload_sha256": g.get("payload_sha256")}).encode(), admin_unsafe(st, s2))
    old3 = b3.get(f"{api}/auth/session").status               # the role change revoked the person's sessions
    b3, s3 = platform_session(st, u3, otp3)
    role3 = (s3.get("principal") or {}).get("platform_role")
    revoke = b1.request("PUT", f"{api}/platform/users/{pu.get('id')}/super-admin-role",
                        json.dumps({"super_admin": False, "role_after": "platform_viewer", "reason": "E2E-94"}).encode(),
                        admin_unsafe(st, s1))
    rv = revoke.json()
    revoked = b2.request("POST", f"{api}/platform/approvals/{rv.get('id')}/approve",
                         json.dumps({"payload_sha256": rv.get("payload_sha256")}).encode(), admin_unsafe(st, s2))
    gone = b3.get(f"{api}/auth/session").status
    final = b1.get(f"{api}/platform/users/{pu.get('id')}").json().get("role")
    c("SA role through 2P", grant.status == 202 and role_pending == "platform_viewer" and granted.status == 200
      and old3 == 401 and role3 == "super_admin" and revoke.status == 202 and revoked.status == 200 and gone == 401
      and final == "platform_viewer",
      f"grant {grant.status} (before approval {role_pending}); approve {granted.status}; old session {old3}; new role {role3}; "
      f"revoke {revoke.status}/{revoked.status}; session {gone}; role {final}")
    r.add("E2E-94", "P4-T03a: PATCH IdP có issuer ⇒ 422; thay đổi IdP của tenant-a do nền tảng khởi xướng ⇒ 202 + yêu cầu "
          "phê duyệt platform, CHƯA có hiệu lực (Owner đọc IdP không đổi), audit của tenant + thông báo Owner; người yêu cầu "
          "tự duyệt ⇒ 403; Super Admin thứ hai duyệt ⇒ executed, có hiệu lực, audit tenant ghi cả hai người; role Super "
          "Admin chỉ qua 2P (tạo trực tiếp ⇒ 403; gán rồi gỡ qua phê duyệt, session của người đó bị thu hồi)", c.ok,
          "; ".join(c.rows))


# ---------------------------------------------------------------------------------------------------- E2E-95
def check_tenant_settings(r, st: Stack, state: dict) -> None:
    a_id = tenant_id(st, "tenant-a")
    ob, osess, owner = owner_session(st, "tenant-a")
    tb, tsess, admin = seeded(st, "tenant_admin", "e2e95-ta")
    base = f"{_app(st)}/tenants/{a_id}"
    c = _Conds()
    got = ob.get(f"{base}/settings")
    view = got.json()
    sec = view.get("settings") or {}
    patch = tb.request("PATCH", f"{base}/settings", json.dumps({"policy": {"four_eyes": False}}).encode(),
                       unsafe(st, tsess, **{"If-Match": got.header("ETag")}))
    c("PATCH security key 422", patch.status == 422, f"PATCH {patch.status}")

    def body(four_eyes: bool) -> bytes:
        e = sec.get("enrollment") or {}
        return json.dumps({"enrollment": {k: e.get(k) for k in ("identity_mode", "web_auth_enabled", "self_enroll",
                                                                "requires_approval")},
                           "node_expiry": sec.get("node_expiry"),
                           "policy": {"four_eyes": four_eyes, "sensitive_groups": (sec.get("policy") or {}).get("sensitive_groups", [])},
                           "routes": sec.get("routes") or {"four_eyes": False}}).encode()

    on = ob.request("PUT", f"{base}/settings/security", body(True), unsafe(st, osess, **{"If-Match": got.header("ETag")}))
    off = ob.request("PUT", f"{base}/settings/security", body(False), unsafe(st, osess, **{"If-Match": on.header("ETag")}))
    appr = off.json()
    still = ob.get(f"{base}/settings").json().get("settings", {}).get("policy", {}).get("four_eyes")
    c("on 200, off 202 not in effect", on.status == 200 and off.status == 202 and appr.get("scope") == "tenant"
      and off.header("Location") == f"/api/v1/tenants/{a_id}/approvals/{appr.get('id')}" and still is True,
      f"on {on.status}; off {off.status} {appr.get('action')}; still on {still}")
    notes = [n for n in tb.get(f"{base}/notifications?limit=50").json().get("items", [])
             if n.get("kind") == "approval.requested" and (n.get("payload") or {}).get("approval_id") == appr.get("id")]
    decision = json.dumps({"payload_sha256": appr.get("payload_sha256")}).encode()
    self_ = ob.request("POST", f"{base}/approvals/{appr.get('id')}/approve", decision, unsafe(st, osess))
    done = tb.request("POST", f"{base}/approvals/{appr.get('id')}/approve", decision, unsafe(st, tsess))
    after = ob.get(f"{base}/settings").json().get("settings", {}).get("policy", {}).get("four_eyes")
    c("Admin notified, Owner self 403, Admin executes", len(notes) == 1 and self_.status == 403 and done.status == 200
      and done.json().get("status") == "executed" and after is False,
      f"notified {len(notes)}; self {self_.status}; Admin {done.status} {done.json().get('status')}; four_eyes {after}")
    bb, _, _ = owner_session(st, "tenant-b")
    cross = [bb.get(f"{base}/settings").status, bb.get(f"{base}/identity-provider").status]
    c("tenant-b 404", cross == [404, 404], f"tenant-b {cross}")
    wrong = ob.request("POST", f"{base}/request-deletion", json.dumps({"confirm_slug": "tenant-b", "reason": "E2E"}).encode(),
                       unsafe(st, osess))
    asked = ob.request("POST", f"{base}/request-deletion", json.dumps({"confirm_slug": "tenant-a", "reason": "E2E-95"}).encode(),
                       unsafe(st, osess))
    platform_ev = psql_one(st, "SELECT count(*) FROM audit_events WHERE tenant_id IS NULL AND action = "
                           f"'platform.tenant.deletion_requested' AND resource_id = '{a_id}'")
    status = psql_one(st, f"SELECT status FROM tenants WHERE id = '{a_id}'")
    c("deletion request", wrong.status == 422 and asked.status == 200 and asked.json().get("platform_notified") is True
      and platform_ev == "1" and status == "active",
      f"wrong slug {wrong.status}; request {asked.status} {asked.json().get('platform_notified')}; platform audit "
      f"{platform_ev}; tenant {status}")
    r.add("E2E-95", "P4-T03a: thiết lập tenant — PATCH /settings khóa bảo mật ⇒ 422; Owner bật 4-eyes ⇒ 200; tắt ⇒ 202 + "
          "yêu cầu phê duyệt TRONG tenant (Admin được báo), chưa có hiệu lực; Owner tự duyệt ⇒ 403; Admin duyệt ⇒ "
          "executed, 4-eyes tắt; Owner tenant-b ⇒ 404; yêu cầu xóa tenant: sai slug ⇒ 422, đúng ⇒ 200 (nền tảng được báo, "
          "audit platform), tenant vẫn active", c.ok, "; ".join(c.rows))


def run_all(r, st: Stack, guarded) -> None:
    """E2E-94, E2E-95 (independent)."""
    state: dict = {}
    guarded(r, "E2E-94", check_platform_admin, st, state)
    guarded(r, "E2E-95", check_tenant_settings, st, state)
