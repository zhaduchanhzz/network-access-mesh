"""P4-T13 Support Access Grant on the dev/CI stack — FUNCTIONAL only (§22.1): the api and worker built from the tree,
real Keycloak logins with TOTP through the edge on admin. (the two Super Admins of E2E-24/E2E-42 — platform staff) and
app. (Owners and an Admin of tenant-a), PostgreSQL of the stack, the worker's grant.expire schedule.

  E2E-106 support acts ⇒ the tenant's audit shows actor_type=support: a Super Admin asks for support_operator access to
          tenant-a (201 pending; the tenant's trail records the request, its Owner is notified support.grant_requested);
          before the decision a tenant route on admin. ⇒ 403; the Owner approves (step-up) ⇒ the staff session lists the
          grant; the staff member syncs tenant-a's devices from admin. (202) and is refused a write its role lacks (403);
          the tenant's audit filtered actor_type=support lists both — actor.type support with the grant id —, the platform
          audit does not; the Owner revokes ⇒ the very next staff request ⇒ 403
  E2E-107 break-glass needs a second Super Admin; an Admin never grants beyond the ceiling: effective_role tenant_owner ⇒
          422; a support_admin request: the tenant's Admin and Owner approving ⇒ 403 (support_admin only through
          break-glass); the requester's own break-glass ⇒ 403; the second Super Admin ⇒ 200 approval_kind breakglass, a high
          security_event support.break_glass in tenant-a, every Owner notified support.break_glass, the tenant's trail
          records it; the staff member reads tenant-a; a Super Admin revokes it
  E2E-105 an expired grant stops by itself: a 1-minute grant approved by the Owner opens tenant-a, and once its window is
          over the next request ⇒ 403 with no action of anyone; the lists show it expired at once and grant.expire (worker,
          every minute) records expired in the table and both trails
Standard library only. Passwords, TOTP keys, cookies and CSRF tokens stay in this process (and its redaction set).
"""
from __future__ import annotations

import json
import secrets
import time

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


def _staff(st: Stack) -> tuple[dict, dict]:
    sa1, sa2 = getattr(st, "platform_sa", None), getattr(st, "platform_sa2", None)
    if not sa1 or not sa2:
        raise StackError("no Super Admins of E2E-24 / E2E-42 (st.platform_sa, st.platform_sa2)")
    return sa1, sa2


def _ask(st: Stack, b, sess: dict, tenant: str, role: str, minutes: int, tag: str):
    body = {"tenant_id": tenant, "effective_role": role, "reason": f"{tag}: customer ticket", "ticket_ref": tag,
            "duration_minutes": minutes}
    return b.request("POST", f"{_admin(st)}/platform/support-grants", json.dumps(body).encode(),
                     admin_unsafe(st, sess, **{"Idempotency-Key": f"{tag.lower()}-" + secrets.token_hex(6)}))


def _grant_db(st: Stack, gid: str) -> str:
    return psql_one(st, f"SELECT status FROM support_access_grants WHERE id = '{gid}'")


# ---------------------------------------------------------------------------------------------------- E2E-106
def check_support_actions(r, st: Stack, state: dict) -> None:
    sa1, _ = _staff(st)
    b1, s1 = platform_session(st, sa1)
    a_id = tenant_id(st, "tenant-a")
    ob, osess, _ = owner_session(st, "tenant-a")
    state["owner"] = (ob, osess)
    c = _Conds()
    ten = f"{_admin(st)}/tenants/{a_id}"
    asked = _ask(st, b1, s1, a_id, "support_operator", 30, "E2E-106")
    g = asked.json()
    gid = g.get("id", "")
    c("request 201 pending", asked.status == 201 and g.get("status") == "pending" and g.get("active") is False,
      f"POST {asked.status} {g.get('status')}")
    before = b1.get(f"{ten}/devices?limit=5").status
    seen = [x for x in ob.get(f"{_app(st)}/tenants/{a_id}/support-grants?limit=50").json().get("items", []) if x.get("id") == gid]
    notes = [n for n in ob.get(f"{_app(st)}/tenants/{a_id}/notifications?limit=50").json().get("items", [])
             if n.get("kind") == "support.grant_requested" and (n.get("payload") or {}).get("grant_id") == gid]
    c("pending ⇒ no access; tenant sees it; Owner notified", before == 403 and len(seen) == 1 and len(notes) == 1,
      f"staff read before approval {before}; tenant list {len(seen)}; notification {len(notes)}")
    ok = ob.request("POST", f"{_app(st)}/tenants/{a_id}/support-grants/{gid}/approve", None, unsafe(st, osess))
    sess_grants = [x for x in b1.get(f"{_admin(st)}/auth/session").json().get("support_grants", []) if x.get("id") == gid]
    c("Owner approves ⇒ live, in the staff session", ok.status == 200 and ok.json().get("active") is True
      and ok.json().get("approval_kind") == "tenant" and len(sess_grants) == 1,
      f"approve {ok.status} active={ok.json().get('active')}; session grants {len(sess_grants)}")
    sync = b1.request("POST", f"{ten}/devices/sync", None, admin_unsafe(st, s1, **{"Idempotency-Key": "e2e106-" + secrets.token_hex(6)}))
    read = b1.get(f"{ten}/devices?limit=5").status
    denied = b1.request("POST", f"{ten}/tags", json.dumps({"name": "tag:e2e106"}).encode(),
                        admin_unsafe(st, s1, **{"Idempotency-Key": "e2e106-" + secrets.token_hex(6)}))
    c("staff syncs (202) and reads (200); write beyond the role ⇒ 403", sync.status == 202 and read == 200 and denied.status == 403,
      f"sync {sync.status}; read {read}; tag create {denied.status}")
    time.sleep(2)
    aud = ob.get(f"{_app(st)}/tenants/{a_id}/audit?actor_type=support&limit=100").json().get("items", [])
    mine = [e for e in aud if (e.get("actor") or {}).get("support_grant_id") == gid]
    actions = sorted({e.get("action") for e in mine})
    all_support = all((e.get("actor") or {}).get("type") == "support" for e in aud)
    c("tenant audit: actor_type=support + grant id (sync + denial)", all_support
      and any(a.startswith("device.sync") for a in actions)
      and any(e.get("outcome") == "denied" and e.get("action") == "tag.create" for e in mine),
      f"support events {len(mine)}: {actions}")
    plat = psql_one(st, "SELECT count(*) FROM audit_events WHERE tenant_id IS NULL AND actor_type = 'support'")
    c("no support event on the platform trail", plat == "0", f"platform support events {plat}")
    rv = ob.request("POST", f"{_app(st)}/tenants/{a_id}/support-grants/{gid}/revoke", None, unsafe(st, osess))
    after = b1.get(f"{ten}/devices?limit=5").status
    c("revoke ⇒ next request 403", rv.status == 200 and rv.json().get("status") == "revoked" and after == 403,
      f"revoke {rv.status} {rv.json().get('status')}; next staff request {after}")
    r.add("E2E-106", "P4-T13: support thao tác ⇒ audit tenant thấy actor_type=support — xin grant (pending, tenant thấy, Owner "
          "được báo; chưa duyệt ⇒ 403); Owner duyệt ⇒ session của staff có grant; staff sync thiết bị (202), đọc (200), ghi "
          "ngoài role ⇒ 403; audit tenant lọc actor_type=support có cả hai kèm support_grant_id, audit platform không; Owner thu "
          "hồi ⇒ request kế tiếp 403", c.ok, "; ".join(c.rows))


# ---------------------------------------------------------------------------------------------------- E2E-107
def check_breakglass(r, st: Stack, state: dict) -> None:
    sa1, sa2 = _staff(st)
    b1, s1 = platform_session(st, sa1)
    b2, s2 = platform_session(st, sa2)
    a_id = tenant_id(st, "tenant-a")
    ob, osess = state.get("owner") or owner_session(st, "tenant-a")[:2]
    tb, tsess, _ = seeded(st, "tenant_admin", "e2e107-ta")
    c = _Conds()
    owner_role = _ask(st, b1, s1, a_id, "tenant_owner", 30, "E2E-107")
    c("effective_role tenant_owner ⇒ 422", owner_role.status == 422, f"POST tenant_owner {owner_role.status}")
    asked = _ask(st, b1, s1, a_id, "support_admin", 30, "E2E-107")
    gid = asked.json().get("id", "")
    path = f"{_app(st)}/tenants/{a_id}/support-grants/{gid}/approve"
    by_admin = tb.request("POST", path, None, unsafe(st, tsess))
    by_owner = ob.request("POST", path, None, unsafe(st, osess))
    c("tenant Admin / Owner cannot grant support_admin ⇒ 403", asked.status == 201 and by_admin.status == 403
      and by_owner.status == 403, f"request {asked.status}; Admin {by_admin.status}; Owner {by_owner.status}")
    bg = f"{_admin(st)}/platform/support-grants/{gid}/approve-breakglass"
    self_ = b1.request("POST", bg, None, admin_unsafe(st, s1))
    sec_before = psql_one(st, f"SELECT count(*) FROM security_events WHERE tenant_id = '{a_id}' AND kind = 'support.break_glass'")
    done = b2.request("POST", bg, None, admin_unsafe(st, s2))
    d = done.json()
    c("requester ⇒ 403; second Super Admin ⇒ break-glass", self_.status == 403 and done.status == 200
      and d.get("approval_kind") == "breakglass" and d.get("active") is True,
      f"self {self_.status}; second {done.status} {d.get('approval_kind')} active={d.get('active')}")
    sec = psql_one(st, f"SELECT count(*) FROM security_events WHERE tenant_id = '{a_id}' AND kind = 'support.break_glass' "
                       "AND severity = 'high'")
    notes = [n for n in ob.get(f"{_app(st)}/tenants/{a_id}/notifications?limit=50").json().get("items", [])
             if n.get("kind") == "support.break_glass" and (n.get("payload") or {}).get("grant_id") == gid]
    trail = psql_one(st, f"SELECT count(*) FROM audit_events WHERE tenant_id = '{a_id}' AND action = 'support_grant.breakglass' "
                         f"AND support_grant_id = '{gid}'")
    c("high security event + Owner notified + tenant trail", int(sec or 0) == int(sec_before or 0) + 1 and len(notes) == 1
      and trail == "1", f"security events {sec_before}→{sec}; notification {len(notes)}; tenant audit {trail}")
    read = b1.get(f"{_admin(st)}/tenants/{a_id}/devices?limit=5").status
    rv = b2.request("POST", f"{_admin(st)}/platform/support-grants/{gid}/revoke", None, admin_unsafe(st, s2))
    after = b1.get(f"{_admin(st)}/tenants/{a_id}/devices?limit=5").status
    c("staff reads under break-glass; Super Admin revokes ⇒ 403", read == 200 and rv.status == 200 and after == 403,
      f"read {read}; revoke {rv.status}; after {after}")
    r.add("E2E-107", "P4-T13: break-glass cần Super Admin thứ hai; role hiệu lực tenant_owner ⇒ 422; grant support_admin: Admin "
          "và Owner của tenant duyệt ⇒ 403 (chỉ qua break-glass); người xin tự break-glass ⇒ 403; SA thứ hai ⇒ 200 breakglass, "
          "security_event high, Owner được báo, audit tenant; staff đọc được; SA thu hồi ⇒ 403", c.ok, "; ".join(c.rows))


# ---------------------------------------------------------------------------------------------------- E2E-105
def check_expiry(r, st: Stack, state: dict) -> None:
    sa1, _ = _staff(st)
    b1, s1 = platform_session(st, sa1)
    a_id = tenant_id(st, "tenant-a")
    ob, osess = state.get("owner") or owner_session(st, "tenant-a")[:2]
    c = _Conds()
    asked = _ask(st, b1, s1, a_id, "support_operator", 1, "E2E-105")
    gid = asked.json().get("id", "")
    ok = ob.request("POST", f"{_app(st)}/tenants/{a_id}/support-grants/{gid}/approve", None, unsafe(st, osess))
    live = b1.get(f"{_admin(st)}/tenants/{a_id}/devices?limit=5").status
    c("1-minute grant approved ⇒ access", asked.status == 201 and ok.status == 200 and live == 200,
      f"request {asked.status}; approve {ok.status}; read {live}")
    expires = asked.json().get("expires_at", "")
    deadline = time.monotonic() + 75
    while time.monotonic() < deadline and psql_one(st, f"SELECT (expires_at <= now())::text FROM support_access_grants WHERE id = '{gid}'") != "true":
        time.sleep(3)
    gone = b1.get(f"{_admin(st)}/tenants/{a_id}/devices?limit=5").status
    listed = [x for x in ob.get(f"{_app(st)}/tenants/{a_id}/support-grants?limit=50").json().get("items", []) if x.get("id") == gid]
    eff = listed[0].get("status") if listed else None
    c("window over ⇒ next request 403, listed expired at once", gone == 403 and eff == "expired",
      f"expires_at {expires}; request after the window {gone}; effective status {eff}")
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline and _grant_db(st, gid) != "expired":
        time.sleep(10)
    db = _grant_db(st, gid)
    trails = psql_one(st, "SELECT count(*) FROM audit_events WHERE actor_type = 'system' AND support_grant_id = "
                          f"'{gid}' AND action IN ('support_grant.expire', 'platform.support_grant.expire')")
    c("grant.expire records expired (table + both trails)", db == "expired" and trails == "2", f"status {db}; expiry events {trails}")
    r.add("E2E-105", "P4-T13: grant hết hạn tự vô hiệu — grant 1 phút được Owner duyệt mở tenant-a; hết cửa sổ ⇒ request kế "
          "tiếp 403 không cần ai thao tác, danh sách thấy expired ngay; job grant.expire (worker, mỗi phút) ghi expired vào "
          "bảng + audit platform và tenant", c.ok, "; ".join(c.rows))


def run_all(r, st: Stack, guarded) -> None:
    """E2E-106, E2E-107, E2E-105 (in this order: one open grant per person and tenant; the expiry waits last)."""
    state: dict = {}
    guarded(r, "E2E-106", check_support_actions, st, state)
    guarded(r, "E2E-107", check_breakglass, st, state)
    guarded(r, "E2E-105", check_expiry, st, state)
