"""Tenant Portal API (P4-T04) on the dev/CI stack — FUNCTIONAL only (§22.1): the api built from the tree behind the
rendered edge, a Tenant Owner of tenant-a signed in through Keycloak with TOTP (dualcontrol.owner_session).

  E2E-87  the in-portal inbox and the device review report through the edge on app.:
          - three Portal notifications are written as the producer writes them (superuser, the shape of
            notifications.Enqueue: status sent, recipient membership, payload of the kind): one to the Owner, one to
            another member of tenant-a, one to a member of tenant-b;
          - GET …/notifications?unread=true lists the Owner's own notification (never the other two);
          - POST …/notifications/{id}/read without X-CSRF-Token ⇒ 403; with it ⇒ 200 + read_at; again ⇒ 200 with the same
            read_at (idempotent); another member's notification ⇒ 404 (audited denied, reason not_own_resource), tenant-b's
            ⇒ 404, a missing id ⇒ 404 — the same problem body; the two other rows stay unread; ?unread=true no longer
            lists it; audit notification.mark_read ×2 (one repeated) in tenant-a;
          - GET …/devices with tagged / has_expiry (the review report tagged=true&has_expiry=false — §7.4, ADR-23): every
            answer is consistent with the items' tags and expiry, the four combinations partition the list; a non-boolean
            value ⇒ 4xx problem; a cursor of another filter ⇒ 422
Standard library only; no credential printed.
"""
from __future__ import annotations

import json
import uuid

from backend import psql
from dualcontrol import owner_session, psql_one, tenant_id, unsafe
from stack import Stack, StackError


def _notify(st: Stack, tenant: str, membership: str) -> str:
    nid = str(uuid.uuid4())
    payload = json.dumps({"device_id": str(uuid.uuid4()), "device_name": "e2e-85", "expires_at": "2026-12-01T00:00:00Z",
                          "tenant_name": "E2E", "tenant_slug": "e2e", "locale": "vi"})
    psql(st, "INSERT INTO notification_outbox (id, tenant_id, recipient_membership_id, kind, payload, status, sent_at) "
             f"VALUES ('{nid}', '{tenant}', '{membership}', 'device.expiring', '{payload}'::jsonb, 'sent', now())")
    return nid


def check_portal(r, st: Stack) -> None:
    b, sess, _ = owner_session(st, "tenant-a")
    a_id, b_id = tenant_id(st, "tenant-a"), tenant_id(st, "tenant-b")
    me = next(m["membership_id"] for m in sess.get("memberships", []) if m.get("tenant_id") == a_id)
    other = psql_one(st, f"SELECT id FROM tenant_memberships WHERE tenant_id = '{a_id}' AND id <> '{me}' AND status = "
                         "'active' ORDER BY id LIMIT 1")
    b_member = psql_one(st, f"SELECT id FROM tenant_memberships WHERE tenant_id = '{b_id}' AND status = 'active' "
                            "ORDER BY id LIMIT 1")
    if not other or not b_member:
        raise StackError(f"members: other {other!r}, tenant-b {b_member!r}")
    mine, theirs, foreign = _notify(st, a_id, me), _notify(st, a_id, other), _notify(st, b_id, b_member)
    api = f"https://app.{st.domain}/api/v1/tenants/{a_id}"

    def ids(resp) -> list[str]:
        return [n.get("id") for n in resp.json().get("items", [])]

    unread0 = ids(b.get(f"{api}/notifications?unread=true&limit=200"))
    hdr = unsafe(st, sess)
    nocsrf = b.request("POST", f"{api}/notifications/{mine}/read", None, {"Origin": f"https://app.{st.domain}"})
    first = b.request("POST", f"{api}/notifications/{mine}/read", None, hdr)
    again = b.request("POST", f"{api}/notifications/{mine}/read", None, hdr)
    refused = {name: b.request("POST", f"{api}/notifications/{nid}/read", None, hdr)
               for name, nid in (("other", theirs), ("tenant-b", foreign), ("missing", str(uuid.uuid4())))}
    bodies = {name: (x.status, x.json().get("code"), x.json().get("detail")) for name, x in refused.items()}
    unread1 = ids(b.get(f"{api}/notifications?unread=true&limit=200"))
    still = psql(st, f"SELECT id, read_at IS NULL FROM notification_outbox WHERE id IN ('{theirs}', '{foreign}') ORDER BY id")
    audit = psql_one(st, f"SELECT count(*) || '/' || count(*) FILTER (WHERE details ->> 'repeated' = 'true') FROM audit_events "
                         f"WHERE tenant_id = '{a_id}' AND action = 'notification.mark_read' AND resource_id = '{mine}' "
                         "AND outcome = 'success'")
    denied = psql_one(st, f"SELECT details ->> 'reason' FROM audit_events WHERE tenant_id = '{a_id}' AND outcome = 'denied' "
                          f"AND action = 'notification.mark_read' AND resource_id = '{theirs}' ORDER BY occurred_at DESC LIMIT 1")
    ra = first.json().get("read_at")
    inbox_ok = (mine in unread0 and theirs not in unread0 and foreign not in unread0 and nocsrf.status == 403
                and first.status == 200 and ra and again.status == 200 and again.json().get("read_at") == ra
                and len(set(bodies.values())) == 1 and bodies["other"][:2] == (404, "not_found")
                and mine not in unread1 and [x[1] for x in still] == ["t", "t"] and audit == "2/1"
                and denied == "not_own_resource")

    # device filters: tagged × has_expiry partition the list; the review report is consistent
    def devices(q: str):
        resp = b.get(f"{api}/devices?limit=200{q}")
        return resp.status, resp.json().get("items", []), resp.json().get("next_cursor")
    st_all, every, _ = devices("")
    parts = {}
    for tg in ("true", "false"):
        for ex in ("true", "false"):
            s, items, _ = devices(f"&tagged={tg}&has_expiry={ex}")
            ok = s == 200 and all((len(d.get("tags") or []) > 0) == (tg == "true")
                                  and (d.get("expiry") is not None) == (ex == "true") for d in items)
            parts[(tg, ex)] = (ok, sorted(d["id"] for d in items))
    union = sorted(i for _, v in parts.values() for i in v)
    bad = b.get(f"{api}/devices?tagged=maybe")
    cursor1 = b.get(f"{api}/devices?limit=1").json().get("next_cursor")
    cross = b.get(f"{api}/devices?limit=1&tagged=false&cursor={cursor1}") if cursor1 else None
    filters_ok = (st_all == 200 and all(ok for ok, _ in parts.values()) and union == sorted(d["id"] for d in every)
                  and 400 <= bad.status < 500 and bad.header("Content-Type").startswith("application/problem+json")
                  and (cross is None or cross.status == 422))
    r.add("E2E-87", "P4-T04: hộp thông báo qua edge — GET ?unread=true chỉ thông báo của chính Owner; POST …/{id}/read "
          "thiếu CSRF ⇒ 403, có ⇒ 200 + read_at, lặp lại giữ read_at; của thành viên khác / tenant-b / không tồn tại ⇒ "
          "cùng 404 (audit denied not_own_resource), hai hàng kia vẫn chưa đọc; audit notification.mark_read 2 (1 lặp); "
          "lọc thiết bị tagged × has_expiry chia đúng danh sách (báo cáo rà soát tagged node không hết hạn), giá trị lạ "
          "⇒ 4xx problem, cursor của bộ lọc khác ⇒ 422", inbox_ok and filters_ok,
          f"unread trước {len(unread0)} (của tôi {mine in unread0}), không CSRF {nocsrf.status}, lần 1 {first.status}, lần 2 "
          f"{again.status} (giữ read_at {again.json().get('read_at') == ra}), từ chối {bodies}, unread sau có của tôi "
          f"{mine in unread1}, hàng khác chưa đọc {[x[1] for x in still]}, audit {audit}, denied {denied}; thiết bị "
          f"{len(every)}: " + ", ".join(f"tagged={k[0]}/has_expiry={k[1]}:{len(v[1])}{'' if v[0] else '!'}"
                                        for k, v in parts.items())
          + f"; lạ {bad.status}; cursor chéo {cross.status if cross else 'n/a (≤1 thiết bị)'}", limit=900)


def run_all(r, st: Stack, guarded) -> None:
    guarded(r, "E2E-87", check_portal, st)
