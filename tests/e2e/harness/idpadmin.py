"""P3-T15 — IdP administration is not a back door into a tenant (§8.2), on the dev/CI stack — FUNCTIONAL only (§22.1):
the api/worker built from the tree, the edge rendered from the tree (template v8), real Keycloak with TOTP.

  E2E-40  a Keycloak administrator (master realm) resets the credential of a user of tenant-a through the Admin API
          ⇒ after `meshguard-worker admin idp-audit-sync`: one audit row idp.user.credential_reset of tenant-a, visible
          to its Owner through GET /tenants/{t}/audit (actor system, idp_actor_kind idp_admin, the member it concerns),
          one notification idp.admin_change for the Owner (GET /tenants/{t}/notifications), one tenant security event
          idp.credential_reset (high); a second sync imports nothing again; a client update is imported with the
          allow-listed fields only — the client's secret is in no audit row, security event or notification
  E2E-41  the Keycloak console is refused without an approval: no Platform Console session ⇒ 401, a Super Admin with
          a session but no approved console session ⇒ 403 (audited idp.console.access, no_console_session); through
          auth.<domain> the console, the master realm and the Admin API are 404; the console is served by the edge on
          admin. only, behind the one forward_auth of the rendered Caddyfile (the tunnel-facing listener has no admin.
          site — golden `tunnel` of tools/test_render_edge.py)
  E2E-42  dual control of a console session: the request (CSRF, Idempotency-Key, replay ⇒ same request) answers 202
          + Location; self-approval ⇒ 403; a second Super Admin (fresh TOTP sign-in) approves the exact payload hash ⇒
          executed; from the bound address the console loads (index with the admin origin, its assets), the console's
          OIDC login (security-admin-console, PKCE, through the gate) gives a token the Admin API accepts on admin.;
          impersonation through the console ⇒ 403 + critical security event; a session approved for another CIDR is
          refused (source_ip_not_allowed); GET /platform/idp-console/sessions shows both sessions active
  E2E-43  every console sign-in raises an alert: after idp-audit-sync, the console login of E2E-42 is a security event
          idp.console_login (high) with the client and the account, a platform audit row idp.console.login, a platform
          notification idp.console_login to the Super Admins/Platform Operators; the failed attempt is
          idp.console_login_failed (medium)
Standard library only. Passwords, TOTP keys, cookies, tokens and client secrets stay in this process (and its
redaction set).
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import time
import urllib.parse

from backend import TOTP, Browser, KeycloakAdmin, admin_cmd, container, keycloak_login, portal_login, psql
from dualcontrol import new_user, owner_session, psql_one, tenant_id, unsafe
from stack import Stack, StackError


def audit_sync(st: Stack) -> tuple[int, str]:
    """One pass of idp.audit_sync now, inside the worker (the only source the edge lets reach the Admin API)."""
    p = st.docker("exec", container(st, "worker"), "/usr/local/bin/meshguard", "admin", "idp-audit-sync", check=False,
                  timeout=300)
    return p.returncode, st.redact(p.stdout + p.stderr)


def summary(out: str) -> str:
    """The result line of idp-audit-sync ("realms N, imported M"), not its JSON log — the detail of a case is 400
    characters."""
    lines = [ln for ln in out.splitlines() if ln.startswith("idp-audit-sync:")]
    return lines[-1].removeprefix("idp-audit-sync:").strip() if lines else "?"


def admin_unsafe(st: Stack, sess: dict, **extra) -> dict:
    return {"Origin": f"https://admin.{st.domain}", "X-CSRF-Token": sess["csrf_token"], "Content-Type": "application/json",
            **extra}


# ---------------------------------------------------------------------------------------------------- E2E-40
def check_credential_reset(r, st: Stack, state: dict) -> None:
    ob, osess, _ = owner_session(st, "tenant-a")
    a_id = tenant_id(st, "tenant-a")
    # the member whose credential is reset has signed in once (an identity of tenant-a exists for it); seed-membership
    # only seeds tenant_owner/tenant_admin — an admin, not an Owner (the Owners are who must be notified)
    target = new_user(st, "tenant-a", "e2e-reset")
    p = admin_cmd(st, ["seed-membership", "--tenant", "tenant-a", "--role", "tenant_admin", "--subject", target["sub"],
                       "--display-name", "E2E Reset Target"])
    if p.returncode != 0:
        raise StackError(f"seed-membership: {st.redact(p.stdout + p.stderr)[-300:]}")
    portal_login(st, Browser(st), f"app.{st.domain}", "scope=tenant&tenant=tenant-a", target)
    kc = KeycloakAdmin(st)
    pw = secrets.token_urlsafe(20)
    st.secret_values.add(pw)
    kc._call("PUT", f"/admin/realms/tenant-a/users/{target['sub']}/reset-password",
             body={"type": "password", "value": pw, "temporary": True})
    # a client change of the same realm: imported with allow-listed fields only, never the client's secret
    client_secret = kc.client_secret("tenant-a")
    st.secret_values.add(client_secret)
    c = kc._call("GET", "/admin/realms/tenant-a/clients?clientId=mg-portal")[0]
    c["description"] = (c.get("description") or "")[:200] + " (E2E-40)"
    kc._call("PUT", f"/admin/realms/tenant-a/clients/{c['id']}", body=c)
    rc1, out1 = audit_sync(st)
    rows = psql(st, "SELECT details ->> 'idp_event_id', actor_type, details ->> 'idp_actor_kind', "
                    f"details ->> 'identity_id' IS NOT NULL FROM audit_events WHERE tenant_id = '{a_id}' "
                    f"AND action = 'idp.user.credential_reset' AND resource_id = '{target['sub']}'")
    event_id = rows[0][0] if rows else ""
    api = f"https://app.{st.domain}/api/v1/tenants/{a_id}"
    seen = ob.get(f"{api}/audit?action=idp.user.credential_reset&limit=50").json().get("items", [])
    mine = [e for e in seen if (e.get("resource") or {}).get("id") == target["sub"]]
    notes = [n for n in ob.get(f"{api}/notifications?limit=200").json().get("items", [])
             if n.get("kind") == "idp.admin_change" and (n.get("payload") or {}).get("event_id") == event_id]
    sec = psql(st, "SELECT severity FROM security_events WHERE tenant_id = '" + a_id + "' AND kind = "
                   f"'idp.credential_reset' AND details ->> 'idp_event_id' = '{event_id}'")
    rc2, out2 = audit_sync(st)
    again = psql_one(st, f"SELECT count(*) FROM audit_events WHERE tenant_id = '{a_id}' AND details ->> 'idp_event_id' "
                         f"= '{event_id}'")
    again_notes = psql_one(st, f"SELECT count(*) FROM notification_outbox WHERE tenant_id = '{a_id}' AND kind = "
                               f"'idp.admin_change' AND payload ->> 'event_id' = '{event_id}'")
    client = psql(st, "SELECT details ->> 'client_id', details ->> 'idp_representation', details::text FROM audit_events "
                      f"WHERE tenant_id = '{a_id}' AND action = 'idp.client.update' ORDER BY occurred_at DESC LIMIT 1")
    leaked = psql_one(st, "SELECT count(*) FROM (SELECT details::text t FROM audit_events WHERE action LIKE 'idp.%' UNION "
                          "ALL SELECT details::text FROM security_events WHERE source = 'idp.audit_sync' UNION ALL SELECT "
                          "payload::text FROM notification_outbox WHERE kind LIKE 'idp.%') x WHERE strpos(t, "
                          f"'{client_secret}') > 0 OR strpos(t, '{pw}') > 0")
    ev = mine[0] if mine else {}
    ok = (rc1 == 0 and rows and rows[0][1:] == ["system", "idp_admin", "t"] and len(mine) == 1
          and (ev.get("actor") or {}).get("type") == "system" and ev.get("outcome") == "success"
          and (ev.get("details") or {}).get("idp_actor_kind") == "idp_admin" and len(notes) == 1
          and (notes[0].get("payload") or {}).get("action") == "idp.user.credential_reset" and sec == [["high"]]
          and rc2 == 0 and again == "1" and again_notes == str(len(psql(st, "SELECT 1 FROM tenant_memberships m JOIN roles "
                                                                            f"ro ON ro.id = m.role_id WHERE m.tenant_id = '{a_id}' "
                                                                            "AND ro.key = 'tenant_owner' AND m.status = 'active'")))
          and client and client[0][0] == "mg-portal" and client[0][1] == "redacted" and leaked == "0")
    r.add("E2E-40", "P3-T15: admin Keycloak (realm master) reset credential của một thành viên tenant-a qua Admin API ⇒ "
          "idp-audit-sync: đúng 1 hàng audit idp.user.credential_reset của tenant-a, Owner thấy qua GET /tenants/{t}/audit "
          "(actor system, idp_actor_kind idp_admin, gắn identity), 1 thông báo idp.admin_change cho Owner, security "
          "event idp.credential_reset (high); chạy lại không nhập trùng; đổi client chỉ ghi trường trong allow-list — "
          "secret của client và mật khẩu mới không có trong audit/security event/thông báo", ok,
          f"sync {rc1} ({summary(out1)})/{rc2} ({summary(out2)}); hàng {[x[1:] for x in rows]}; API thấy {len(mine)} "
          f"({(ev.get('actor') or {}).get('type')}, {ev.get('outcome')}); thông báo {len(notes)} (outbox {again_notes}); "
          f"security {sec}; sau lần 2: {again} hàng; client {[x[:2] for x in client]}; lộ secret {leaked}")
    state.update(owner_browser=ob, owner_session=osess, a_id=a_id)


# ---------------------------------------------------------------------------------------------------- E2E-41
def platform_session(st: Stack, user: dict, otp: TOTP | None = None) -> tuple[Browser, dict]:
    b = Browser(st)
    sess, _ = portal_login(st, b, f"admin.{st.domain}", "scope=platform", user, otp or user.get("otp") or TOTP())
    return b, sess


def check_console_refused(r, st: Stack, state: dict) -> None:
    sa1 = getattr(st, "platform_sa", None)
    if not sa1:
        raise StackError("no Super Admin of E2E-24 (st.platform_sa)")
    b1, s1 = platform_session(st, sa1)
    admin, auth = f"https://admin.{st.domain}", f"https://auth.{st.domain}"
    anon = Browser(st).get(f"{admin}/admin/master/console/")
    refused = {p: b1.get(admin + p).status for p in ("/admin/master/console/", "/realms/master/.well-known/openid-configuration",
                                                       "/admin/realms/tenant-a/users", "/resources/x/admin/keycloak.v2/a.js")}
    via_auth = {p: Browser(st).get(auth + p).status for p in ("/admin/master/console/", "/admin/",
                                                              "/realms/master/protocol/openid-connect/auth",
                                                              "/admin/realms/tenant-a/users")}
    sa1_id = psql_one(st, f"SELECT id FROM identities WHERE subject = '{sa1['sub']}'")
    audited = psql_one(st, "SELECT count(*) FROM audit_events WHERE tenant_id IS NULL AND action = 'idp.console.access' "
                           f"AND outcome = 'denied' AND actor_identity_id = '{sa1_id}' AND details ->> 'reason' = "
                           "'no_console_session'")
    caddy = (st.work / "render" / "edge" / "caddy" / "Caddyfile").read_text(encoding="utf-8")
    code = "\n".join(ln for ln in caddy.splitlines() if not ln.lstrip().startswith("#"))
    admin_site = re.search(r"(?ms)^admin\." + re.escape(st.domain) + r" \{\n(.*?)\n\}\n", code + "\n")
    rendered = (code.count("forward_auth api.:8080") == 1 and admin_site is not None
                and "forward_auth api.:8080" in admin_site.group(1) and "uri /internal/edge/idp-console" in admin_site.group(1))
    ok = (anon.status == 401 and all(v == 403 for v in refused.values()) and all(v == 404 for v in via_auth.values())
          and int(audited or 0) >= 1 and rendered)
    state.update(sa1=sa1, sa1_browser=b1, sa1_session=s1, sa1_id=sa1_id)
    r.add("E2E-41", "P3-T15: console Keycloak bị từ chối khi chưa có phê duyệt — không phiên Platform Console ⇒ 401; Super "
          "Admin có phiên nhưng chưa có phiên console đã duyệt ⇒ 403 cho console, realm master, Admin API, tài nguyên "
          "(audit idp.console.access no_console_session); qua auth.<domain> console/realm master/Admin API ⇒ 404; "
          "Caddyfile render: console chỉ ở admin. sau đúng một forward_auth (listener tunnel-facing không có admin. — "
          "golden tunnel)", ok,
          f"không phiên {anon.status}; SA chưa duyệt {refused}; qua auth. {via_auth}; audit từ chối {audited}; "
          f"Caddyfile {rendered}")


# ---------------------------------------------------------------------------------------------------- E2E-42
def request_session(st: Stack, b: Browser, sess: dict, body: dict, key: str):
    return b.request("POST", f"https://admin.{st.domain}/api/v1/platform/idp-console/sessions",
                     json.dumps(body).encode(), admin_unsafe(st, sess, **{"Idempotency-Key": key}))


def approve(st: Stack, b: Browser, sess: dict, approval: dict):
    return b.request("POST", f"https://admin.{st.domain}/api/v1/platform/approvals/{approval.get('id')}/approve",
                     json.dumps({"payload_sha256": approval.get("payload_sha256")}).encode(), admin_unsafe(st, sess))


def console_login(st: Stack, b: Browser, password: str) -> tuple[str, list[str], int]:
    """The console's own OIDC login (keycloak-js: security-admin-console, Authorization Code + PKCE) through admin.;
    returns the access token, the steps and the status of the token request."""
    admin = f"https://admin.{st.domain}"
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    redirect = f"{admin}/admin/master/console/"
    q = urllib.parse.urlencode({"client_id": "security-admin-console", "redirect_uri": redirect, "response_type": "code",
                                "response_mode": "query", "scope": "openid", "state": secrets.token_hex(8),
                                "nonce": secrets.token_hex(8), "code_challenge": challenge,
                                "code_challenge_method": "S256"})
    loc, steps = keycloak_login(st, b, f"{admin}/realms/master/protocol/openid-connect/auth?{q}",
                                {"username": "mg-bootstrap-admin", "password": password}, TOTP(), f"admin.{st.domain}")
    code = urllib.parse.parse_qs(urllib.parse.urlsplit(loc).query).get("code", [""])[0]
    st.secret_values.add(code)
    t = b.request("POST", f"{admin}/realms/master/protocol/openid-connect/token", urllib.parse.urlencode({
        "grant_type": "authorization_code", "client_id": "security-admin-console", "code": code,
        "redirect_uri": redirect, "code_verifier": verifier}).encode(),
        {"Content-Type": "application/x-www-form-urlencoded", "Origin": admin})
    token = t.json().get("access_token", "") if t.status == 200 else ""
    st.secret_values.add(token)
    return token, steps, t.status


def failed_console_login(st: Stack, b: Browser) -> int:
    """A console sign-in with a wrong password (through the gate): Keycloak answers its form again."""
    admin = f"https://admin.{st.domain}"
    q = urllib.parse.urlencode({"client_id": "security-admin-console", "redirect_uri": f"{admin}/admin/master/console/",
                                "response_type": "code", "response_mode": "query", "scope": "openid",
                                "state": secrets.token_hex(8), "code_challenge": "x" * 43, "code_challenge_method": "S256"})
    page = b.get(f"{admin}/realms/master/protocol/openid-connect/auth?{q}")
    m = re.search(r'action="([^"]+)"', page.body.decode("utf-8", "replace"))
    if page.status != 200 or not m:
        return page.status
    action = m.group(1).replace("&amp;", "&")
    return b.request("POST", action, urllib.parse.urlencode({"username": "mg-bootstrap-admin",
                                                               "password": "wrong-" + secrets.token_hex(6)}).encode(),
                     {"Content-Type": "application/x-www-form-urlencoded"}).status


def check_console_session(r, st: Stack, state: dict) -> None:
    b1, s1 = state["sa1_browser"], state["sa1_session"]
    admin = f"https://admin.{st.domain}"
    key = "e2e-console-" + secrets.token_hex(6)
    req = request_session(st, b1, s1, {"reason": "E2E-42", "duration_minutes": 15}, key)
    replay = request_session(st, b1, s1, {"reason": "E2E-42", "duration_minutes": 15}, key)
    appr = req.json()
    payload = appr.get("payload") or {}
    self_ = approve(st, b1, s1, appr)
    # the second Super Admin: bootstrap-super-admin (fewer than two active ones), TOTP sign-in on admin.
    kc = KeycloakAdmin(st)
    sa2 = {"username": "e2e-sa2-" + secrets.token_hex(3), "password": secrets.token_urlsafe(18)}
    st.secret_values.add(sa2["password"])
    sa2["sub"] = kc.create_user("platform", sa2["username"], sa2["password"])
    p = admin_cmd(st, ["bootstrap-super-admin", "--subject", sa2["sub"], "--display-name", "E2E SA2"],
                  env={"MG_IDP_ID_PLATFORM": st.env["MG_IDP_ID_PLATFORM"]})
    otp2 = TOTP()
    b2, s2 = platform_session(st, sa2, otp2)
    st.platform_sa2 = {**sa2, "otp": otp2}   # P4-T03a (admin.py): the second Super Admin of the platform 2P cases
    seen = b2.get(f"{admin}/api/v1/platform/approvals/{appr.get('id')}").json()
    ok_approve = approve(st, b2, s2, seen)
    executed = ok_approve.json().get("status")
    # the console from the bound address (this host on the edge network = the requester's address)
    page = b1.get(f"{admin}/admin/master/console/")
    html = page.body.decode("utf-8", "replace")
    env = re.search(r'<script id="environment" type="application/json">(.*?)</script>', html, re.S)
    envj = json.loads(env.group(1)) if env else {}
    assets = sorted(set(re.findall(r'(?:src|href)="(/resources/[^"]+\.(?:js|css))"', html)))
    asset = b1.get(admin + assets[0]).status if assets else 0
    pw = (st.work / "secrets" / "harness" / "kc_admin_password").read_text(encoding="utf-8")
    t0 = psql_one(st, "SELECT now()")
    failed = failed_console_login(st, b1)
    token, steps, tok_status = console_login(st, b1, pw)
    serverinfo = b1.get(f"{admin}/admin/serverinfo", {"Authorization": "Bearer " + token}).status if token else 0
    target = psql_one(st, "SELECT subject FROM identities i JOIN tenants t ON t.id = i.tenant_id WHERE t.slug = 'tenant-a' "
                          "LIMIT 1")
    imp = b1.request("POST", f"{admin}/admin/realms/tenant-a/users/{target}/impersonation", b"",
                     {"Authorization": "Bearer " + token, "Origin": admin})
    imp_sec = psql_one(st, "SELECT severity FROM security_events WHERE kind = 'idp.console_impersonation_attempt' "
                           f"AND details ->> 'identity_id' = '{state['sa1_id']}' ORDER BY occurred_at DESC LIMIT 1")
    # a console session approved for another network: refused from here
    s2b = request_session(st, b2, s2, {"reason": "E2E-42 other network", "duration_minutes": 10,
                                       "source_cidr": "192.0.2.0/24"}, "e2e-console-" + secrets.token_hex(6))
    other = s2b.json()
    approve(st, b1, s1, b1.get(f"{admin}/api/v1/platform/approvals/{other.get('id')}").json())
    wrong_net = b2.get(f"{admin}/admin/master/console/").status
    sa2_id = psql_one(st, f"SELECT id FROM identities WHERE subject = '{sa2['sub']}'")
    wrong_reason = psql_one(st, "SELECT details ->> 'reason' FROM audit_events WHERE action = 'idp.console.access' AND "
                                f"actor_identity_id = '{sa2_id}' ORDER BY occurred_at DESC LIMIT 1")
    listed = b1.get(f"{admin}/api/v1/platform/idp-console/sessions?limit=20").json().get("items", [])
    statuses = {x.get("id"): (x.get("status"), x.get("source_cidr")) for x in listed}
    opened = psql_one(st, "SELECT count(*) FROM security_events WHERE kind = 'idp.console_session_opened' AND details ->> "
                          f"'approval_id' IN ('{appr.get('id')}', '{other.get('id')}')")
    ok = (req.status == 202 and req.header("Location") == f"/api/v1/platform/approvals/{appr.get('id')}"
          and replay.status == 202 and replay.json().get("id") == appr.get("id")
          and payload.get("source_cidr") == f"{st.host_ip}/32" and payload.get("duration_minutes") == 15
          and self_.status == 403 and p.returncode == 0 and seen.get("payload") == payload
          and ok_approve.status == 200 and executed == "executed"
          and page.status == 200 and envj.get("authUrl") == admin and envj.get("serverBaseUrl") == admin
          and asset == 200 and failed == 200 and tok_status == 200 and serverinfo == 200
          and imp.status == 403 and imp_sec == "critical" and s2b.status == 202 and wrong_net == 403
          and wrong_reason == "source_ip_not_allowed"
          and statuses.get(appr.get("id")) == ("active", f"{st.host_ip}/32")
          and statuses.get(other.get("id")) == ("active", "192.0.2.0/24") and opened == "2")
    state.update(console_t0=t0, sa2=sa2)
    r.add("E2E-42", "P3-T15: phiên console 2P — xin (CSRF, Idempotency-Key; lặp lại ⇒ cùng yêu cầu) ⇒ 202 + Location, "
          "payload = người xin + CIDR của chính địa chỉ đó + 15 phút; tự duyệt ⇒ 403; Super Admin thứ hai (TOTP) duyệt "
          "đúng hash ⇒ executed; từ địa chỉ đã duyệt console tải được (index với origin admin, tài nguyên), đăng nhập OIDC "
          "của console (security-admin-console, PKCE) qua cổng ⇒ token dùng được với Admin API trên admin.; "
          "impersonation qua console ⇒ 403 + security event critical; phiên duyệt cho CIDR khác ⇒ 403 "
          "source_ip_not_allowed; danh sách phiên: cả hai active", ok,
          f"xin {req.status} lặp {replay.status} cùng id {replay.json().get('id') == appr.get('id')}; CIDR "
          f"{payload.get('source_cidr')} {payload.get('duration_minutes')} phút; tự duyệt {self_.status}; SA2 duyệt "
          f"{ok_approve.status} {executed}; console {page.status} ({envj.get('authUrl')}), tài nguyên {asset}; đăng nhập "
          f"sai {failed}, đăng nhập {steps} token {tok_status}, serverinfo {serverinfo}; impersonation {imp.status} "
          f"({imp_sec}); CIDR khác {wrong_net} ({wrong_reason}); danh sách {list(statuses.values())}; mở phiên {opened}")


# ---------------------------------------------------------------------------------------------------- E2E-43
def check_console_alert(r, st: Stack, state: dict) -> None:
    t0 = state.get("console_t0") or "-infinity"
    rc, out = audit_sync(st)
    logins = psql(st, "SELECT severity, details ->> 'idp_client', details ->> 'username' FROM security_events WHERE "
                      f"kind = 'idp.console_login' AND occurred_at >= '{t0}'::timestamptz - interval '5 minutes' "
                      "AND details ->> 'idp_client' = 'security-admin-console' ORDER BY occurred_at")
    failed = psql(st, "SELECT severity FROM security_events WHERE kind = 'idp.console_login_failed' AND occurred_at >= "
                      f"'{t0}'::timestamptz - interval '5 minutes' AND details ->> 'idp_client' = 'security-admin-console'")
    audit = psql(st, "SELECT outcome, count(*) FROM audit_events WHERE tenant_id IS NULL AND action = 'idp.console.login' "
                     f"AND details ->> 'idp_client' = 'security-admin-console' AND occurred_at >= '{t0}'::timestamptz "
                     "GROUP BY 1 ORDER BY 1")
    notes = psql(st, "SELECT payload ->> 'client', payload ->> 'username', recipient_email IS NOT NULL FROM "
                     "notification_outbox WHERE tenant_id IS NULL AND kind = 'idp.console_login' AND created_at >= "
                     f"'{t0}'::timestamptz AND payload ->> 'client' = 'security-admin-console'")
    rc2, _ = audit_sync(st)
    again = psql_one(st, "SELECT count(*) FROM security_events WHERE kind = 'idp.console_login' AND occurred_at >= "
                         f"'{t0}'::timestamptz - interval '5 minutes' AND details ->> 'idp_client' = 'security-admin-console'")
    ok = (rc == 0 and len(logins) == 1 and logins[0] == ["high", "security-admin-console", "mg-bootstrap-admin"]
          and failed == [["medium"]] and dict((o, n) for o, n in audit) == {"failure": "1", "success": "1"}
          and len(notes) >= 1 and all(n[:2] == ["security-admin-console", "mg-bootstrap-admin"] and n[2] == "t"
                                      for n in notes)
          and rc2 == 0 and again == "1")
    r.add("E2E-43", "P3-T15: mỗi lần đăng nhập console sinh cảnh báo — sau idp-audit-sync, lần đăng nhập console của E2E-42 "
          "là security event idp.console_login (high, client security-admin-console, tài khoản), hàng audit platform "
          "idp.console.login, thông báo platform idp.console_login tới Super Admin/Platform Operator (email đã xác "
          "minh); lần đăng nhập sai là idp.console_login_failed (medium); chạy lại không trùng", ok,
          f"sync {rc} ({summary(out)})/{rc2}; security {logins}, sai {failed}; audit {audit}; thông báo "
          f"{len(notes)} {notes[:1]}; sau lần 2 {again}")


def run_all(r, st: Stack, guarded) -> None:
    """E2E-40 … E2E-43 in order (E2E-42/43 build on E2E-41)."""
    state: dict = {}
    guarded(r, "E2E-40", check_credential_reset, st, state)
    if guarded(r, "E2E-41", check_console_refused, st, state) is None and "sa1_browser" in state:
        if guarded(r, "E2E-42", check_console_session, st, state) is None:
            guarded(r, "E2E-43", check_console_alert, st, state)
