"""Checks of the fixes of the G2 review, round 2 (OWASP ASVS 5.0.0 L2 — docs/planning/evidence/G2-security-review.md),
on the dev/CI stack with the real Keycloak (realms rendered from the tree, idp image built from the tree) — FUNCTIONAL
only (§22.1). Each check replays a probe of the review and expects the fixed behaviour:

  E2E-26  A-1  logout ends the Keycloak SSO session (RP-Initiated Logout with id_token_hint): a new login on the same
               browser asks for password + OTP again (probe P1, realms tenant-a and platform); logout keeps CSRF;
               platform logins always prompt=login
  E2E-27  A-3  password blocklist: the five passwords of probe P4 are refused, a random one is accepted
  E2E-28  A-4  account console: changing the password re-authenticates first (probe P6 — max_auth_age 0)
  E2E-29  A-6  platform sessions carry amr with the second factor; without the amr mapper a platform login is refused
               (403, audit, security event) — restored afterwards
  E2E-30  A-2  `meshguard admin revoke-sessions` ends the BFF sessions of a person locked at Keycloak (probe P5) and keeps
               the identity out until `enable-identity`
  E2E-31  A-8  idp:8080 is reachable from the edge only (not from another member of the edge network); master realm
               hardened by infrastructure/idp/realm-update.sh (idempotent on the fresh realms; check_realm on Keycloak's
               export)
Standard library only; no credential printed or put on a command line.
"""
from __future__ import annotations

import base64
import hashlib
import os
import secrets
import subprocess
import time
import urllib.error
import urllib.parse

from backend import TOTP, Browser, KeycloakAdmin, admin_cmd, forms, keycloak_login, portal_login, psql
from stack import ROOT, Stack, StackError

# the five common passwords of probe P4 of the review (public, weak by design — what the blocklist must refuse)
P4 = tuple("password1234 qwertyuiop123 Password1234! meshguard2026 tenant-a12345".split())


def admin_api(st: Stack) -> KeycloakAdmin:
    kc = KeycloakAdmin(st)
    kc.st = st          # kc_call renews the token with it (the master token lives 60 s)
    return kc


def new_user(st: Stack, kc: KeycloakAdmin, realm: str, prefix: str) -> dict:
    u = {"username": f"{prefix}-" + secrets.token_hex(3), "password": secrets.token_urlsafe(18)}
    st.secret_values.add(u["password"])
    u["sub"] = kc.create_user(realm, u["username"], u["password"])
    return u


def kc_call(kc: KeycloakAdmin, method: str, path: str, body=None):
    """Admin API call; an HTTPError becomes ('error', status) — the token is renewed when it expired."""
    for attempt in (1, 2):
        try:
            return kc._call(method, path, body=body)
        except urllib.error.HTTPError as e:
            if e.code == 401 and attempt == 1:
                kc.__init__(kc.st)
                continue
            return {"error": e.code}
    return {"error": 0}


def logout(b: Browser, host: str, csrf: str) -> tuple[int, str]:
    r = b.request("POST", f"https://{host}/api/v1/auth/logout", b"", {"Origin": f"https://{host}", "X-CSRF-Token": csrf})
    return r.status, r.json().get("redirect_to", "")


# ---------------------------------------------------------------------------------------------------- A-1
def check_logout(r, st: Stack) -> None:
    kc = admin_api(st)
    detail, ok = [], True
    for host, query, realm in ((f"app.{st.domain}", "scope=tenant&tenant=tenant-a", "tenant-a"),
                               (f"admin.{st.domain}", "scope=platform", "platform")):
        u, otp, b = new_user(st, kc, realm, "e2e-logout"), TOTP(), Browser(st)
        sess, steps1 = portal_login(st, b, host, query, u, otp)
        nocsrf = b.request("POST", f"https://{host}/api/v1/auth/logout", b"", {"Origin": f"https://{host}"})
        status, to = logout(b, host, sess["csrf_token"])
        st.secret_values.add(urllib.parse.parse_qs(urllib.parse.urlsplit(to).query).get("id_token_hint", [""])[0])
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(to).query)
        to_ok = (to.startswith(f"https://auth.{st.domain}/realms/{realm}/protocol/openid-connect/logout?")
                 and q.get("client_id") == ["mg-portal"] and q.get("post_logout_redirect_uri") == [f"https://{host}/"]
                 and bool(q.get("id_token_hint")))
        k = b.get(to)                                         # the browser goes to Keycloak's end_session_endpoint
        back = k.status in (302, 303) and k.header("Location").startswith(f"https://{host}/")
        after = b.get(f"https://{host}/api/v1/auth/session").status
        start = b.get(f"https://{host}/api/v1/auth/login?{query}")
        prompt = urllib.parse.parse_qs(urllib.parse.urlsplit(start.header("Location")).query).get("prompt", [""])[0]
        cb, steps2 = keycloak_login(st, b, start.header("Location"), u, otp, host)
        relog = b.get(cb).status
        good = (nocsrf.status == 403 and status == 200 and to_ok and back and after == 401
                and steps2 == ["password", "otp"] and relog == 302 and (realm != "platform" or prompt == "login"))
        ok &= good
        detail.append(f"{realm}: login {steps1}; logout không CSRF {nocsrf.status}; logout {status}, redirect_to "
                      f"end_session (client_id, post_logout_redirect_uri, id_token_hint) {to_ok}; Keycloak {k.status} → "
                      f"{host}/ {back}; session {after}; login lại prompt={prompt or '-'} bước {steps2}, callback {relog}")
    r.add("E2E-26", "A-1: đăng xuất kết thúc cả phiên SSO của Keycloak (RP-Initiated Logout, id_token_hint): đăng nhập "
          "lại cùng trình duyệt phải nhập mật khẩu + OTP (P1, tenant-a và platform); logout giữ CSRF; platform luôn "
          "prompt=login", ok, "; ".join(detail))


# ---------------------------------------------------------------------------------------------------- A-3
def check_blocklist(r, st: Stack) -> None:
    kc = admin_api(st)
    detail, ok = [], True
    for realm in ("tenant-a", "platform"):
        u = new_user(st, kc, realm, "e2e-bl")
        res = {}
        for pw in P4:
            out = kc_call(kc, "PUT", f"/admin/realms/{realm}/users/{u['sub']}/reset-password",
                          {"type": "password", "value": pw, "temporary": False})
            res[pw] = out.get("error", 204) if isinstance(out, dict) else 204
        good_pw = secrets.token_urlsafe(18)
        st.secret_values.add(good_pw)
        out = kc_call(kc, "PUT", f"/admin/realms/{realm}/users/{u['sub']}/reset-password",
                      {"type": "password", "value": good_pw, "temporary": False})
        accepted = out.get("error", 204) if isinstance(out, dict) else 204
        ok &= all(v == 400 for v in res.values()) and accepted == 204
        detail.append(f"{realm}: " + ", ".join(f"{k} ⇒ {v}" for k, v in res.items()) + f"; ngẫu nhiên 24 ký tự ⇒ {accepted}")
    pol = kc_call(kc, "GET", "/admin/realms/tenant-a").get("passwordPolicy", "")
    ok &= "passwordBlacklist(mg-passwords-v1.txt)" in pol
    r.add("E2E-27", "A-3: danh sách mật khẩu cấm trong image idp (passwordBlacklist): 5 mật khẩu của P4 bị từ chối (400), "
          "mật khẩu ngẫu nhiên được nhận", ok, "; ".join(detail))


# ---------------------------------------------------------------------------------------------------- A-4
def check_reauth_before_password_change(r, st: Stack) -> None:
    kc = admin_api(st)
    u, otp, b = new_user(st, kc, "tenant-a", "e2e-aia"), TOTP(), Browser(st)
    portal_login(st, b, f"app.{st.domain}", "scope=tenant&tenant=tenant-a", u, otp)   # a fresh Keycloak SSO session
    time.sleep(2)                                    # max_auth_age 0: any authentication ≥ 1 s old is re-checked
    auth = f"auth.{st.domain}"
    redirect = f"https://{auth}/realms/tenant-a/account/"
    ver = secrets.token_urlsafe(48)
    ch = base64.urlsafe_b64encode(hashlib.sha256(ver.encode()).digest()).rstrip(b"=").decode()
    q = urllib.parse.urlencode({"client_id": "account-console", "redirect_uri": redirect, "response_type": "code",
                                "scope": "openid", "state": secrets.token_hex(8), "nonce": secrets.token_hex(8),
                                "code_challenge": ch, "code_challenge_method": "S256", "kc_action": "UPDATE_PASSWORD"})
    resp = b.get(f"https://{auth}/realms/tenant-a/protocol/openid-connect/auth?{q}")
    trail, first_form = [], None
    for _ in range(10):
        if resp.status in (302, 303):
            loc = resp.header("Location")
            if loc.startswith(redirect):
                trail.append("→ account")
                break
            resp = b.get(loc)
            continue
        fs = forms(resp.body.decode("utf-8", "replace"))
        f = next((x for x in fs if "password-new" in x["inputs"]), None)
        if f:
            first_form = first_form or "password-new"
            trail.append("password-new")
            newpw = secrets.token_urlsafe(18)
            st.secret_values.add(newpw)
            resp = b.request("POST", f["action"], urllib.parse.urlencode({**f["inputs"], "password-new": newpw,
                                                                           "password-confirm": newpw}).encode(),
                             {"Content-Type": "application/x-www-form-urlencoded"})
            trail.append(f"POST {resp.status}")
            break
        f = next((x for x in fs if "password" in x["inputs"]), None)
        if f:
            first_form = first_form or "password"
            trail.append("password")
            resp = b.request("POST", f["action"], urllib.parse.urlencode({**f["inputs"], "username": u["username"],
                                                                           "password": u["password"]}).encode(),
                             {"Content-Type": "application/x-www-form-urlencoded"})
            continue
        f = next((x for x in fs if "otp" in x["inputs"]), None)
        if f:
            trail.append("otp")
            resp = b.request("POST", f["action"], urllib.parse.urlencode({**f["inputs"], "otp": otp.code()}).encode(),
                             {"Content-Type": "application/x-www-form-urlencoded"})
            continue
        trail.append(f"{resp.status} {[sorted(x['inputs']) for x in fs]}")
        break
    cfg = kc_call(kc, "GET", "/admin/realms/tenant-a/authentication/required-actions/UPDATE_PASSWORD/config")
    ok = first_form == "password" and trail[:3] == ["password", "otp", "password-new"] and \
        cfg.get("config", {}).get("max_auth_age") == "0"
    r.add("E2E-28", "A-4: đổi mật khẩu ở account console (kc_action=UPDATE_PASSWORD) 2 s sau khi đăng nhập phải xác "
          "thực lại (mật khẩu + OTP) trước form mật khẩu mới — max_auth_age 0 (P6)", ok,
          f"bước {trail}; config UPDATE_PASSWORD {cfg.get('config')}")


# ---------------------------------------------------------------------------------------------------- A-6
def check_mfa_evidence(r, st: Stack) -> None:
    kc = admin_api(st)
    rows = psql(st, "SELECT origin, coalesce(acr, '-'), array_to_string(amr, ',') FROM sessions WHERE revoked_at IS NULL "
                    "ORDER BY created_at DESC LIMIT 20")
    admin_amr = [x[2] for x in rows if x[0] == "admin"]
    portal = kc_call(kc, "GET", "/admin/realms/platform/clients?clientId=mg-portal")[0]
    mappers = kc_call(kc, "GET", f"/admin/realms/platform/clients/{portal['id']}/protocol-mappers/models")
    amr = next((m for m in mappers if m.get("protocolMapper") == "oidc-amr-mapper"), None)
    detail = [f"phiên admin sống: amr {admin_amr[:3]}"]
    ok = bool(admin_amr) and all("otp" in a.split(",") for a in admin_amr) and amr is not None
    if amr is None:  # nothing to remove: the realm itself is wrong
        r.add("E2E-29", "A-6: bằng chứng MFA (amr)", False, "; ".join(detail) + "; realm platform thiếu mapper amr")
        return
    host = f"admin.{st.domain}"
    # a staff member whose TOTP is already enrolled (the enrolling login itself carries no otp: the harness signs in
    # twice — backend.portal_login), then the realm loses its amr mapper (a break-glass mistake)
    u, otp, first = new_user(st, kc, "platform", "e2e-mfa"), TOTP(), Browser(st)
    _, steps0 = portal_login(st, first, host, "scope=platform", u, otp)
    before = int(psql(st, "SELECT count(*) FROM audit_events WHERE action = 'auth.login' AND outcome = 'denied' "
                          "AND details->>'reason' = 'mfa_evidence_missing'")[0][0])
    kc_call(kc, "DELETE", f"/admin/realms/platform/clients/{portal['id']}/protocol-mappers/models/{amr['id']}")
    try:
        b = Browser(st)
        start = b.get(f"https://{host}/api/v1/auth/login?scope=platform")
        cb, steps = keycloak_login(st, b, start.header("Location"), u, otp, host)
        refused = b.get(cb)
        session = b.get(f"https://{host}/api/v1/auth/session").status
    finally:
        restored = {k: v for k, v in amr.items() if k != "id"}
        kc_call(kc, "POST", f"/admin/realms/platform/clients/{portal['id']}/protocol-mappers/models", restored)
    after = int(psql(st, "SELECT count(*) FROM audit_events WHERE action = 'auth.login' AND outcome = 'denied' "
                         "AND details->>'reason' = 'mfa_evidence_missing'")[0][0])
    b2 = Browser(st)
    _, steps2 = portal_login(st, b2, host, "scope=platform", u, otp)
    ok &= (steps0 == ["password", "configure_totp", "password", "otp"] and steps == ["password", "otp"]
           and refused.status == 401 and refused.json().get("code") == "reauth_required" and session == 401
           and after >= 1 and steps2 == ["password", "otp"])
    detail.append(f"đăng nhập đầu (đăng ký TOTP) bước {steps0}; bỏ mapper amr: bước {steps} ⇒ callback {refused.status} "
                  f"{refused.json().get('code')}, session {session}, hàng audit mfa_evidence_missing {before}→{after} (từ chối ẩn danh "
                  f"gộp theo nguồn — G2 F2); "
                  f"trả mapper: đăng nhập lại {steps2}")
    r.add("E2E-29", "A-6: phiên platform mang amr có yếu tố thứ hai (Keycloak: mapper amr + tham chiếu pwd/otp); ID token "
          "platform không có bằng chứng MFA ⇒ 401 reauth_required, không session, audit mfa_evidence_missing (mapper trả lại "
          "sau ca); lần đăng nhập đăng ký TOTP phải đăng nhập lại", ok, "; ".join(detail))


# ---------------------------------------------------------------------------------------------------- A-2
def check_revoke_sessions(r, st: Stack) -> None:
    kc = admin_api(st)
    host, query = f"app.{st.domain}", "scope=tenant&tenant=tenant-a"
    idp = st.env["MG_IDP_ID_TENANT_A"]
    u, otp, b, other = new_user(st, kc, "tenant-a", "e2e-off"), TOTP(), Browser(st), Browser(st)
    portal_login(st, b, host, query, u, otp)
    v, ov = new_user(st, kc, "tenant-a", "e2e-stay"), Browser(st)
    portal_login(st, ov, host, query, v)
    user = kc_call(kc, "GET", f"/admin/realms/tenant-a/users/{u['sub']}")
    user["enabled"] = False
    kc_call(kc, "PUT", f"/admin/realms/tenant-a/users/{u['sub']}", user)
    kc_call(kc, "POST", f"/admin/realms/tenant-a/users/{u['sub']}/logout")
    survives = b.get(f"https://{host}/api/v1/auth/session").status          # P5: the BFF session outlives the lock
    p = admin_cmd(st, ["revoke-sessions", "--idp", idp, "--subject", u["sub"]])
    out = st.redact(p.stdout + p.stderr)
    after = b.get(f"https://{host}/api/v1/auth/session").status
    stays = ov.get(f"https://{host}/api/v1/auth/session").status
    user["enabled"] = True                                                   # Keycloak lets the person in again …
    kc_call(kc, "PUT", f"/admin/realms/tenant-a/users/{u['sub']}", user)
    start = other.get(f"https://{host}/api/v1/auth/login?{query}")
    cb, _ = keycloak_login(st, other, start.header("Location"), u, otp, host)
    locked = other.get(cb)                                                   # … the platform does not
    p2 = admin_cmd(st, ["enable-identity", "--idp", idp, "--subject", u["sub"]])
    again = Browser(st)
    sess, _ = portal_login(st, again, host, query, u, otp)
    audit = psql(st, "SELECT action FROM audit_events WHERE action LIKE 'identity.%' AND resource_id = "
                     f"(SELECT id::text FROM identities WHERE subject = '{u['sub']}') ORDER BY occurred_at, action")
    actions = [a[0] for a in audit]
    ok = (survives == 200 and p.returncode == 0 and "sessions revoked: 1" in out and "active → disabled" in out
          and after == 401 and stays == 200 and locked.status == 403 and p2.returncode == 0 and bool(sess)
          and actions == ["identity.sessions.revoke.requested", "identity.sessions.revoke.succeeded", "identity.enable"])
    r.add("E2E-30", "A-2: khóa ở Keycloak không chạm phiên BFF (P5 — giới hạn còn lại); `admin revoke-sessions` thu hồi "
          "phiên BFF của đúng người đó và khóa identity (Keycloak mở lại vẫn bị nền tảng từ chối) tới `enable-identity`; "
          "cặp audit", ok,
          f"sau khóa Keycloak {survives}; revoke-sessions exit {p.returncode} ({'1 phiên' if 'sessions revoked: 1' in out else out[-200:]}); "
          f"sau lệnh {after}, người khác {stays}; Keycloak mở lại ⇒ callback {locked.status}; enable-identity exit "
          f"{p2.returncode} ⇒ đăng nhập lại {bool(sess)}; audit {actions}")


# ---------------------------------------------------------------------------------------------------- A-8
def check_idp_network(r, st: Stack) -> None:
    kc = admin_api(st)
    idp_ip = st.docker("inspect", "-f", f'{{{{(index .NetworkSettings.Networks "{st.name("idp")}").IPAddress}}}}',
                       st.compose("ps", "-q", "idp").stdout.strip()).stdout.strip()
    on_edge = st.docker("inspect", "-f", f'{{{{index .NetworkSettings.Networks "{st.name("edge")}"}}}}',
                        st.compose("ps", "-q", "idp").stdout.strip(), check=False).stdout.strip()
    probe = st.docker("run", "--rm", "--name", st.name("direct"), "--network", st.name("edge"), "--read-only",
                      "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", st.images["alpine"], "sh", "-c",
                      "for u in http://idp:8080/realms/master/.well-known/openid-configuration "
                      f"http://{idp_ip}:8080/realms/master/.well-known/openid-configuration; do "
                      'if wget -q -T 5 -O /dev/null "$u" 2>/dev/null; then echo "REACHED $u"; else echo "refused"; fi; done',
                      check=False, timeout=60)
    lines = probe.stdout.split()
    env = {**os.environ, "MG_IDP_PROJECT": st.prefix, "MG_IDP_REALMS": str(st.work / "render" / "idp" / "idp" / "realms"),
           "DOCKER": " ".join(st.docker_cmd)}
    script = str(ROOT / "infrastructure" / "idp" / "realm-update.sh")
    runs = []
    for _ in range(2):
        p = subprocess.run(["bash", script], capture_output=True, text=True, env=env, timeout=600, encoding="utf-8")
        runs.append((p.returncode, st.redact(p.stdout + p.stderr)))
    chk = subprocess.run(["bash", script, "--check"], capture_output=True, text=True, env=env, timeout=600, encoding="utf-8")
    master = kc_call(kc, "GET", "/admin/realms/master")
    first, second = runs
    ok = (lines == ["refused", "refused"] and on_edge in ("", "<no value>", "<nil>") and first[0] == 0
          and "realm platform: 0 thay đổi" in first[1] and "realm master: 7 thay đổi" in first[1]
          and first[1].count("check_realm trên bản export của Keycloak — đạt") == 3 and second[0] == 0
          and "realm master: 0 thay đổi" in second[1] and chk.returncode == 0
          and master.get("bruteForceProtected") is True and master.get("permanentLockout") is False)
    if not ok and (first[0] != 0 or second[0] != 0):
        raise StackError(f"realm-update.sh: {first[1][-600:]} | {second[1][-300:]}")
    r.add("E2E-31", "A-8: chỉ edge tới được idp:8080 (container khác trên mạng edge: theo tên và theo IP đều không); "
          "realm-update.sh: realm mới 0 thay đổi, realm master được gia cố (brute force, event, policy), chạy lại 0 thay "
          "đổi, --check sạch, check_realm đạt trên bản export của Keycloak", ok,
          f"từ mạng edge: {lines}; idp trên mạng edge: {on_edge or 'không'}; lần 1 exit {first[0]} "
          f"({[x for x in first[1].splitlines() if x.startswith('realm ')][:4]}); lần 2 exit {second[0]}; --check exit "
          f"{chk.returncode}; master bruteForceProtected {master.get('bruteForceProtected')}")


def run_all(r, st: Stack, guarded) -> None:
    for tid, fn in (("E2E-26", check_logout), ("E2E-27", check_blocklist), ("E2E-28", check_reauth_before_password_change),
                    ("E2E-29", check_mfa_evidence), ("E2E-30", check_revoke_sessions), ("E2E-31", check_idp_network)):
        guarded(r, tid, fn, st)
