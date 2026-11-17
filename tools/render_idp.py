#!/usr/bin/env python3
"""Render the IdP (Keycloak) of one environment: compose project mg-idp + the realms to import (P2-T05; §8.2, §8.3,
§14.4 of the master plan).

Usage:
  python3 tools/render_idp.py <env file> <out_dir> [--image <ref>]
  python3 tools/render_idp.py new-ids            # three fresh UUIDv7 for the MG_IDP_ID_* of a new environment

<env file>  infrastructure/environments/<env>/<env>.env — MG_BASE_DOMAIN and MG_IDP_ID_PLATFORM, MG_IDP_ID_TENANT_A,
            MG_IDP_ID_TENANT_B: the identity_providers.id of each realm. The Portal callback is
            /api/v1/auth/callback/{idpId} (§8.3, one redirect URI per IdP), so the id is part of the redirect URI
            registered in the realm; P2-T11 registers the identity_providers rows with exactly these ids. The process
            environment overrides the file (tools/mgenv.py), e.g. MG_BASE_DOMAIN=<test domain> for a dev stack.
--image     image built from infrastructure/docker/idp, pinned by digest (<name>@sha256:<64 hex>), or a local image ID
            (sha256:<64 hex>) for a dev/CI stack. Default: [images.mg-idp] in versions.lock.

Optional SMTP sink (staging/dev only): MG_IDP_MAIL_SINK=mailpit in the env file adds a Mailpit service `mailsink`
([images.mailpit]) to project mg-idp on a project-internal network `mail` (internal: no route out, no relay) that only
idp and mailsink join, and gives every realm an unauthenticated smtpServer → mailsink:1025, from
noreply@<MG_BASE_DOMAIN>. Mail never leaves the host; read it with the Mailpit UI (port 8025 on the `mail` network,
through an SSH tunnel). Unset/empty = no SMTP (the P2-T05 default). Any other value is refused. A real SMTP relay
(auth, TLS, password as a secret) is P3-T05a — never put an SMTP password in a realm template.

Writes, relative to /opt/meshguard/core on the host:
  compose.idp.yaml                  compose project mg-idp (idp + idp-db)
  idp/realms/<realm>.json           platform, tenant-a, tenant-b — Keycloak imports them with --import-realm
  idp/initdb/10-keycloak-db.sql     role/DB of Keycloak inside idp-db (copied unchanged)
  idp/initdb/20-idp-backup-role.sql read-only role idp_backup of the idp-backup service (P2-T05b; copied unchanged)

The realm templates (infrastructure/idp/realms/*.json.tmpl) hold only ${MG_*} placeholders and are expanded by
tools/mgenv.py. Every rendered realm must pass check_realm() — the security invariants of P2-T05 — before anything is
written; tools/test_render_idp.py runs the same checks (plus negative cases) in CI. Standard library only.
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import string
import sys
import time
import tomllib
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import mgenv  # noqa: E402 — env file of the environment (no secrets)
from render_edge import DOMAIN_RE, EDGE_IPS  # noqa: E402 — same domain rule and the edge's static IP on mg-idp

ROOT = pathlib.Path(__file__).resolve().parents[1]
TEMPLATE_VERSION = "2"
COMPOSE_TMPL = ROOT / "infrastructure" / "compose" / "compose.idp.yaml.tmpl"
REALM_DIR = ROOT / "infrastructure" / "idp" / "realms"
INITDB = [ROOT / "infrastructure" / "idp" / "initdb" / n for n in ("10-keycloak-db.sql", "20-idp-backup-role.sql")]
VERSIONS = ROOT / "versions.lock"

# Per realm: scope, Portal origin (§8.3: platform staff log in on admin.<domain>, tenant users on app.<domain>), the env
# variable holding the identity_providers.id, and the SSO session limits = Portal session limits of §8.3 step 6.
REALMS = {
    "platform": {"scope": "platform", "origin": "admin", "idp_var": "MG_IDP_ID_PLATFORM", "sso": (900, 28800)},
    "tenant-a": {"scope": "tenant", "origin": "app", "idp_var": "MG_IDP_ID_TENANT_A", "sso": (1800, 43200)},
    "tenant-b": {"scope": "tenant", "origin": "app", "idp_var": "MG_IDP_ID_TENANT_B", "sso": (1800, 43200)},
}
PORTAL, DRIVER = "mg-portal", "mg-idp-driver"
CLIENTS = {PORTAL, DRIVER, "admin-cli"}          # any other client in a template needs a review first
DRIVER_ROLES = {"manage-users", "view-users", "query-users"}   # realm-management roles of the driver (§8.2 (2))
# required actions Keycloak 26.8.2 creates by default: an import that lists requiredActions gets ONLY those (P2-T05)
REQUIRED_ACTIONS = {"TERMS_AND_CONDITIONS", "UPDATE_PROFILE", "VERIFY_EMAIL", "CONFIGURE_TOTP", "UPDATE_PASSWORD",
                    "delete_account", "UPDATE_EMAIL", "webauthn-register", "webauthn-register-passwordless",
                    "VERIFY_PROFILE", "delete_credential", "idp_link", "CONFIGURE_RECOVERY_AUTHN_CODES",
                    "update_user_locale"}
IMAGE_RE = re.compile(r"^(?:[a-z0-9][a-z0-9._/:-]*@)?sha256:[0-9a-f]{64}$")   # name@sha256:… or a local image ID
# G2 vòng 2 (docs/planning/evidence/G2-security-review.md):
# A-3 — danh sách mật khẩu cấm nướng trong image idp (infrastructure/docker/idp/Dockerfile: /opt/keycloak/mg/
#       password-blacklists/<file>); đổi nội dung danh sách ⇒ đổi tên file (v2…) để realm nào cũng phải cập nhật policy.
BLOCKLIST_FILE = "mg-passwords-v1.txt"
# A-4 — required action đổi/thêm/gỡ credential từ account console (AIA): luôn xác thực lại (max_auth_age 0; mặc định
#       của Keycloak 26.8.2 là 300 s — P12).
REAUTH_ACTIONS = ("UPDATE_PASSWORD", "CONFIGURE_TOTP", "delete_credential", "webauthn-register",
                  "webauthn-register-passwordless")
# A-6 — tham chiếu amr (RFC 8176) của từng bước trong flow mg-browser-forms, mapper amr trên mg-portal.
AMR_REFS = {"auth-username-password-form": "pwd", "auth-otp-form": "otp"}
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


class ParamError(ValueError):
    pass


def uuid7() -> str:
    """UUIDv7 (RFC 9562): 48-bit Unix time in ms + random — §6.1 prefers v7 for primary keys."""
    b = bytearray(int(time.time() * 1000).to_bytes(6, "big") + os.urandom(10))
    b[6] = (b[6] & 0x0F) | 0x70
    b[8] = (b[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(b)))


def pinned_image(name: str = "mg-idp") -> str:
    images = tomllib.loads(VERSIONS.read_text(encoding="utf-8")).get("images", {})
    entry = images.get(name)
    if not entry or not re.fullmatch(r"sha256:[0-9a-f]{64}", entry.get("index", "")):
        raise ParamError(f"image {name} chưa pin trong versions.lock ([images.{name}] — ghi digest), "
                         "hoặc truyền --image <name>@sha256:<digest> (chỉ cho mg-idp)")
    return f"{entry['image']}@{entry['index']}"


MAIL_SINKS = {"", "mailpit"}
SMTP_SINK_PORT = "1025"
# Mailpit — staging/dev only. Text inserted into the rendered compose (two-space service indent, like the template).
MAILSINK_SERVICE = """\
  mailsink:                         # SMTP mẫu (Mailpit) — CHỈ staging/dev (MG_IDP_MAIL_SINK=mailpit). Nhận mọi thư của
                                    # Keycloak; network `mail` là internal ⇒ không có đường ra, không relay (không đặt
                                    # MP_SMTP_RELAY_*). Đọc thư: UI cổng 8025 trên network mail, qua SSH tunnel.
    image: ${mailpit_image}
    user: "65534:65534"
    read_only: true
    environment:                    # không secret
      MP_SMTP_BIND_ADDR: 0.0.0.0:${smtp_port}
      MP_UI_BIND_ADDR: 0.0.0.0:8025
      MP_MAX_MESSAGES: "500"
      MP_DISABLE_VERSION_CHECK: "true"
    tmpfs:
      - /tmp:size=64m,mode=1777     # DB tạm của Mailpit — thư mất khi khởi động lại (hộp thư thử)
    networks:
      mail:
        aliases: [mailsink]
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    mem_limit: 128m
    pids_limit: 64
    healthcheck:
      test: ["CMD", "/mailpit", "readyz"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s
    restart: unless-stopped
    logging:
      driver: json-file
      options: {max-size: "10m", max-file: "3"}
    labels:
      meshguard.role: idp-mailsink

"""
IDP_DATA_LINE = "      mg-idp-data: {}               # → idp-db\n"
IDP_MAIL_LINE = "      mail: {}                      # → mailsink:1025 (SMTP mẫu, chỉ khi MG_IDP_MAIL_SINK=mailpit)\n"
MAIL_NETWORK = "  mail:                             # chỉ idp + mailsink; internal = không có đường ra\n    internal: true\n"


def smtp_server(base_domain: str) -> dict:
    """smtpServer of a realm for the Mailpit sink: no auth, no TLS (internal network), no secret."""
    return {"host": "mailsink", "port": SMTP_SINK_PORT, "from": f"noreply@{base_domain}",
            "fromDisplayName": "MeshGuard (staging)", "auth": "false", "ssl": "false", "starttls": "false"}


def add_mail_sink(compose: str, mailpit_image: str) -> str:
    """Insert the mailsink service, the idp attachment and the `mail` network into the rendered compose."""
    for anchor in (IDP_DATA_LINE, "\nsecrets:\n", "\nnetworks:\n  mg-idp:\n"):
        if compose.count(anchor) != 1:
            raise ParamError(f"compose.idp.yaml.tmpl đã đổi — không tìm thấy đúng một chỗ chèn {anchor!r}")
    if re.search(r"^\S", compose.split("\nnetworks:\n  mg-idp:\n", 1)[1], flags=re.M):
        raise ParamError("compose.idp.yaml.tmpl đã đổi — `networks:` không còn là khóa top-level cuối cùng")
    service = string.Template(MAILSINK_SERVICE).substitute(mailpit_image=mailpit_image, smtp_port=SMTP_SINK_PORT)
    compose = compose.replace(IDP_DATA_LINE, IDP_DATA_LINE + IDP_MAIL_LINE)
    compose = compose.replace("\nsecrets:\n", "\n" + service + "secrets:\n")
    return compose.rstrip("\n") + "\n" + MAIL_NETWORK


def _execs(flows: dict, alias: str) -> list[dict]:
    return sorted(flows[alias].get("authenticationExecutions", []), key=lambda e: e.get("priority", 0))


def _strings(o, path: str = ""):
    if isinstance(o, dict):
        for k, v in o.items():
            yield from _strings(v, f"{path}.{k}")
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from _strings(v, f"{path}[{i}]")
    elif isinstance(o, str):
        yield path, o


def check_realm(rep: dict, realm: str, base_domain: str, idp_id: str) -> list[str]:
    """Security invariants of a rendered realm (P2-T05). Returns the list of violations (empty = OK)."""
    spec = REALMS[realm]
    p: list[str] = []

    def need(ok: bool, what: str) -> None:
        if not ok:
            p.append(f"{realm}: {what}")

    text = json.dumps(rep, ensure_ascii=False)
    need("${" not in text, "còn placeholder ${…} — Keycloak sẽ tự thay bằng biến môi trường của nó lúc import")
    long = [k for k, v in _strings(rep) if len(v) > 255]
    need(not long, f"chuỗi dài hơn 255 ký tự (cột varchar(255) của Keycloak ⇒ import thất bại): {long}")
    need('"impersonation"' not in text, "nhắc tới role impersonation (§8.2 (2))")
    need("credentials" not in rep and all("credentials" not in u for u in rep.get("users", [])),
         "template không được chứa credential")
    need(rep.get("realm") == realm and rep.get("enabled") is True, "tên realm / enabled")
    attrs = rep.get("attributes", {})
    need(attrs.get("meshguard.idp_id") == idp_id and attrs.get("meshguard.scope") == spec["scope"],
         "attributes meshguard.idp_id / meshguard.scope")
    need(rep.get("sslRequired") == "all", "sslRequired phải là all (mọi lời gọi qua TLS của edge)")
    need(rep.get("registrationAllowed") is False, "tự đăng ký phải tắt (user chỉ vào qua lời mời/driver)")
    need(rep.get("organizationsEnabled") is False, "Organizations phải tắt (issuer theo realm — §8.2)")
    # brute force: bật, khóa TẠM (không khóa vĩnh viễn — tránh DoS khóa Tenant Owner)
    need(rep.get("bruteForceProtected") is True and rep.get("permanentLockout") is False
         and 3 <= int(rep.get("failureFactor", 0)) <= 10, "brute-force detection")
    m = re.search(r"\blength\((\d+)\)", rep.get("passwordPolicy", ""))
    need(bool(m) and int(m.group(1)) >= 12, "passwordPolicy phải có length(>=12)")
    bl = re.findall(r"\bpasswordBlacklist\(([^)]*)\)", rep.get("passwordPolicy", ""))
    need(bl == [BLOCKLIST_FILE], f"passwordPolicy phải có đúng passwordBlacklist({BLOCKLIST_FILE}) — danh sách trong image "
                                 f"idp (G2 vòng 2 A-3), có {bl}")
    need(rep.get("otpPolicyType") == "totp" and rep.get("otpPolicyCodeReusable") is False, "OTP policy (TOTP, dùng một lần)")
    need((rep.get("ssoSessionIdleTimeout"), rep.get("ssoSessionMaxLifespan")) == spec["sso"],
         f"phiên SSO phải là {spec['sso']} giây (§8.3 bước 6)")
    need(int(rep.get("accessCodeLifespanLogin", 1800)) <= 600, "đăng nhập phải xong trong ≤ 10 phút (auth_requests — §8.3)")
    need(rep.get("eventsEnabled") is True and rep.get("adminEventsEnabled") is True
         and rep.get("adminEventsDetailsEnabled") is True, "login event + admin event (P3-T15)")
    smtp = rep.get("smtpServer") or {}
    need(not ({"password", "authTokenUrl", "authTokenClientSecret"} & set(smtp)) and smtp.get("auth", "false") == "false",
         "smtpServer không được mang mật khẩu/xác thực (SMTP thật có secret — P3-T05a, qua Admin API)")

    # MFA bắt buộc: browser flow = cookie | (mật khẩu REQUIRED + OTP REQUIRED), không có nhánh điều kiện
    flows = {f.get("alias"): f for f in rep.get("authenticationFlows", [])}
    need(rep.get("browserFlow") == "mg-browser" and {"mg-browser", "mg-browser-forms"} <= set(flows), "browserFlow mg-browser")
    if {"mg-browser", "mg-browser-forms"} <= set(flows):
        top = [(e.get("authenticator") or e.get("flowAlias"), e.get("requirement")) for e in _execs(flows, "mg-browser")]
        forms = [(e.get("authenticator"), e.get("requirement")) for e in _execs(flows, "mg-browser-forms")]
        need(top == [("auth-cookie", "ALTERNATIVE"), ("mg-browser-forms", "ALTERNATIVE")], f"mg-browser = {top}")
        need(forms == [("auth-username-password-form", "REQUIRED"), ("auth-otp-form", "REQUIRED")],
             f"mg-browser-forms phải là mật khẩu + OTP đều REQUIRED, có {forms}")
        # amr (A-6): mỗi bước mang tham chiếu của nó (pwd, otp), maxAge > 0 (0 ⇒ Keycloak bỏ bước cũ hơn 1 s khỏi amr)
        cfgs = {c.get("alias"): c.get("config", {}) for c in rep.get("authenticatorConfig", [])}
        refs = {e.get("authenticator"): cfgs.get(e.get("authenticatorConfig"), {}) for e in _execs(flows, "mg-browser-forms")}
        need(all(refs.get(a, {}).get("default.reference.value") == v
                 and int(refs.get(a, {}).get("default.reference.maxAge", "0")) > 0 for a, v in AMR_REFS.items()),
             f"mg-browser-forms: mỗi bước phải có authenticatorConfig default.reference.value {AMR_REFS} và maxAge > 0 "
             "(amr — G2 vòng 2 A-6)")
    ra = {a.get("alias"): a for a in rep.get("requiredActions", [])}
    need(set(ra) == REQUIRED_ACTIONS, f"requiredActions phải đủ bộ mặc định của Keycloak 26.8.2 (thiếu "
                                      f"{sorted(REQUIRED_ACTIONS - set(ra))}, thừa {sorted(set(ra) - REQUIRED_ACTIONS)})")
    totp = ra.get("CONFIGURE_TOTP", {})
    need(totp.get("enabled") is True and totp.get("defaultAction") is True, "CONFIGURE_TOTP phải bật và là default action")
    lax = [a for a in REAUTH_ACTIONS if ra.get(a, {}).get("config", {}).get("max_auth_age") != "0"]
    need(not lax, f"required action {lax}: config max_auth_age phải là \"0\" (đổi credential luôn xác thực lại — G2 vòng 2 A-4)")

    clients = {c.get("clientId"): c for c in rep.get("clients", [])}
    need(set(clients) == CLIENTS, f"client phải đúng {sorted(CLIENTS)}, có {sorted(clients)}")
    for cid, c in clients.items():
        need("secret" not in c, f"client {cid} không được mang secret trong template")
        need(c.get("implicitFlowEnabled") is False and c.get("directAccessGrantsEnabled") is False,
             f"client {cid}: implicit/direct access grant phải tắt")
        need(all("*" not in u for u in c.get("redirectUris", [])) and not c.get("webOrigins"),
             f"client {cid}: không wildcard redirect, không webOrigins (BFF — CORS tắt)")
        attrs = c.get("attributes", {})
        need(attrs.get("oauth2.device.authorization.grant.enabled", "false") == "false"
             and attrs.get("oidc.ciba.grant.enabled", "false") == "false"
             and attrs.get("standard.token.exchange.enabled", "false") == "false", f"client {cid}: grant phụ phải tắt")
    portal = clients.get(PORTAL, {})
    want_redirect = f"https://{spec['origin']}.{base_domain}/api/v1/auth/callback/{idp_id}"
    need(portal.get("redirectUris") == [want_redirect], f"{PORTAL}: redirect URI phải đúng một giá trị {want_redirect}")
    need(portal.get("publicClient") is False and portal.get("standardFlowEnabled") is True
         and portal.get("serviceAccountsEnabled") is False and portal.get("fullScopeAllowed") is False,
         f"{PORTAL}: client bí mật, chỉ Authorization Code")
    pa = portal.get("attributes", {})
    need(pa.get("pkce.code.challenge.method") == "S256", f"{PORTAL}: PKCE S256 bắt buộc")
    need(pa.get("use.refresh.tokens") == "false", f"{PORTAL}: không cấp refresh token (BFF chỉ cần ID token)")
    need(pa.get("exclude.issuer.from.auth.response") == "false", f"{PORTAL}: phải trả iss trong authorization response (RFC 9207)")
    need({"basic", "acr"} <= set(portal.get("defaultClientScopes", [])), f"{PORTAL}: scope basic (sub, auth_time) và acr")
    want_plr = f"https://{spec['origin']}.{base_domain}/"
    need(pa.get("post.logout.redirect.uris") == want_plr,
         f"{PORTAL}: post.logout.redirect.uris phải đúng một giá trị {want_plr} (RP-Initiated Logout — G2 vòng 2 A-1)")
    amr = [m for m in portal.get("protocolMappers", []) if m.get("protocolMapper") == "oidc-amr-mapper"]
    need(len(amr) == 1 and amr[0].get("config", {}).get("id.token.claim") == "true",
         f"{PORTAL}: cần đúng một mapper oidc-amr-mapper vào ID token (BFF đòi bằng chứng MFA — G2 vòng 2 A-6)")
    need(len(portal.get("protocolMappers", [])) == len(amr), f"{PORTAL}: không mapper nào khác ngoài amr")
    drv = clients.get(DRIVER, {})
    need(drv.get("serviceAccountsEnabled") is True and drv.get("standardFlowEnabled") is False
         and drv.get("publicClient") is False and drv.get("fullScopeAllowed") is False,
         f"{DRIVER}: chỉ client credentials (service account), client bí mật")
    need("kc-admin-api" in drv.get("defaultClientScopes", []), f"{DRIVER}: cần scope kc-admin-api (audience Admin API)")
    need(clients.get("admin-cli", {}).get("enabled") is False, "admin-cli phải tắt trong realm này")
    users = rep.get("users", [])
    need(len(users) == 1 and users[0].get("serviceAccountClientId") == DRIVER
         and users[0].get("username") == f"service-account-{DRIVER}" and not users[0].get("realmRoles")
         and {k: set(v) for k, v in users[0].get("clientRoles", {}).items()} == {"realm-management": DRIVER_ROLES},
         f"chỉ một user: service account của {DRIVER} với đúng {sorted(DRIVER_ROLES)}")
    csm = rep.get("clientScopeMappings", {})
    need(set(csm) == {"realm-management"}
         and [(x.get("client"), set(x.get("roles", []))) for x in csm["realm-management"]] == [(DRIVER, DRIVER_ROLES)],
         f"clientScopeMappings: {DRIVER} chỉ được scope {sorted(DRIVER_ROLES)}")
    return p


def render(env: dict[str, str], image: str) -> dict[str, str]:
    base_domain = env.get("MG_BASE_DOMAIN", "")
    if not DOMAIN_RE.fullmatch(base_domain):
        raise ParamError("MG_BASE_DOMAIN thiếu hoặc không hợp lệ")
    if not IMAGE_RE.match(image):
        raise ParamError("image phải pin theo digest (<name>@sha256:<64 hex>) hoặc là image ID sha256:<64 hex>")
    ids = {}
    for realm, spec in REALMS.items():
        v = env.get(spec["idp_var"], "")
        if not UUID_RE.match(v):
            raise ParamError(f"{spec['idp_var']} thiếu hoặc không phải UUID (chữ thường): {v!r}")
        ids[realm] = v
    if len(set(ids.values())) != len(ids):
        raise ParamError("MG_IDP_ID_* phải khác nhau")
    sink = env.get("MG_IDP_MAIL_SINK", "")
    if sink not in MAIL_SINKS:
        raise ParamError(f"MG_IDP_MAIL_SINK chỉ nhận 'mailpit' hoặc để trống, có {sink!r}")
    files: dict[str, str] = {}
    problems: list[str] = []
    for realm in REALMS:
        text = mgenv.expand_text((REALM_DIR / f"{realm}.json.tmpl").read_text(encoding="utf-8"), env)
        try:
            rep = json.loads(text)
        except json.JSONDecodeError as e:
            raise ParamError(f"{realm}: JSON không hợp lệ sau khi render: {e}") from e
        if sink:
            rep["smtpServer"] = smtp_server(base_domain)
            text = json.dumps(rep, ensure_ascii=False, indent=2) + "\n"
        problems += check_realm(rep, realm, base_domain, ids[realm])
        files[f"idp/realms/{realm}.json"] = text
    if problems:
        raise ParamError("realm vi phạm bất biến P2-T05:\n  " + "\n  ".join(problems))
    values = {"template_version": TEMPLATE_VERSION, "idp_image": image, "auth_host": f"auth.{base_domain}",
              "edge_idp_ip": EDGE_IPS["edge_idp_ip"]}
    files["compose.idp.yaml"] = string.Template(COMPOSE_TMPL.read_text(encoding="utf-8")).substitute(values)
    if sink:
        files["compose.idp.yaml"] = add_mail_sink(files["compose.idp.yaml"], pinned_image("mailpit"))
    for f in INITDB:
        files[f"idp/initdb/{f.name}"] = f.read_text(encoding="utf-8")
    return files


def issuers(env: dict[str, str]) -> dict[str, str]:
    return {realm: f"https://auth.{env['MG_BASE_DOMAIN']}/realms/{realm}" for realm in REALMS}


def main(argv: list[str]) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    if len(argv) == 2 and argv[1] == "new-ids":
        for spec in REALMS.values():
            print(f"{spec['idp_var']}={uuid7()}")
        return 0
    args = argv[1:]
    image = None
    if "--image" in args:
        i = args.index("--image")
        if i + 1 >= len(args):
            print(__doc__)
            return 2
        image = args[i + 1]
        del args[i:i + 2]
    if len(args) != 2:
        print(__doc__)
        return 2
    try:
        env = mgenv.environment(pathlib.Path(args[0]))
        files = render(env, image or pinned_image())
    except (ParamError, mgenv.EnvError, OSError, KeyError, ValueError) as e:
        print(f"render failed: {e}", file=sys.stderr)
        return 1
    out = pathlib.Path(args[1])
    for rel, text in files.items():
        path = out / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
    print(f"rendered {len(files)} files into {out}")
    for realm, iss in issuers(env).items():
        print(f"  {realm:9} issuer {iss}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
