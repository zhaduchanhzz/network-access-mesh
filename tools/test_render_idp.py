#!/usr/bin/env python3
"""Unit test of tools/render_idp.py (P2-T05): realm templates + compose of the IdP, without a running Keycloak.

    python tools/test_render_idp.py        # exit code 0 = pass. Standard library only.

Checks: the three realms render for a sample environment and for the real staging env file and pass check_realm();
the output is deterministic; tenant-a and tenant-b differ only by name/id, platform only by the documented keys
(origin, SSO limits, names); every weakening of a security invariant is caught (negative cases); bad parameters are
refused; the rendered compose keeps secrets out of environment variables and keeps the hardening.
"""
from __future__ import annotations

import copy
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import mgenv  # noqa: E402
import render_idp as ri  # noqa: E402

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8")
failures = 0
IMG = "ghcr.io/zhaduchanhzz/network-access-mesh/idp@sha256:" + "ab" * 32
ENV = {"MG_BASE_DOMAIN": "example.com", "MG_IDP_ID_PLATFORM": "00000000-0000-7000-8000-000000000001",
       "MG_IDP_ID_TENANT_A": "00000000-0000-7000-8000-000000000002",
       "MG_IDP_ID_TENANT_B": "00000000-0000-7000-8000-000000000003"}


def check(ok: bool, name: str, detail: str = "") -> None:
    global failures
    print(f"{'PASS' if ok else 'FAIL'} {name}{'' if ok else ': ' + detail}")
    failures += 0 if ok else 1


def raises(fn, name: str) -> None:
    try:
        fn()
    except (ri.ParamError, mgenv.EnvError) as e:
        check(True, f"{name} ({str(e).splitlines()[0][:70]})")
        return
    check(False, name, "no error raised")


files = ri.render(ENV, IMG)
check(sorted(files) == ["compose.idp.yaml", "idp/initdb/10-keycloak-db.sql", "idp/initdb/20-idp-backup-role.sql",
                        "idp/realms/platform.json", "idp/realms/tenant-a.json", "idp/realms/tenant-b.json"],
      "render writes 6 files", str(sorted(files)))
check(files == ri.render(ENV, IMG), "output is deterministic")
reps = {r: json.loads(files[f"idp/realms/{r}.json"]) for r in ri.REALMS}
for realm, rep in reps.items():
    ids = ENV[ri.REALMS[realm]["idp_var"]]
    check(ri.check_realm(rep, realm, "example.com", ids) == [], f"{realm}: every invariant holds")
    portal = next(c for c in rep["clients"] if c["clientId"] == ri.PORTAL)
    origin = "admin" if realm == "platform" else "app"
    check(portal["redirectUris"] == [f"https://{origin}.example.com/api/v1/auth/callback/{ids}"],
          f"{realm}: exact Portal callback on {origin}.<domain> with the idpId (§8.3)", str(portal["redirectUris"]))
    check(portal["attributes"].get("post.logout.redirect.uris") == f"https://{origin}.example.com/",
          f"{realm}: post-logout redirect = root of {origin}.<domain> (G2 round 2, A-1)")
    check(rep["passwordPolicy"].endswith(f" and passwordBlacklist({ri.BLOCKLIST_FILE})"),
          f"{realm}: password blocklist of the idp image (G2 round 2, A-3)", rep["passwordPolicy"])
check(len(set(ri.issuers(ENV).values())) == 3, "three distinct issuers", str(ri.issuers(ENV)))

# tenant-a == tenant-b modulo name and id; platform differs only by documented keys
def normalized(rep: dict) -> dict:
    r = copy.deepcopy(rep)
    r["realm"] = r["displayName"] = "X"
    r["attributes"]["meshguard.idp_id"] = "ID"
    r["attributes"]["meshguard.scope"] = "SCOPE"
    r["ssoSessionIdleTimeout"] = r["ssoSessionMaxLifespan"] = 0
    for c in r["clients"]:
        if c["clientId"] == ri.PORTAL:
            c["name"], c["redirectUris"] = "NAME", ["REDIRECT"]
            c["attributes"]["post.logout.redirect.uris"] = "PLR"
    return r


ta, tb = (json.loads(json.dumps(reps[t]).replace(t, "TENANT").replace(ENV[v], "ID"))
          for t, v in (("tenant-a", "MG_IDP_ID_TENANT_A"), ("tenant-b", "MG_IDP_ID_TENANT_B")))
check(ta == tb, "tenant-a and tenant-b templates are identical except name/id")
check(normalized(reps["platform"]) == normalized(reps["tenant-a"]),
      "platform differs from tenants only by name, scope, idpId, SSO limits, Portal name/origin")

# negative cases: each weakening must be reported by check_realm
def mutated(fn) -> list[str]:
    rep = copy.deepcopy(reps["tenant-a"])
    fn(rep)
    return ri.check_realm(rep, "tenant-a", "example.com", ENV["MG_IDP_ID_TENANT_A"])


def client(rep: dict, cid: str) -> dict:
    return next(c for c in rep["clients"] if c["clientId"] == cid)


def flow(rep: dict, alias: str) -> dict:
    return next(f for f in rep["authenticationFlows"] if f["alias"] == alias)


NEG = {
    "direct access grant on the Portal": lambda r: client(r, ri.PORTAL).update(directAccessGrantsEnabled=True),
    "implicit flow on the Portal": lambda r: client(r, ri.PORTAL).update(implicitFlowEnabled=True),
    "PKCE plain": lambda r: client(r, ri.PORTAL)["attributes"].update({"pkce.code.challenge.method": "plain"}),
    "PKCE not required": lambda r: client(r, ri.PORTAL)["attributes"].pop("pkce.code.challenge.method"),
    "wildcard redirect URI": lambda r: client(r, ri.PORTAL).update(redirectUris=["https://app.example.com/*"]),
    "callback of another IdP": lambda r: client(r, ri.PORTAL).update(
        redirectUris=["https://app.example.com/api/v1/auth/callback/" + ENV["MG_IDP_ID_TENANT_B"]]),
    "callback on the admin origin": lambda r: client(r, ri.PORTAL).update(
        redirectUris=["https://admin.example.com/api/v1/auth/callback/" + ENV["MG_IDP_ID_TENANT_A"]]),
    "client secret in the template": lambda r: client(r, ri.PORTAL).update(secret="x" * 32),
    "public Portal client": lambda r: client(r, ri.PORTAL).update(publicClient=True),
    "web origins (CORS)": lambda r: client(r, ri.PORTAL).update(webOrigins=["+"]),
    "refresh tokens for the Portal": lambda r: client(r, ri.PORTAL)["attributes"].update({"use.refresh.tokens": "true"}),
    "no iss in the authorization response": lambda r: client(r, ri.PORTAL)["attributes"].update(
        {"exclude.issuer.from.auth.response": "true"}),
    "conditional OTP": lambda r: flow(r, "mg-browser-forms")["authenticationExecutions"][1].update(requirement="CONDITIONAL"),
    "OTP removed from the browser flow": lambda r: flow(r, "mg-browser-forms")["authenticationExecutions"].pop(),
    "another browser flow bound": lambda r: r.update(browserFlow="browser"),
    "CONFIGURE_TOTP not a default action": lambda r: next(a for a in r["requiredActions"]
                                                           if a["alias"] == "CONFIGURE_TOTP").update(defaultAction=False),
    "requiredActions reduced to CONFIGURE_TOTP": lambda r: r.update(
        requiredActions=[a for a in r["requiredActions"] if a["alias"] == "CONFIGURE_TOTP"]),
    "driver gets realm-admin": lambda r: r["users"][0]["clientRoles"]["realm-management"].append("realm-admin"),
    "driver scope widened": lambda r: r["clientScopeMappings"]["realm-management"][0]["roles"].append("manage-clients"),
    "driver without kc-admin-api": lambda r: client(r, ri.DRIVER).update(defaultClientScopes=["basic"]),
    "driver with browser login": lambda r: client(r, ri.DRIVER).update(standardFlowEnabled=True),
    "admin-cli enabled": lambda r: client(r, "admin-cli").update(enabled=True),
    "extra client": lambda r: r["clients"].append({"clientId": "other", "implicitFlowEnabled": False,
                                                   "directAccessGrantsEnabled": False}),
    "impersonation role granted": lambda r: r["users"][0]["clientRoles"]["realm-management"].append("impersonation"),
    "human user with a password": lambda r: r["users"].append({"username": "alice", "credentials": [{"type": "password"}]}),
    "brute force off": lambda r: r.update(bruteForceProtected=False),
    "permanent lockout": lambda r: r.update(permanentLockout=True),
    "short passwords": lambda r: r.update(passwordPolicy="length(8) and notUsername"),
    "reusable OTP codes": lambda r: r.update(otpPolicyCodeReusable=True),
    "self registration": lambda r: r.update(registrationAllowed=True),
    "sslRequired external": lambda r: r.update(sslRequired="external"),
    "Organizations on": lambda r: r.update(organizationsEnabled=True),
    "longer SSO session": lambda r: r.update(ssoSessionIdleTimeout=7200),
    "admin events off": lambda r: r.update(adminEventsEnabled=False),
    "placeholder left for Keycloak": lambda r: r.update(displayName="${env.HOME}"),
    "description longer than varchar(255)": lambda r: client(r, ri.PORTAL).update(description="x" * 256),
    "device grant on a client": lambda r: client(r, ri.PORTAL)["attributes"].update(
        {"oauth2.device.authorization.grant.enabled": "true"}),
    "SMTP password in the template": lambda r: r.update(smtpServer={**ri.smtp_server("example.com"), "auth": "true",
                                                                     "user": "u", "password": "p"}),
    "SMTP auth on": lambda r: r.update(smtpServer={**ri.smtp_server("example.com"), "auth": "true"}),
    # G2 round 2
    "no password blocklist (A-3)": lambda r: r.update(passwordPolicy=r["passwordPolicy"].replace(
        f" and passwordBlacklist({ri.BLOCKLIST_FILE})", "")),
    "blocklist file not in the image (A-3)": lambda r: r.update(passwordPolicy=r["passwordPolicy"].replace(
        ri.BLOCKLIST_FILE, "other.txt")),
    "no post-logout redirect URI (A-1)": lambda r: client(r, ri.PORTAL)["attributes"].pop("post.logout.redirect.uris"),
    "post-logout redirect '+' (A-1)": lambda r: client(r, ri.PORTAL)["attributes"].update({"post.logout.redirect.uris": "+"}),
    "post-logout redirect wildcard (A-1)": lambda r: client(r, ri.PORTAL)["attributes"].update(
        {"post.logout.redirect.uris": "https://app.example.com/*"}),
    "post-logout redirect on admin (A-1)": lambda r: client(r, ri.PORTAL)["attributes"].update(
        {"post.logout.redirect.uris": "https://admin.example.com/"}),
    "no amr mapper (A-6)": lambda r: client(r, ri.PORTAL).update(protocolMappers=[]),
    "amr mapper not in the ID token (A-6)": lambda r: client(r, ri.PORTAL)["protocolMappers"][0]["config"].update(
        {"id.token.claim": "false"}),
    "extra Portal mapper": lambda r: client(r, ri.PORTAL)["protocolMappers"].append(
        {"name": "x", "protocolMapper": "oidc-hardcoded-claim-mapper", "config": {}}),
    "no amr reference on OTP (A-6)": lambda r: flow(r, "mg-browser-forms")["authenticationExecutions"][1].pop(
        "authenticatorConfig"),
    "amr reference maxAge 0 (A-6)": lambda r: r["authenticatorConfig"][0]["config"].update({"default.reference.maxAge": "0"}),
    "OTP step referenced as pwd (A-6)": lambda r: r["authenticatorConfig"][1]["config"].update(
        {"default.reference.value": "pwd"}),
    "UPDATE_PASSWORD default max_auth_age (A-4)": lambda r: next(a for a in r["requiredActions"]
                                                                  if a["alias"] == "UPDATE_PASSWORD").update(config={}),
    "delete_credential max_auth_age 300 (A-4)": lambda r: next(a for a in r["requiredActions"]
                                                               if a["alias"] == "delete_credential").update(
        config={"max_auth_age": "300"}),
}
for name, fn in NEG.items():
    probs = mutated(fn)
    check(bool(probs), f"negative: {name} is refused", "check_realm reported nothing")

# bad parameters
raises(lambda: ri.render(ENV, "ghcr.io/zhaduchanhzz/network-access-mesh/idp:latest"), "image by tag is refused")
raises(lambda: ri.render({**ENV, "MG_IDP_ID_TENANT_B": ""}, IMG), "missing MG_IDP_ID_TENANT_B is refused")
raises(lambda: ri.render({**ENV, "MG_IDP_ID_TENANT_B": ENV["MG_IDP_ID_TENANT_A"]}, IMG), "duplicate idp ids are refused")
raises(lambda: ri.render({**ENV, "MG_IDP_ID_PLATFORM": "not-a-uuid"}, IMG), "malformed idp id is refused")
raises(lambda: ri.render({**ENV, "MG_BASE_DOMAIN": "Example.COM"}, IMG), "invalid base domain is refused")
check(bool(ri.IMAGE_RE.match("sha256:" + "0" * 64)), "a local image ID (dev/CI stack) is accepted")

# compose: hardening kept, no secret in the environment
c = files["compose.idp.yaml"]
check("${" not in c and "$" not in c, "compose: no placeholder or $ left (docker compose would interpolate it)")
check(f"image: {IMG}" in c and "image: docker.io/library/postgres@sha256:" in c, "compose: both images pinned by digest")
check("KC_HOSTNAME: https://auth.example.com" in c and "KC_PROXY_TRUSTED_ADDRESSES: 10.249.7.2" in c,
      "compose: hostname auth.<domain>; only the edge (10.249.7.2 on mg-idp) is a trusted proxy")
# G2 round 2, A-8: idp is reachable from the edge only — on mg-idp (edge + idp), never on mg-edge
idp_svc = c.split("\n  idp:\n", 1)[1].split("\nsecrets:\n", 1)[0]
idp_nets = re.findall(r"^      ([a-z][a-z0-9-]*):", idp_svc.split("    networks:\n", 1)[1].split("    cap_drop:", 1)[0], flags=re.M)
check(idp_nets == ["mg-idp", "mg-idp-data", "mg-egress"] and "mg-edge" not in c.split("\nnetworks:\n", 1)[1],
      "compose: idp only on mg-idp (edge + idp), mg-idp-data and mg-egress — not on mg-edge (A-8)", str(idp_nets))
check(ri.EDGE_IPS["edge_idp_ip"] == "10.249.7.2", "the edge's static address on mg-idp (networks.sh 10.249.7.0/24)")
check(c.count("read_only: true\n") >= 2 and c.count("cap_drop: [ALL]") == 2 and c.count('"no-new-privileges:true"') == 2,
      "compose: read-only rootfs, cap_drop ALL, no-new-privileges on both services")
check('user: "1000:1000"' in c and 'user: "999:999"' in c, "compose: non-root users")
check("ports:" not in c, "compose: no published port")
cmd = re.search(r"command: \[(.*)\]", c)
check(bool(cmd) and cmd.group(1).index("--config-file=/run/secrets/keycloak.conf") < cmd.group(1).index('"start"')
      and "--optimized" in cmd.group(1), "compose: kc.sh --config-file=<secret> start --optimized")
env_keys = re.findall(r"^      ([A-Z][A-Z0-9_]+): ", c, flags=re.M)
bad = [k for k in env_keys if re.search(r"PASSWORD|SECRET|TOKEN", k) and not k.endswith("_FILE")]
check(env_keys and not bad, "compose: no environment variable carries a secret", str(bad))
check(all(s in c for s in ("/opt/meshguard/secrets/idp/keycloak.conf", "/opt/meshguard/secrets/idp/db_password",
                           "/opt/meshguard/secrets/idp/db_superuser_password",
                           "/opt/meshguard/secrets/idp/backup_db_password")), "compose: secrets are files")
role = files["idp/initdb/20-idp-backup-role.sql"]
check("CREATE ROLE idp_backup LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS" in role
      and "GRANT pg_read_all_data TO idp_backup;" in role and "default_transaction_read_only = on" in role
      and "cat /run/secrets/idp_backup_db_password" in role and not re.search(r"GRANT (?!pg_read_all_data|CONNECT)", role),
      "initdb: idp_backup is read-only (pg_read_all_data + CONNECT), password from the Docker secret")
check("mg-idp-data: {}" in c and "networks: [mg-idp-data]" in c, "compose: idp-db only on mg-idp-data")
check("mailsink" not in c and all("smtpServer" not in files[f"idp/realms/{r}.json"] for r in ri.REALMS),
      "no MG_IDP_MAIL_SINK: no SMTP sink, no smtpServer (P2-T05 default)")

# optional SMTP sink (staging/dev): Mailpit on a project-internal network, unauthenticated smtpServer in every realm
SINK_ENV = {**ENV, "MG_IDP_MAIL_SINK": "mailpit"}
sf = ri.render(SINK_ENV, IMG)
check(sorted(sf) == sorted(files), "sink: same 6 files")
check(sf == ri.render(SINK_ENV, IMG), "sink: output is deterministic")
for realm in ri.REALMS:
    rep = json.loads(sf[f"idp/realms/{realm}.json"])
    check(rep.get("smtpServer") == {"host": "mailsink", "port": "1025", "from": "noreply@example.com",
                                    "fromDisplayName": "MeshGuard (staging)", "auth": "false", "ssl": "false",
                                    "starttls": "false"}, f"sink: {realm} sends to mailsink:1025, no auth", str(rep.get("smtpServer")))
    check(ri.check_realm(rep, realm, "example.com", ENV[ri.REALMS[realm]["idp_var"]]) == [], f"sink: {realm} invariants hold")
    base = json.loads(files[f"idp/realms/{realm}.json"])
    rep.pop("smtpServer")
    check(rep == base, f"sink: {realm} differs from the default only by smtpServer")
sc = sf["compose.idp.yaml"]
mp = ri.pinned_image("mailpit")
check(mp.startswith("docker.io/axllent/mailpit@sha256:") and f"image: {mp}" in sc, "sink: Mailpit pinned by digest from versions.lock", mp)
check("${" not in sc and "$" not in sc, "sink: compose has no placeholder or $ left")
check(sc.count("cap_drop: [ALL]") == 3 and sc.count('"no-new-privileges:true"') == 3 and sc.count("read_only: true\n") >= 3
      and 'user: "65534:65534"' in sc, "sink: Mailpit non-root, read-only, cap_drop ALL, no-new-privileges")
check("ports:" not in sc and not re.search(r"^\s+MP_SMTP_RELAY\w*:", sc, flags=re.M), "sink: no published port, no relay")
svc = sc.split("\n  mailsink:", 1)[1].split("\nsecrets:\n", 1)[0]
check("mail:\n        aliases: [mailsink]" in svc and not re.search(r"mg-(edge|egress|idp-data)", svc),
      "sink: mailsink is only on the `mail` network")
check(sc.count(ri.IDP_MAIL_LINE) == 1 and sc.index(ri.IDP_MAIL_LINE) < sc.index("\n  mailsink:"),
      "sink: idp joins the `mail` network")
check(sc.endswith("\n  mail:                             # chỉ idp + mailsink; internal = không có đường ra\n    internal: true\n")
      and "networks: [mg-idp-data]" in sc, "sink: `mail` is internal and project-local; idp-db still only on mg-idp-data")
start, end = sc.index("\n  mailsink:") + 1, sc.index("\nsecrets:\n") + 1      # top-level secrets: (no indent)
check((sc[:start] + sc[end:]).replace(ri.IDP_MAIL_LINE, "").replace(ri.MAIL_NETWORK, "") == c,
      "sink: compose = default + mailsink + one network line + `mail` network, nothing else")
raises(lambda: ri.render({**ENV, "MG_IDP_MAIL_SINK": "smtp.example.com"}, IMG), "unknown MG_IDP_MAIL_SINK is refused")

# the real staging env file renders (with a stand-in image digest)
staging = mgenv.environment(ri.ROOT / "infrastructure" / "environments" / "staging" / "staging.env")
try:
    sf = ri.render(staging, IMG)
    check(len(sf) == 6, "staging.env renders the IdP")
except (ri.ParamError, mgenv.EnvError) as e:
    check(False, "staging.env renders the IdP", str(e))
# G2 round 2, A-3: the image the realms name in passwordBlacklist() builds that very file from the pinned source
import tomllib  # noqa: E402

docker = (ri.ROOT / "infrastructure" / "docker" / "idp" / "Dockerfile").read_text(encoding="utf-8")
src = tomllib.loads(ri.VERSIONS.read_text(encoding="utf-8"))["sources"]["password-blocklist"]
check(f"ADD --checksum=sha256:{src['sha256']} \\\n    {src['url']}" in docker
      and f"ADD --checksum=sha256:{src['license_sha256']} \\\n    {src['license_url']}" in docker,
      "idp Dockerfile downloads the blocklist and its licence pinned by versions.lock (sha256 checked in the build)")
check(f"/out/{ri.BLOCKLIST_FILE}" in docker and docker.count(ri.BLOCKLIST_FILE) >= 3
      and "KC_SPI_PASSWORD_POLICY__PASSWORD_BLACKLIST__BLACKLISTS_PATH=/opt/keycloak/mg/password-blacklists" in docker,
      f"idp Dockerfile writes {ri.BLOCKLIST_FILE} outside the tmpfs /opt/keycloak/data and points Keycloak at it")
words = [w for w in (ri.ROOT / "infrastructure" / "docker" / "idp" / "password-blocklist" / "context-words.txt")
         .read_text(encoding="utf-8").splitlines() if w and not w.startswith("#")]
check({"meshguard", "tenant-a", "password"} <= set(words) and all(w == w.lower() and " " not in w for w in words),
      "documented context words (ASVS 6.1.2) present, lower case", str(len(words)))
example = mgenv.parse_env_file(ri.ROOT / ".env.example")
check(all(k in example for k in ("MG_IDP_ID_PLATFORM", "MG_IDP_ID_TENANT_A", "MG_IDP_ID_TENANT_B")),
      ".env.example documents MG_IDP_ID_*")
sys.exit(1 if failures else 0)
