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
check("KC_HOSTNAME: https://auth.example.com" in c and "KC_PROXY_TRUSTED_ADDRESSES: 10.249.0.2" in c,
      "compose: hostname auth.<domain>; only the edge (10.249.0.2) is a trusted proxy")
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

# the real staging env file renders (with a stand-in image digest)
staging = mgenv.environment(ri.ROOT / "infrastructure" / "environments" / "staging" / "staging.env")
try:
    sf = ri.render(staging, IMG)
    check(len(sf) == 6, "staging.env renders the IdP")
except (ri.ParamError, mgenv.EnvError) as e:
    check(False, "staging.env renders the IdP", str(e))
example = mgenv.parse_env_file(ri.ROOT / ".env.example")
check(all(k in example for k in ("MG_IDP_ID_PLATFORM", "MG_IDP_ID_TENANT_A", "MG_IDP_ID_TENANT_B")),
      ".env.example documents MG_IDP_ID_*")
sys.exit(1 if failures else 0)
