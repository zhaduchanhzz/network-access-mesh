#!/usr/bin/env python3
"""IdP part of the backup restore drill (tests/backup/drill.sh, P2-T05b): what Keycloak itself reports before the
backup and after the restore. Standard library only; runs on the drill machine and talks plain HTTP to the Keycloak
container on its test network (master realm: sslRequired=external accepts private addresses).

    python3 -I kc_drill.py prepare --base http://<ip>:8080 --admin-conf <file> --state <json> --domain <d>
    python3 -I kc_drill.py verify  --base http://<ip>:8080 --admin-conf <file> --state <json> --domain <d>

prepare  admin token of the bootstrap admin (master realm, from keycloak.conf — never printed), creates one user
         `drill-<random>` in realm tenant-a, records the realms, the user count of every realm and the user's id.
verify   the same realms, the same user counts, the drill user with the same id, and the OIDC discovery document of
         platform, tenant-a and tenant-b with issuer https://auth.<domain>/realms/<realm>.
Exit status 0 = every check passed. Only names, counts and ids are printed.
"""
from __future__ import annotations

import argparse
import json
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request

failures = 0


def check(ok: bool, name: str, detail: str = "") -> None:
    global failures
    print(f"{'PASS' if ok else 'FAIL'} {name}{'' if ok else ': ' + detail}")
    failures += 0 if ok else 1


def admin_credentials(path: str) -> tuple[str, str]:
    conf = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.rstrip("\n").split("=", 1)
                conf[k.strip()] = v
    return conf["bootstrap-admin-username"], conf["bootstrap-admin-password"]


class KC:
    def __init__(self, base: str, conf: str) -> None:
        self.base = base.rstrip("/")
        user, pw = admin_credentials(conf)
        body = urllib.parse.urlencode({"grant_type": "password", "client_id": "admin-cli", "username": user,
                                       "password": pw}).encode()
        tok = self.call("POST", "/realms/master/protocol/openid-connect/token", body,
                        {"Content-Type": "application/x-www-form-urlencoded"}, auth=False)
        self.token = tok["access_token"]

    def call(self, method: str, path: str, body: bytes | None = None, headers: dict | None = None, auth: bool = True,
             want_location: bool = False):
        h = dict(headers or {})
        if auth:
            h["Authorization"] = "Bearer " + self.token
        req = urllib.request.Request(self.base + path, data=body, method=method, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310 — fixed http URL of the drill
                raw = r.read()
                if want_location:
                    return r.headers.get("Location", "")
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            raise SystemExit(f"FAIL {method} {path}: HTTP {e.code}") from None


def snapshot(kc: KC) -> dict:
    realms = sorted(r["realm"] for r in kc.call("GET", "/admin/realms"))
    counts = {r: kc.call("GET", f"/admin/realms/{r}/users/count") for r in realms}
    return {"realms": realms, "user_counts": counts}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["prepare", "verify"])
    ap.add_argument("--base", required=True)
    ap.add_argument("--admin-conf", required=True)
    ap.add_argument("--state", required=True)
    ap.add_argument("--domain", required=True)
    a = ap.parse_args()
    kc = KC(a.base, a.admin_conf)
    if a.mode == "prepare":
        name = "drill-" + secrets.token_hex(4)
        # Keycloak 26 (declarative user profile) drops unmanaged attributes: only profile fields are checked
        user = {"username": name, "enabled": True, "email": f"{name}@drill.invalid", "emailVerified": True,
                "firstName": "Drill", "lastName": "P2-T05b"}
        loc = kc.call("POST", "/admin/realms/tenant-a/users", json.dumps(user).encode(),
                      {"Content-Type": "application/json"}, want_location=True)
        uid = loc.rstrip("/").rsplit("/", 1)[-1]
        state = snapshot(kc) | {"drill_user": {"realm": "tenant-a", "username": name, "id": uid}}
        with open(a.state, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
        check(bool(uid) and "platform" in state["realms"], f"prepare: realms {state['realms']}, user counts "
              f"{state['user_counts']}, drill user {name} ({uid}) in tenant-a")
        return 1 if failures else 0
    with open(a.state, encoding="utf-8") as f:
        want = json.load(f)
    got = snapshot(kc)
    check(got["realms"] == want["realms"], f"verify: realms after restore {got['realms']}", str(want["realms"]))
    check(got["user_counts"] == want["user_counts"], f"verify: user counts after restore {got['user_counts']}",
          str(want["user_counts"]))
    du = want["drill_user"]
    u = kc.call("GET", f"/admin/realms/{du['realm']}/users/{du['id']}")
    check(bool(u) and u.get("username") == du["username"] and u.get("email") == f"{du['username']}@drill.invalid"
          and u.get("lastName") == "P2-T05b" and u.get("enabled") is True,
          f"verify: drill user {du['username']} ({du['id']}) restored with the same id, e-mail and name")
    for realm in ("platform", "tenant-a", "tenant-b"):
        d = kc.call("GET", f"/realms/{realm}/.well-known/openid-configuration", auth=False)
        check(d.get("issuer") == f"https://auth.{a.domain}/realms/{realm}", f"verify: discovery of {realm}, issuer {d.get('issuer')}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
