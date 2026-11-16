#!/usr/bin/env python3
"""Upsert (or delete) DNS records of the platform at Cloudflare (P1-T18, §15.4). Run on the host that holds the DNS
token as a file secret — the token is read from the file and never printed.

    sudo python3 cf_dns.py apply  [<zone>] <records.json> [--token-file F]
    sudo python3 cf_dns.py delete [<zone>] <records.json> [--token-file F]   # undo: remove exactly these records

<zone> defaults to MG_DNS_ZONE of the environment's env file (tools/mgenv.py). records.json may use ${MG_*}
placeholders — e.g. infrastructure/environments/staging/dns-public.json:
  [{"type": "A", "name": "*.mesh.${MG_BASE_DOMAIN}", "content": "${MG_PUBLIC_IPV4}", "ttl": 300},
   {"type": "CAA", "name": "mesh.${MG_BASE_DOMAIN}", "data": {"flags": 0, "tag": "issue", "value": "..."}}]
A records are always created DNS-only (proxied=false): Cloudflare Proxy in front of the control plane is unsupported
(HS-15). Records are matched by (type, name[, CAA tag]); prints one line per record with its action and record id.
Standard library only.
"""
from __future__ import annotations

import json
import pathlib
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "tools"))
import mgenv  # noqa: E402

API = "https://api.cloudflare.com/client/v4"
COMMENT = "MeshGuard (managed by infrastructure/gateway/cf_dns.py)"


def call(token: str, method: str, path: str, body: dict | None = None) -> dict:
    req = urllib.request.Request(API + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                                          "User-Agent": "meshguard-staging"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        try:
            return json.load(e)
        except ValueError:
            return {"success": False, "errors": [{"code": e.code, "message": e.reason}]}


def errs(d: dict) -> str:
    return "; ".join(f"{x.get('code')}: {x.get('message')}" for x in d.get("errors", []))[:200] or "no detail"


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if "--token-file" in sys.argv:
        args.remove(sys.argv[sys.argv.index("--token-file") + 1])
    if len(args) not in (2, 3) or args[0] not in ("apply", "delete"):
        print(__doc__)
        return 2
    mode, rec_file = args[0], args[-1]
    # zone: explicit (old form "<mode> <zone> <records.json>") or MG_DNS_ZONE of the environment's env file
    zone_name = args[1] if len(args) == 3 else mgenv.environment(mgenv.find_env_file(pathlib.Path(rec_file))).get("MG_DNS_ZONE", "")
    if not zone_name:
        print("zone unknown: pass it or set MG_DNS_ZONE in the env file")
        return 2
    token_file = sys.argv[sys.argv.index("--token-file") + 1] if "--token-file" in sys.argv \
        else "/opt/meshguard/secrets/edge/cloudflare_dns_token"
    token = open(token_file, encoding="utf-8").read().strip()
    wanted = mgenv.load_params(rec_file)   # ${MG_*} expanded (public IP, domain, ACME account)
    z = call(token, "GET", f"/zones?name={urllib.parse.quote(zone_name)}")
    if not z.get("success") or not z.get("result"):
        print(f"zone {zone_name}: not accessible — {errs(z)}")
        return 1
    zid = z["result"][0]["id"]
    rc = 0
    for w in wanted:
        q = urllib.parse.urlencode({"type": w["type"], "name": w["name"], "per_page": 100})
        existing = call(token, "GET", f"/zones/{zid}/dns_records?{q}").get("result") or []
        if w["type"] == "CAA":
            existing = [e for e in existing if (e.get("data") or {}).get("tag") == w["data"]["tag"]]
        label = f'{w["type"]} {w["name"]}' + (f' {w["data"]["tag"]}' if w["type"] == "CAA" else "")
        if mode == "delete":
            for e in existing:
                d = call(token, "DELETE", f"/zones/{zid}/dns_records/{e['id']}")
                print(f"{label}: delete {e['id']} {'ok' if d.get('success') else errs(d)}")
            if not existing:
                print(f"{label}: nothing to delete")
            continue
        body = {"type": w["type"], "name": w["name"], "ttl": w.get("ttl", 300), "comment": COMMENT}
        if w["type"] == "CAA":
            body["data"] = w["data"]
        else:
            body["content"] = w["content"]
            body["proxied"] = False
        if existing:
            d = call(token, "PUT", f"/zones/{zid}/dns_records/{existing[0]['id']}", body)
            action = "update"
        else:
            d = call(token, "POST", f"/zones/{zid}/dns_records", body)
            action = "create"
        ok = d.get("success")
        rc |= 0 if ok else 1
        print(f"{label}: {action} {'ok id=' + d['result']['id'] if ok else errs(d)}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
