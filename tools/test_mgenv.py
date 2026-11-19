#!/usr/bin/env python3
"""Unit test of tools/mgenv.py (environment parameters: one env file per environment, ${MG_*} placeholders).

    python tools/test_mgenv.py        # exit code 0 = pass. Standard library only.

Also checks the real staging env file: every placeholder used under infrastructure/environments/staging/ resolves,
and no environment value (public IP, domain, LAN, tunnel) is hard-coded in the parameter files any more.
"""
from __future__ import annotations

import base64
import json
import os
import pathlib
import re
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import mgenv  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[1]
failures = 0


def check(ok: bool, name: str, detail: str = "") -> None:
    global failures
    print(f"{'PASS' if ok else 'FAIL'} {name}{'' if ok else ': ' + detail}")
    failures += 0 if ok else 1


def raises(fn, name: str) -> None:
    try:
        fn()
    except mgenv.EnvError:
        check(True, name)
        return
    check(False, name, "no error raised")


with tempfile.TemporaryDirectory() as d:
    env_dir = pathlib.Path(d) / "environments" / "lab"
    (env_dir / "tenants").mkdir(parents=True)
    (env_dir / "lab.env").write_text("# comment\nMG_PUBLIC_IPV4=203.0.113.7\nMG_PORT=8443\n"
                                     "MG_LIST=1.1.1.1, 8.8.8.8\nMG_BASE_DOMAIN=example.com  # inline comment\n",
                                     encoding="utf-8")
    p = env_dir / "tenants" / "t.json"
    p.write_text(json.dumps({"ip": "${MG_PUBLIC_IPV4}", "port": "${MG_PORT:int}", "ns": "${MG_LIST:list}",
                             "name": "*.mesh.${MG_BASE_DOMAIN}", "fixed": 3, "nested": [{"x": "${MG_PORT}"}]}),
                 encoding="utf-8")
    saved = {k: os.environ.pop(k) for k in list(os.environ) if k.startswith("MG_")}
    try:
        got = mgenv.load_params(p)
        check(got == {"ip": "203.0.113.7", "port": 8443, "ns": ["1.1.1.1", "8.8.8.8"], "name": "*.mesh.example.com",
                      "fixed": 3, "nested": [{"x": "8443"}]}, "expand string/int/list/embedded/nested", str(got))
        check(mgenv.find_env_file(p) == env_dir / "lab.env", "env file found from a subdirectory")
        os.environ["MG_PUBLIC_IPV4"] = "198.51.100.9"
        check(mgenv.load_params(p)["ip"] == "198.51.100.9", "process environment overrides the env file")
        del os.environ["MG_PUBLIC_IPV4"]
        raises(lambda: mgenv.expand("${MG_MISSING}", {}), "missing variable is an error")
        raises(lambda: mgenv.expand("${MG_EMPTY}", {"MG_EMPTY": ""}), "empty variable is an error")
        raises(lambda: mgenv.expand_text("x ${MG_PORT:int}", {"MG_PORT": "1"}), "typed placeholder inside text is an error")
        plain = pathlib.Path(d) / "plain.json"
        plain.write_text('{"a": "b"}', encoding="utf-8")
        check(mgenv.load_params(plain) == {"a": "b"}, "file without placeholders needs no env file")
    finally:
        os.environ.update(saved)

# the real staging environment
staging = ROOT / "infrastructure" / "environments" / "staging"
env = mgenv.environment(staging / "staging.env")
for f in sorted(staging.rglob("*.json")):
    try:
        mgenv.load_params(f)
        check(True, f"staging/{f.relative_to(staging).as_posix()}: every placeholder resolves")
    except (mgenv.EnvError, ValueError) as e:
        check(False, f"staging/{f.relative_to(staging).as_posix()}", str(e))
literals = [env[k] for k in ("MG_PUBLIC_IPV4", "MG_LAN_IPV4", "MG_LAN_CIDR", "MG_TUNNEL_HOST_IPV4", "MG_TUNNEL_VPS_IPV4",
                             "MG_BASE_DOMAIN", "MG_ACME_ACCOUNT_URI")]
for f in sorted([*staging.rglob("*.json"), ROOT / "infrastructure" / "host" / "mg-staging-firewall.nft"]):
    text = f.read_text(encoding="utf-8")
    hard = [v for v in literals if v in text]
    check(not hard, f"{f.relative_to(ROOT).as_posix()}: no hard-coded environment value", str(hard))

# the host firewall template renders with the staging env file into exactly what apply-firewall.sh accepts: it refuses
# any rendered text that still holds "${MG_" — comments included (deploy rehearsal P4, F-1: a comment of the template
# naming the placeholder syntax made the documented `mgenv.py render … | bash apply-firewall.sh` always refuse)
fw = mgenv.expand_text((ROOT / "infrastructure" / "host" / "mg-staging-firewall.nft").read_text(encoding="utf-8"), env)
guard = re.search(r"grep -q '([^']+)'", (ROOT / "infrastructure" / "host" / "apply-firewall.sh").read_text(encoding="utf-8"))
check(guard is not None and guard.group(1) == "${MG_", "apply-firewall.sh: refuses rendered text holding '${MG_'")
check("${MG_" not in fw, "mg-staging-firewall.nft rendered with staging.env: no '${MG_' left (apply-firewall.sh accepts it)")

# public outputs of the key ceremony (P2-T04a): present in every env file (empty until the ceremony is done), and when
# filled, an age X25519 recipient and an Ed25519 SubjectPublicKeyInfo — never a private key pasted by mistake.
AGE_RECIPIENT = re.compile(r"^age1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58}$")
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
for f in [staging / "staging.env", ROOT / ".env.example"]:
    name = f.relative_to(ROOT).as_posix()
    text = f.read_text(encoding="utf-8")
    values = mgenv.parse_env_file(f)
    for key in ("MG_BACKUP_RECOVERY_RECIPIENT", "MG_BACKUP_MANIFEST_PUBKEY"):
        check(key in values, f"{name}: defines {key}")
    rec, pub = values.get("MG_BACKUP_RECOVERY_RECIPIENT", ""), values.get("MG_BACKUP_MANIFEST_PUBKEY", "")
    check(not rec or bool(AGE_RECIPIENT.fullmatch(rec)), f"{name}: MG_BACKUP_RECOVERY_RECIPIENT is empty or an age recipient")
    try:
        der = base64.b64decode(pub, validate=True) if pub else b""
    except ValueError:
        der = b"invalid"
    check(not pub or (len(der) == 44 and der.startswith(ED25519_SPKI_PREFIX)),
          f"{name}: MG_BACKUP_MANIFEST_PUBKEY is empty or an Ed25519 public key (SPKI, base64)")
    leaked = [m for m in ("AGE-SECRET-KEY-", "PRIVATE KEY", "MC4CAQAwBQYDK2Vw") if m in text]
    check(not leaked, f"{name}: no private key material", str(leaked))
sys.exit(1 if failures else 0)
