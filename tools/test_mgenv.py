#!/usr/bin/env python3
"""Unit test of tools/mgenv.py (environment parameters: one env file per environment, ${MG_*} placeholders).

    python tools/test_mgenv.py        # exit code 0 = pass. Standard library only.

Also checks the real staging env file: every placeholder used under infrastructure/environments/staging/ resolves,
and no environment value (public IP, domain, LAN, tunnel) is hard-coded in the parameter files any more.
"""
from __future__ import annotations

import json
import os
import pathlib
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
sys.exit(1 if failures else 0)
