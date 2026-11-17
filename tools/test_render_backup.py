#!/usr/bin/env python3
"""Unit test of tools/render_backup.py (P2-T03a, P2-T05b): the compose project mg-backup, without Docker.

    python tools/test_render_backup.py        # exit code 0 = pass. Standard library only.

Checks: the compose renders for a sample environment and is deterministic; every service keeps the hardening
(non-root, read-only rootfs, cap_drop ALL, no-new-privileges, no published port, no Docker socket); each service writes
only its own destination directory, the ACME volume and the recipient file are read-only; pg-backup is only on mg-data,
idp-backup only on mg-idp-data, edge-backup has no network; no environment variable carries a secret and the DB
passwords are file secrets; the recipient is the one of the env file; refusals (empty recipient, a private key, a
mistyped recipient, an image by tag); the real staging env file renders exactly when its recipient is filled in.
"""
from __future__ import annotations

import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import mgenv  # noqa: E402
import render_backup as rb  # noqa: E402

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8")
failures = 0
IMG = "ghcr.io/zhaduchanhzz/network-access-mesh/backup@sha256:" + "cd" * 32
RECIPIENT = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"   # public example key of the age README
ENV = {"MG_BACKUP_RECOVERY_RECIPIENT": RECIPIENT}


def check(ok: bool, name: str, detail: str = "") -> None:
    global failures
    print(f"{'PASS' if ok else 'FAIL'} {name}{'' if ok else ': ' + detail}")
    failures += 0 if ok else 1


def raises(fn, name: str, must_not_contain: str = "") -> None:
    try:
        fn()
    except (rb.ParamError, mgenv.EnvError) as e:
        ok = not must_not_contain or must_not_contain not in str(e)
        check(ok, f"{name} ({str(e).splitlines()[0][:70]})", "the error echoes the value")
        return
    check(False, name, "no error raised")


files = rb.render(ENV, IMG)
check(sorted(files) == ["compose.backup.yaml"], "render writes compose.backup.yaml", str(sorted(files)))
check(files == rb.render(ENV, IMG), "output is deterministic")
c = files["compose.backup.yaml"]
check("$" not in c, "compose: no placeholder or $ left (docker compose would interpolate it)")
check("name: mg-backup" in c and f"image: {IMG}" in c, "compose: project mg-backup, image pinned by digest")


def service(name: str) -> str:
    """Text of one service block (up to the next top-level service or section)."""
    m = re.search(rf"^  {name}:\n(.*?)(?=^  [a-z][a-z-]*:\n|^[a-z]+:)", c, flags=re.M | re.S)
    return m.group(1) if m else ""


svcs = {s: service(s) for s in ("pg-backup", "idp-backup", "edge-backup")}
check(all(svcs.values()), "compose: pg-backup, idp-backup, edge-backup defined", str({k: bool(v) for k, v in svcs.items()}))
anchor = re.search(r"^x-backup: &backup\n(.*?)^x-backup-env", c, flags=re.M | re.S)
common = anchor.group(1) if anchor else ""
check(all(s in common for s in ("read_only: true", "cap_drop: [ALL]", '"no-new-privileges:true"', "pids_limit:", "mem_limit:")),
      "compose: read-only rootfs, cap_drop ALL, no-new-privileges, limits in the shared block")
check(all(b.startswith("    <<: *backup\n") for b in svcs.values()), "compose: every service uses the shared hardened block")
check(svcs["pg-backup"].count('user: "10007:20007"') == 1 and svcs["idp-backup"].count('user: "10007:20007"') == 1
      and 'user: "10001:20007"' in svcs["edge-backup"], "compose: non-root users (10007 backup, 10001 edge; group 20007)")
check("ports:" not in c and "docker.sock" not in c and "privileged" not in c and "cap_add" not in c,
      "compose: no published port, no Docker socket, no privilege")
check(re.search(r"networks: \[mg-data\]", svcs["pg-backup"]) is not None and "mg-idp-data" not in svcs["pg-backup"],
      "compose: pg-backup only on mg-data")
check(re.search(r"networks: \[mg-idp-data\]", svcs["idp-backup"]) is not None and "mg-data]" not in svcs["idp-backup"],
      "compose: idp-backup only on mg-idp-data")
check("network_mode: none" in svcs["edge-backup"] and "networks:" not in svcs["edge-backup"], "compose: edge-backup has no network")

# mounts: one writable destination per service, everything else read-only
for name, dest in (("pg-backup", "postgres"), ("idp-backup", "idp"), ("edge-backup", "edge")):
    blocks = re.findall(r"      - type: (bind|volume)[^\n]*\n((?:        .*\n)+)", svcs[name])
    writable = [b for t, b in blocks if "read_only: true" not in b]
    check(len(writable) == 1 and f"source: /opt/meshguard/backups/{dest}\n" in writable[0] and "target: /backups" in writable[0],
          f"compose: {name} writes only /opt/meshguard/backups/{dest}", str(writable))
    check(any("backup-recovery.age-recipient" in b and "read_only: true" in b for _, b in blocks),
          f"compose: {name} reads the host's recipient file read-only")
edge_vol = [b for t, b in re.findall(r"      - type: (volume)[^\n]*\n((?:        .*\n)+)", svcs["edge-backup"])]
check(len(edge_vol) == 1 and "source: edge-data" in edge_vol[0] and "read_only: true" in edge_vol[0],
      "compose: the ACME volume is mounted read-only into edge-backup")
check(re.search(r"edge-data:\n    external: true\n    name: mg-edge_edge-data\n", c) is not None,
      "compose: edge-data is the external volume mg-edge_edge-data")

# secrets and environment
env_keys = re.findall(r"^      ([A-Z][A-Z0-9_]+): ", c, flags=re.M) + re.findall(r"^  (MG_[A-Z0-9_]+): ", c, flags=re.M)
bad = [k for k in env_keys if re.search(r"PASSWORD|SECRET|TOKEN", k) and not k.endswith("_FILE")]
check(env_keys and not bad, "compose: no environment variable carries a secret", str(bad))
check("/opt/meshguard/secrets/backup/pg_backup_password" in c and "/opt/meshguard/secrets/backup/idp_backup_password" in c
      and "MG_BACKUP_PG_PASSWORD_FILE: /run/secrets/pg_backup_password" in svcs["pg-backup"]
      and "MG_BACKUP_PG_PASSWORD_FILE: /run/secrets/idp_backup_password" in svcs["idp-backup"],
      "compose: DB passwords are file secrets of mg-sec-backup")
check("secrets:" not in svcs["edge-backup"], "compose: edge-backup gets no secret")
check(f"MG_BACKUP_RECIPIENT: {RECIPIENT}" in c and c.count("<<: *backup-env") == 3,
      "compose: every service encrypts to the env file's recipient")
check("MG_BACKUP_PG_USER: mg_backup" in svcs["pg-backup"] and "MG_BACKUP_PG_USER: idp_backup" in svcs["idp-backup"],
      "compose: dedicated read-only DB roles (mg_backup, idp_backup)")
check("/run/mgbackup:size=1m,mode=0700,uid=10007,gid=20007" in svcs["pg-backup"], "compose: pgpass only on a private tmpfs")
times = re.findall(r'MG_BACKUP_DAILY_AT: "(\d\d:\d\d)"', c)
check(len(times) == 3 and len(set(times)) == 3, "compose: three distinct daily slots", str(times))
check("run --rm pg-backup once --label pre-migration" in c, "compose: documents the pre-migration trigger")

# refusals
raises(lambda: rb.render({}, IMG), "missing recipient is refused")
raises(lambda: rb.render({"MG_BACKUP_RECOVERY_RECIPIENT": ""}, IMG), "empty recipient is refused")
secret = "AGE-SECRET-KEY-1" + "Q" * 58
raises(lambda: rb.render({"MG_BACKUP_RECOVERY_RECIPIENT": secret}, IMG), "a private key is refused", must_not_contain="QQQQ")
flipped = RECIPIENT[:20] + ("q" if RECIPIENT[20] != "q" else "p") + RECIPIENT[21:]
raises(lambda: rb.render({"MG_BACKUP_RECOVERY_RECIPIENT": flipped}, IMG), "a mistyped recipient (checksum) is refused")
raises(lambda: rb.render({"MG_BACKUP_RECOVERY_RECIPIENT": RECIPIENT + " " + RECIPIENT}, IMG), "two recipients are refused")
raises(lambda: rb.render(ENV, "ghcr.io/zhaduchanhzz/network-access-mesh/backup:latest"), "image by tag is refused")
check(bool(rb.IMAGE_RE.match("sha256:" + "0" * 64)), "a local image ID (drill) is accepted")

# the real staging env file: renders once the key ceremony's recipient is recorded, refuses while it is empty
staging = mgenv.environment(rb.ROOT / "infrastructure" / "environments" / "staging" / "staging.env")
if staging.get("MG_BACKUP_RECOVERY_RECIPIENT"):
    try:
        check(len(rb.render(staging, IMG)) == 1, "staging.env renders the backup services")
    except rb.ParamError as e:
        check(False, "staging.env renders the backup services", str(e))
else:
    raises(lambda: rb.render(staging, IMG), "staging.env: refused while MG_BACKUP_RECOVERY_RECIPIENT is empty (P2-T04a)")
sys.exit(1 if failures else 0)
