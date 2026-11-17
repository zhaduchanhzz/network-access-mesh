#!/usr/bin/env python3
"""Test of infrastructure/host/migrate.sh (P2-T16) with a stub `docker` — no Docker needed:

  - the pre-migration backup of mg-backup runs FIRST (`pg-backup once --label pre-migration`, P2-T03a);
  - a failed backup stops the script before the migrate job (exit 1, migrate never invoked);
  - a failed migrate is an error; both succeeding ⇒ exit 0;
  - missing rendered compose files ⇒ refused before anything runs.

    python3 tools/test_host_migrate.py        # exit code 0 = pass. Needs bash. Standard library only.
"""
from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "infrastructure" / "host" / "migrate.sh"
failures = 0
for _s in (sys.stdout, sys.stderr):
    if hasattr(_s, "reconfigure"):
        _s.reconfigure(encoding="utf-8")


def check(ok: bool, name: str, detail: str = "") -> None:
    global failures
    print(f"{'PASS' if ok else 'FAIL'} {name}{'' if ok else ': ' + detail}")
    failures += 0 if ok else 1


bash = shutil.which("bash")
if not bash:
    print("SKIP: bash not found")
    sys.exit(0)

with tempfile.TemporaryDirectory() as d:
    d = pathlib.Path(d)
    core = d / "core"
    core.mkdir()
    log = d / "calls.log"
    stub = d / "docker-stub"
    # the stub records each invocation and fails the step named in STUB_FAIL (backup | migrate)
    stub.write_text("#!/bin/sh\n"
                    'echo "$*" >> "$STUB_LOG"\n'
                    'case "$*" in\n'
                    '  *"pg-backup once --label pre-migration"*) [ "$STUB_FAIL" = backup ] && exit 3 ;;\n'
                    '  *"--profile migrate run --rm -T migrate"*) [ "$STUB_FAIL" = migrate ] && exit 4 ;;\n'
                    "esac\nexit 0\n", encoding="utf-8", newline="\n")
    stub.chmod(0o755)

    def run(fail: str, files: bool = True) -> tuple[int, list[str], str]:
        for f in ("compose.backup.yaml", "compose.app.yaml"):
            p = core / f
            if files:
                p.write_text("name: x\n", encoding="utf-8")
            elif p.exists():
                p.unlink()
        if log.exists():
            log.unlink()
        env = {**os.environ, "MG_CORE_DIR": core.as_posix(), "DOCKER": stub.as_posix(), "STUB_LOG": log.as_posix(),
               "STUB_FAIL": fail}
        p = subprocess.run([bash, SCRIPT.as_posix()], capture_output=True, text=True, env=env, encoding="utf-8")
        calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
        return p.returncode, calls, p.stdout + p.stderr

    rc, calls, out = run("")
    check(rc == 0 and len(calls) == 2 and "-p mg-backup" in calls[0] and "pg-backup once --label pre-migration" in calls[0]
          and "-p mg-app" in calls[1] and "--profile migrate run --rm -T migrate" in calls[1],
          "backup pre-migration first, then the migrate job of mg-app", f"rc {rc}, calls {calls}")
    rc, calls, out = run("backup")
    check(rc == 1 and len(calls) == 1 and "DỪNG" in out, "failed backup ⇒ stop, migrate never invoked",
          f"rc {rc}, calls {calls}")
    rc, calls, out = run("migrate")
    check(rc == 1 and len(calls) == 2, "failed migrate ⇒ error", f"rc {rc}, calls {calls}")
    rc, calls, out = run("", files=False)
    check(rc == 1 and not calls, "missing compose files ⇒ refused before anything runs", f"rc {rc}, calls {calls}")
sys.exit(1 if failures else 0)
