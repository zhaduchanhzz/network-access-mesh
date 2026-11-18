#!/usr/bin/env python3
"""G3 tool (P3-T14, Gate G3 — §19 Phase 3, §20 row P3-T14, §22.3 M3): provisioning loop and E2E of tenant C through the
real Platform API, the real orchestrator and the real Host Agent, reusing the harnesses (Keycloak + TOTP login and
browser of tests/e2e/harness, orphan detector of P3-T07, enrollment helper of P3-T14a, policy core of P3-T08a,
suspend/resume of P3-T08, deprovision of P3-T09 with dual control).

  python3 tests/g3/g3.py build   --out DIR                       build tests/g3/hostside (go test -c, [images.golang])
  python3 tests/g3/g3.py loop    --env ENVFILE --creds FILE [--target T.json] [--n 20] [--slug-prefix g3-] --out DIR
  python3 tests/g3/g3.py tenant-c --env ENVFILE --creds FILE [--target T.json] [--slug g3-c-<tag>] --out DIR
  python3 tests/g3/g3.py report  --out DIR                       print loop.md / tenant-c.md again from the JSON
  python3 tests/g3/g3.py dev-up | dev-down                       dev/CI rehearsal on the stack of make e2e-functional

Common options: --hostside-bin PATH (a binary built by `build`, e.g. on the build VM, when the platform host is remote),
--owner-email-domain (default example.invalid: the Owner invitation of step 16 must not reach a real mailbox),
--timeout (per job, default 900 s), --keep-clients (tenant-c: leave the client containers for inspection).

Staging (run by the coordinator — the tool never touches anything but the API, the containers it starts and read-only
views of the host; see docs/planning/evidence/P3-T14.md §3 for the exact commands):
  --env infrastructure/environments/staging/staging.env --creds <file 0600 outside config/secrets/> --target <json>
  with host_docker/client_docker = "ssh … mgdeploy@${MG_LAN_IPV4} sudo -n docker" / the client machine (HS-24).
Exit 0 ⇔ every round / step passed. Standard library only (+ docker, ssh as configured).
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import secrets
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
for _s in (sys.stdout, sys.stderr):
    if hasattr(_s, "reconfigure"):
        _s.reconfigure(encoding="utf-8")

import g3stats  # noqa: E402
from g3target import G3Error, Target, load_creds  # noqa: E402


def target(args) -> Target:
    over = json.loads(pathlib.Path(args.target).read_text(encoding="utf-8")) if args.target else {}
    return Target(pathlib.Path(args.env), over)


def prepare(t: Target, args) -> None:
    import g3host  # noqa: PLC0415
    binary = pathlib.Path(args.hostside_bin) if args.hostside_bin else None
    if binary is None or not binary.is_file():
        binary = g3host.build_hostside(t, pathlib.Path(args.out) / "bin")
    g3host.install(t, binary)


def cleanup_tool(t: Target) -> None:
    t.hd("volume", "rm", "-f", t.name("bin"), check=False)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="g3.py", description=__doc__.split("\n\n")[0])
    ap.add_argument("cmd", choices=("build", "loop", "tenant-c", "report", "dev-up", "dev-down"))
    ap.add_argument("--env", help="infrastructure/environments/<env>/<env>.env")
    ap.add_argument("--target", help="target JSON (overrides of the host layout — g3target.py)")
    ap.add_argument("--creds", help="credential file of the two Super Admins (JSON, 0600)")
    ap.add_argument("--out", default="g3-out", help="output directory (JSON, Markdown, evidence of a failed round)")
    ap.add_argument("--n", type=int, default=20)
    ap.add_argument("--slug-prefix", default="g3-")
    ap.add_argument("--slug", default="")
    ap.add_argument("--owner-email-domain", default="example.invalid")
    ap.add_argument("--timeout", type=float, default=900)
    ap.add_argument("--hostside-bin", default="")
    ap.add_argument("--keep-clients", action="store_true")
    ap.add_argument("--allow-no-deprovision", action="store_true",
                    help="loop: a build without DELETE /platform/tenants (P3-T09) ends the round as FAIL but is not fatal")
    args = ap.parse_args(argv[1:])
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    try:
        if args.cmd == "dev-up":
            import g3dev  # noqa: PLC0415
            g3dev.up()
            return 0
        if args.cmd == "dev-down":
            import g3dev  # noqa: PLC0415
            g3dev.down()
            return 0
        if args.cmd == "report":
            import g3scenarios  # noqa: PLC0415
            for name, render in (("loop", g3scenarios.loop_markdown), ("tenant-c", g3scenarios.tenant_c_markdown)):
                f = out / f"{name}.json"
                if f.exists():
                    md = render(json.loads(f.read_text(encoding="utf-8")))
                    (out / f"{name}.md").write_text(md, encoding="utf-8")
                    print(md)
            return 0
        if not args.env:
            ap.error("--env là bắt buộc")
        t = target(args)
        if args.cmd == "build":
            import g3host  # noqa: PLC0415
            print(g3host.build_hostside(t, out / "bin"))
            return 0
        if not args.creds:
            ap.error("--creds là bắt buộc (file JSON 0600 của 2 Super Admin — không nằm trong config/secrets/)")
        creds = load_creds(pathlib.Path(args.creds), t)
        import g3scenarios  # noqa: PLC0415
        from g3platform import Platform  # noqa: PLC0415
        pf = Platform(t, creds)
        prepare(t, args)
        try:
            if args.cmd == "loop":
                return g3scenarios.run_loop(t, pf, out, args.n, args.slug_prefix, args.owner_email_domain, args.timeout,
                                            require_deprovision=not args.allow_no_deprovision)
            slug = args.slug or f"{args.slug_prefix}c-{secrets.token_hex(2)}"
            if not g3stats.SLUG_RE.match(slug) or "--" in slug:
                ap.error(f"slug {slug!r} không hợp lệ")
            return g3scenarios.run_tenant_c(t, pf, out, slug, args.owner_email_domain, args.timeout, keep=args.keep_clients)
        finally:
            cleanup_tool(t)
    except G3Error as e:
        print(f"[g3] LỖI: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    if os.name == "nt" and hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(main(sys.argv))
