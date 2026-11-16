#!/usr/bin/env python3
"""Golden test of tools/render_edge.py (P1-T06; first part of the P1-T10a render checks).

    python tools/test_render_edge.py            # compare against tests/golden/edge/*/expected
    python tools/test_render_edge.py --update   # rewrite the golden files after an intentional template change

For every case it also extracts the tenant regex from the rendered Caddyfile and checks that the tenant label is
captured correctly for a mesh domain of 3 and of 4 labels (§14.6 — no hard-coded {labels.N}), and that invalid
parameters are rejected. Standard library only; exit code 0 = pass.
"""
from __future__ import annotations

import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import render_edge as re_  # noqa: E402

GOLDEN = re_.ROOT / "tests" / "golden" / "edge"

BAD = {
    "acme name": {"acme": "prod"},
    "wildcard bind": {"lan_ipv4": "0.0.0.0"},
    "loopback bind": {"lan_ipv4": "127.0.0.1"},
    "ipv6 bind": {"lan_ipv4": "2001:db8::1"},
    "image by tag": {"image": "ghcr.io/zhaduchanhzz/network-access-mesh/edge:latest"},
    "no resolvers": {"dns_resolvers": []},
    "private resolver": {"dns_resolvers": ["192.168.1.1"]},
    "bad domain": {"base_domain": "Example.COM"},
    "no entry ip": {"public_entry_ipv4": ""},
    "wildcard entry ip": {"public_entry_ipv4": "0.0.0.0"},
}


def tenant_regex(caddyfile: str) -> re.Pattern:
    m = re.search(r"vars_regexp tenant \{http\.request\.host\} (\S+)", caddyfile)
    if not m:
        raise AssertionError("tenant matcher not found in Caddyfile")
    return re.compile(m.group(1))


def check_regex(caddyfile: str, base_domain: str) -> list[str]:
    rx = tenant_regex(caddyfile)
    mesh = f"mesh.{base_domain}"
    errors = []
    for host, want in [
        (f"tenant-a.{mesh}", "tenant-a"),
        (f"t01.{mesh}", "t01"),
        (f"b2.{mesh}", None),                    # slug needs >= 3 characters (same regex as render_instance)
        (f"tenant-.{mesh}", None),               # must end with a letter or digit
        (f"Tenant-a.{mesh}", None),              # lower case only
        (f"x.tenant-a.{mesh}", None),            # exactly one label before the mesh domain
        (f"tenant-a.{mesh}.evil.test", None),    # anchored at the end
        (f"tenant-a{mesh}", None),               # the dot is literal, not "any character"
        (f"tenant-a.{mesh.replace('.', 'x', 1)}", None),
    ]:
        m = rx.fullmatch(host)
        got = m.group(1) if m else None
        if got != want:
            errors.append(f"{host!r}: captured {got!r}, want {want!r}")
    return errors


def check_structure(caddyfile: str, params: dict) -> list[str]:
    """Invariants of §14.6 that must hold for every rendering."""
    errors = []
    must = [
        "default_bind 10.249.0.2",
        "strict_sni_host on",
        "bind 10.249.2.2",                                  # admin listener only on mg-admin
        "bind 10.249.3.2",                                  # metrics listener only on mg-obs
        "abort @outside",
        "header_up -X-MG-Token",
        "header_up -X-MG-Instance",
        "header_up -Authorization",
        "request>headers>X-Mg-Token delete",
        f'["{params["public_entry_ipv4"]}"]',               # static /bootstrap-dns answer
        "handle_errors 502 503 504",
    ]
    errors += [f"missing {m!r}" for m in must if m not in caddyfile]
    code = "\n".join(line for line in caddyfile.splitlines() if not line.lstrip().startswith("#"))
    block = re.search(r"@tenant \{\n(.*?)\n\t\}", code, re.S)
    tenant_paths = re.search(r"^\s*path (.+)$", block.group(1), re.M) if block else None
    if not tenant_paths:
        errors.append("tenant path allow-list not found")
    else:
        allowed = tenant_paths.group(1).split()
        for forbidden in ("/api/*", "/api/v1/*", "/swagger*", "/verify", "/version", "/health", "/metrics",
                          "/debug/*", "/bootstrap-dns", "/apple*", "/windows", "*"):
            if forbidden in allowed:
                errors.append(f"public allow-list contains {forbidden}")
    if re.search(r"(?m)^\s*(bind|default_bind) .*(0\.0\.0\.0|::)", code):
        errors.append("wildcard bind address")
    if "{labels." in code:
        errors.append("hard-coded {labels.N} (EG-03)")
    return errors


def main() -> int:
    update = "--update" in sys.argv
    failures = 0
    cases = sorted(p for p in GOLDEN.iterdir() if (p / "params.json").is_file())
    for case in cases:
        params = json.loads((case / "params.json").read_text(encoding="utf-8"))
        files = re_.render(params)
        expected_dir = case / "expected"
        if update:
            re_.write(files, expected_dir)
            print(f"updated {case.name}")
            continue
        want = {p.relative_to(expected_dir).as_posix(): p.read_text(encoding="utf-8")
                for p in expected_dir.rglob("*") if p.is_file()}
        if set(want) != set(files):
            print(f"FAIL {case.name}: file set differs: {sorted(set(want) ^ set(files))}")
            failures += 1
            continue
        diff = [rel for rel in files if files[rel] != want[rel]]
        if diff:
            print(f"FAIL {case.name}: content differs in {diff}")
            failures += 1
        else:
            print(f"PASS {case.name}: {len(files)} files identical to golden")
        errors = check_regex(files["caddy/Caddyfile"], params["base_domain"])
        if errors:
            print(f"FAIL {case.name}: tenant regex: " + "; ".join(errors))
            failures += 1
        else:
            print(f"PASS {case.name}: tenant label captured correctly ({params['base_domain'].count('.') + 2} labels)")
        errors = check_structure(files["caddy/Caddyfile"], params)
        if errors:
            print(f"FAIL {case.name}: structure: " + "; ".join(errors))
            failures += 1
        else:
            print(f"PASS {case.name}: listener/allow-list invariants of §14.6 hold")
        for name, override in BAD.items():
            try:
                re_.render({**params, **override})
                print(f"FAIL {case.name}: accepted invalid parameter ({name})")
                failures += 1
            except (re_.ParamError, ValueError):
                pass
        print(f"PASS {case.name}: {len(BAD)} invalid parameter sets rejected")
    if not cases:
        print("FAIL: no golden cases found")
        return 1
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
