#!/usr/bin/env python3
"""Golden test of tools/render_instance.py (P1-T07).

    python tools/test_render_instance.py            # compare against tests/golden/headscale/*/expected
    python tools/test_render_instance.py --update   # rewrite the golden files after an intentional template change

Also checks that invalid parameters are rejected. Standard library only; exit code 0 = pass.
"""
from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import render_instance as ri  # noqa: E402

GOLDEN = ri.ROOT / "tests" / "golden" / "headscale"

BAD = {
    "reserved slug": {"slug": "admin"},
    "double hyphen": {"slug": "acme--corp"},
    "punycode prefix": {"slug": "xn--abc"},
    "uppercase slug": {"slug": "Acme"},
    "net outside pool": {"net_cidr": "192.168.10.0/29"},
    "net not /29": {"net_cidr": "10.250.0.0/28"},
    "run_uid outside range": {"run_uid": 1000},
    "region outside 900-999": {"derp_region_id": 1},
    "expiry in days": {"node_expiry": "90d"},
    "no nameservers": {"nameservers": []},
    "image by tag": {"image": "docker.io/headscale/headscale:v0.29.7"},
    "non-canonical uuid": {"tenant_id": "1111111111111111111111111111111A"},
}


def main() -> int:
    update = "--update" in sys.argv
    failures = 0
    cases = sorted(p for p in GOLDEN.iterdir() if (p / "params.json").is_file())
    for case in cases:
        params = json.loads((case / "params.json").read_text(encoding="utf-8"))
        files = ri.render(params)
        expected_dir = case / "expected"
        if update:
            ri.write(files, expected_dir)
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
        base = params
        for name, override in BAD.items():
            try:
                ri.render({**base, **override})
                print(f"FAIL {case.name}: accepted invalid parameter ({name})")
                failures += 1
            except (ri.ParamError, ValueError):
                pass
        print(f"PASS {case.name}: {len(BAD)} invalid parameter sets rejected")
    if not cases:
        print("FAIL: no golden cases found")
        return 1
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
