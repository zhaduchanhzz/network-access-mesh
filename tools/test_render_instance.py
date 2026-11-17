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
    "unknown headscale_build": {"headscale_build": "custom"},
    "image and headscale_build together": {"image": "docker.io/headscale/headscale@sha256:" + "1" * 64,
                                            "headscale_build": "official"},
    "log level debug (§11.3 step 8)": {"log_level": "debug"},
}

OFFICIAL = "docker.io/headscale/headscale@sha256:" + "a" * 64
PATCHED = "ghcr.io/zhaduchanhzz/network-access-mesh/headscale@sha256:" + "b" * 64
LOCK_UNPINNED = {"images": {"headscale": {"image": OFFICIAL.split("@")[0], "index": OFFICIAL.split("@")[1]}}}
LOCK_PINNED = {"images": {**LOCK_UNPINNED["images"],
                          "mg-headscale": {"image": PATCHED.split("@")[0], "index": PATCHED.split("@")[1]}}}
LOCK_PENDING = {"images": {**LOCK_UNPINNED["images"], "mg-headscale": {"image": PATCHED.split("@")[0], "index": ""}}}


def check_headscale_image() -> int:
    """The image switch of P2-T10a: patched once [images.mg-headscale] is pinned, official as fallback/rollback."""
    failures = 0

    def expect(name: str, params: dict, lock: dict, want: str | None, note_has: str = "") -> None:
        nonlocal failures
        try:
            image, note = ri.headscale_image(params, lock)
        except ri.ParamError as e:
            image, note = None, str(e)
        if image != want or note_has not in note:
            print(f"FAIL headscale image ({name}): got {image!r} / {note!r}, want {want!r} / …{note_has}…")
            failures += 1

    expect("default, mg-headscale pinned", {}, LOCK_PINNED, PATCHED, "bản vá")
    expect("default, mg-headscale not pinned: explicit fallback", {}, LOCK_UNPINNED, OFFICIAL, "DỰ PHÒNG")
    expect("default, mg-headscale pending (no digest)", {}, LOCK_PENDING, OFFICIAL, "DỰ PHÒNG")
    expect("official (rollback)", {"headscale_build": "official"}, LOCK_PINNED, OFFICIAL, "rollback")
    expect("patched", {"headscale_build": "patched"}, LOCK_PINNED, PATCHED, "bản vá")
    expect("patched but not pinned", {"headscale_build": "patched"}, LOCK_UNPINNED, None, "not pinned")
    expect("explicit image = patched digest", {"image": PATCHED}, LOCK_PINNED, PATCHED, "bản vá")
    expect("explicit image = official digest", {"image": OFFICIAL}, LOCK_PINNED, OFFICIAL, "chính thức")
    expect("unknown build", {"headscale_build": "latest"}, LOCK_PINNED, None, "must be one of")
    real = ri.headscale_image({"headscale_build": "official"})[0]
    if not real.startswith("docker.io/headscale/headscale@sha256:"):
        print(f"FAIL headscale image: versions.lock official = {real}")
        failures += 1
    print(f"{'FAIL' if failures else 'PASS'} headscale image switch: 10 cases")
    return failures


def check_log_level() -> int:
    """log_level (P3-T02): default info — the golden files — and warn/error render into log.level only."""
    case = sorted(p for p in GOLDEN.iterdir() if (p / "params.json").is_file())[0]
    params = json.loads((case / "params.json").read_text(encoding="utf-8"))
    base = ri.render(params)
    failures = 0
    for level in ("warn", "error"):
        files = ri.render({**params, "log_level": level})
        want = base["config/config.yaml"].replace("  level: info\n", f"  level: {level}\n")
        diff = [rel for rel in files if rel not in ("config/config.yaml", "meta/instance.json") and files[rel] != base[rel]]
        if files["config/config.yaml"] != want or want == base["config/config.yaml"] or diff:
            print(f"FAIL log_level {level}: config.yaml or other files differ unexpectedly")
            failures += 1
    print(f"{'FAIL' if failures else 'PASS'} log_level: default info (golden), warn and error only change log.level")
    return failures


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
            bad = {**base, **override}
            if "image" in override and "headscale_build" not in override:
                bad.pop("headscale_build", None)   # test the image rule itself, not the "both given" rule
            try:
                ri.render(bad)
                print(f"FAIL {case.name}: accepted invalid parameter ({name})")
                failures += 1
            except (ri.ParamError, ValueError):
                pass
        print(f"PASS {case.name}: {len(BAD)} invalid parameter sets rejected")
    if not cases:
        print("FAIL: no golden cases found")
        return 1
    failures += check_headscale_image()
    failures += check_log_level()
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
