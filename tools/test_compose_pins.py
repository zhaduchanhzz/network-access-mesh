#!/usr/bin/env python3
"""T-13 (§18.1, P5-T09): every image the repository runs is pinned by digest.

  - compose files and templates under infrastructure/ (static compose.core.yaml, crowdsec-hub, maintenance, and the
    literal images of the *.tmpl files — the ${…} ones are checked by the golden tests of their render tool): every
    literal `image:` is <repository>@sha256:<64 hex> and that (repository, digest) is an [images.*] entry of
    versions.lock (index or amd64 digest);
  - Dockerfiles under infrastructure/: every `FROM` that is not a build stage or an ${ARG}, and every ARG default that
    names an image, carries @sha256:<64 hex>.

Standard library only; exit 0 ⇔ every check passes.
"""
from __future__ import annotations

import pathlib
import re
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]
DIGEST = re.compile(r"^(?P<repo>[a-z0-9.-]+(?::\d+)?/[a-z0-9._/-]+)(?::[A-Za-z0-9._-]+)?@(?P<digest>sha256:[0-9a-f]{64})$")
IMAGE_LINE = re.compile(r"^\s*image:\s*(?P<ref>[^\s#]+)")
FROM_LINE = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(?P<ref>\S+)(?:\s+AS\s+(?P<stage>\S+))?", re.I)
# an ARG default that names an image: registry/path with a tag or a digest (a Go module path such as filippo.io/age is
# not an image)
ARG_IMAGE = re.compile(r"^\s*ARG\s+(?P<name>[A-Z_][A-Z0-9_]*)=(?P<ref>[a-z0-9.-]+(?::\d+)?/[^\s:@]+[:@]\S+)$")


def lock_pins() -> set[tuple[str, str]]:
    lock = tomllib.loads((ROOT / "versions.lock").read_text(encoding="utf-8"))
    pins = set()
    for entry in lock.get("images", {}).values():
        for key in ("index", "amd64"):
            if entry.get("image") and entry.get(key):
                pins.add((entry["image"], entry[key].split()[0]))
    return pins


def check_compose(pins: set[tuple[str, str]]) -> tuple[list[str], int]:
    errors, n = [], 0
    files = sorted({*ROOT.glob("infrastructure/**/compose*.yaml"), *ROOT.glob("infrastructure/**/compose*.yaml.tmpl")})
    for f in files:
        for i, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            m = IMAGE_LINE.match(line)
            if not m or m.group("ref").startswith("${"):
                continue
            n += 1
            ref = m.group("ref").strip("'\"")
            d = DIGEST.match(ref)
            where = f"{f.relative_to(ROOT)}:{i}"
            if not d:
                errors.append(f"{where}: image {ref!r} is not pinned by digest")
            elif (d.group("repo"), d.group("digest")) not in pins:
                errors.append(f"{where}: {d.group('repo')}@{d.group('digest')[:19]}… is not an [images.*] pin of versions.lock")
    return errors, n


def check_dockerfiles() -> tuple[list[str], int]:
    errors, n = [], 0
    for f in sorted(ROOT.glob("infrastructure/**/Dockerfile*")):
        stages: set[str] = set()
        for i, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            where = f"{f.relative_to(ROOT)}:{i}"
            a = ARG_IMAGE.match(line)
            if a:
                n += 1
                if not DIGEST.match(a.group("ref")):
                    errors.append(f"{where}: ARG {a.group('name')} names an image without a digest")
                continue
            m = FROM_LINE.match(line)
            if not m:
                continue
            ref = m.group("ref")
            if m.group("stage"):
                stages.add(m.group("stage").lower())
            if ref.startswith("${") or ref.lower() in stages or ref == "scratch":
                continue
            n += 1
            if not DIGEST.match(ref):
                errors.append(f"{where}: FROM {ref!r} is not pinned by digest")
    return errors, n


def main() -> int:
    pins = lock_pins()
    e1, n1 = check_compose(pins)
    e2, n2 = check_dockerfiles()
    for e in e1 + e2:
        print("FAIL", e)
    print(f"{n1} literal compose images (all in versions.lock), {n2} Dockerfile base images/ARGs — "
          f"{'OK' if not e1 + e2 else f'{len(e1 + e2)} errors'}")
    # self-test of the patterns: a tag alone, a digest of the wrong length, and a valid pin
    assert not DIGEST.match("docker.io/library/postgres:18")
    assert not DIGEST.match("docker.io/library/postgres@sha256:abc")
    assert DIGEST.match("docker.io/library/postgres:18.7@sha256:" + "a" * 64)
    assert not ARG_IMAGE.match("ARG AGE_MODULE=filippo.io/age") and ARG_IMAGE.match("ARG X=docker.io/library/golang:1")
    return 1 if e1 + e2 else 0


if __name__ == "__main__":
    sys.exit(main())
