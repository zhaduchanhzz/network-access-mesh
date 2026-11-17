#!/usr/bin/env python3
"""Render the backup services of one environment: compose project mg-backup (P2-T03a, P2-T05b; §14.4, §17.1 of the
master plan) — pg-backup (PostgreSQL of the platform), idp-backup (Keycloak's database), edge-backup (the edge's ACME
volume), all from the image built from infrastructure/docker/backup.

Usage:
  python3 tools/render_backup.py <env file> <out_dir> [--image <ref>]

<env file>  infrastructure/environments/<env>/<env>.env — MG_BACKUP_RECOVERY_RECIPIENT: the age X25519 recipient of the
            platform recovery key (key ceremony, P2-T04a). Empty or invalid ⇒ nothing is rendered: the services would
            refuse to run anyway, and a deployment must not look complete without working backups. The process
            environment overrides the file (tools/mgenv.py), e.g. a throwaway recipient for a restore drill.
--image     image built from infrastructure/docker/backup, pinned by digest (<name>@sha256:<64 hex>), or a local image
            ID (sha256:<64 hex>) for a drill. Default: [images.mg-backup] in versions.lock (pinned after the `images`
            workflow has built it — P2-T16).

Writes compose.backup.yaml into <out_dir> (on the host: /opt/meshguard/core/compose.backup.yaml). The services also
read the host's copy of the recipient (/opt/meshguard/core/keys/backup-recovery.age-recipient, written by the key
ceremony) and refuse to run when it differs from the rendered one. tools/test_render_backup.py checks the invariants.
Standard library only.
"""
from __future__ import annotations

import os
import pathlib
import re
import string
import sys
import tomllib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import mgenv  # noqa: E402 — env file of the environment (no secrets)

ROOT = pathlib.Path(__file__).resolve().parents[1]
TEMPLATE_VERSION = "1"
COMPOSE_TMPL = ROOT / "infrastructure" / "compose" / "compose.backup.yaml.tmpl"
VERSIONS = ROOT / "versions.lock"
EDGE_VOLUME = "mg-edge_edge-data"   # volume `edge-data` of compose project mg-edge (compose.edge.yaml.tmpl)
IMAGE_RE = re.compile(r"^(?:[a-z0-9][a-z0-9._/:-]*@)?sha256:[0-9a-f]{64}$")   # name@sha256:… or a local image ID
BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
RECIPIENT_RE = re.compile(rf"^age1[{BECH32}]{{58}}$")


class ParamError(ValueError):
    pass


def bech32_valid(hrp: str, data: str) -> bool:
    values = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + [BECH32.index(c) for c in data]
    gen = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= gen[i]
    return chk == 1


def check_recipient(r: str) -> None:
    """The same rule as the service (apps/backup ValidRecipient): one age X25519 recipient, valid checksum."""
    if not r:
        raise ParamError("MG_BACKUP_RECOVERY_RECIPIENT trống — làm nghi thức khóa (P2-T04a, docs/operations/key-ceremony.md) "
                         "rồi ghi recipient vào file tham số môi trường")
    if "AGE-SECRET-KEY" in r.upper():
        raise ParamError("MG_BACKUP_RECOVERY_RECIPIENT chứa PRIVATE KEY — xóa ngay khỏi file tham số, không commit")
    if not RECIPIENT_RE.fullmatch(r):
        raise ParamError("MG_BACKUP_RECOVERY_RECIPIENT không phải recipient age X25519 (age1 + 58 ký tự bech32)")
    if not bech32_valid("age", r[4:]):
        raise ParamError("MG_BACKUP_RECOVERY_RECIPIENT sai mã kiểm bech32 (chép nhầm)")


def pinned_image() -> str:
    lock = tomllib.loads(VERSIONS.read_text(encoding="utf-8"))
    img = lock.get("images", {}).get("mg-backup")
    if not img:
        raise ParamError("versions.lock chưa có [images.mg-backup] — pin digest sau khi workflow `images` build image "
                         "backup (P2-T16), hoặc truyền --image")
    return f"{img['image']}@{img['index']}"


def render(env: dict[str, str], image: str) -> dict[str, str]:
    if not IMAGE_RE.match(image):
        raise ParamError("image phải pin theo digest (<name>@sha256:<64 hex>) hoặc là image ID sha256:<64 hex>")
    recipient = env.get("MG_BACKUP_RECOVERY_RECIPIENT", "").strip()
    check_recipient(recipient)
    values = {"template_version": TEMPLATE_VERSION, "image": image, "recipient": recipient, "edge_volume": EDGE_VOLUME}
    return {"compose.backup.yaml": string.Template(COMPOSE_TMPL.read_text(encoding="utf-8")).substitute(values)}


def main(argv: list[str]) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    args = argv[1:]
    image = None
    if "--image" in args:
        i = args.index("--image")
        if i + 1 >= len(args):
            print(__doc__)
            return 2
        image = args[i + 1]
        del args[i:i + 2]
    if len(args) != 2:
        print(__doc__)
        return 2
    try:
        env = mgenv.environment(pathlib.Path(args[0]))
        files = render(env, image or pinned_image())
    except (ParamError, mgenv.EnvError, OSError, KeyError, ValueError) as e:
        print(f"render failed: {e}", file=sys.stderr)
        return 1
    out = pathlib.Path(args[1])
    for rel, text in files.items():
        path = out / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(text, encoding="utf-8", newline="\n")
        os.replace(tmp, path)
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
