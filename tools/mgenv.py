#!/usr/bin/env python3
"""Environment parameters of a MeshGuard environment — the ONLY place for public IP, domain, LAN/tunnel addresses.

Each environment has one file `infrastructure/environments/<env>/<env>.env` (KEY=VALUE, `#` comments, no quoting, no
shell expansion, **no secrets** — secrets stay in file secrets, §14.2). Parameter files (JSON) and text templates
(nftables, ...) refer to the values as placeholders; every tool reads them through this module, so moving to another
VPS, domain or LAN means editing the env file, re-rendering and re-applying (current.md, "Luân chuyển").

Placeholders (inside JSON string values or text):
  ${MG_X}        the value as a string (may be embedded in a longer string)
  ${MG_X:int}    the whole JSON value becomes an integer
  ${MG_X:list}   the whole JSON value becomes a list (comma-separated in the env file)
A placeholder whose variable is missing or empty is an error — never a silent default.

Lookup of the env file: $MG_ENV_FILE if set, otherwise `<dir>/<dir name>.env` in the directory of the parameter file
or the nearest parent directory that has one (e.g. tenants/tenant-a.json → staging/staging.env).
Precedence: process environment over the env file (one-off override: MG_PUBLIC_IPV4=... python3 tools/render_...).

    python3 tools/mgenv.py show   <env file>                 # print the variables
    python3 tools/mgenv.py render <template> [<env file>]    # expand ${MG_*} in a text file to stdout
    python3 tools/mgenv.py json   <params.json>              # print the expanded JSON
    eval "$(python3 tools/mgenv.py export <env file>)"       # export the variables into a shell

Standard library only.
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import shlex
import sys

PLACEHOLDER = re.compile(r"\$\{(MG_[A-Z0-9_]+)(?::(int|list))?\}")
KEY = re.compile(r"^MG_[A-Z0-9_]+$")


class EnvError(ValueError):
    pass


def parse_env_file(path: pathlib.Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for n, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.split("#", 1)[0].strip() if not raw.lstrip().startswith("#") else ""
        if not line:
            continue
        if "=" not in line:
            raise EnvError(f"{path}:{n}: expected KEY=VALUE")
        key, value = (s.strip() for s in line.split("=", 1))
        if not KEY.match(key):
            raise EnvError(f"{path}:{n}: variable names must look like MG_NAME")
        values[key] = value
    return values


def find_env_file(start: pathlib.Path) -> pathlib.Path | None:
    if os.environ.get("MG_ENV_FILE"):
        return pathlib.Path(os.environ["MG_ENV_FILE"])
    d = start if start.is_dir() else start.parent
    for cand in [d, *d.parents]:
        f = cand / f"{cand.name}.env"
        if f.is_file():
            return f
        if cand.name == "environments":
            break
    return None


def environment(env_file: pathlib.Path | None) -> dict[str, str]:
    values = parse_env_file(env_file) if env_file else {}
    values.update({k: v for k, v in os.environ.items() if KEY.match(k)})
    return values


def _value(name: str, env: dict[str, str]) -> str:
    v = env.get(name, "")
    if not v:
        raise EnvError(f"{name} is not set (env file or environment)")
    return v


def expand_text(text: str, env: dict[str, str]) -> str:
    def sub(m: re.Match) -> str:
        if m.group(2):
            raise EnvError(f"{m.group(0)}: typed placeholders are only allowed as a whole JSON value")
        return _value(m.group(1), env)
    return PLACEHOLDER.sub(sub, text)


def expand(obj, env: dict[str, str]):
    if isinstance(obj, dict):
        return {k: expand(v, env) for k, v in obj.items()}
    if isinstance(obj, list):
        return [expand(v, env) for v in obj]
    if isinstance(obj, str):
        m = PLACEHOLDER.fullmatch(obj)
        if m and m.group(2) == "int":
            return int(_value(m.group(1), env))
        if m and m.group(2) == "list":
            return [s.strip() for s in _value(m.group(1), env).split(",") if s.strip()]
        return expand_text(obj, env)
    return obj


def load_params(path: str | os.PathLike) -> dict:
    """Read a JSON parameter file and expand its ${MG_*} placeholders (the env file is needed only if it has any)."""
    p = pathlib.Path(path)
    raw = p.read_text(encoding="utf-8")
    data = json.loads(raw)
    if "${MG_" not in raw:
        return data
    env_file = find_env_file(p)
    return expand(data, environment(env_file))


def main(argv: list[str]) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if len(argv) < 3 or argv[1] not in ("show", "render", "json", "export"):
        print(__doc__)
        return 2
    try:
        if argv[1] == "json":
            print(json.dumps(load_params(argv[2]), indent=2, ensure_ascii=False))
            return 0
        if argv[1] == "render":
            tmpl = pathlib.Path(argv[2])
            env_file = pathlib.Path(argv[3]) if len(argv) > 3 else find_env_file(tmpl)
            sys.stdout.write(expand_text(tmpl.read_text(encoding="utf-8"), environment(env_file)))
            return 0
        env = environment(pathlib.Path(argv[2]))
        for k in sorted(env):
            print(f"export {k}={shlex.quote(env[k])}" if argv[1] == "export" else f"{k}={env[k]}")
        return 0
    except (EnvError, OSError, ValueError) as e:
        print(f"mgenv: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
