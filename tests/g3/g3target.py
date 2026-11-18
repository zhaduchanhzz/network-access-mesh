"""Where the G3 tool acts (P3-T14): the environment (infrastructure/environments/<env>/<env>.env through tools/mgenv.py —
never an IP or a domain in code), the Docker command of the platform host and of the client host, the names of the
platform's containers/networks/paths (design constants of §14.2–§14.4 on a real host; written by `g3.py dev-up` for
the dev stack), the credentials of the two platform staff (a file the operator names — never config/secrets/), and the
redaction set of the run.

Target JSON (optional, --target; every key overrides the default of the environment):
  connect            address dialled for admin.<domain> (default ${MG_LAN_IPV4}: LAN-direct to the edge — §2 of current.md)
  ca_file            CA bundle for the edge's certificate ("" = system roots: Let's Encrypt on staging)
  host_docker        Docker of the platform host, e.g. "sudo -n docker" (tool on the host) or
                     "ssh -i KEY -o IdentitiesOnly=yes -o BatchMode=yes mgdeploy@${MG_LAN_IPV4} sudo -n docker"
  client_docker      Docker of the client host (HS-24: another machine than the Headscale host for "network E2E")
  app_project        compose project of api/worker (mg-app)        agent_container   Host Agent (mg-agent)
  prober_container   prober of mg-obs (mg-obs-prober-1)            admin_network     mg-admin (prober callers)
  edge_container / edge_network   mg-edge / mg-edge                tenants_dir       /opt/meshguard/tenants
  backup_password_file  the password file of mg_backup (read-only role of the orphan detector)
  client_network / client_add_host / client_ca_dir   how a client container reaches <slug>.mesh.<domain>
  resource_prefix    prefix of the tool's own Docker objects (volumes, containers) on both hosts
Values may hold ${MG_*} placeholders of the environment file. Standard library only.
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import pathlib
import re
import shlex
import subprocess
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests" / "e2e" / "harness"))
import mgenv  # noqa: E402

SECRET_RE = re.compile(r"hskey-(?:api|auth|authreq)-[A-Za-z0-9_-]+|(?i:bearer\s+)[A-Za-z0-9._~+/=-]{8,}")
PREFIX_RE = re.compile(r"^[a-z][a-z0-9-]{1,20}$")


class G3Error(RuntimeError):
    pass


def defaults(env: dict[str, str]) -> dict:
    """Defaults of a real host (staging/production): the layout of infrastructure/host (layout.sh, networks.sh) and the
    compose projects of infrastructure/compose — design constants, not environment values."""
    return {
        "connect": env.get("MG_LAN_IPV4", ""),
        "ca_file": "",
        "host_docker": "sudo -n docker",
        "client_docker": "",
        "app_project": "mg-app",
        "agent_container": "mg-agent",
        "prober_container": "mg-obs-prober-1",
        "admin_network": "mg-admin",
        "edge_container": "mg-edge",
        "edge_network": "mg-edge",
        "tenants_dir": "/opt/meshguard/tenants",
        "backup_password_file": "/opt/meshguard/secrets/backup/pg_backup_password",
        "client_network": "bridge",
        "client_add_host": "",
        "client_ca_dir": "",
        "resource_prefix": "g3",
    }


class Target:
    def __init__(self, env_file: pathlib.Path, overrides: dict | None = None) -> None:
        if not env_file.is_file():
            raise G3Error(f"không thấy file môi trường {env_file}")
        self.env_file = env_file
        self.env = mgenv.environment(env_file)
        self.domain = self.env.get("MG_BASE_DOMAIN", "")
        if not self.domain:
            raise G3Error(f"{env_file}: thiếu MG_BASE_DOMAIN")
        cfg = defaults(self.env)
        for k, v in (overrides or {}).items():
            if k not in cfg:
                raise G3Error(f"target: khóa lạ {k!r} (có: {', '.join(sorted(cfg))})")
            cfg[k] = v
        self.cfg = {k: self.expand(v) if isinstance(v, str) else v for k, v in cfg.items()}
        if not PREFIX_RE.match(self.cfg["resource_prefix"]):
            raise G3Error("resource_prefix: ^[a-z][a-z0-9-]{1,20}$")
        if not self.cfg["connect"]:
            raise G3Error("connect: địa chỉ để gọi admin.<domain> (mặc định MG_LAN_IPV4 của file môi trường)")
        self.host_docker = shlex.split(self.cfg["host_docker"])
        self.client_docker = shlex.split(self.cfg["client_docker"]) if self.cfg["client_docker"] else self.host_docker
        self.secret_values: set[str] = set()
        lock = tomllib.loads((ROOT / "versions.lock").read_text(encoding="utf-8"))["images"]
        self.images = {k: f"{lock[k]['image']}@{lock[k]['index']}" for k in ("alpine", "tailscale", "golang")}

    # what backend.Browser / portal_login read from their `st` (tests/e2e/harness/backend.py)
    @property
    def edge_ip(self) -> str:
        return self.cfg["connect"]

    def expand(self, value: str) -> str:
        def sub(m: re.Match) -> str:
            if m.group(1) not in self.env:
                raise G3Error(f"placeholder ${{{m.group(1)}}} không có trong {self.env_file.name}")
            return self.env[m.group(1)]
        return re.sub(r"\$\{(MG_[A-Z0-9_]+)\}", sub, value)

    def name(self, what: str) -> str:
        return f"{self.cfg['resource_prefix']}-{what}"

    def redact(self, text: str) -> str:
        for v in sorted((x for x in self.secret_values if x), key=len, reverse=True):
            text = text.replace(v, "[REDACTED]")
        return SECRET_RE.sub("[REDACTED]", text)

    # ------------------------------------------------------------------------------------------------ processes
    def run(self, cmd: list[str], *, check: bool = True, timeout: float = 300, input: str | bytes | None = None,
            binary: bool = False) -> subprocess.CompletedProcess:  # noqa: A002
        """A command (never a secret in its arguments), output captured, never echoed; stdin is the only way a secret
        reaches a command."""
        kw: dict = {"input": input} if input is not None else {"stdin": subprocess.DEVNULL}
        if not binary:
            kw.update(text=True, encoding="utf-8", errors="replace")
        try:
            p = subprocess.run(cmd, capture_output=True, timeout=timeout, **kw)
        except subprocess.TimeoutExpired as e:
            raise G3Error(f"timeout sau {timeout}s: {' '.join(cmd[:6])} …") from e
        if check and p.returncode != 0:
            err = p.stderr if isinstance(p.stderr, str) else p.stderr.decode("utf-8", "replace")
            out = p.stdout if isinstance(p.stdout, str) else p.stdout.decode("utf-8", "replace")
            raise G3Error(f"exit {p.returncode}: {' '.join(cmd[:8])} …\n{self.redact((err or out).strip())[-1500:]}")
        return p

    @staticmethod
    def command(prefix: list[str], args: list[str] | tuple[str, ...]) -> list[str]:
        """prefix + args; through ssh the remote shell re-parses the joined words, so each argument is quoted (an
        argument like "cat > /out/x" must reach `sh -c` whole, not become a redirection on the remote host)."""
        if prefix and pathlib.PurePath(prefix[0]).name.removesuffix(".exe") == "ssh":
            return [*prefix, *(shlex.quote(a) for a in args)]
        return [*prefix, *args]

    def host_cmd(self, *args: str) -> list[str]:
        return self.command(self.host_docker, args)

    def client_cmd(self, *args: str) -> list[str]:
        return self.command(self.client_docker, args)

    def hd(self, *args: str, **kw) -> subprocess.CompletedProcess:
        """docker on the platform host."""
        return self.run(self.host_cmd(*args), **kw)

    def cd(self, *args: str, **kw) -> subprocess.CompletedProcess:
        """docker on the client host."""
        return self.run(self.client_cmd(*args), **kw)

    def pipe(self, src: list[str], dst: list[str], timeout: float = 60) -> tuple[int, int, str]:
        """src | dst without the bytes passing through this process's memory as text (key file → client container)."""
        a = subprocess.Popen(src, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
        b = subprocess.Popen(dst, stdin=a.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        a.stdout.close()
        try:
            _, err_b = b.communicate(timeout=timeout)
            _, err_a = a.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as e:
            a.kill()
            b.kill()
            raise G3Error(f"timeout: {' '.join(src[:4])} | {' '.join(dst[:4])}") from e
        return a.returncode, b.returncode, self.redact((err_a + err_b).decode("utf-8", "replace"))[-500:]

    def worker_container(self) -> str:
        p = self.hd("ps", "-q", "--filter", f"label=com.docker.compose.project={self.cfg['app_project']}",
                    "--filter", "label=com.docker.compose.service=worker")
        ids = p.stdout.split()
        if len(ids) != 1:
            raise G3Error(f"worker của project {self.cfg['app_project']}: {len(ids)} container đang chạy (cần đúng 1)")
        return ids[0]


# ---------------------------------------------------------------------------------------------------- credentials
def load_creds(path: pathlib.Path, t: Target | None = None) -> list[dict]:
    """The two platform staff of the dual control (Super Admins of the platform realm), from a JSON file the operator
    names — refused inside config/secrets/ (the owner's ceremony keys live there) and when group/other can read it:

      {"super_admins": [{"username": "…", "password": "…", "totp_base32": "…"}, {…}]}

    totp_base32 is the key of the authenticator app (Base32, as in the otpauth:// URI); totp_raw is the raw secret that
    Keycloak's "configure TOTP" form carries (the dev stack learns it at the first login). Values join the redaction
    set; they are never printed."""
    p = path.resolve()
    forbidden = (ROOT / "config" / "secrets").resolve()
    if p == forbidden or forbidden in p.parents:
        raise G3Error("file credential không được nằm trong config/secrets/ — dùng file riêng do người vận hành chỉ định")
    if os.name == "posix" and p.stat().st_mode & 0o077:
        raise G3Error(f"{p.name}: quyền phải là 0600 (group/other không được đọc)")
    doc = json.loads(p.read_text(encoding="utf-8"))
    sas = doc.get("super_admins") or []
    if len(sas) != 2:
        raise G3Error("cần đúng 2 Super Admin (dual control: người yêu cầu ≠ người duyệt)")
    out = []
    for i, u in enumerate(sas, 1):
        if not u.get("username") or not u.get("password"):
            raise G3Error(f"super_admins[{i}]: thiếu username/password")
        try:
            key = (base64.b32decode(re.sub(r"[\s=]", "", u["totp_base32"]).upper() + "=" * (-len(re.sub(r"[\s=]", "", u["totp_base32"])) % 8))
                   if u.get("totp_base32") else str(u.get("totp_raw", "")).encode())
        except (binascii.Error, ValueError) as e:
            raise G3Error(f"super_admins[{i}].totp_base32 không phải Base32") from e
        if not key:
            raise G3Error(f"super_admins[{i}]: thiếu totp_base32 hoặc totp_raw")
        out.append({"username": u["username"], "password": u["password"], "totp_key": key})
        if t is not None:
            t.secret_values.update({u["password"], u.get("totp_base32", ""), u.get("totp_raw", "")})
    if out[0]["username"] == out[1]["username"]:
        raise G3Error("hai Super Admin phải là hai người khác nhau")
    return out
