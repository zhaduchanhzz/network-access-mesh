"""Official Tailscale clients of tenant C for the G3 tool (P3-T14) — containers of [images.tailscale] on the CLIENT host
(Target.client_docker; HS-24: for a result above "functional" it must not be the Headscale host), userspace networking,
state in memory. The one-time key issued by the enrollment helper (P3-T14a, phase enroll-issue on the platform host)
is piped from the key volume of the platform host straight into the client's tmpfs (docker … cat | docker exec -i …):
it never becomes a string of this process and is removed right after `tailscale up`.

Traffic checks are the harness's: real TCP through WireGuard with `tailscale nc` to a listener on the peer (never
`tailscale ping` as proof — HS-25, CL-09), and a local connection to the listener as control.
"""
from __future__ import annotations

import json
import time

from g3target import G3Error, Target

SOCK = "--socket=/tmp/ts.sock"
PORT = 8000                       # test-allow-intra.hujson: tcp:8000 inside the tenant


class Client:
    def __init__(self, t: Target, name: str, slug: str):
        self.t, self.host, self.slug = t, name, slug
        self.container = t.name(f"client-{name}")

    def start(self) -> None:
        t = self.t
        args = ["run", "-d", "--name", self.container, "--hostname", self.host, "--network", t.cfg["client_network"],
                "--read-only", "--tmpfs", "/tmp:size=16m,mode=1777", "--tmpfs", "/run/g3:size=1m,mode=0700",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--memory", "256m", "--pids-limit", "128",
                "--label", "meshguard.role=g3-client", "-e", "TS_NO_LOGS_NO_SUPPORT=true"]
        if t.cfg["client_add_host"]:
            args += ["--add-host", f"{self.slug}.mesh.{t.domain}:{t.cfg['client_add_host']}"]
        if t.cfg["client_ca_dir"]:
            args += ["-v", f"{t.cfg['client_ca_dir']}:/etc/g3-ca:ro", "-e", "SSL_CERT_FILE=/etc/g3-ca/ca.crt",
                     "-e", "SSL_CERT_DIR=/etc/g3-ca"]
        script = ("tailscaled --tun=userspace-networking --state=mem: --socket=/tmp/ts.sock --statedir=/tmp/st "
                  ">/tmp/tsd.log 2>&1 & exec sleep infinity")
        t.cd(*args, "--entrypoint", "sh", t.images["tailscale"], "-c", script)

    def exec(self, *args: str, timeout: float = 60, check: bool = False, input: str | None = None):  # noqa: A002
        return self.t.cd("exec", *(["-i"] if input is not None else []), self.container, *args, check=check,
                         timeout=timeout, input=input)

    def push_key(self, key_volume: str, key_file: str) -> None:
        """key file (platform host volume) → /run/g3/authkey in the client (tmpfs 0700), bytes piped host to host."""
        t = self.t
        src = t.host_cmd("run", "--rm", "--network", "none", "--user", "65532:65532", "-v", f"{key_volume}:/k:ro",
               t.images["alpine"], "cat", f"/k/{key_file}")
        dst = t.client_cmd("exec", "-i", self.container, "sh", "-ec", "umask 077; cat > /run/g3/authkey")
        a, b, err = t.pipe(src, dst)
        if a != 0 or b != 0:
            raise G3Error(f"chuyển key tới {self.host}: exit {a}/{b} {err}")

    def up(self) -> tuple[int, str]:
        login = f"https://{self.slug}.mesh.{self.t.domain}"
        p = self.exec("sh", "-c", f"i=0; while [ ! -S /tmp/ts.sock ] && [ $i -lt 50 ]; do sleep 0.2; i=$((i+1)); done; "
                      f"timeout 60 tailscale {SOCK} up --login-server={login} --auth-key=file:/run/g3/authkey "
                      f"--hostname={self.host} --accept-dns=false --timeout=45s; rc=$?; rm -f /run/g3/authkey; exit $rc",
                      timeout=120)
        return p.returncode, self.t.redact(p.stdout + p.stderr)[-300:]

    def status(self) -> dict:
        p = self.exec("tailscale", SOCK, "status", "--json", timeout=30)
        try:
            return json.loads(p.stdout)
        except ValueError:
            return {}

    def ip4(self) -> str:
        return next((a for a in (self.status().get("Self") or {}).get("TailscaleIPs") or [] if "." in a), "")

    def peers(self) -> list[dict]:
        return list((self.status().get("Peer") or {}).values())

    def wait_peers(self, n: int, timeout: float = 90) -> int:
        end, got = time.time() + timeout, -1
        while time.time() < end:
            got = len(self.peers())
            if got == n:
                return got
            time.sleep(2)
        return got

    def listen(self) -> None:
        self.t.cd("exec", "-d", self.container, "nc", "-lk", "-p", str(PORT), "-e", "echo", f"g3 {self.slug} {self.host} tcp/{PORT}")

    def local(self) -> str:
        return self.exec("sh", "-c", f"echo | nc -w 3 127.0.0.1 {PORT}", timeout=30).stdout.strip()

    def tcp(self, ip: str, wait_s: int = 8) -> str:
        """Real TCP to ip:PORT over the tailnet ('' = no connection) — checks.tcp of the harness."""
        script = (f'f=$(mktemp -u); mkfifo "$f"; (sleep {wait_s + 2} >"$f" 2>/dev/null &); '
                  f'timeout {wait_s} tailscale {SOCK} nc {ip} {PORT} <"$f" 2>/dev/null; rm -f "$f"')
        return self.exec("sh", "-c", script, timeout=wait_s + 30).stdout.strip()

    def remove(self) -> None:
        self.t.cd("rm", "-f", self.container, check=False)
