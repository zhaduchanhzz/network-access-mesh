"""Stack dev/CI of P2-T01a: parameters, render, ephemeral CA, secrets, networks, compose — used by e2e.py.

Everything is rendered by the repository's own tools (tools/render_instance.py, render_edge.py, render_idp.py and,
since P2-T16, render_app.py — the backend api/worker/migrate/db-bootstrap and, since P4-T01a, the SPA container web, with
images built from the tree) from the
`ci` environment (infrastructure/environments/ci); the only CI-specific change to a rendered file is the edge's `tls`
block (ACME DNS-01 → certificate of the run's internal CA — ci_tls()). Secrets are generated per run into
<work>/secrets as 0400 files owned by their consumer's UID (an alpine helper container sets the ownership), handed to
containers as files; their values are only ever held in this process (for log redaction) and never printed.

Run parameters (environment, none secret):
  E2E_PREFIX       prefix of every Docker object (default mge2e): containers, networks, volumes, compose project
  E2E_WORK         working directory (default <tmp>/<prefix>-work) — removed by `down`
  E2E_OUT          results: summary, results.json, redacted logs (default <work>-out) — kept
  DOCKER           docker command (default "docker"; e.g. "sudo docker" on a host where docker needs sudo)
  E2E_KEEP_CACHE   1 (default) keeps the Go module/build cache volumes <prefix>-gomod/-gocache between runs
  E2E_HEADSCALE_LOCK_KEY  versions.lock [images.<key>] of Headscale (default: mg-headscale if present, else headscale)
  MG_*             override a value of infrastructure/environments/ci/ci.env (e.g. MG_E2E_NET_BASE=10.232)
Standard library only (+ openssl CLI for the CA).
"""
from __future__ import annotations

import ipaddress
import json
import os
import pathlib
import re
import secrets
import shlex
import shutil
import string
import subprocess
import sys
import tempfile
import time
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[3]
HERE = ROOT / "tests" / "e2e" / "harness"
ENV_DIR = ROOT / "infrastructure" / "environments" / "ci"
sys.path.insert(0, str(ROOT / "tools"))
import mgenv  # noqa: E402
import render_app  # noqa: E402
import render_edge  # noqa: E402
import render_idp  # noqa: E402
import render_instance  # noqa: E402
import render_mail  # noqa: E402
import render_monitoring  # noqa: E402 — project mg-obs (P3-T16)

TENANTS = ("tenant-a", "tenant-b")
CLIENTS = {"a1": "tenant-a", "a2": "tenant-a", "b1": "tenant-b", "b2": "tenant-b"}
RELAY_ONLY = {"a1", "a2"}                 # TS_DEBUG_ALWAYS_USE_DERP in compose.yaml
HEADSCALE_LOCK_KEYS = ("mg-headscale", "headscale")   # first one present in versions.lock wins
ADMIN_ROLES = ("mg_migrator", "mg_backup")
LOGIN_ROLES = ("mg_api_tenant", "mg_worker_tenant", "mg_api_platform", "mg_worker_platform", "mg_readonly",
               "mg_audit_writer", "mg_partition_maint")
ALNUM = string.ascii_letters + string.digits
SECRET_RE = re.compile(r"hskey-(?:api|auth|authreq)-[A-Za-z0-9_-]+|(?i:bearer\s+)[A-Za-z0-9._~+/=-]{8,}")
PREFIX_RE = re.compile(r"^[a-z][a-z0-9-]{1,20}$")
# uid:gid of each consumer (images: postgres 999, Keycloak 1000, edge 10001, distroless nonroot 65532, client root)
UID = {"postgres": "999:999", "idp": "1000:1000", "edge": "10001:10001", "dbinit": "65532:65532", "client": "0:0"}
# Backend (P2-T16): file secrets of compose.app.yaml → <work>/secrets/<path>, group = the fixed GID of §14.2 (root:<gid>
# 0440, as infrastructure/host/app-secrets.sh lays them out on the host). One copy per consumer, same values as the
# role passwords db-init sets.
APP_SECRET_GROUPS = {"api": 20002, "worker": 20003, "app": 20001, "migrate": 20004, "kek-app": 20001, "kek-ops": 20003,
                     "obs": 20006}   # P3-T16: Prometheus (65534 + mg-sec-obs) — copy of the edge's metrics token
APP_ROLES = ("mg_api_tenant", "mg_api_platform", "mg_worker_tenant", "mg_worker_platform", "mg_audit_writer",
             "mg_partition_maint")
# (api, worker, web) before the build — render without Docker (e2e.py render, test_stack.py)
DUMMY_IMAGES = ("sha256:" + "0" * 64, "sha256:" + "1" * 64, "sha256:" + "2" * 64)
# The ACME DNS-01 block of the rendered Caddyfile, replaced by the run's certificate (ci_tls).
TLS_DNS01 = re.compile(r"\n\ttls \{\n\t\tdns cloudflare \{file\./run/secrets/cloudflare_dns_token\}\n"
                       r"\t\tresolvers [0-9. ]+\n\t\}\n")


class StackError(RuntimeError):
    pass


def log(msg: str) -> None:
    print(f"[e2e {time.strftime('%H:%M:%S')}] {msg}", flush=True)


class Stack:
    def __init__(self) -> None:
        self.prefix = os.environ.get("E2E_PREFIX", "mge2e")
        if not PREFIX_RE.match(self.prefix):
            raise StackError("E2E_PREFIX must match ^[a-z][a-z0-9-]{1,20}$")
        self.work = pathlib.Path(os.environ.get("E2E_WORK") or pathlib.Path(tempfile.gettempdir()) / f"{self.prefix}-work")
        self.out = pathlib.Path(os.environ.get("E2E_OUT") or f"{self.work}-out")
        self.docker_cmd = shlex.split(os.environ.get("DOCKER", "docker"))
        self.keep_cache = os.environ.get("E2E_KEEP_CACHE", "1") == "1"
        self.secret_values: set[str] = set()

        env = mgenv.environment(ENV_DIR / "ci.env")       # ci.env + MG_* of the process environment
        base = env.get("MG_E2E_NET_BASE", "")
        if not re.fullmatch(r"10\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)", base) or base in ("10.249", "10.250"):
            raise StackError("MG_E2E_NET_BASE must look like 10.<n> and differ from 10.249/10.250 (host and tenant pools)")
        tnet = ipaddress.ip_network(env.get("MG_E2E_TENANT_NET", ""))
        if tnet.prefixlen != 28 or not tnet.subnet_of(render_instance.TENANT_NET_POOL):
            raise StackError(f"MG_E2E_TENANT_NET must be a /28 inside {render_instance.TENANT_NET_POOL}")
        net_a, net_b = (str(n) for n in tnet.subnets(new_prefix=29))
        self.domain = env["MG_BASE_DOMAIN"]
        self.mesh = f"mesh.{self.domain}"
        self.edge_ip = f"{base}.0.2"
        self.admin_ip, self.obs_ip = f"{base}.2.2", f"{base}.3.2"
        self.worker_edge_ip = f"{base}.0.4"           # render_edge.APP_IPS: the edge's Admin-API allow-list (P2-T16)
        self.edge_idp_ip = f"{base}.7.2"              # the edge on the idp network (G2 round 2, A-8)
        self.host_ip = f"{base}.0.1"                  # this host on the edge network: the only admin. source (P2-T16)
        self.app_images = DUMMY_IMAGES                # (api, worker, web) — build_app_images() sets the local IDs
        # P3-T16: static addresses of project mg-obs (render_monitoring.OBS_IPS / PROBER_IPS on the stack's subnets)
        self.obs_ips = {k: f"{base}.3.{v.rsplit('.', 1)[1]}" for k, v in render_monitoring.OBS_IPS.items()}
        self.prober_admin_ip = f"{base}.2.{render_monitoring.PROBER_IPS['prober_admin_ip'].rsplit('.', 1)[1]}"
        # name → (subnet, internal, ip-range for dynamic allocation) — same layout as infrastructure/host/networks.sh
        self.networks = {
            "edge": (f"{base}.0.0/24", False, f"{base}.0.128/25"),
            "data": (f"{base}.1.0/24", True, None),
            "admin": (f"{base}.2.0/24", True, f"{base}.2.128/25"),
            "obs": (f"{base}.3.0/24", True, f"{base}.3.128/25"),
            "sec": (f"{base}.4.0/24", True, None),
            "egress": (f"{base}.5.0/24", False, None),
            "idp-data": (f"{base}.6.0/24", True, None),
            "idp": (f"{base}.7.0/24", True, f"{base}.7.128/25"),   # edge + idp only (G2 round 2, A-8)
            "mail": (f"{base}.8.0/24", True, None),                # mailrelay, worker, idp (P3-T05b-mail)
            "t-tenant-a": (net_a, True, None),
            "t-tenant-b": (net_b, True, None),
        }
        lock = tomllib.loads((ROOT / "versions.lock").read_text(encoding="utf-8"))["images"]
        img = lambda k: f"{lock[k]['image']}@{lock[k]['index']}"  # noqa: E731
        hs_key = headscale_lock_key(lock, os.environ.get("E2E_HEADSCALE_LOCK_KEY"))
        self.headscale_lock_key = hs_key
        self.images = {"headscale": img(hs_key), "edge": img("mg-edge"), "stund": img("mg-stund"),
                       "idp": img("mg-idp"), "postgres": img("postgres"), "tailscale": img("tailscale"),
                       "alpine": img("alpine"), "golang": img("golang"), "distroless": img("distroless-static"),
                       "probe": f"{self.prefix}-probe:e2e",   # P3-T03a: built from the tree (build_probe_image)
                       "node": img("node"),                   # fake Worker of the mail relay (P3-T05b-mail)
                       # P3-T16: official pins + node_exporter rebuilt from source (build_node_exporter_image)
                       "prometheus": img("prometheus"), "alertmanager": img("alertmanager"),
                       "node-exporter": f"{self.prefix}-node-exporter:e2e"}
        env.update(MG_E2E_EDGE_IPV4=self.edge_ip, MG_E2E_TENANT_A_CIDR=net_a, MG_E2E_TENANT_B_CIDR=net_b,
                   MG_E2E_HEADSCALE_IMAGE=self.images["headscale"], MG_E2E_EDGE_IMAGE=self.images["edge"],
                   MG_E2E_ADMIN_ALLOW=f"{self.host_ip}/32")
        self.env = env

    # ------------------------------------------------------------------------------------------------ processes
    def redact(self, text: str) -> str:
        for v in sorted(self.secret_values, key=len, reverse=True):
            text = text.replace(v, "[REDACTED]")
        return SECRET_RE.sub("[REDACTED]", text)

    def run(self, cmd: list[str], *, check: bool = True, timeout: float | None = 300,
            input: str | None = None) -> subprocess.CompletedProcess:  # noqa: A002
        """Run a command (never with a secret in its arguments), capturing output. Output is never echoed (it may hold
        a credential) — callers decide what to print, through redact(). `input` is written to its stdin (a pipe) — the
        only way a credential reaches an admin command (P2-T11, P2-T16)."""
        try:
            stdin = {"input": input} if input is not None else {"stdin": subprocess.DEVNULL}
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, encoding="utf-8", errors="replace",
                               **stdin)
        except subprocess.TimeoutExpired as e:
            raise StackError(f"timeout after {timeout}s: {' '.join(cmd[:6])} …") from e
        if check and p.returncode != 0:
            tail = self.redact((p.stderr or p.stdout or "").strip())[-1500:]
            raise StackError(f"exit {p.returncode}: {' '.join(cmd[:8])} …\n{tail}")
        return p

    def docker(self, *args: str, **kw) -> subprocess.CompletedProcess:
        return self.run([*self.docker_cmd, *args], **kw)

    def compose_files(self) -> list[str]:
        r = self.work / "render"
        files = [r / "tenant-a" / "compose.yaml", r / "tenant-b" / "compose.yaml", r / "edge" / "compose.edge.yaml",
                 r / "idp" / "compose.idp.yaml", r / "app" / "compose.app.yaml", r / "obs" / "compose.monitoring.yaml",
                 ROOT / "compose.yaml"]
        return [x for f in files for x in ("-f", str(f))]

    def compose(self, *args: str, **kw) -> subprocess.CompletedProcess:
        return self.docker("compose", "-p", self.prefix, "--project-directory", str(ROOT),
                           "--env-file", str(self.work / "stack.env"), *self.compose_files(), *args, **kw)

    def name(self, what: str) -> str:
        return f"{self.prefix}-{what}"

    def exec(self, container: str, *args: str, **kw) -> subprocess.CompletedProcess:
        return self.docker("exec", self.name(container), *args, **kw)

    def headscale(self, slug: str, *args: str, **kw) -> subprocess.CompletedProcess:
        return self.exec(f"hs-{slug}", "headscale", *args, **kw)

    def helper(self, script: str, *mounts: str, network: str = "none") -> subprocess.CompletedProcess:
        """Run a shell script (never holding a secret) as root in the pinned alpine image."""
        vols = [x for m in mounts for x in ("-v", m)]
        return self.docker("run", "--rm", "--network", network, *vols, self.images["alpine"], "sh", "-ec", script)

    # ------------------------------------------------------------------------------------------------ render
    def render(self) -> None:
        out = self.work / "render"
        for slug in TENANTS:
            params = mgenv.expand(json.loads((ENV_DIR / "tenants" / f"{slug}.json").read_text(encoding="utf-8")), self.env)
            files = render_instance.render(params)
            render_instance.write(files, out / slug)
            log(f"render {slug}: {', '.join(sorted(files))} (image {params['image'].split('@')[0]})")
        # The edge's static IPs and internal subnets are module constants of render_edge (the host layout of
        # infrastructure/host/networks.sh); the stack uses its own subnets. Updated in place: render_idp shares the dict
        # (KC_PROXY_TRUSTED_ADDRESSES = the edge's IP on the idp network).
        render_edge.EDGE_IPS.update(edge_ip=self.edge_ip, edge_admin_ip=self.admin_ip, edge_obs_ip=self.obs_ip,
                                    edge_idp_ip=self.edge_idp_ip)
        render_edge.INTERNAL.update(admin_subnet=self.networks["admin"][0], obs_subnet=self.networks["obs"][0])
        render_edge.APP_IPS.update(worker_edge_ip=self.worker_edge_ip)
        render_mail.MAIL_NET.update(subnet=self.networks["mail"][0])   # mailrelay listens on the stack's mail network
        params = mgenv.expand(json.loads((ENV_DIR / "edge.json").read_text(encoding="utf-8")), self.env)
        files = render_edge.render(params)
        files["caddy/Caddyfile"] = ci_tls(files["caddy/Caddyfile"])
        render_edge.write(files, out / "edge")
        log(f"render edge: Caddyfile (template {render_edge.TEMPLATE_VERSION}, tls → CA nội bộ), compose.edge.yaml")
        files = render_idp.render(self.env, self.images["idp"])
        render_edge.write(files, out / "idp")
        log(f"render idp: {len([f for f in files if f.startswith('idp/realms/')])} realm, compose.idp.yaml")
        render_monitoring.OBS_IPS.update(self.obs_ips)
        render_monitoring.PROBER_IPS.update(prober_admin_ip=self.prober_admin_ip)
        self.render_app()
        self.render_obs()
        pol = self.work / "policies"
        pol.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / "infrastructure" / "headscale" / "templates" / "test-allow-intra.hujson",
                        pol / "test-allow-intra.hujson")
        os.chmod(pol / "test-allow-intra.hujson", 0o644)
        for p in out.rglob("*"):   # config is not secret; Headscale/Keycloak/Caddy run as other UIDs
            os.chmod(p, 0o755 if p.is_dir() else 0o644)

    def render_app(self) -> None:
        """compose.app.yaml (P2-T16) by tools/render_app.py with the images of this run (dummy IDs before the build)."""
        files = render_app.render(self.env, *self.app_images)
        render_edge.write(files, self.work / "render" / "app")
        os.chmod(self.work / "render" / "app" / "compose.app.yaml", 0o644)
        log(f"render app: compose.app.yaml (template {render_app.TEMPLATE_VERSION}, api {self.app_images[0][:19]}…, "
            f"worker {self.app_images[1][:19]}…, web {self.app_images[2][:19]}…)")

    def obs_built(self, key: str) -> str:
        """The image ID of an image built from the tree, or a dummy ID before the build (render without Docker)."""
        ref = self.images[key]
        return ref if render_monitoring.IMAGE_RE.match(ref) else DUMMY_IMAGES[0]

    def render_obs(self) -> None:
        """Project mg-obs (P3-T16) by tools/render_monitoring.py for the ci environment (the stack's addresses), the
        instance targets of the two tenants (the labels of their Headscale containers, like obs-targets.sh), the drill
        directory and the backup status files read by node-exporter: postgres overdue (last success 30 h ago — max age
        26 h), edge fresh, idp absent — the sources of PlatformBackupOverdue and PlatformBackupStatusMissing (E2E-78)."""
        out = self.work / "render" / "obs"
        files = render_monitoring.render(self.env, self.obs_built("probe"), node_exporter_image=self.obs_built("node-exporter"))
        render_edge.write(files, out)
        rows = []
        for slug in TENANTS:
            p = json.loads((ENV_DIR / "tenants" / f"{slug}.json").read_text(encoding="utf-8"))
            rows.append((p["tenant_id"], p["instance_id"], f"mg-hs-{slug}"))
        entries, _ = render_monitoring.instance_targets(rows)
        render_monitoring.write_atomic(out / "monitoring" / "prometheus" / "targets" / "instances.json",
                                       json.dumps(entries, indent=2) + "\n")
        (out / "monitoring" / "drill").mkdir(parents=True, exist_ok=True)
        now = time.time()
        status = {"postgres": now - 30 * 3600, "edge": now - 600}
        for target in ("postgres", "idp", "edge"):
            d = self.work / "obs" / "backups" / target
            d.mkdir(parents=True, exist_ok=True)
            os.chmod(d, 0o755)
            if target in status:   # the format of apps/backup (same HELP texts — node_exporter merges families on them)
                render_monitoring.write_atomic(d / "status.prom",
                                               render_monitoring.backup_status_prom(target, status[target]))
        log(f"render obs: compose.monitoring.yaml (template {render_monitoring.TEMPLATE_VERSION}), prometheus.yml, "
            f"alertmanager.yml, {len(entries)} instance target(s), status.prom postgres (quá hạn) + edge")

    def build_node_exporter_image(self) -> None:
        """node_exporter v1.12.1 rebuilt from source (infrastructure/docker/node-exporter, P3-T16)."""
        t0 = time.time()
        tag = f"{self.prefix}-node-exporter:e2e"
        ctx = ROOT / "infrastructure" / "docker" / "node-exporter"
        self.docker("build", "-q", "-f", str(ctx / "Dockerfile"), "--label", "meshguard.role=e2e", "-t", tag, str(ctx),
                    timeout=1800)
        self.images["node-exporter"] = self.docker("image", "inspect", "-f", "{{.Id}}", tag).stdout.strip()
        log(f"build node-exporter (infrastructure/docker/node-exporter): {self.images['node-exporter'][:19]}… trong "
            f"{time.time() - t0:.0f} s")

    def build_app_images(self) -> None:
        """api and worker images built from the tree with the production Dockerfile (infrastructure/docker/app), and the
        SPA image web (infrastructure/docker/web — npm ci + vite build + Caddy, context = the repository; P4-T01a)."""
        ids = []
        for app in ("api", "worker", "web"):
            t0 = time.time()
            tag = f"{self.prefix}-{app}:e2e"
            if app == "web":
                dockerfile, args = "web", []
            else:
                dockerfile = "app"
                args = ["--build-arg", f"APP={app}", "--build-arg", "VERSION=e2e", "--build-arg", "COMMIT=e2e"]
            self.docker("build", "-q", "-f", str(ROOT / "infrastructure" / "docker" / dockerfile / "Dockerfile"), *args,
                        "--label", "meshguard.role=e2e", "-t", tag, str(ROOT), timeout=1800)
            ids.append(self.docker("image", "inspect", "-f", "{{.Id}}", tag).stdout.strip())
            log(f"build {app} (infrastructure/docker/{dockerfile}/Dockerfile): {ids[-1][:19]}… trong {time.time() - t0:.0f} s")
        self.app_images = (ids[0], ids[1], ids[2])

    def reuse_app_images(self) -> None:
        """`e2e.py test` in a process of its own: the api/worker/web images `up` built (tags <prefix>-<app>:e2e), so a
        re-render of compose.app.yaml (E2E-77) does not fall back to the dummy IDs."""
        ids = [self.docker("image", "inspect", "-f", "{{.Id}}", f"{self.prefix}-{app}:e2e", check=False).stdout.strip()
               for app in ("api", "worker", "web")]
        if all(ids):
            self.app_images = (ids[0], ids[1], ids[2])

    def build_probe_image(self) -> None:
        """The prober image built from the tree with its production Dockerfile (infrastructure/docker/probe, P3-T03a)."""
        t0 = time.time()
        tag = f"{self.prefix}-probe:e2e"
        self.docker("build", "-q", "-f", str(ROOT / "infrastructure" / "docker" / "probe" / "Dockerfile"),
                    "--build-arg", "APP=probe", "--build-arg", "VERSION=e2e", "--build-arg", "COMMIT=e2e",
                    "--label", "meshguard.role=e2e", "-t", tag, str(ROOT), timeout=1800)
        self.images["probe"] = self.docker("image", "inspect", "-f", "{{.Id}}", tag).stdout.strip()
        log(f"build probe (infrastructure/docker/probe/Dockerfile): {self.images['probe'][:19]}… trong {time.time() - t0:.0f} s")

    def build_idp_image(self) -> None:
        """The idp image built from the tree (infrastructure/docker/idp) — the realms rendered from the tree need what the
        tree's image holds (password blocklist of G2 round 2 A-3; the pinned [images.mg-idp] may predate it)."""
        t0 = time.time()
        tag = f"{self.prefix}-idp:e2e"
        ctx = ROOT / "infrastructure" / "docker" / "idp"
        self.docker("build", "-q", "-f", str(ctx / "Dockerfile"), "--label", "meshguard.role=e2e", "-t", tag, str(ctx),
                    timeout=1800)
        self.images["idp"] = self.docker("image", "inspect", "-f", "{{.Id}}", tag).stdout.strip()
        log(f"build idp (infrastructure/docker/idp/Dockerfile): {self.images['idp'][:19]}… trong {time.time() - t0:.0f} s")

    def write_stack_env(self) -> None:
        values = {"MGE_PREFIX": self.prefix, "MGE_WORK": str(self.work), "MGE_MESH_DOMAIN": self.mesh,
                  "MGE_EDGE_IP": self.edge_ip, "MGE_IMG_POSTGRES": self.images["postgres"],
                  "MGE_IMG_TAILSCALE": self.images["tailscale"], "MGE_IMG_STUND": self.images["stund"],
                  "MGE_IMG_DISTROLESS": self.images["distroless"], "MGE_IMG_PROBE": self.images["probe"],
                  "MGE_ADMIN_SUBNET": self.networks["admin"][0], "MGE_IMG_NODE": self.images["node"],
                  "MGE_MAIL_FROM": render_mail.sender(self.env)[1]}
        text = "# Sinh bởi tests/e2e/harness/stack.py — tham số KHÔNG bí mật của stack dev/CI (compose.yaml).\n"
        (self.work / "stack.env").write_text(text + "".join(f"{k}={v}\n" for k, v in values.items()), encoding="utf-8")

    # ------------------------------------------------------------------------------------------------ CA + secrets
    def new_secret(self, rel: str, value: str | None = None) -> str:
        v = value if value is not None else "".join(secrets.choice(ALNUM) for _ in range(40))
        self.secret_values.add(v)
        self.write_private(self.work / "secrets" / rel, v)
        return v

    def write_private(self, path: pathlib.Path, value: str) -> None:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(value)

    def make_ca(self) -> None:
        """Ephemeral CA of this run → one wildcard certificate for *.mesh.<domain>; the CA key is deleted at once."""
        ca_dir, tmp = self.work / "ca", self.work / "ca-private"
        ca_dir.mkdir(parents=True, exist_ok=True)
        tmp.mkdir(mode=0o700, parents=True, exist_ok=True)
        edge = self.work / "secrets" / "edge"
        edge.mkdir(parents=True, exist_ok=True)
        ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes"]
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        old = os.umask(0o077)
        try:
            self.run(["openssl", "req", "-x509", *ec, "-keyout", str(tmp / "ca.key"), "-out", str(ca_dir / "ca.crt"),
                      "-days", "1", "-subj", f"/O=MeshGuard CI/CN=MeshGuard ephemeral CI CA {self.prefix} {stamp}",
                      "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                      "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                      "-addext", f"nameConstraints=critical,permitted;DNS:{self.domain}"])
            self.run(["openssl", "req", "-new", *ec, "-keyout", str(edge / "tls_key"), "-out", str(tmp / "edge.csr"),
                      "-subj", f"/CN=*.{self.mesh}"])
            sans = ",".join(f"DNS:{h}" for h in (f"*.{self.mesh}", f"app.{self.domain}", f"admin.{self.domain}",
                                                  f"auth.{self.domain}"))
            (tmp / "edge.ext").write_text(f"subjectAltName={sans}\nbasicConstraints=critical,CA:FALSE\n"
                                          "keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n",
                                          encoding="ascii")
            self.run(["openssl", "x509", "-req", "-in", str(tmp / "edge.csr"), "-CA", str(ca_dir / "ca.crt"),
                      "-CAkey", str(tmp / "ca.key"), "-set_serial", "0x" + secrets.token_hex(16), "-days", "1",
                      "-extfile", str(tmp / "edge.ext"), "-out", str(edge / "tls_cert")])
        finally:
            os.umask(old)
            shutil.rmtree(tmp, ignore_errors=True)        # the CA key never outlives the signing of the one leaf
        os.chmod(ca_dir / "ca.crt", 0o644)
        self.secret_values.add((edge / "tls_key").read_text(encoding="ascii").strip())
        info = self.run(["openssl", "x509", "-in", str(ca_dir / "ca.crt"), "-noout", "-subject", "-enddate"]).stdout
        log("CA nội bộ dùng-một-lần: " + " ".join(info.split()) + f"; name constraint DNS:{self.domain} "
            f"(*.{self.mesh}, app./admin./auth.); khóa CA đã xóa")

    def make_secrets(self) -> None:
        (self.work / "secrets").mkdir(mode=0o700, parents=True, exist_ok=True)
        s = self.new_secret
        pg = s("postgres/superuser_password")
        s("dbinit/pg_superuser_password", pg)              # one copy per consumer (§14.2)
        for role in (*ADMIN_ROLES, *LOGIN_ROLES):
            s(f"dbinit/role_{role}")
        roles = {r: (self.work / "secrets" / "dbinit" / f"role_{r}").read_text(encoding="utf-8")
                 for r in (*ADMIN_ROLES, *LOGIN_ROLES)}
        # backend (P2-T16): each consumer's copy of the role passwords, the edge admin token, the two keyrings
        s("api/db_api_tenant_password", roles["mg_api_tenant"])
        s("api/db_api_platform_password", roles["mg_api_platform"])
        s("worker/db_worker_tenant_password", roles["mg_worker_tenant"])
        s("worker/db_worker_platform_password", roles["mg_worker_platform"])
        s("worker/db_partition_password", roles["mg_partition_maint"])
        s("app/db_audit_writer_password", roles["mg_audit_writer"])
        for r in ("mg_migrator", *APP_ROLES):
            s(f"migrate/{r}", roles[r])
        s("appboot/pg_superuser_password", pg)
        s("appboot/pg_backup_password", roles["mg_backup"])
        for ring, kid in (("kek-app", "e2e-app-1"), ("kek-ops", "e2e-ops-1")):
            s(f"{ring}/{kid}", secrets.token_hex(32) + "\n")
            self.write_private(self.work / "secrets" / ring / "ACTIVE", kid + "\n")
        idp_db = s("idp/db_password")
        s("idp/db_superuser_password")
        s("idp/backup_db_password")                        # role idp_backup of idp-db (initdb 20-…, P2-T05b)
        admin_pw = "".join(secrets.choice(ALNUM) for _ in range(40))
        self.secret_values.add(admin_pw)
        # same keys as infrastructure/idp/secrets.sh (Keycloak --config-file); checked against that script
        conf = {"db-password": idp_db, "bootstrap-admin-username": "mg-bootstrap-admin", "bootstrap-admin-password": admin_pw}
        want = set(re.findall(r'echo "([a-z-]+)=', (ROOT / "infrastructure" / "idp" / "secrets.sh").read_text(encoding="utf-8")))
        if want != set(conf):
            raise StackError(f"keycloak.conf keys {sorted(conf)} differ from infrastructure/idp/secrets.sh {sorted(want)}")
        self.write_private(self.work / "secrets" / "idp" / "keycloak.conf",
                           "# Sinh bởi tests/e2e/harness — dùng một lần.\n" + "".join(f"{k}={v}\n" for k, v in conf.items()))
        for name in ("admin_token", "metrics_token", "bouncer_key", "cloudflare_dns_token"):
            v = s(f"edge/{name}")
            if name == "admin_token":                      # copies: the caller of the admin listener, api/worker
                s("harness/admin_token", v)
                s("app/edge_admin_token", v)
            if name == "metrics_token":                    # copy of Prometheus (P3-T16: obs/edge_metrics_token)
                s("obs/edge_metrics_token", v)
        s("harness/kc_admin_password", admin_pw)           # the harness's copy: Keycloak Admin API of the checks
        for c in CLIENTS:                                  # filled with a pre-auth key right before the client starts
            self.write_private(self.work / "secrets" / "clients" / f"{c}.authkey", "")
        for d in ("data/tenant-a", "data/tenant-b", "logs/edge", "bin"):
            (self.work / d).mkdir(parents=True, exist_ok=True)

    def own_files(self) -> None:
        """Give each secret/data directory to the UID that uses it (0400 files) — Docker binds files as they are."""
        script = "\n".join([
            f"chown -R {UID['postgres']} /w/secrets/postgres; chmod 0700 /w/secrets/postgres; chmod 0400 /w/secrets/postgres/*",
            f"chown -R {UID['dbinit']} /w/secrets/dbinit; chmod 0500 /w/secrets/dbinit; chmod 0400 /w/secrets/dbinit/*",
            f"chown {UID['idp']} /w/secrets/idp/keycloak.conf",
            f"chown {UID['postgres']} /w/secrets/idp/db_password /w/secrets/idp/db_superuser_password"
            " /w/secrets/idp/backup_db_password",
            "chmod 0400 /w/secrets/idp/*",
            f"chown -R {UID['edge']} /w/secrets/edge; chmod 0700 /w/secrets/edge; chmod 0400 /w/secrets/edge/*",
            f"chown {UID['edge']} /w/logs/edge; chmod 0750 /w/logs/edge",
            "chown 30001:30001 /w/data/tenant-a; chown 30002:30002 /w/data/tenant-b; chmod 0700 /w/data/*",
            *[f"chown -R 0:{g} /w/secrets/{d}; chmod 0750 /w/secrets/{d}; chmod 0440 /w/secrets/{d}/*"
              for d, g in APP_SECRET_GROUPS.items()],
            "chown 0:999 /w/secrets/appboot/pg_superuser_password; chown 0:20007 /w/secrets/appboot/pg_backup_password",
            "chmod 0755 /w/secrets/appboot; chmod 0440 /w/secrets/appboot/*",
        ])
        self.helper(script, f"{self.work}:/w")

    def make_mail_secrets(self) -> None:
        """The relay's files (P3-T05b-mail) by the host script itself — infrastructure/host/mail-secrets.sh, as root in a
        throw-away container of the pinned golang image (bash + openssl) with MG_SECRETS_ROOT=<work>/secrets: HMAC key and
        TLS key root:20009 0440, certificate and CA 0444, CA key gone. Then the fake Worker's copy of the key (UID 1000 of
        the node image) and its record directory; the harness keeps the key for redaction and its own HMAC check."""
        script = "/repo/infrastructure/host/mail-secrets.sh"
        p = self.docker("run", "--rm", "--network", "none", "-v", f"{ROOT}:/repo:ro", "-v", f"{self.work / 'secrets'}:/s",
                        "-e", "MG_SECRETS_ROOT=/s", "--entrypoint", "bash", self.images["golang"], script, timeout=120)
        log("mail-secrets.sh: " + " | ".join(ln for ln in p.stdout.splitlines() if ln.startswith(("tls_cert: subject",
                                                                                                     "ca.crt:   subject"))))
        self.helper("mkdir -p /w/secrets/fakeworker /w/fakeworker; cp /w/secrets/mail/relay_hmac_key /w/secrets/fakeworker/; "
                    "chown -R 1000:1000 /w/secrets/fakeworker; chmod 0500 /w/secrets/fakeworker; "
                    "chmod 0400 /w/secrets/fakeworker/relay_hmac_key; chmod 0777 /w/fakeworker", f"{self.work}:/w")
        self.mail_key = self.helper("cat /w/secrets/mail/relay_hmac_key", f"{self.work}:/w").stdout.strip()
        self.secret_values.add(self.mail_key)
        self.secret_values.add(self.helper("cat /w/secrets/mail/tls_key", f"{self.work}:/w").stdout.strip())

    def set_mail_key(self, value: str) -> None:
        """Rewrite the relay's HMAC key file IN PLACE (same inode: the running mailrelay sees it at its next message)."""
        self.secret_values.add(value)
        self.run([*self.docker_cmd, "run", "--rm", "-i", "--network", "none", "-v", f"{self.work}:/w", self.images["alpine"],
                  "sh", "-c", "cat > /w/secrets/mail/relay_hmac_key"], input=value)

    def fresh_dir(self, rel: str) -> pathlib.Path:
        """An empty directory <work>/<rel> owned by this process (a previous run may have handed it to another UID)."""
        self.helper(f"rm -rf /w/{rel}", f"{self.work}:/w")
        d = self.work / rel
        d.mkdir(mode=0o700, parents=True)
        return d

    def own_client_keys(self, names: list[str]) -> None:
        paths = " ".join(f"/w/secrets/{n}" for n in names)
        self.helper(f"chown {UID['client']} {paths}; chmod 0400 {paths}", f"{self.work}:/w")

    # ------------------------------------------------------------------------------------------------ docker objects
    def create_networks(self) -> None:
        for name, (subnet, internal, ip_range) in self.networks.items():
            flags = (["--internal"] if internal else []) + (["--ip-range", ip_range] if ip_range else [])
            if name == "edge":   # this host on the edge network = .1 (Docker would take the first address of the range)
                flags += ["--gateway", self.host_ip]
            self.docker("network", "create", *flags, "--subnet", subnet, "--label", "meshguard.role=e2e",
                        "--label", f"meshguard.e2e.prefix={self.prefix}", self.name(name))
        log("network: " + ", ".join(f"{self.name(n)} {s}{' internal' if i else ''}"
                                    for n, (s, i, _) in self.networks.items()))

    def build_dbinit(self) -> None:
        for v in ("gomod", "gocache"):
            self.docker("volume", "create", "--label", "meshguard.role=e2e", self.name(v))
        t0 = time.time()
        self.docker("run", "--rm", "-v", f"{ROOT}:/src:ro", "-v", f"{self.name('gomod')}:/go/pkg/mod",
                    "-v", f"{self.name('gocache')}:/root/.cache/go-build", "-v", f"{self.work / 'bin'}:/out",
                    "-e", "GOTOOLCHAIN=local", "-e", "GOFLAGS=-mod=readonly", "-e", "CGO_ENABLED=0", "-w", "/src",
                    self.images["golang"], "go", "build", "-buildvcs=false", "-trimpath",
                    "-o", "/out/mg-e2e-dbinit", "./tests/e2e/harness/dbinit", timeout=900)
        log(f"build tests/e2e/harness/dbinit trong {self.images['golang'].split('@')[0]}: {time.time() - t0:.0f} s")

    def build_enroll(self) -> None:
        """The enrollment test helper of P3-T14a as a static test binary (go test -c -tags mgtestfixture) — E2E-32."""
        t0 = time.time()
        self.docker("run", "--rm", "-v", f"{ROOT}:/src:ro", "-v", f"{self.name('gomod')}:/go/pkg/mod",
                    "-v", f"{self.name('gocache')}:/root/.cache/go-build", "-v", f"{self.work / 'bin'}:/out",
                    "-e", "GOTOOLCHAIN=local", "-e", "GOFLAGS=-mod=readonly", "-e", "CGO_ENABLED=0", "-w", "/src",
                    self.images["golang"], "go", "test", "-c", "-buildvcs=false", "-trimpath", "-tags", "mgtestfixture",
                    "-o", "/out/mg-e2e-enroll", "./tests/e2e/helpers", timeout=900)
        log(f"build tests/e2e/helpers (go test -c -tags mgtestfixture): {time.time() - t0:.0f} s")

    def teardown(self, *, quiet: bool = False) -> None:
        """Remove every object of this prefix (and only those). Safe to run when nothing exists."""
        if (self.work / "stack.env").exists() and (self.work / "render" / "app" / "compose.app.yaml").exists():
            self.compose("--profile", "tools", "--profile", "migrate", "--profile", "bootstrap", "down", "-v",
                         "--remove-orphans", "--timeout", "10", check=False, timeout=180)
        ids = self.docker("ps", "-aq", "--filter", f"label=com.docker.compose.project={self.prefix}", check=False).stdout.split()
        for extra in ("probe", "caller", "direct", "enroll", "obs-", "pw"):   # pw*: Playwright + bộ chuyển tiếp (P4-T14)
            ids += self.docker("ps", "-aq", "--filter", f"name=^{self.name(extra)}", check=False).stdout.split()
        if ids:
            self.docker("rm", "-f", *ids, check=False)
        for n in (*self.networks, "pw"):                 # pw: mạng riêng của trình duyệt Playwright (P4-T14)
            self.docker("network", "rm", self.name(n), check=False)
        for v in ("edge-data", "idp-db-data", "prometheus-data", "alertmanager-data"):
            self.docker("volume", "rm", "-f", f"{self.prefix}_{v}", check=False)
        if not self.keep_cache:
            self.docker("volume", "rm", "-f", self.name("gomod"), self.name("gocache"), check=False)
        for app in ("api", "worker", "web", "idp", "probe", "node-exporter"):   # images built from the tree (cache kept)
            self.docker("image", "rm", "-f", f"{self.prefix}-{app}:e2e", check=False)
        if self.work.exists():
            self.helper("rm -rf /w/* /w/.[!.]* 2>/dev/null || true", f"{self.work}:/w")
            shutil.rmtree(self.work, ignore_errors=True)
        if not quiet:
            left = [self.docker("ps", "-aq", "--filter", f"name=^{self.prefix}-", check=False).stdout.split(),
                    self.docker("network", "ls", "-q", "--filter", f"name=^{self.prefix}-", check=False).stdout.split(),
                    self.docker("volume", "ls", "-q", "--filter", f"name=^{self.prefix}", check=False).stdout.split()]
            log(f"dọn xong: còn {len(left[0])} container, {len(left[1])} network, {len(left[2])} volume mang tiền tố "
                f"{self.prefix}" + (" (cache Go giữ lại: E2E_KEEP_CACHE=1)" if self.keep_cache and left[2] else ""))


def headscale_lock_key(lock_images: dict, override: str | None = None) -> str:
    """versions.lock entry of the Headscale image: the override if given, else the patched build [images.mg-headscale]
    once it is pinned (P2-T10a), else the official [images.headscale] — switching needs a change to the lock only."""
    key = override or next((k for k in HEADSCALE_LOCK_KEYS if k in lock_images), "")
    if key not in lock_images or not render_instance.IMAGE_RE.match(f"{lock_images[key].get('image')}@{lock_images[key].get('index')}"):
        raise StackError(f"versions.lock: [images.{key or 'headscale'}] thiếu hoặc không pin theo digest")
    return key


def ci_tls(caddyfile: str) -> str:
    """The rendered Caddyfile with its ACME DNS-01 `tls` block replaced by the run's certificate — nothing else."""
    if len(TLS_DNS01.findall(caddyfile)) != 1:
        raise StackError("Caddyfile.tmpl đổi: không tìm thấy đúng một khối tls DNS-01 — cập nhật stack.ci_tls()")
    out = TLS_DNS01.sub("\n\ttls /run/secrets/edge_tls_cert /run/secrets/edge_tls_key\n", caddyfile)
    head = ("# [stack dev/CI P2-T01a] Bản render của tools/render_edge.py; khác duy nhất: khối tls (snippet tls_acme) dùng\n"
            "# chứng chỉ do CA nội bộ dùng-một-lần của lượt chạy ký (thay ACME DNS-01). Không bao giờ dùng ngoài CI.\n")
    return head + out
