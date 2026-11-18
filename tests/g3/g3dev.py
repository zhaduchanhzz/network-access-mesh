"""Dev/CI rehearsal of the G3 tool (P3-T14) — FUNCTIONAL only (§22.1, HS-24: clients, Headscale and edge on one Docker
host). The stack of `make e2e-functional` (tests/e2e/harness, `e2e.py up`) has no Host Agent, so its worker runs without
the orchestrator; `dev-up` adds what staging has on top of it, the way staging is wired:

  - the platform IdP registered and the worker's keycloak driver bootstrapped (the harness's own E2E-20/E2E-21 steps:
    idp-bootstrap, register-platform-idp, client secret of the platform realm), two Super Admins (bootstrap-super-admin;
    the tool's credential file, 0600, in the run's work directory — dev only);
  - the Host Agent built from the tree, run like compose mg-agent (network none, rootfs read-only, cap_drop ALL +
    CHOWN/FOWNER/DAC_OVERRIDE, socket 0660 group 20003, peer UID 65532) under a host root <G3DEV_ROOT> (tenants/,
    backups/tenants/, run/, cfg/ — never /opt/meshguard), edge = the stack's edge, tenant pool G3DEV_POOL, run_uid
    G3DEV_RUN_UIDS, public entry = the edge's address; a test key ceremony (manifest signing key + age recovery
    recipient) for the final backup of the deprovision;
  - a `hosts` row with that pool/range/entry (as the provisioning harness of P3-T07 inserts it);
  - the worker recreated with the orchestrator: MG_AGENT_*, MG_PROVISION_*, MG_PROBER_URL, MG_BACKUP_MANIFEST_PUBKEY
    (a compose override next to the harness's files — render_app gives none of these on the ci stack);
  - target.json for g3.py (connect = edge address, the run's CA, client containers on the edge network).

`dev-down` removes all of it (agent, tenant containers/networks mg-*-<prefix>-*, root, volumes, image) then the stack.
Parameters (environment): E2E_PREFIX (g3drv), MG_E2E_NET_BASE, MG_E2E_TENANT_NET, DOCKER, E2E_WORK — as the harness;
G3DEV_POOL (10.250.219.0/24), G3DEV_RUN_UIDS (39400-39499), G3DEV_ROOT (/tmp/<prefix>-root).
"""
from __future__ import annotations

import ipaddress
import json
import os
import pathlib
import secrets
import subprocess
import sys
import time

from g3target import ROOT, G3Error

HARNESS = ROOT / "tests" / "e2e" / "harness"
sys.path.insert(0, str(HARNESS))
import backend  # noqa: E402
import checks  # noqa: E402
import render_app  # noqa: E402
import stack  # noqa: E402
from stack import Stack, log  # noqa: E402

WORKER_UID, WORKER_GID = 65532, 20003


class G3Stack(Stack):
    """The harness's stack + the compose override of the G3 rehearsal (worker with the orchestrator)."""

    def override(self) -> pathlib.Path:
        return self.work / "render" / "g3" / "compose.g3.yaml"

    def compose_files(self) -> list[str]:
        files = super().compose_files()
        return files + (["-f", str(self.override())] if self.override().exists() else [])


def params() -> dict:
    prefix = os.environ.get("E2E_PREFIX", "g3drv")
    p = {"pool": os.environ.get("G3DEV_POOL", "10.250.219.0/24"), "uids": os.environ.get("G3DEV_RUN_UIDS", "39400-39499"),
         "root": pathlib.Path(os.environ.get("G3DEV_ROOT", f"/tmp/{prefix}-root"))}
    pool = ipaddress.ip_network(p["pool"])
    taken = [ipaddress.ip_network(n) for n in ("10.250.0.0/24", "10.250.240.0/20", "10.250.224.0/24")] + \
            [ipaddress.ip_network(f"10.250.{i}.0/24") for i in range(230, 240)]
    if not pool.subnet_of(ipaddress.ip_network("10.250.0.0/16")) or any(pool.overlaps(n) for n in taken):
        raise G3Error("G3DEV_POOL: trong 10.250.0.0/16, ngoài staging, e2e 10.250.23x, agent-it 10.250.240.0/20, P3-T07 10.250.224.0/24")
    lo, hi = (int(x) for x in p["uids"].split("-"))
    if not 1000 <= lo < hi or WORKER_UID in range(lo, hi + 1):
        raise G3Error("G3DEV_RUN_UIDS: lo-hi, không chứa 65532")
    if not str(p["root"]).startswith("/tmp/"):
        raise G3Error("G3DEV_ROOT phải nằm dưới /tmp (không bao giờ /opt/meshguard)")
    return p


def check_free(st: Stack, cidrs: list[str]) -> None:
    mine = [ipaddress.ip_network(c) for c in cidrs]
    ids = st.docker("network", "ls", "-q").stdout.split()
    for line in st.docker("network", "inspect", "-f", "{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{end}}", *ids).stdout.splitlines():
        name, *subs = line.split()
        for s in subs:
            try:
                n = ipaddress.ip_network(s)
            except ValueError:
                continue
            if n.version == 4 and any(n.overlaps(m) for m in mine) and not name.startswith(st.prefix + "-"):
                raise G3Error(f"network {name} {s} chồng dải của lượt chạy {cidrs}")


def psql(st: Stack, sql: str) -> str:
    return st.exec("postgres", "psql", "-U", "postgres", "-d", "meshguard", "-tA", "-v", "ON_ERROR_STOP=1", "-c", sql).stdout.strip()


def up() -> pathlib.Path:
    """The stack (e2e.py up) + the G3 additions; returns the target.json for g3.py."""
    os.environ.setdefault("E2E_PREFIX", "g3drv")
    p = params()
    st = G3Stack()
    check_free(st, [p["pool"]])
    log(f"G3 dev: dựng stack {st.prefix} (e2e.py up — build image từ cây, ~10–15 phút)")
    r = subprocess.run([sys.executable, str(HARNESS / "e2e.py"), "up"], timeout=3600)
    if r.returncode != 0:
        raise G3Error(f"e2e.py up exit {r.returncode}")
    st = G3Stack()
    res = checks.Results(st)

    # --- platform IdP + keycloak driver of the worker (E2E-20 + the platform part of E2E-21)
    backend.check_idp_bootstrap(res, st)
    pr = backend.admin_cmd(st, ["register-platform-idp"], env={"MG_IDP_ID_PLATFORM": st.env["MG_IDP_ID_PLATFORM"]})
    secret = backend.client_secret_via_script(st, "platform")
    st.secret_values.add(secret)
    sr = backend.admin_cmd(st, ["set-idp-client-secret", st.env["MG_IDP_ID_PLATFORM"]], stdin=secret + "\n")
    if pr.returncode or sr.returncode or res.failed:
        raise G3Error(f"IdP nền tảng: register {pr.returncode}, client secret {sr.returncode}, {res.rows[-1:]}")

    # --- two Super Admins, TOTP enrolled at their first login (the raw secret Keycloak's form carries)
    sas = []
    for i in (1, 2):
        kc = backend.KeycloakAdmin(st)
        u = {"username": f"g3-sa{i}-" + secrets.token_hex(3), "password": secrets.token_urlsafe(18)}
        st.secret_values.add(u["password"])
        sub = kc.create_user("platform", u["username"], u["password"])
        b = backend.admin_cmd(st, ["bootstrap-super-admin", "--subject", sub, "--display-name", f"G3 SA{i}"],
                              env={"MG_IDP_ID_PLATFORM": st.env["MG_IDP_ID_PLATFORM"]})
        if b.returncode:
            raise G3Error(f"bootstrap-super-admin {i}: {st.redact(b.stdout + b.stderr)[-300:]}")
        otp = backend.TOTP()
        backend.portal_login(st, backend.Browser(st), f"admin.{st.domain}", "scope=platform", u, otp)
        sas.append({**u, "totp_raw": otp.key.decode()})
        time.sleep(31)                      # the next login must not reuse this 30 s TOTP window
    g3dir = st.work / "g3"
    g3dir.mkdir(mode=0o700, exist_ok=True)
    creds = g3dir / "creds.json"
    creds.write_text(json.dumps({"super_admins": sas}), encoding="utf-8")
    os.chmod(creds, 0o600)

    # --- hostside binary (keygen now; orphans/enrollment later from g3.py) and the test key ceremony
    import g3host  # noqa: PLC0415
    from g3target import Target  # noqa: PLC0415
    t = Target(stack.ENV_DIR / "ci.env", {"host_docker": " ".join(st.docker_cmd), "resource_prefix": st.prefix,
                                          "connect": st.edge_ip})
    binary = g3host.build_hostside(t, st.work / "bin")
    keys = st.work / "g3" / "keys"
    st.helper("rm -rf /w/g3/keys; mkdir -p /w/g3/keys; chown 65532:65532 /w/g3/keys; chmod 0700 /w/g3/keys", f"{st.work}:/w")
    st.docker("run", "--rm", "--network", "none", "--user", "65532:65532", "-v", f"{binary}:/b/g3-hostside:ro",
              "-v", f"{keys}:/keys", "-e", "MG_G3_PHASE=keygen", "-e", "MG_G3_KEYGEN_OUT=/keys", st.images["alpine"],
              "/b/g3-hostside", "-test.run", "^TestG3HostSide$", "-test.count=1")
    pub = st.helper("cat /w/g3/keys/manifest_pubkey", f"{st.work}:/w").stdout.strip()
    rec = st.helper("cat /w/g3/keys/recovery_recipient", f"{st.work}:/w").stdout.strip()

    # --- host root of the agent (same path inside and outside its container)
    root = p["root"]
    token = "".join(secrets.choice(stack.ALNUM) for _ in range(40))
    st.secret_values.add(token)
    st.docker("run", "--rm", "--network", "none", "-v", "/tmp:/hosttmp", st.images["alpine"], "sh", "-ec",
              f"rm -rf /hosttmp/{root.name}; mkdir -p /hosttmp/{root.name}")
    st.docker("run", "--rm", "-i", "--network", "none", "-v", f"{root}:{root}", "-v", f"{keys}:/keys:ro",
              st.images["alpine"], "sh", "-ec",
              f"cd {root}; install -d -o 0 -g 0 -m 0755 tenants cfg; install -d -o 0 -g 0 -m 0700 backups backups/tenants; "
              f"install -d -o 0 -g {WORKER_GID} -m 0750 run; umask 077; cat > cfg/agent_token; "
              f"chown 0:{WORKER_GID} cfg/agent_token; chmod 0440 cfg/agent_token; "
              f"install -o 0 -g 0 -m 0400 /keys/manifest_signing_key cfg/manifest_signing_key; "
              f"printf '%s\\n' '{st.images['headscale']}' > cfg/allowlist; chmod 0644 cfg/allowlist", input=token)
    st.helper("rm -f /w/g3/keys/manifest_signing_key", f"{st.work}:/w")

    # --- Host Agent from the tree
    image = f"{st.prefix}-agent:dev"
    st.docker("build", "-q", "-f", str(ROOT / "infrastructure" / "docker" / "agent" / "Dockerfile"), "--build-arg", "VERSION=g3dev",
              "--build-arg", "COMMIT=dev", "--label", "meshguard.role=g3", "-t", image, str(ROOT), timeout=1800)
    helper_image = st.docker("image", "inspect", "-f", "{{.Id}}", image).stdout.strip()
    st.docker("rm", "-f", st.name("agent"), check=False)
    env = {"MG_ENV": "ci", "MG_LOG_LEVEL": "info", "MG_BASE_DOMAIN": st.domain, "MG_AGENT_DRIVER": "compose",
           "MG_AGENT_SOCKET": f"{root}/run/agent.sock", "MG_AGENT_SOCKET_GID": str(WORKER_GID),
           "MG_AGENT_PEER_UIDS": str(WORKER_UID), "MG_AGENT_TOKEN_FILE": f"{root}/cfg/agent_token",
           "MG_AGENT_IMAGE_ALLOWLIST_FILE": f"{root}/cfg/allowlist", "MG_AGENT_TENANTS_DIR": f"{root}/tenants",
           "MG_AGENT_BACKUPS_DIR": f"{root}/backups/tenants", "MG_AGENT_RUN_UID_RANGE": p["uids"],
           "MG_AGENT_TENANT_NET_POOL": p["pool"], "MG_AGENT_PUBLIC_ENTRY_IPV4": st.edge_ip,
           "MG_AGENT_EDGE_CONTAINER": st.name("edge"), "MG_AGENT_EDGE_NETWORK": st.name("edge"),
           "MG_AGENT_EDGE_SUPERVISOR_INTERVAL": "5s", "MG_AGENT_HELPER_IMAGE": helper_image,
           "MG_AGENT_COMPOSE_BIN": "/usr/local/bin/docker-compose",
           "MG_AGENT_MANIFEST_SIGNING_KEY_FILE": f"{root}/cfg/manifest_signing_key",
           "MG_AGENT_BACKUP_RECOVERY_RECIPIENT": rec, "MG_BACKUP_MANIFEST_PUBKEY": pub,
           "DOCKER_HOST": "unix:///var/run/docker.sock", "DOCKER_CONFIG": "/tmp/docker"}
    st.docker("run", "-d", "--name", st.name("agent"), "--label", "meshguard.role=g3", "--network", "none", "--read-only",
              "--tmpfs", "/tmp:size=16m,mode=1777", "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "FOWNER",
              "--cap-add", "DAC_OVERRIDE", "--security-opt", "no-new-privileges", "--user", "0:0", "--pids-limit", "256",
              "--memory", "512m", "-v", "/var/run/docker.sock:/var/run/docker.sock", "-v", f"{root}:{root}",
              *[x for k, v in env.items() for x in ("-e", f"{k}={v}")], image)
    if not checks.wait(lambda: st.docker("exec", st.name("agent"), "/usr/local/bin/meshguard-agent", "healthcheck",
                                         check=False).returncode == 0, 60):
        logs = st.docker("logs", "--tail", "40", st.name("agent"), check=False)
        raise G3Error("agent không healthy:\n" + st.redact(logs.stdout + logs.stderr)[-1500:])
    log(f"Host Agent {st.name('agent')} ({image}) — pool {p['pool']}, run_uid {p['uids']}, edge {st.name('edge')}")

    # --- the host of the placement + quota of a rehearsal
    lo, hi = p["uids"].split("-")
    psql(st, "INSERT INTO hosts (id, name, region, run_uid_range, tenant_net_pool, public_entry) VALUES "
             f"(gen_random_uuid(), 'g3-dev-host', 'lab', int4range({lo}, {hi}, '[]'), '{p['pool']}'::cidr, "
             f"jsonb_build_object('ipv4', '{st.edge_ip}', 'mode', 'direct')) ON CONFLICT DO NOTHING")
    psql(st, "UPDATE system_settings SET value = '50' WHERE key = 'quota.max_tenants'")

    # --- worker with the orchestrator (compose override)
    digest, version = render_app.headscale_runtime()
    ov = st.override()
    ov.parent.mkdir(parents=True, exist_ok=True)
    ov.write_text("\n".join([
        "# G3 rehearsal (tests/g3/g3dev.py): the worker of the dev stack with the Host Agent and the orchestrator",
        "services:", "  worker:", "    environment:",
        "      MG_AGENT_SOCKET: /run/meshguard/agent.sock", "      MG_AGENT_TOKEN_FILE: /run/secrets/agent_token",
        f"      MG_PROVISION_HEADSCALE_DIGEST: \"{digest}\"", f"      MG_PROVISION_HEADSCALE_VERSION: \"{version}\"",
        f"      MG_PROVISION_NAMESERVERS: \"{st.env['MG_TENANT_NAMESERVERS']}\"",
        "      MG_PROVISION_DNS_CHECK: skip                 # bước 4: stack dev/ci không có DNS công khai",
        f"      MG_PROVISION_EDGE_ADDR: \"{st.edge_ip}:443\"", f"      MG_PROBER_URL: \"http://{st.prober_admin_ip}:8080\"",
        f"      MG_BACKUP_MANIFEST_PUBKEY: \"{pub}\"",
        "    secrets:", "      - {source: g3_agent_token, target: agent_token}",
        "    volumes:", f"      - {{type: bind, source: {root}/run, target: /run/meshguard, read_only: true}}",
        "secrets:", f"  g3_agent_token: {{file: {root}/cfg/agent_token}}", ""]), encoding="utf-8")
    st.compose("up", "-d", "--wait", "--wait-timeout", "240", "worker", timeout=300)
    wl = st.docker("logs", "--since", "2m", backend.container(st, "worker"), check=False)
    log("worker tạo lại: " + ("orchestrator OK" if "tenant orchestrator configured" in wl.stdout + wl.stderr else "KHÔNG thấy orchestrator"))

    target = {"connect": st.edge_ip, "ca_file": str(st.work / "ca" / "ca.crt"), "host_docker": " ".join(st.docker_cmd),
              "client_docker": " ".join(st.docker_cmd), "app_project": st.prefix, "agent_container": st.name("agent"),
              "prober_container": st.name("prober"), "admin_network": st.name("admin"), "edge_container": st.name("edge"),
              "edge_network": st.name("edge"), "tenants_dir": f"{root}/tenants",
              "backup_password_file": str(st.work / "secrets" / "appboot" / "pg_backup_password"),
              "client_network": st.name("edge"), "client_add_host": st.edge_ip, "client_ca_dir": str(st.work / "ca"),
              "resource_prefix": st.prefix}
    tf = g3dir / "target.json"
    tf.write_text(json.dumps(target, indent=2), encoding="utf-8")
    log(f"G3 dev sẵn sàng: --env {stack.ENV_DIR / 'ci.env'} --target {tf} --creds {creds} --hostside-bin {binary}")
    return tf


def down() -> None:
    os.environ.setdefault("E2E_PREFIX", "g3drv")
    p = params()
    st = G3Stack()
    pre = st.prefix
    names = st.docker("ps", "-a", "--format", "{{.Names}}").stdout.split()
    mine = [n for n in names if n.startswith((f"mg-hs-{pre}-", f"mg-helper-{pre}-", f"{pre}-agent", f"{pre}-client-",
                                               f"{pre}-hostside-", f"{pre}-probe-"))]
    if mine:
        st.docker("rm", "-f", *mine, check=False)
    st.docker("run", "--rm", "--network", "none", "-v", "/tmp:/hosttmp", st.images["alpine"], "sh", "-c",
              f"rm -rf /hosttmp/{p['root'].name}", check=False)
    for v in (st.name("bin"), st.name("enroll")):
        st.docker("volume", "rm", "-f", v, check=False)
    os.environ["E2E_KEEP_CACHE"] = "0"
    subprocess.run([sys.executable, str(HARNESS / "e2e.py"), "down"], timeout=1800, check=False)
    nets = [n for n in st.docker("network", "ls", "--format", "{{.Name}}").stdout.split() if n.startswith(f"mg-t-{pre}-")]
    if nets:
        st.docker("network", "rm", *nets, check=False)
    st.docker("image", "rm", "-f", f"{pre}-agent:dev", check=False)
    if st.out.parent == pathlib.Path("/tmp"):           # results of `e2e.py up` the harness keeps (<work>-out)
        st.docker("run", "--rm", "--network", "none", "-v", "/tmp:/hosttmp", st.images["alpine"], "rm", "-rf",
                  f"/hosttmp/{st.out.name}", f"/hosttmp/{st.work.name}.lock", check=False)
    st.docker("volume", "rm", "-f", st.name("gomod"), st.name("gocache"), check=False)
    left = [x for x in st.docker("ps", "-a", "--format", "{{.Names}}").stdout.split() if pre in x] + \
           [x for x in st.docker("network", "ls", "--format", "{{.Name}}").stdout.split() if pre in x] + \
           [x for x in st.docker("volume", "ls", "--format", "{{.Name}}").stdout.split() if pre in x] + \
           [x for x in st.docker("image", "ls", "--format", "{{.Repository}}").stdout.split() if pre in x]
    log(f"G3 dev down: còn {len(left)} đối tượng Docker mang '{pre}'" + (f": {left}" if left else ""))
