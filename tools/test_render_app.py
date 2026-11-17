#!/usr/bin/env python3
"""Unit test of tools/render_app.py (P2-T16): the compose project mg-app, without Docker.

    python tools/test_render_app.py        # exit code 0 = pass. Standard library only.

Checks: the compose renders for a sample environment and is deterministic; every service keeps the hardening (non-root
65532, read-only rootfs, cap_drop ALL, no-new-privileges, CPU/RAM/PID limits, no published port, no Docker socket); the
secret groups are the fixed GIDs of §14.2 per service; no environment variable carries a secret (only *_FILE/*_DIR)
and every *_FILE/*_DIR points at a mounted secret; kek-ops only in the worker; each service declares only the secrets
it uses; the networks of §14.3 (worker's static address on mg-edge = the edge's allow-list, api without one so
`compose run api admin …` works); MG_TRUSTED_PROXIES is exactly the edge's address; the egress deny list covers the
platform pools and the environment's addresses; migrate/db-bootstrap only behind profiles; refusals (image by tag,
one image only, unknown environment, missing deny-list values outside ci); the real staging env file renders.
"""
from __future__ import annotations

import ipaddress
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import mgenv  # noqa: E402
import render_app as ra  # noqa: E402
import render_edge  # noqa: E402

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8")
failures = 0
API = "ghcr.io/zhaduchanhzz/network-access-mesh/api@sha256:" + "ab" * 32
WORKER = "ghcr.io/zhaduchanhzz/network-access-mesh/worker@sha256:" + "cd" * 32
ENV = {"MG_ENV": "staging", "MG_BASE_DOMAIN": "example.com", "MG_LAN_CIDR": "192.0.2.0/24",
       "MG_TUNNEL_HOST_IPV4": "10.248.0.2", "MG_TUNNEL_VPS_IPV4": "10.248.0.1", "MG_PUBLIC_IPV4": "203.0.113.10"}


def check(ok: bool, name: str, detail: str = "") -> None:
    global failures
    print(f"{'PASS' if ok else 'FAIL'} {name}{'' if ok else ': ' + detail}")
    failures += 0 if ok else 1


def raises(fn, name: str) -> None:
    try:
        fn()
    except (ra.ParamError, mgenv.EnvError) as e:
        check(True, f"{name} ({str(e).splitlines()[0][:70]})")
        return
    check(False, name, "no error raised")


files = ra.render(ENV, API, WORKER)
check(sorted(files) == ["compose.app.yaml"], "render writes compose.app.yaml", str(sorted(files)))
check(files == ra.render(ENV, API, WORKER), "output is deterministic")
c = files["compose.app.yaml"]
check("$" not in c, "compose: no placeholder or $ left (docker compose would interpolate it)")
check("name: mg-app" in c and f"image: {API}" in c and f"image: {WORKER}" in c, "compose: project mg-app, images by digest")


def service(name: str) -> str:
    m = re.search(rf"^  {name}:\n(.*?)(?=^  [a-z][a-z-]*:\n|^[a-z]+:)", c, flags=re.M | re.S)
    return m.group(1) if m else ""


def env_of(body: str) -> dict[str, str]:
    """Environment of a service: its own keys plus the anchors it merges."""
    out: dict[str, str] = {}
    blocks = {"x-db": re.search(r"^x-db: &db\n(.*?)^\n", c, re.M | re.S), "x-process": re.search(r"^x-process: &process\n(.*?)^\n", c, re.M | re.S)}
    merged = []
    if "<<: *process" in body:
        merged += ["x-db", "x-process"]
    elif "<<: *db" in body:
        merged += ["x-db"]
    for name in merged:
        for k, v in re.findall(r"^  ([A-Z][A-Z0-9_]+): (\S+)", blocks[name].group(1), re.M):
            out[k] = v
    env_block = re.search(r"^    environment:\n((?:      .*\n)+)", body, re.M)
    for k, v in re.findall(r"^      ([A-Z][A-Z0-9_]+): (\S+)", env_block.group(1) if env_block else "", re.M):
        out[k] = v
    return out


svcs = {s: service(s) for s in ("api", "worker", "migrate", "db-bootstrap")}
check(all(svcs.values()), "compose: api, worker, migrate, db-bootstrap defined", str({k: bool(v) for k, v in svcs.items()}))
hard = re.search(r"^x-hardening: &hardening\n(.*?)^x-db", c, re.M | re.S).group(1)
check(all(s in hard for s in ("read_only: true", "cap_drop: [ALL]", '"no-new-privileges:true"')),
      "compose: read-only rootfs, cap_drop ALL, no-new-privileges in the shared block")
for name, body in svcs.items():
    check(body.startswith("    <<: *hardening\n") and 'user: "65532:65532"' in body and "mem_limit:" in body and
          "cpus:" in body and "pids_limit:" in body, f"compose: {name} hardened, non-root 65532, CPU/RAM/PID limits")
check("ports:" not in c and "docker.sock" not in c and "privileged" not in c and "cap_add" not in c and "network_mode" not in c,
      "compose: no published port, no Docker socket, no privilege")
groups = {n: sorted(re.search(r'group_add: \[(.*?)\]', b).group(1).replace('"', "").split(", ")) for n, b in svcs.items()}
check(groups == {"api": ["20001", "20002"], "worker": ["20001", "20003"], "migrate": ["20004"],
                 "db-bootstrap": ["20004", "20007", "999"]}, "compose: secret groups of §14.2 per service", str(groups))

# secrets: only files, each *_FILE/*_DIR is mounted, nothing secret in the environment
for name, body in svcs.items():
    e = env_of(body)
    bad = [k for k in e if re.search(r"PASSWORD|SECRET|TOKEN|KEK|_KEY", k) and not k.endswith(("_FILE", "_DIR"))]
    check(not bad, f"compose: {name}: no secret value in the environment", str(bad))
    targets = set(re.findall(r"target: (\S+)\}", body)) | set(re.findall(r"^      target: (\S+)", body, re.M))
    mounts = {"/run/secrets/" + t for t in re.findall(r"\{source: \S+, target: (\S+)\}", body)}
    mounts |= set(re.findall(r"^\s+target: (/run/\S+)", body, re.M))
    if "*keyring-app" in body:
        mounts.add("/run/secrets/kek-app")
    if "*migrate-dir" in body:
        mounts.add("/run/mg-migrate")
    unmounted = [f"{k}={v}" for k, v in e.items() if k.endswith(("_FILE", "_DIR"))
                 and not any(v == m or v.startswith(m + "/") for m in mounts)]
    check(not unmounted, f"compose: {name}: every *_FILE/*_DIR is a mounted secret", str(unmounted))
check("kek-ops" in svcs["worker"] and all("kek-ops" not in svcs[s] for s in ("api", "migrate", "db-bootstrap")),
      "compose: keyring kek-ops mounted in the worker only (§7.6)")
check("*keyring-app" in svcs["api"] and "*keyring-app" in svcs["worker"] and "kek" not in svcs["migrate"] + svcs["db-bootstrap"],
      "compose: keyring kek-app in api and worker only")
check(all("pg_superuser_password" not in svcs[s] and "SUPERUSER" not in svcs[s] for s in ("api", "worker", "migrate")) and
      "app_pg_superuser_password" in svcs["db-bootstrap"], "compose: the superuser password only in db-bootstrap")
check("partition" in svcs["worker"] and "partition" not in svcs["api"] and "audit_writer" in svcs["api"] and
      "audit_writer" not in svcs["worker"], "compose: partition role in the worker, audit writer in the api only")
check(all(f"source: {s}," in c for s in re.findall(r"^  (app_[a-z_]+): \{file: /opt/meshguard/secrets/", c, re.M)) and
      len(re.findall(r"^  app_[a-z_]+: \{file: /opt/meshguard/secrets/[a-z]+/[a-z_]+\}$", c, re.M)) == 9,
      "compose: 9 file secrets under /opt/meshguard/secrets, each used by a service")
for path in re.findall(r"source: (/opt/meshguard/secrets/\S+)", c):
    check(path in ("/opt/meshguard/secrets/kek-app", "/opt/meshguard/secrets/kek-ops", "/opt/meshguard/secrets/migrate"),
          f"compose: bind mount {path} is a keyring or the migrate job's directory")
check(c.count("create_host_path: false") == 3 and c.count("read_only: true\n  bind:") + c.count("read_only: true\n        bind:") == 3,
      "compose: directory mounts read-only, never created on the host")

# configuration values
api, worker = env_of(svcs["api"]), env_of(svcs["worker"])
edge = render_edge.EDGE_IPS["edge_ip"]
check(api.get("MG_TRUSTED_PROXIES") == edge and "MG_TRUSTED_PROXIES" not in worker,
      "compose: MG_TRUSTED_PROXIES is exactly the edge's address (G2)", api.get("MG_TRUSTED_PROXIES", ""))
check(api["MG_DB_TENANT_USER"] == "mg_api_tenant" and api["MG_DB_PLATFORM_USER"] == "mg_api_platform" and
      worker["MG_DB_TENANT_USER"] == "mg_worker_tenant" and worker["MG_DB_PLATFORM_USER"] == "mg_worker_platform",
      "compose: each process logs in with its own roles (§6.1)")
check(api["MG_ENV"] == "staging" and api["MG_BASE_DOMAIN"] == "example.com" and api["MG_DB_URL"].startswith("postgres://postgres:5432/")
      and "@" not in api["MG_DB_URL"], "compose: environment, domain, DB URL without credentials")
check(api["MG_EDGE_ADMIN_URL"] == f"http://{render_edge.EDGE_IPS['edge_admin_ip']}:{render_edge.INTERNAL['admin_port']}"
      and api["MG_IDP_PLATFORM_ADDR"] == f"{edge}:443", "compose: edge admin listener and IdP route from the edge's constants")
deny = [ipaddress.ip_network(x) for x in api["MG_EGRESS_DENY_CIDRS"].split(",")]
want = [ipaddress.ip_network(x) for x in (ra.DOCKER_POOL, "10.249.0.0/16", "10.250.0.0/16", "192.0.2.0/24", "10.248.0.2",
                                          "10.248.0.1", "203.0.113.10")]
check(deny == want and worker["MG_EGRESS_DENY_CIDRS"] == api["MG_EGRESS_DENY_CIDRS"],
      "compose: egress deny = Docker pool, platform + tenant pools, LAN, tunnel, public entry", str(deny))
check(re.search(r"mg-edge:\n        ipv4_address: " + re.escape(render_edge.APP_IPS["worker_edge_ip"]), svcs["worker"]) is not None
      and "ipv4_address" not in svcs["api"], "compose: worker static on mg-edge (the edge's Admin-API allow-list), api not")
check(all(re.search(rf"^      {n}:", svcs[s], re.M) for s in ("api", "worker") for n in ("mg-edge", "mg-data", "mg-admin", "mg-obs", "mg-egress"))
      and svcs["migrate"].count("networks: [mg-data]") == 1 and svcs["db-bootstrap"].count("networks: [mg-data]") == 1,
      "compose: networks of §14.3 (jobs on mg-data only)")
check(all("gw_priority: 1" in svcs[s].split("mg-egress:", 1)[1][:60] for s in ("api", "worker")),
      "compose: default route of api/worker on mg-egress")
check("profiles: [migrate]" in svcs["migrate"] and "profiles: [bootstrap]" in svcs["db-bootstrap"] and
      "profiles" not in svcs["api"] + svcs["worker"], "compose: one-shot jobs only behind profiles")
check('command: ["migrate", "up"]' in svcs["migrate"] and 'command: ["migrate", "bootstrap"]' in svcs["db-bootstrap"],
      "compose: migrate up / migrate bootstrap")
check(all('test: ["CMD", "/usr/local/bin/meshguard", "healthcheck"]' in svcs[s] for s in ("api", "worker")),
      "compose: healthcheck = /readyz of the process")
check("pre-migration" in c and "migrate.sh" in c, "compose: documents the pre-migration backup of the migrate step")

# refusals
raises(lambda: ra.render(ENV, "ghcr.io/x/api:latest", WORKER), "image by tag is refused")
raises(lambda: ra.render({**ENV, "MG_ENV": "dev"}, API, WORKER), "MG_ENV dev is refused (deployments only)")
raises(lambda: ra.render({**ENV, "MG_BASE_DOMAIN": "Example.COM"}, API, WORKER), "invalid domain is refused")
noentry = {k: v for k, v in ENV.items() if k != "MG_PUBLIC_IPV4"}
raises(lambda: ra.render(noentry, API, WORKER), "staging without MG_PUBLIC_IPV4 is refused (deny list)")
raises(lambda: ra.render({**ENV, "MG_LAN_CIDR": "192.0.2.1/24"}, API, WORKER), "a CIDR with host bits is refused")
ci = ra.render({"MG_ENV": "ci", "MG_BASE_DOMAIN": "meshguard-ci.test"}, "sha256:" + "0" * 64, "sha256:" + "1" * 64)
check("MG_ENV: ci" in ci["compose.app.yaml"], "ci stack: local image IDs, no LAN/tunnel/public values needed")
_stdout, sys.stdout = sys.stdout, open(__import__("os").devnull, "w", encoding="utf-8")   # main prints the usage
try:
    usage_rc = ra.main(["render_app.py", "x.env", "out", "--api-image", API])
finally:
    sys.stdout.close()
    sys.stdout = _stdout
check(usage_rc == 2, "one image without the other is a usage error")

# the real staging env file
staging = mgenv.environment(ra.ROOT / "infrastructure" / "environments" / "staging" / "staging.env")
try:
    s = ra.render(staging, API, WORKER)["compose.app.yaml"]
    check(f"MG_BASE_DOMAIN: {staging['MG_BASE_DOMAIN']}" in s and staging["MG_PUBLIC_IPV4"] in s,
          "staging.env renders mg-app with its domain and public entry in the deny list")
except ra.ParamError as e:
    check(False, "staging.env renders mg-app", str(e))
try:
    ra.pinned_images()
    check(True, "versions.lock pins api and worker of the same commit")
except ra.ParamError as e:
    print(f"INFO versions.lock: {e} (pinned after the `images` workflow — P2-T16 runbook)")
sys.exit(1 if failures else 0)
