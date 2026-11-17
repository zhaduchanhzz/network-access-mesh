#!/usr/bin/env python3
"""Unit test of tools/render_agent.py (P3-T02): compose project mg-agent and the image allowlist, without Docker.

    python tools/test_render_agent.py        # exit code 0 = pass. Standard library only.

Checks: deterministic render; the agent's hardening of §14.4 (root but cap_drop ALL + exactly CHOWN, FOWNER,
DAC_OVERRIDE; network_mode none; read-only rootfs with a tmpfs for DOCKER_CONFIG; no-new-privileges; PID/RAM/CPU
limits; no published port); the Docker socket, tenants/ and backups/tenants/ mounted at the SAME path, run/ at
/run/meshguard, the allowlist read-only, the token as a file secret (never in the environment); every value from
versions.lock [ids] (worker UID/GID, run_uid range, tenant pool) and the env file (domain, public entry); the allowlist
is exactly the two Headscale images of versions.lock in the format of agentspec.ParseAllowlist; refusals (image by
tag, unknown environment, public entry in the tenant pool, missing domain, unpinned image); the real staging env file
renders.
"""
from __future__ import annotations

import pathlib
import re
import sys
import tomllib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import mgenv  # noqa: E402
import render_agent as ra  # noqa: E402

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8")
failures = 0
IMAGE = "ghcr.io/zhaduchanhzz/network-access-mesh/agent@sha256:" + "ab" * 32
ENV = {"MG_ENV": "staging", "MG_BASE_DOMAIN": "example.com", "MG_PUBLIC_IPV4": "203.0.113.10"}
LOCK = tomllib.loads(ra.VERSIONS.read_text(encoding="utf-8"))


def check(ok: bool, name: str, detail: str = "") -> None:
    global failures
    print(f"{'PASS' if ok else 'FAIL'} {name}{'' if ok else ': ' + detail}")
    failures += 0 if ok else 1


def main() -> int:
    files = ra.render(ENV, IMAGE)
    again = ra.render(dict(ENV), IMAGE)
    check(files == again, "deterministic")
    c = files["compose.agent.yaml"]
    check("$" not in c.replace("${", "") and "${" not in c, "no placeholder left, no interpolation")
    lines = c.splitlines()
    services = [ln for ln in lines if re.match(r"^  [a-z]", ln) and lines.index(ln) > lines.index("services:")
                and lines.index(ln) < lines.index("secrets:")]
    check(services == ["  agent:"], "one service, agent", str(services))
    for want in ("    user: \"0:0\"", "    network_mode: none", "    read_only: true", "    cap_drop: [ALL]",
                 "    cap_add: [CHOWN, FOWNER, DAC_OVERRIDE]", "    security_opt: [\"no-new-privileges:true\"]",
                 "    pids_limit: 256", "    mem_limit: 512m", "    cpus: 1.0", "      - /tmp:size=16m,mode=1777",
                 f"    image: {IMAGE}", "      MG_AGENT_DRIVER: compose", "      DOCKER_HOST: unix:///var/run/docker.sock",
                 "      DOCKER_CONFIG: /tmp/docker", "      MG_AGENT_TOKEN_FILE: /run/secrets/agent_token",
                 f"      MG_AGENT_HELPER_IMAGE: {IMAGE}", "      MG_AGENT_EDGE_NETWORK: mg-edge",
                 "    file: /opt/meshguard/secrets/worker/agent_token", "name: mg-agent", "    restart: unless-stopped"):
        check(want in lines, f"hardening/line: {want.strip()}")
    for bad in ("ports:", "expose:", "privileged", "network_mode: host", "pid:", "ipc:", "devices:", "env_file", "SYS_ADMIN",
                "NET_ADMIN", "NET_RAW"):
        check(bad not in c, f"absent: {bad}")
    mounts = re.findall(r"source: (/\S+)\n\s+target: (\S+)", c)
    want_mounts = [("/var/run/docker.sock", "/var/run/docker.sock"), ("/opt/meshguard/tenants", "/opt/meshguard/tenants"),
                   ("/opt/meshguard/backups/tenants", "/opt/meshguard/backups/tenants"), ("/opt/meshguard/run", "/run/meshguard"),
                   ("/opt/meshguard/core/agent/allowlist", "/etc/meshguard/agent/allowlist")]
    check(mounts == want_mounts, "mounts: Docker socket, tenants/ and backups/tenants/ at the same path, run/, allowlist", str(mounts))
    check(c.count("read_only: true") == 2 and "target: /etc/meshguard/agent/allowlist\n        read_only: true" in c,
          "rootfs and allowlist read-only")
    check(c.count("create_host_path: false") == 4, "no host path created by compose")
    env_vars = re.findall(r"^      ([A-Z_]+): ", c, re.M)
    check(not [v for v in env_vars if re.search(r"(PASSWORD|TOKEN$|SECRET|_KEY$)", v)], "no secret in the environment", str(env_vars))
    ids = LOCK["ids"]
    for k, v in (("MG_AGENT_SOCKET_GID", f"\"{ids['mg-sec-worker']}\""), ("MG_AGENT_PEER_UIDS", f"\"{ids['api_worker_uid']}\""),
                 ("MG_AGENT_RUN_UID_RANGE", ids["tenant_run_uid_range"]), ("MG_AGENT_TENANT_NET_POOL", ids["tenant_net_pool"]),
                 ("MG_AGENT_PUBLIC_ENTRY_IPV4", "203.0.113.10"), ("MG_BASE_DOMAIN", "example.com"), ("MG_ENV", "staging")):
        check(f"      {k}: {v}" in lines, f"{k} = {v}")
    allow = files["agent/allowlist"]
    entries = [ln.split("#")[0].strip() for ln in allow.splitlines() if ln.split("#")[0].strip()]
    want = [f"{LOCK['images'][n]['image']}@{LOCK['images'][n]['index']}" for n in ra.TENANT_IMAGES]
    check(entries == want, "allowlist = [images.mg-headscale] + [images.headscale] of versions.lock", str(entries))
    check(all(re.fullmatch(r"[a-z0-9./_:-]+@sha256:[0-9a-f]{64}", e) for e in entries), "allowlist format of agentspec.ParseAllowlist")
    check(len(set(e.split("@")[1] for e in entries)) == len(entries), "allowlist: distinct digests")
    # refusals
    bad = {
        "image by tag": (ENV, "ghcr.io/x/agent:latest"),
        "unknown environment": ({**ENV, "MG_ENV": "prod"}, IMAGE),
        "public entry in the tenant pool": ({**ENV, "MG_PUBLIC_IPV4": "10.250.3.4"}, IMAGE),
        "public entry not IPv4": ({**ENV, "MG_PUBLIC_IPV4": "2001:db8::1"}, IMAGE),
        "public entry loopback": ({**ENV, "MG_PUBLIC_IPV4": "127.0.0.1"}, IMAGE),
        "missing domain": ({k: v for k, v in ENV.items() if k != "MG_BASE_DOMAIN"}, IMAGE),
    }
    for name, (env, image) in bad.items():
        try:
            ra.render(env, image)
            check(False, f"refused: {name}", "accepted")
        except ra.ParamError:
            check(True, f"refused: {name}")
    unpinned = {**LOCK, "images": {**LOCK["images"], "headscale": {**LOCK["images"]["headscale"], "index": ""}}}
    try:
        ra.render(ENV, IMAGE, unpinned)
        check(False, "refused: unpinned headscale image", "accepted")
    except ra.ParamError:
        check(True, "refused: unpinned headscale image")
    # the real staging env file renders (its public entry and domain)
    staging = ra.ROOT / "infrastructure" / "environments" / "staging" / "staging.env"
    real = ra.render(mgenv.environment(staging), IMAGE)
    check("MG_AGENT_PUBLIC_ENTRY_IPV4:" in real["compose.agent.yaml"], "staging env file renders")
    print(f"{'FAIL' if failures else 'PASS'} test_render_agent: {failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
