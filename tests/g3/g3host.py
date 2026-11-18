"""Host-side operations of the G3 tool (P3-T14) on the platform host, all through `docker` (local or over SSH — paths
are paths OF THAT HOST):

  build_hostside   tests/g3/hostside → static test binary (go test -c -tags mgtestfixture) in [images.golang]
  install          the binary into a Docker volume <prefix>-bin of the platform host (works over SSH too)
  hostside         runs it with the WORKER'S IDENTITY: worker image + environment + mounts (--volumes-from, read-only)
                   + network namespace + UID/groups; phases orphans / enroll-issue / enroll-verify / enroll-cleanup
  edge_check       `meshguard-probe call edge` in a throwaway container of the prober's image on the admin network —
                   exactly the RPC the worker's step 18 (edge.verify) makes: /key 200 with the instance's own key, every
                   forbidden path 404 (allow-list of §14.6)
  instance_health  Docker health of mg-hs-<slug>
  policy_apply     `meshguard admin policy-apply` in the running worker (the policy core, P3-T08a), policy on stdin
Standard library only; nothing secret is printed (the binary only emits public identifiers).
"""
from __future__ import annotations

import json
import pathlib
import time

from g3target import ROOT, G3Error, Target

MARKER = "G3JSON "
WORKER_GROUPS = ("20001", "20003")       # mg-sec-app, mg-sec-worker (compose.app.yaml.tmpl)
BACKUP_GROUP = "20007"                   # mg-sec-backup: the mg_backup password file (layout.sh)


def build_hostside(t: Target, out_dir: pathlib.Path, docker: list[str] | None = None) -> pathlib.Path:
    """Compile the binary in the pinned Go image on the machine of `docker` (default: the platform host's Docker must
    see this repository — use a local Docker, e.g. on the build VM, when the platform host is remote)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    d = docker or t.host_docker
    vols = [f"{t.name('gomod')}:/go/pkg/mod", f"{t.name('gocache')}:/root/.cache/go-build"]
    t.run([*d, "run", "--rm", "-v", f"{ROOT}:/src:ro", *[x for v in vols for x in ("-v", v)], "-v", f"{out_dir}:/out",
           "-e", "GOTOOLCHAIN=local", "-e", "GOFLAGS=-mod=readonly", "-e", "CGO_ENABLED=0", "-w", "/src", t.images["golang"],
           "sh", "-c", "go vet -tags mgtestfixture ./tests/g3/hostside && go test -c -buildvcs=false -trimpath -tags mgtestfixture "
           f"-o /out/g3-hostside ./tests/g3/hostside && chown {_uid()} /out/g3-hostside"], timeout=1200)
    return out_dir / "g3-hostside"


def _uid() -> str:
    import os  # noqa: PLC0415
    return f"{os.getuid()}:{os.getgid()}" if hasattr(os, "getuid") else "0:0"


def ensure_image(t: Target, ref: str, client: bool = False) -> None:
    run = t.cd if client else t.hd
    if run("image", "inspect", ref, check=False).returncode != 0:
        run("pull", "-q", ref, timeout=900)


def install(t: Target, binary: pathlib.Path) -> str:
    """Copy the binary into the volume <prefix>-bin of the platform host (stdin of an alpine container)."""
    vol = t.name("bin")
    ensure_image(t, t.images["alpine"])
    t.hd("volume", "create", "--label", "meshguard.role=g3", vol)
    t.hd("run", "--rm", "-i", "--network", "none", "-v", f"{vol}:/out", t.images["alpine"], "sh", "-ec",
         "cat > /out/g3-hostside; chmod 0755 /out/g3-hostside", input=binary.read_bytes(), binary=True, timeout=300)
    return vol


def docker_gid(t: Target) -> str:
    return t.hd("run", "--rm", "--network", "none", "-v", "/var/run/docker.sock:/s:ro", t.images["alpine"], "stat", "-c",
                "%g", "/s").stdout.strip()


def worker_identity(t: Target) -> dict:
    wid = t.worker_container()
    doc = json.loads(t.hd("inspect", wid).stdout)[0]
    return {"id": wid, "image": doc["Image"], "env": [e for e in doc["Config"]["Env"] if e.startswith("MG_")],
            "groups": doc["HostConfig"].get("GroupAdd") or list(WORKER_GROUPS), "user": doc["Config"].get("User") or "65532:65532"}


def hostside(t: Target, phase: str, env: dict[str, str], mounts: list[str] = (), groups: list[str] = (),
             timeout: float = 300) -> tuple[int, dict, str]:
    """One phase of the binary in a container with the worker's identity; returns (exit, G3JSON doc, redacted output)."""
    w = worker_identity(t)
    args = ["run", "--rm", "--name", t.name(f"hostside-{phase}"), "--network", f"container:{w['id']}",
            "--volumes-from", f"{w['id']}:ro", "--user", w["user"], "--read-only", "--tmpfs", "/tmp:size=16m",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
            "-v", f"{t.name('bin')}:/opt/g3:ro"]
    for g in [*w["groups"], *groups]:
        args += ["--group-add", str(g)]
    for m in mounts:
        args += ["-v", m]
    for e in w["env"]:
        args += ["-e", e]
    for k, v in {**env, "MG_G3_PHASE": phase}.items():
        args += ["-e", f"{k}={v}"]
    args += ["--entrypoint", "/opt/g3/g3-hostside", w["image"], "-test.run", "^TestG3HostSide$", "-test.count=1", "-test.v"]
    p = t.hd(*args, check=False, timeout=timeout)
    doc = {}
    for line in p.stdout.splitlines():
        if line.startswith(MARKER):
            doc = json.loads(line[len(MARKER):])
    return p.returncode, doc, t.redact(p.stdout + p.stderr)


def orphans(t: Target, slug_prefix: str, settled: bool = True) -> dict:
    """The P3-T07 detector over tenants <slug_prefix>* (read-only: Docker socket, tenants directory, mg_backup)."""
    tdir = t.cfg["tenants_dir"]
    rc, doc, out = hostside(t, "orphans", {
        "MG_G3_SLUG_PREFIX": slug_prefix, "MG_G3_TENANTS_DIR": tdir, "MG_G3_EDGE": t.cfg["edge_container"],
        "MG_G3_EDGE_NETWORK": t.cfg["edge_network"], "MG_G3_DB_USER": "mg_backup",
        "MG_G3_DB_PASSWORD_FILE": "/run/g3/pg_backup_password", "MG_G3_SETTLED": "1" if settled else "0"},
        mounts=["/var/run/docker.sock:/var/run/docker.sock:ro", f"{tdir}:{tdir}:ro",
                f"{t.cfg['backup_password_file']}:/run/g3/pg_backup_password:ro"],
        groups=[BACKUP_GROUP, docker_gid(t)])
    if rc != 0 or "findings" not in doc:
        return {"error": f"exit {rc}: {out[-800:]}", "findings": []}
    return {"findings": doc["findings"], "summary": doc.get("summary", "")}


# ---------------------------------------------------------------------------------------------------- checks
def worker_env(t: Target) -> dict[str, str]:
    return dict(e.split("=", 1) for e in worker_identity(t)["env"])


def edge_check(t: Target, slug: str) -> dict:
    """Step 18 again, independently: the prober's `edge` RPC (as the worker calls it) for <slug>.mesh.<domain>."""
    edge_addr = worker_env(t).get("MG_PROVISION_EDGE_ADDR", "")
    prober_url = worker_env(t).get("MG_PROBER_URL", "")
    if not edge_addr or not prober_url:
        return {"ok": False, "summary": "worker không có MG_PROVISION_EDGE_ADDR/MG_PROBER_URL"}
    image = t.hd("inspect", "-f", "{{.Image}}", t.cfg["prober_container"]).stdout.strip()
    p = t.hd("run", "--rm", "-i", "--name", t.name(f"probe-{slug}"), "--network", t.cfg["admin_network"], "--read-only",
             "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--user", "65532:65532", image, "call",
             "--url", prober_url, "edge", input=json.dumps({"address": edge_addr, "host": f"{slug}.mesh.{t.domain}"}),
             check=False, timeout=120)
    try:
        doc = json.loads(p.stdout)
    except ValueError:
        return {"ok": False, "summary": f"exit {p.returncode}: {t.redact(p.stdout + p.stderr)[-200:]}"}
    forb = doc.get("forbidden") or []
    key = ((doc.get("key") or {}).get("json") or {}).get("publicKey", "")
    ok = (p.returncode == 0 and doc.get("ok") is True and doc.get("blocked") == len(forb) and len(forb) >= 20
          and {f.get("class") for f in forb} == {"not_found"} and key.startswith("mkey:"))
    return {"ok": ok, "key_status": (doc.get("key") or {}).get("status"), "blocked": doc.get("blocked"),
            "forbidden": len(forb), "total_ms": doc.get("total_ms"),
            "summary": f"/key {(doc.get('key') or {}).get('status')}, {doc.get('blocked')}/{len(forb)} path cấm ⇒ 404"}


def instance_health(t: Target, slug: str, timeout: float = 120) -> str:
    end, state = time.time() + timeout, ""
    while time.time() < end:
        state = t.hd("inspect", "-f", "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}",
                     f"mg-hs-{slug}", check=False).stdout.strip() or "absent"
        if state == "healthy":
            return state
        time.sleep(3)
    return state


def policy_apply(t: Target, slug: str, text: str, *extra: str) -> tuple[int, dict, str]:
    p = t.hd("exec", "-i", t.worker_container(), "/usr/local/bin/meshguard", "admin", "policy-apply", "--tenant", slug,
             *extra, "--file", "-", check=False, timeout=180, input=text)
    out = {}
    for line in p.stdout.splitlines():
        if line.startswith("{"):
            out = json.loads(line)
    return p.returncode, out, t.redact(p.stderr)[-300:]


def logs_since(t: Target, container: str, since: float, out: pathlib.Path) -> None:
    """Redacted log of a platform container since a time (evidence of a failed round)."""
    p = t.hd("logs", "--since", str(int(since)), container, check=False, timeout=60)
    out.write_text(t.redact(p.stdout + p.stderr), encoding="utf-8")
