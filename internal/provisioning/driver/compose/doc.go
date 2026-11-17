// Package compose is the compose driver of the Host Agent (P3-T02; master plan §11.3 steps 7–11, §11.5, §14.2–§14.5,
// ADR-05): the only code that turns a validated, guarded agentspec value into directories, files, a Docker network and
// a compose project. Only apps/agent imports it (internal/archtest).
//
// What it reproduces — byte for byte where files are concerned — is the manual path of Phase 1–2
// (tools/render_instance.py + infrastructure/host/tenant-deploy.sh / tenant-remove.sh):
//
//   - rendering (render.go): config.yaml, compose.yaml, bootstrap-policy.hujson, extra-records.json and
//     meta/instance.json from the templates embedded in the agent binary (infrastructure/headscale/templates), with
//     typed values only; the result is checked against the isolation invariants of §11.1 / §11.3 step 8 by parsing it
//     back (invariants.go) before anything is written;
//   - storage (storage.go): <tenants>/<instance_id>/ root:run_gid 0750 with config/ and records/ (root:run_gid
//     0750), meta/ (root:root 0700) and data/ — the ONLY path owned by run_uid (0700). Every access goes through
//     os.Root opened at the tenants directory (no "..", no symlink is followed — a symlink where the agent expects a
//     file or directory is refused); a new instance directory is assembled under a hidden name and renamed into
//     place, so meta/instance.json exists from the first moment the guard can see the directory; files are written
//     tmp + fsync + rename + fsync of the directory, and only when their content, owner or mode differ;
//   - network (driver.go): mg-t-<slug>, internal, the /29 net_cidr, labels meshguard.instance_id and
//     meshguard.role=tenant — exactly tenant-deploy.sh; the edge is not attached here (P3-T03);
//   - compose (composecli.go): `docker compose --project-name mg-t-<slug> --file <dir>/compose.yaml …` up / stop /
//     start / restart / down, with a sanitised environment (no .env file, no COMPOSE_* or DOCKER_* of the agent leaks
//     in) and the image pinned by digest in compose.yaml;
//   - status and inventory (status.go, inventory.go): the Docker Engine API (moby client — engine.go), never parsed
//     CLI output.
//
// P3-T03 adds the operations after the container (§11.3 steps 8, 12–14; §11.4):
//
//   - one-shot helper containers (helper.go): network none, read-only, cap_drop ALL, the tenant's run_uid, a hard
//     timeout, always removed — `headscale configtest` with a scratch data directory on tmpfs (configtest.go:
//     ValidateConfig, data/ never mounted) and the Noise key fingerprint (`meshguard-agent noise-fingerprint` of the
//     agent's own image, data/ read-only — the agent never reads a file of the tenant);
//   - the Headscale CLI inside the tenant container over its local socket (headscale.go): BootstrapPolicy (set, read
//     back, compare sha256), BootstrapAPIKey (list, expire the others, create with an explicit expiration — the key in
//     the response only, APIKeySecret never prints) and the API keys of the status;
//   - the edge attachment (edge.go): EnsureEdgeAttachment / RemoveEdgeAttachment and EdgeCycle, one cycle of the edge
//     supervisor that apps/agent runs (re-attach exactly the flagged networks, start guard of every activated
//     instance, gateway of the edge);
//   - the start guard (startguard.go): data/ files present and the fingerprint recorded at activation — a violation
//     is refused and contained (flag cleared, edge detached, container stopped, Critical log line).
//
// Every operation is idempotent: repeated, it changes nothing and returns no error; a partial state (directory without
// container, network without container, container stopped…) converges to the requested phase.
package compose
