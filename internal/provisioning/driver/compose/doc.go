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
// Every operation is idempotent: repeated, it changes nothing and returns no error; a partial state (directory without
// container, network without container, container stopped…) converges to the requested phase.
package compose
