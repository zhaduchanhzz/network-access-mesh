// Package provisioning is the fault-injection harness of the provisioning state machine (P3-T07, master §11.3, §20):
// the REAL orchestrator (internal/provisioning/orchestrator — the job framework with River, the registry, the
// SecretStore, the placer, the Headscale adapter through an edge) drives a REAL Host Agent (the agent image built
// from the tree, hardened like compose.agent.yaml) on a REAL Docker Engine with the REAL Headscale image of
// versions.lock ([images.mg-headscale]) and a real PostgreSQL 18; a failure is injected at one call of one step
// (package faultinject — decorators of the orchestrator's collaborators, nothing in the production code), and after
// every case the orphan detector (package orphans) asserts that no container, network, instance directory or
// SecretStore version is left that the registry does not account for, and that a live instance holds no valid API
// key other than the one stored in the SecretStore.
//
// The tests are in files with the build tags linux && dockerintegration and run only through run.sh
// (`make provisioning-it`), which builds the agent image and the test binary and starts, on a dedicated tenant network
// pool (default 10.250.224.0/24, PIT_POOL):
//
//	<prefix>-pg     PostgreSQL [images.postgres] (throwaway database per run, roles and migrations like a deployment)
//	<prefix>-agent  the Host Agent (network none, read-only, cap_drop ALL + CHOWN/FOWNER/DAC_OVERRIDE, socket 0660 of
//	                group 20003, peer UID 65532 — the worker's), tenants directory under a temporary root
//	<prefix>-edge   the test edge: this binary in edge mode — the admin listener (X-MG-Token, X-MG-Instance →
//	                hs-<slug>:8080, /api/v1/* and GET /version only) and the public listener (<slug>.mesh.<domain>,
//	                the allow-list of §14.6) like the blocks of infrastructure/caddy/Caddyfile.tmpl; the agent attaches
//	                it to tenant networks (gw_priority 1 on <prefix>-net, like mg-edge)
//	<prefix>-run    this binary as the harness (UID 65532, group 20003 — the worker's identity), which starts the
//	                worker as child processes of itself (one per phase of a case; a fault plan in their environment),
//	                so that a worker can be killed with SIGKILL at an exact point (key created, not stored).
//
// The prober of steps 17/18 is a test prober over the public listener of the test edge (real /key of the instance,
// forbidden paths, /derp/probe; the shared STUN responder is not part of the harness); the IdP driver is an in-memory
// keycloak driver that stores the client secret in the real SecretStore.
package provisioning
