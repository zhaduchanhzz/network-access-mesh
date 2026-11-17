// Package contract holds the contract tests of the Headscale adapter (P2-T10, §13.4 rule 4 of the master plan):
// internal/headscale is exercised against a real Headscale container whose configuration is rendered by
// tools/render_instance.py, reached through the real admin listener block of the edge Caddyfile
// (infrastructure/caddy/Caddyfile.tmpl) in a stock Caddy pinned by digest.
//
// The Headscale under test is the MeshGuard build of v0.29.7 with the V-26 patches (P2-T10a,
// infrastructure/docker/headscale): versions.lock [images.mg-headscale] once pinned, otherwise built from the tree by
// run.sh. The official image (versions.lock [images.headscale]) creates the database before phase 1 and runs phase 6:
// the rollback path and the negative control showing that the official build still crashes on V-26.
//
// Every upstream quirk of V-06, V-21, V-26 and V-28 is one test that asserts AND records the observed behaviour
// (JSON lines in $HSCT_OBS_FILE, summarised in docs/planning/evidence/P2-T10.md and P2-T10a.md). Registrations use the
// Tailscale protocol client library pinned in go.mod (tailscale.com/control/tsp and control/ts2021, v1.104.7) so a test
// can send what the official client never sends (RegisterRequest.Expiry); one registration uses the official client
// container (versions.lock [images.tailscale]).
//
// The tests are grouped in phases (TestP1_… to TestP7_…) because some quirks need the runner to act between them:
// restart Headscale, fill or free its data volume, start the official client, swap the image on the same data volume
// (patched → official → patched). Run everything with run.sh; without its environment every test is skipped.
package contract
