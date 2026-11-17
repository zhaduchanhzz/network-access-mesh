module github.com/zhaduchanhzz/network-access-mesh/tests/integration/headscale

go 1.27.4

require (
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.12.0
	github.com/prometheus/client_golang v1.25.0
	github.com/zhaduchanhzz/network-access-mesh v0.0.0-00010101000000-000000000000
	tailscale.com v1.104.7
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/coder/websocket v1.8.15 // indirect
	github.com/dblohm7/wingoes v0.0.0-20260526185140-fb298caac7ca // indirect
	github.com/fxamacker/cbor/v2 v2.9.3 // indirect
	github.com/gaissmai/bart v0.29.0 // indirect
	github.com/go-json-experiment/json v0.0.0-20260820222146-c27c302e5fc3 // indirect
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/hdevalence/ed25519consensus v0.2.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.3 // indirect
	github.com/jsimonetti/rtnetlink v1.4.2 // indirect
	github.com/klauspost/compress v1.20.1 // indirect
	github.com/mdlayher/netlink v1.11.2 // indirect
	github.com/mdlayher/socket v0.7.0 // indirect
	github.com/mfridman/interpolate v0.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/pressly/goose/v3 v3.29.0 // indirect
	github.com/prometheus/client_model v0.6.3 // indirect
	github.com/prometheus/common v0.72.0 // indirect
	github.com/prometheus/procfs v0.22.0 // indirect
	github.com/riverqueue/river v0.51.0 // indirect
	github.com/riverqueue/river/riverdriver v0.51.0 // indirect
	github.com/riverqueue/river/riverdriver/riverpgxv5 v0.51.0 // indirect
	github.com/riverqueue/river/rivershared v0.51.0 // indirect
	github.com/riverqueue/river/rivertype v0.51.0 // indirect
	github.com/sethvargo/go-retry v0.5.0 // indirect
	github.com/tailscale/hujson v0.0.0-20260727124030-b80ff77dac4f // indirect
	github.com/tidwall/gjson v1.20.0 // indirect
	github.com/tidwall/match v1.2.0 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/tidwall/sjson v1.2.5 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go4.org/mem v0.0.0-20240501181205-ae6ca9944745 // indirect
	go4.org/netipx v0.0.0-20260823151212-3075585bcbeb // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/exp v0.0.0-20261011100332-faecfb24eb49 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	golang.zx2c4.com/wireguard/windows v1.0.1 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)

// The adapter under test is the management-plane module of this repository (internal/headscale); the import of
// an internal package is allowed because this module's path is below the repository module's path.
replace github.com/zhaduchanhzz/network-access-mesh => ../../..
