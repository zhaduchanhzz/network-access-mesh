package hsisolation_test

// IT-20 (§5.2 boundary 10, registry fault injection) on the PRODUCTION Locator of P2-T11: the registry of the
// isolation run is a real one — tenants A and B and their live instances in tenant_instances of a PostgreSQL migrated
// like a deployment (storetest: goose, RBAC seed, River; read by the Locator through the api's tenant pool, in each
// tenant's own scope), the API keys of the two real Headscale instances in the real SecretStore (throwaway kek-app
// keyring), the edge admin token file written by run.sh — and the faults are injected into the registry rows
// themselves, as superuser, then undone.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale/locator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}

// apiKeyName is the SecretStore name of an instance API key (as adopt-instance stores it — P2-T11).
const apiKeyName = "headscale-api-key"

// registryRow is what the fixture registered for one tenant: the ids and slug of testdata/params-{a,b}.json, the API
// key run.sh created on the instance, its SecretStore reference, the marker user of the instance.
type registryRow struct {
	tenant, instance uuid.UUID
	slug             string
	key              headscale.Secret
	ref              secrets.Ref
	marker           string
	netCIDR          string
	runUID           int
}

// lockedBuffer collects the Locator's and the adapter's log lines.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// locatorEnv is the production registry of the isolation run.
type locatorEnv struct {
	*env
	su        *pgx.Conn
	dir       *tenants.Service
	sec       *secrets.Store
	tokenFile string
	log       *lockedBuffer
	a, b      registryRow
}

func newKeyring(t *testing.T) *secrets.Keyring {
	t.Helper()
	dir := t.TempDir()
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	if err := os.WriteFile(filepath.Join(dir, "kek-hsiso-1"), []byte(hex.EncodeToString(b)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, secrets.ActiveFile), []byte("kek-hsiso-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	kr, err := secrets.LoadKeyring(secrets.KEKApp, dir)
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

func (l *locatorEnv) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := l.su.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("registry fixture: %v\n%s", err, sql)
	}
}

// newLocatorEnv registers A and B as adopt-instance does: tenant row, live instance row, API key in the SecretStore,
// reference in tenant_instances.api_key_secret_ref.
func newLocatorEnv(t *testing.T, e *env) *locatorEnv {
	t.Helper()
	pg := storetest.Require(t)
	db := pg.NewDatabase(t)
	l := &locatorEnv{env: e, su: pg.Admin(t, db), log: &lockedBuffer{},
		tokenFile: filepath.Join(os.Getenv("MG_HSISO_SECRETS_DIR"), "edge_token")}
	st := pg.OpenStore(t, db, "mg_api_tenant", "mg_api_platform", 4)
	sec, err := secrets.New(st, secrets.Options{App: newKeyring(t)})
	if err != nil {
		t.Fatal(err)
	}
	l.sec, l.dir = sec, tenants.New(st, tenants.Options{BaseDomain: "iso.test"})
	host := uuid.Must(uuid.NewV7())
	l.exec(t, `INSERT INTO hosts (id, name, region, run_uid_range, tenant_net_pool)
		VALUES ($1, 'host-hsiso', 'lab', int4range(30000, 40000), '10.250.0.0/16')`, host)
	// testdata/params-a.json and params-b.json
	l.a = registryRow{tenant: tenantA, instance: instanceA, slug: e.slugA, key: e.keyA, marker: markerA,
		netCIDR: "10.250.253.240/29", runUID: 30011}
	l.b = registryRow{tenant: tenantB, instance: instanceB, slug: e.slugB, key: e.keyB, marker: markerB,
		netCIDR: "10.250.253.248/29", runUID: 30012}
	for _, r := range []*registryRow{&l.a, &l.b} {
		r.ref = secrets.TenantRef(r.tenant, apiKeyName, 1)
		l.exec(t, `INSERT INTO tenants (id, slug, name, status) VALUES ($1, $2::text, $2::text, 'active')`, r.tenant, r.slug)
		l.exec(t, `INSERT INTO tenant_instances (id, tenant_id, host_id, status, headscale_version, image_digest,
				control_hostname, server_url, base_domain, internal_address, run_uid, net_cidr, data_path)
			VALUES ($1, $2, $3, 'running', 'v0.29.7', 'sha256:'||repeat('a', 64), $4||'.mesh.iso.test',
				'https://'||$4||'.mesh.iso.test', $4||'.tail.iso.test', 'hs-'||$4||':8080', $5, $6::cidr, $7)`,
			r.instance, r.tenant, host, r.slug, r.runUID, r.netCIDR, "/opt/meshguard/tenants/"+r.instance.String()+"/data")
		if err := sec.Put(t.Context(), r.ref, []byte(r.key.Reveal())); err != nil {
			t.Fatal(err)
		}
		l.exec(t, `UPDATE tenant_instances SET api_key_secret_ref = $1 WHERE id = $2`, r.ref.String(), r.instance)
	}
	return l
}

// locator is the production Locator over the registry, the SecretStore and the edge token file of run.sh.
func (l *locatorEnv) locator(t *testing.T) *locator.Locator {
	t.Helper()
	loc, err := locator.New(l.dir, l.sec, locator.Options{AdminURL: l.adminURL, EdgeTokenFile: l.tokenFile,
		Timeout: 15 * time.Second, Logger: logx.New(l.log, slog.LevelDebug, "hsiso")})
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

// registries returns a factory of fresh production registries (no cache, no breaker carried over).
func (l *locatorEnv) registries(t *testing.T) func() *headscale.CachingRegistry {
	return func() *headscale.CachingRegistry {
		return headscale.NewRegistry(l.locator(t), headscale.Options{Timeout: 15 * time.Second,
			Retry: headscale.RetryPolicy{Attempts: 1}, Logger: logx.New(l.log, slog.LevelDebug, "hsiso")})
	}
}

// Faults on the two tenant_instances rows: one statement exchanges the columns of A and B (neither column is unique);
// running it again undoes it.
const (
	swapAddress = `UPDATE tenant_instances x SET internal_address = y.internal_address FROM tenant_instances y
		WHERE x.id IN ($1, $2) AND y.id IN ($1, $2) AND x.id <> y.id`
	swapKeyRef = `UPDATE tenant_instances x SET api_key_secret_ref = y.api_key_secret_ref FROM tenant_instances y
		WHERE x.id IN ($1, $2) AND y.id IN ($1, $2) AND x.id <> y.id`
	swapAddressAndKeyRef = `UPDATE tenant_instances x SET internal_address = y.internal_address,
			api_key_secret_ref = y.api_key_secret_ref FROM tenant_instances y
		WHERE x.id IN ($1, $2) AND y.id IN ($1, $2) AND x.id <> y.id`
)

// swapInstances applies one of the swaps above and undoes it when the subtest ends.
func (l *locatorEnv) swapInstances(t *testing.T, swap string) {
	t.Helper()
	l.exec(t, swap, l.a.instance, l.b.instance)
	t.Cleanup(func() { l.exec(t, swap, l.a.instance, l.b.instance) })
}

// swapSlugs exchanges the slugs of the two tenants — the routing key the Locator hands the adapter (the edge forwards
// to hs-<slug>) — through a temporary value (the live slug is unique), and undoes it when the subtest ends.
func (l *locatorEnv) swapSlugs(t *testing.T) {
	t.Helper()
	set := func(a, b string) {
		l.exec(t, `UPDATE tenants SET slug = 'iso-swap-tmp' WHERE id = $1`, l.a.tenant)
		l.exec(t, `UPDATE tenants SET slug = $2::text WHERE id = $1`, l.b.tenant, b)
		l.exec(t, `UPDATE tenants SET slug = $2::text WHERE id = $1`, l.a.tenant, a)
	}
	set(l.b.slug, l.a.slug)
	t.Cleanup(func() { set(l.a.slug, l.b.slug) })
}

// instanceRow reads internal_address and api_key_secret_ref of an instance row (to prove a fault is in place).
func (l *locatorEnv) instanceRow(t *testing.T, id uuid.UUID) (address, keyRef string) {
	t.Helper()
	if err := l.su.QueryRow(context.Background(), `SELECT internal_address, coalesce(api_key_secret_ref, '')
			FROM tenant_instances WHERE id = $1`, id).Scan(&address, &keyRef); err != nil {
		t.Fatal(err)
	}
	return address, keyRef
}

// answersOwnDataOnly: the located target of r is its own (instance, slug, key) and every read op through the
// production registry returns r's marker and never the other's.
func (l *locatorEnv) answersOwnDataOnly(t *testing.T, r, other registryRow) {
	t.Helper()
	tg, err := l.locator(t).Locate(ctx(t), r.tenant)
	if err != nil {
		t.Fatalf("Locate(%s): %v", r.slug, err)
	}
	if tg.InstanceID != r.instance || tg.Slug != r.slug || tg.APIKey.Reveal() != r.key.Reveal() {
		t.Fatalf("Locate(%s) = instance %s slug %s own key %v, want instance %s slug %s and its own key", r.slug,
			tg.InstanceID, tg.Slug, tg.APIKey.Reveal() == r.key.Reveal(), r.instance, r.slug)
	}
	inst := forTenant(t, l.registries(t)(), r.tenant)
	if u := userNames(t, inst); !slices.Contains(u, r.marker) || slices.Contains(u, other.marker) {
		t.Fatalf("ForTenant(%s) lists %v, want %s and never %s", r.slug, u, r.marker, other.marker)
	}
	for name, op := range readOps {
		if name == "SetPolicy" {
			continue
		}
		out, err := op(ctx(t), inst)
		if err != nil || strings.Contains(out, other.marker) {
			t.Errorf("%s for %s: %v, other tenant's marker present: %v", name, r.slug, err, strings.Contains(out, other.marker))
		}
	}
}

// refusedByLocator: the Locator refuses the tenant's entry — the API key reference names another tenant (§5.2
// boundary 10) — before any call to an instance; the registry surfaces it as an internal fault, not "no instance".
func (l *locatorEnv) refusedByLocator(t *testing.T, r registryRow) {
	t.Helper()
	if _, err := l.locator(t).Locate(ctx(t), r.tenant); err == nil || errors.Is(err, headscale.ErrNoInstance) ||
		!strings.Contains(err.Error(), "does not belong to tenant") {
		t.Fatalf("Locate(%s): %v, want the foreign API key reference refused", r.slug, err)
	}
	_, err := l.registries(t)().ForTenant(ctx(t), r.tenant)
	var he *headscale.Error
	if !errors.As(err, &he) || he.Kind != headscale.KindInternal || !strings.Contains(err.Error(), "does not belong to tenant") {
		t.Fatalf("ForTenant(%s): %v, want an internal fault naming the foreign reference", r.slug, err)
	}
}

// TestIT20ProductionLocator — IT-20 on the production Locator: faults injected into the registry rows of A and B.
//
//   - internal_address swapped: not an input of the Locator (the edge routes by the tenant's slug) — both tenants
//     still reach their own instance with their own key, nothing of the other is returned;
//   - routing key swapped (tenants.slug, what designates the instance behind the edge): A's entry routes to B's
//     instance with A's key ⇒ every call 401, nothing of B (and the other way round);
//   - api_key_secret_ref swapped, then both fields of §5.2 swapped (internal_address + api_key_secret_ref), then a
//     complete valid entry of the other tenant (slug + api_key_secret_ref — the case a target cannot reveal): the
//     reference names the other tenant ⇒ the Locator refuses before any call (secret reference of another tenant
//     rejected), logs the integrity fault without any credential;
//   - every fault undone ⇒ the registry answers as before.
func TestIT20ProductionLocator(t *testing.T) {
	e := setup(t)
	prepare(t, e)
	l := newLocatorEnv(t, e)

	t.Run("control: correct registry", func(t *testing.T) {
		l.answersOwnDataOnly(t, l.a, l.b)
		l.answersOwnDataOnly(t, l.b, l.a)
	})
	t.Run("internal_address swapped", func(t *testing.T) {
		l.swapInstances(t, swapAddress)
		if got, _ := l.instanceRow(t, l.a.instance); got != "hs-"+l.b.slug+":8080" {
			t.Fatalf("fault not in place: internal_address of A = %s", got)
		}
		l.answersOwnDataOnly(t, l.a, l.b)
		l.answersOwnDataOnly(t, l.b, l.a)
	})
	t.Run("routing key (slug) swapped", func(t *testing.T) {
		l.swapSlugs(t)
		tg, err := l.locator(t).Locate(ctx(t), l.a.tenant)
		if err != nil || tg.Slug != l.b.slug || tg.APIKey.Reveal() != l.a.key.Reveal() {
			t.Fatalf("fault not in place: Locate(A) = slug %s, A's key %v, %v", tg.Slug, tg.APIKey.Reveal() == l.a.key.Reveal(), err)
		}
		refusedEverywhere(t, l.registries(t), l.a.tenant, l.b.marker)
		refusedEverywhere(t, l.registries(t), l.b.tenant, l.a.marker)
	})
	for _, tc := range []struct {
		name  string
		fault func(t *testing.T)
	}{
		{"api_key_secret_ref swapped", func(t *testing.T) { l.swapInstances(t, swapKeyRef) }},
		{"internal_address and api_key_secret_ref swapped", func(t *testing.T) { l.swapInstances(t, swapAddressAndKeyRef) }},
		{"complete entry of the other tenant (slug and api_key_secret_ref swapped)", func(t *testing.T) {
			l.swapSlugs(t)
			l.swapInstances(t, swapKeyRef)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := strings.Count(l.log.String(), "the API key reference belongs to another owner")
			tc.fault(t)
			if _, got := l.instanceRow(t, l.a.instance); got != l.b.ref.String() {
				t.Fatalf("fault not in place: api_key_secret_ref of A = %s", got)
			}
			l.refusedByLocator(t, l.a)
			l.refusedByLocator(t, l.b)
			if after := strings.Count(l.log.String(), "the API key reference belongs to another owner"); after <= before {
				t.Errorf("the Locator did not log the integrity fault (%d → %d)", before, after)
			}
		})
	}
	t.Run("faults undone: registry as before", func(t *testing.T) {
		l.answersOwnDataOnly(t, l.a, l.b)
		l.answersOwnDataOnly(t, l.b, l.a)
	})
	logs := l.log.String()
	for name, secret := range map[string]string{"API key of A": l.a.key.Reveal(), "API key of B": l.b.key.Reveal(),
		"edge token": e.edgeToken.Reveal()} {
		if strings.Contains(logs, secret) {
			t.Errorf("IT-20: the %s leaked into the Locator/adapter log", name)
		}
	}
	t.Logf("IT-20 production Locator: %d log bytes of the Locator and adapter, no credential", len(logs))
}
