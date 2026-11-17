package locator_test

// Tests of the production Locator (P2-T11, §13.4 rule 2): on a real PostgreSQL migrated like a deployment
// (storetest — goose, RBAC seed, River; the api roles mg_api_tenant/mg_api_platform), the real SecretStore with a
// throwaway kek-app keyring, and a fake edge admin listener with one fake Headscale per slug (headscaletest).

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale/headscaletest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale/locator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}

const keyName = "headscale-api-key"

type env struct {
	t         *testing.T
	db        string
	su        *pgx.Conn
	st        *store.Store
	ss        *secrets.Store
	reg       *tenants.Service
	edge      *headscaletest.Edge
	tokenFile string
	host      uuid.UUID
	n         int
}

// tenant is one registered tenant with its instance and current platform key.
type tenant struct {
	id, instance uuid.UUID
	slug         string
	fake         *headscaletest.Instance
	key, prefix  string
	ref          secrets.Ref
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// newKeyring writes a kek-app keyring with one fresh KEK (64 hex characters) and loads it.
func newKeyring(t *testing.T) *secrets.Keyring {
	t.Helper()
	dir := t.TempDir()
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	writeFile(t, dir, "kek-1", hex.EncodeToString(b)+"\n")
	writeFile(t, dir, secrets.ActiveFile, "kek-1\n")
	kr, err := secrets.LoadKeyring(secrets.KEKApp, dir)
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

func newEnv(t *testing.T) *env {
	t.Helper()
	pg := storetest.Require(t)
	e := &env{t: t, db: pg.NewDatabase(t)}
	e.su = pg.Admin(t, e.db)
	e.st = pg.OpenStore(t, e.db, "mg_api_tenant", "mg_api_platform", 8)
	ss, err := secrets.New(e.st, secrets.Options{App: newKeyring(t)})
	if err != nil {
		t.Fatal(err)
	}
	e.ss, e.reg = ss, tenants.New(e.st, tenants.Options{BaseDomain: "mg.test"})
	tok := headscaletest.NewToken()
	e.edge = headscaletest.NewEdge(t, tok)
	e.tokenFile = writeFile(t, t.TempDir(), "edge_admin_token", tok+"\n")
	e.host = uuid.Must(uuid.NewV7())
	e.exec(`INSERT INTO hosts (id, name, region, run_uid_range, tenant_net_pool)
		VALUES ($1, 'host-1', 'lab', int4range(30000, 40000), '10.250.0.0/16')`, e.host)
	return e
}

func (e *env) exec(sql string, args ...any) {
	e.t.Helper()
	if _, err := e.su.Exec(e.t.Context(), sql, args...); err != nil {
		e.t.Fatalf("fixture: %v\n%s", err, sql)
	}
}

// addTenant registers a tenant (status), its instance (instStatus) and a platform key in the SecretStore.
func (e *env) addTenant(slug, status, instStatus string) *tenant {
	e.t.Helper()
	e.n++
	tn := &tenant{id: uuid.Must(uuid.NewV7()), instance: uuid.Must(uuid.NewV7()), slug: slug}
	e.exec(`INSERT INTO tenants (id, slug, name, status) VALUES ($1, $2::text, $2::text, $3)`, tn.id, slug, status)
	e.exec(`INSERT INTO tenant_instances (id, tenant_id, host_id, status, headscale_version, image_digest,
			control_hostname, server_url, base_domain, internal_address, run_uid, net_cidr, data_path)
		VALUES ($1, $2, $3, $4, 'v0.29.7', 'sha256:'||repeat('a', 64), $5||'.mesh.mg.test', 'https://'||$5||'.mesh.mg.test',
			$5||'.tail.mg.test', 'hs-'||$5||':8080', $6, $7::cidr, $8)`,
		tn.instance, tn.id, e.host, instStatus, slug, 30000+e.n, "10.250.0."+strconv.Itoa(8*e.n)+"/29",
		"/opt/meshguard/tenants/"+tn.instance.String()+"/data")
	tn.fake = e.edge.AddInstance(slug)
	tn.key, tn.prefix = tn.fake.NewKey(90 * 24 * time.Hour)
	tn.ref = secrets.TenantRef(tn.id, keyName, 1)
	if err := e.ss.Put(e.t.Context(), tn.ref, []byte(tn.key)); err != nil {
		e.t.Fatal(err)
	}
	e.exec(`UPDATE tenant_instances SET api_key_secret_ref = $1, api_key_prefix = $2 WHERE id = $3`,
		tn.ref.String(), tn.prefix, tn.instance)
	return tn
}

func (e *env) locator(o locator.Options) *locator.Locator {
	e.t.Helper()
	if o.AdminURL == "" {
		o.AdminURL = e.edge.URL()
	}
	if o.EdgeTokenFile == "" {
		o.EdgeTokenFile = e.tokenFile
	}
	l, err := locator.New(e.reg, e.ss, o)
	if err != nil {
		e.t.Fatal(err)
	}
	return l
}

// countingLocator counts Locate calls (cache misses and reloads of CachingRegistry).
type countingLocator struct {
	inner headscale.Locator
	calls atomic.Int32
}

func (c *countingLocator) Locate(ctx context.Context, id uuid.UUID) (headscale.Target, error) {
	c.calls.Add(1)
	return c.inner.Locate(ctx, id)
}

func prefixes(keys []headscale.APIKey) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k.Prefix)
	}
	return out
}

// TestForTenantReachesTheRightInstance — the acceptance of P2-T11 (§20): ForTenant returns the instance of each tenant
// — its slug, its key — and never the other's; every request the edge saw for a slug carried that tenant's key.
func TestForTenantReachesTheRightInstance(t *testing.T) {
	e := newEnv(t)
	a := e.addTenant("tenant-a", "active", "running")
	b := e.addTenant("tenant-b", "active", "running")
	c := e.addTenant("tenant-c", "provisioning", "starting") // being brought up: reachable too (§11.3 steps 10–18)
	loc := e.locator(locator.Options{Timeout: 7 * time.Second})
	reg := headscale.NewRegistry(loc, headscale.Options{})

	for _, tn := range []*tenant{a, b, c} {
		tg, err := loc.Locate(t.Context(), tn.id)
		if err != nil {
			t.Fatalf("Locate(%s): %v", tn.slug, err)
		}
		if tg.InstanceID != tn.instance || tg.Slug != tn.slug || tg.APIKey.Reveal() != tn.key ||
			tg.AdminURL != e.edge.URL() || tg.Timeout != 7*time.Second || tg.EdgeToken.IsZero() {
			t.Fatalf("Locate(%s) = instance %s slug %s (want %s %s); key of the tenant: %v", tn.slug, tg.InstanceID,
				tg.Slug, tn.instance, tn.slug, tg.APIKey.Reveal() == tn.key)
		}
		inst, err := reg.ForTenant(t.Context(), tn.id)
		if err != nil {
			t.Fatalf("ForTenant(%s): %v", tn.slug, err)
		}
		keys, err := inst.ListAPIKeys(t.Context())
		if err != nil {
			t.Fatalf("ListAPIKeys(%s): %v", tn.slug, err)
		}
		if got := prefixes(keys); len(got) != 1 || got[0] != tn.prefix {
			t.Fatalf("ForTenant(%s) listed %v, want only its own key %s", tn.slug, got, tn.prefix)
		}
	}
	// the edge saw each slug with that tenant's key only
	own := map[string]string{a.slug: a.prefix, b.slug: b.prefix, c.slug: c.prefix}
	for _, r := range e.edge.Requests() {
		if !r.TokenOK {
			t.Errorf("request without the edge token: %+v", r)
		}
		if r.AuthPrefix != "" && r.AuthPrefix != own[r.Slug] {
			t.Errorf("request to %s carried the key %s of another tenant", r.Slug, r.AuthPrefix)
		}
	}
}

// TestNoInstance — unknown, suspended, deleted or failed tenant; removed, stopped, quarantined, allocated instance;
// instance without key: ErrNoInstance from Locate and through ForTenant (instance_unavailable), and the edge is never
// called for them.
func TestNoInstance(t *testing.T) {
	e := newEnv(t)
	cases := map[string]uuid.UUID{"unknown tenant": uuid.Must(uuid.NewV7())}
	for _, st := range []string{"suspended", "deleted", "failed", "pending", "deprovisioning"} {
		cases["tenant "+st] = e.addTenant("t-"+st, st, "running").id
	}
	for _, st := range []string{"removed", "stopped", "quarantined", "allocated", "failed"} {
		cases["instance "+st] = e.addTenant("i-"+st, "active", st).id
	}
	nokey := e.addTenant("no-key", "active", "running")
	e.exec(`UPDATE tenant_instances SET api_key_secret_ref = NULL WHERE id = $1`, nokey.instance)
	cases["no API key registered"] = nokey.id

	loc := e.locator(locator.Options{})
	reg := headscale.NewRegistry(loc, headscale.Options{})
	for name, id := range cases {
		if _, err := loc.Locate(t.Context(), id); !errors.Is(err, headscale.ErrNoInstance) {
			t.Errorf("%s: Locate error %v, want ErrNoInstance", name, err)
		}
		_, err := reg.ForTenant(t.Context(), id)
		var he *headscale.Error
		if !errors.Is(err, headscale.ErrNoInstance) || !errors.As(err, &he) || he.Kind != headscale.KindUnavailable {
			t.Errorf("%s: ForTenant error %v, want instance_unavailable wrapping ErrNoInstance", name, err)
		}
	}
	if n := len(e.edge.Requests()); n != 0 {
		t.Errorf("the edge was called %d times for tenants without a reachable instance", n)
	}
	// a P3 job may allow suspended tenants explicitly (policy drift of a suspended tenant — §11.4)
	susp := cases["tenant suspended"]
	l2 := e.locator(locator.Options{TenantStatuses: []string{"active", "suspended"}})
	if _, err := l2.Locate(t.Context(), susp); err != nil {
		t.Errorf("explicitly allowed suspended tenant: %v", err)
	}
}

// TestKeyRotationRelocates — a key rotated in the registry is picked up without a restart: the cached target still has
// the old key, the instance answers 401, CachingRegistry locates again (bypassing its cache) and replays once.
func TestKeyRotationRelocates(t *testing.T) {
	e := newEnv(t)
	a := e.addTenant("tenant-a", "active", "running")
	cl := &countingLocator{inner: e.locator(locator.Options{})}
	reg := headscale.NewRegistry(cl, headscale.Options{CacheTTL: time.Hour})
	inst, err := reg.ForTenant(t.Context(), a.id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inst.ListAPIKeys(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := cl.calls.Load(); n != 1 {
		t.Fatalf("Locate calls = %d after the first call, want 1", n)
	}

	// rotation as adopt-instance does it: new key on the instance, new secret version, reference moved, old key expired
	newKey, newPrefix := a.fake.NewKey(90 * 24 * time.Hour)
	ref2, err := e.ss.Rotate(t.Context(), a.ref, []byte(newKey))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.reg.SetInstanceAPIKey(t.Context(), a.id, a.instance, tenants.APIKey{Ref: ref2.String(),
		Prefix: newPrefix}); err != nil {
		t.Fatal(err)
	}
	inst2, err := reg.ForTenant(t.Context(), a.id) // still the cached target (old key)
	if err != nil {
		t.Fatal(err)
	}
	if err := inst2.ExpireAPIKey(t.Context(), a.prefix); err != nil { // with the old key, still valid
		t.Fatal(err)
	}
	keys, err := inst2.ListAPIKeys(t.Context()) // old key now refused ⇒ 401 ⇒ Locate again ⇒ replay with the new key
	if err != nil {
		t.Fatalf("after rotation: %v", err)
	}
	if n := cl.calls.Load(); n != 2 {
		t.Errorf("Locate calls = %d, want 2 (one reload after the 401)", n)
	}
	if !slices.Contains(prefixes(keys), newPrefix) {
		t.Errorf("listed %v, want the new key %s", prefixes(keys), newPrefix)
	}
	var sawNew bool
	for _, r := range e.edge.Requests() {
		sawNew = sawNew || r.AuthPrefix == newPrefix
	}
	if !sawNew {
		t.Error("no request carried the rotated key")
	}
}

// TestLifecycleChangeSeenWithinTTL — G2 L1: with a one-hour cache TTL, a tenant suspended and an instance quarantined in
// the registry (plain SQL — no lifecycle code calls Invalidate) are refused by the very next ForTenant: ErrNoInstance
// (instance_unavailable) and no request reaches the edge. Restored, they are reachable again without a restart.
func TestLifecycleChangeSeenWithinTTL(t *testing.T) {
	e := newEnv(t)
	a := e.addTenant("tenant-a", "active", "running")
	b := e.addTenant("tenant-b", "active", "running")
	loc := e.locator(locator.Options{})
	reg := headscale.NewRegistry(loc, headscale.Options{CacheTTL: time.Hour})
	// The re-check itself: the live instance of an active tenant passes; a target of another instance is stale.
	if err := loc.CheckTarget(t.Context(), a.id, headscale.Target{InstanceID: a.instance}); err != nil {
		t.Fatalf("CheckTarget of the live instance: %v", err)
	}
	if err := loc.CheckTarget(t.Context(), a.id, headscale.Target{InstanceID: b.instance}); !errors.Is(err, headscale.ErrTargetStale) {
		t.Fatalf("CheckTarget of another instance: %v, want ErrTargetStale", err)
	}
	for _, tn := range []*tenant{a, b} {
		inst, err := reg.ForTenant(t.Context(), tn.id)
		if err != nil {
			t.Fatalf("ForTenant(%s): %v", tn.slug, err)
		}
		if _, err := inst.ListAPIKeys(t.Context()); err != nil {
			t.Fatalf("ListAPIKeys(%s): %v", tn.slug, err)
		}
	}
	e.exec(`UPDATE tenants SET status = 'suspended' WHERE id = $1`, a.id)
	e.exec(`UPDATE tenant_instances SET status = 'quarantined' WHERE id = $1`, b.instance)
	before := len(e.edge.Requests())
	for _, tn := range []*tenant{a, b} {
		_, err := reg.ForTenant(t.Context(), tn.id)
		var he *headscale.Error
		if !errors.Is(err, headscale.ErrNoInstance) || !errors.As(err, &he) || he.Kind != headscale.KindUnavailable {
			t.Errorf("%s within the TTL: %v, want instance_unavailable wrapping ErrNoInstance", tn.slug, err)
		}
	}
	if n := len(e.edge.Requests()); n != before {
		t.Fatalf("%d requests reached the edge for a suspended tenant or a quarantined instance", n-before)
	}
	e.exec(`UPDATE tenants SET status = 'active' WHERE id = $1`, a.id)
	e.exec(`UPDATE tenant_instances SET status = 'running' WHERE id = $1`, b.instance)
	for _, tn := range []*tenant{a, b} {
		if _, err := reg.ForTenant(t.Context(), tn.id); err != nil {
			t.Errorf("%s restored: %v", tn.slug, err)
		}
	}
}

// TestEdgeTokenRotation — the token file is read at every Locate: after a rotation the edge answers 403 once, the
// registry locates again and the call succeeds.
func TestEdgeTokenRotation(t *testing.T) {
	e := newEnv(t)
	a := e.addTenant("tenant-a", "active", "running")
	reg := headscale.NewRegistry(e.locator(locator.Options{}), headscale.Options{CacheTTL: time.Hour})
	inst, err := reg.ForTenant(t.Context(), a.id)
	if err != nil {
		t.Fatal(err)
	}
	tok := headscaletest.NewToken()
	writeFile(t, filepath.Dir(e.tokenFile), filepath.Base(e.tokenFile), tok+"\n")
	e.edge.SetToken(tok)
	if _, err := inst.ListAPIKeys(t.Context()); err != nil {
		t.Fatalf("after the token rotation: %v", err)
	}
}

// TestReferenceOfAnotherTenantRefused — boundary 10 of §5.2: a key reference owned by tenant B in the row of tenant A
// (a corrupted or tampered registry) is refused before the SecretStore is read and before any call; it is a platform
// fault, not "no instance".
func TestReferenceOfAnotherTenantRefused(t *testing.T) {
	e := newEnv(t)
	a := e.addTenant("tenant-a", "active", "running")
	b := e.addTenant("tenant-b", "active", "running")
	e.exec(`UPDATE tenant_instances SET api_key_secret_ref = $1 WHERE id = $2`, b.ref.String(), a.instance)
	loc := e.locator(locator.Options{})
	_, err := loc.Locate(t.Context(), a.id)
	if err == nil || errors.Is(err, headscale.ErrNoInstance) || !strings.Contains(err.Error(), "does not belong") {
		t.Fatalf("Locate with B's reference: %v", err)
	}
	if strings.Contains(err.Error(), b.key) || strings.Contains(err.Error(), a.key) {
		t.Fatal("the error carries a key")
	}
	if _, err := headscale.NewRegistry(loc, headscale.Options{}).ForTenant(t.Context(), a.id); err == nil {
		t.Fatal("ForTenant succeeded with another tenant's key reference")
	}
	if n := len(e.edge.Requests()); n != 0 {
		t.Fatalf("the edge was called %d times", n)
	}

	// a destroyed key version: a platform fault too (not ErrNoInstance)
	e.exec(`UPDATE tenant_instances SET api_key_secret_ref = $1 WHERE id = $2`, a.ref.String(), a.instance)
	if err := e.ss.Destroy(t.Context(), a.ref); err != nil {
		t.Fatal(err)
	}
	if _, err := loc.Locate(t.Context(), a.id); err == nil || errors.Is(err, headscale.ErrNoInstance) ||
		!errors.Is(err, secrets.ErrDestroyed) {
		t.Fatalf("Locate with a destroyed key: %v", err)
	}
}

// TestOptionsAndTokenFile — construction and token-file checks; no error repeats the content of the file.
func TestOptionsAndTokenFile(t *testing.T) {
	dir := t.TempDir()
	good := writeFile(t, dir, "good", headscaletest.NewToken()+"\n")
	canary := "CANARY" + strings.Repeat("x", 30) // 36 characters: wrong length
	bad := writeFile(t, dir, "bad", canary)
	nop := tenants.New(nil, tenants.Options{})
	for name, o := range map[string]locator.Options{
		"path in URL":  {AdminURL: "http://10.0.0.1:8081/api", EdgeTokenFile: good},
		"query in URL": {AdminURL: "http://10.0.0.1:8081?x=1", EdgeTokenFile: good},
		"user in URL":  {AdminURL: "http://u:p@10.0.0.1:8081", EdgeTokenFile: good},
		"scheme":       {AdminURL: "ftp://10.0.0.1:8081", EdgeTokenFile: good},
		"no token":     {AdminURL: "http://10.0.0.1:8081"},
	} {
		if _, err := locator.New(nop, &secrets.Store{}, o); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := locator.New(nil, &secrets.Store{}, locator.Options{AdminURL: "http://10.0.0.1:8081", EdgeTokenFile: good}); err == nil {
		t.Error("nil registry accepted")
	}
	l, err := locator.New(nop, &secrets.Store{}, locator.Options{AdminURL: "http://10.0.0.1:8081/", EdgeTokenFile: bad})
	if err != nil {
		t.Fatal(err)
	}
	_, err = l.Candidate(uuid.New(), "tenant-a", headscale.NewSecret("x"))
	if err == nil || strings.Contains(err.Error(), canary) || !strings.Contains(err.Error(), "40 characters") {
		t.Fatalf("bad token file: %v", err)
	}
	l, _ = locator.New(nop, &secrets.Store{}, locator.Options{AdminURL: "http://10.0.0.1:8081", EdgeTokenFile: good})
	tg, err := l.Candidate(uuid.New(), "tenant-a", headscale.NewSecret("k"))
	if err != nil || tg.AdminURL != "http://10.0.0.1:8081" || tg.Slug != "tenant-a" {
		t.Fatalf("Candidate: %+v %v", tg, err)
	}
	if _, err := l.Candidate(uuid.New(), "Bad_Slug", headscale.NewSecret("k")); err == nil {
		t.Error("candidate with an invalid slug accepted")
	}
}
