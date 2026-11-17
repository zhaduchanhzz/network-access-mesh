package provisioning_test

// Integration tests of `meshguard admin adopt-instance` (P2-T11) below the command line: a real PostgreSQL migrated like
// a deployment (storetest, api roles), the real SecretStore, the production locator, and a fake edge admin listener
// with fake Headscale instances (headscaletest) — tenant-a and tenant-b to adopt, tenant-c the demo tenant that must
// never be touched. The same flow against Headscale 0.29.7 and the real edge block: tests/integration/adopt.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/netip"
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
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale/headscaletest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale/locator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning"
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

const (
	baseDomain = "mg.test"
	day        = 24 * time.Hour
)

// recAuditor records the audit events (and can refuse the first one).
type recAuditor struct {
	mu     sync.Mutex
	events []provisioning.AuditEvent
	fail   bool
}

func (r *recAuditor) Record(_ context.Context, ev provisioning.AuditEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail {
		return errors.New("audit store down")
	}
	r.events = append(r.events, ev)
	return nil
}

func (r *recAuditor) actions() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, e := range r.events {
		out = append(out, e.Action)
	}
	return out
}

type fixture struct {
	t     *testing.T
	su    *pgx.Conn
	st    *store.Store
	ss    *secrets.Store
	ten   *tenants.Service
	plat  *platform.Service
	edge  *headscaletest.Edge
	loc   *locator.Locator
	audit *recAuditor
	logs  *bytes.Buffer
	ad    *provisioning.Adopter
	// fake instances behind the edge
	a, b, c *headscaletest.Instance
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pg := storetest.Require(t)
	db := pg.NewDatabase(t)
	f := &fixture{t: t, su: pg.Admin(t, db), st: pg.OpenStore(t, db, "mg_api_tenant", "mg_api_platform", 8),
		audit: &recAuditor{}, logs: &bytes.Buffer{}}
	dir := t.TempDir()
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	write(t, filepath.Join(dir, "kek-1"), hex.EncodeToString(k)+"\n")
	write(t, filepath.Join(dir, secrets.ActiveFile), "kek-1\n")
	kr, err := secrets.LoadKeyring(secrets.KEKApp, dir)
	if err != nil {
		t.Fatal(err)
	}
	log := logx.New(f.logs, slog.LevelDebug, "test")
	if f.ss, err = secrets.New(f.st, secrets.Options{App: kr, Logger: log}); err != nil {
		t.Fatal(err)
	}
	f.ten, f.plat = tenants.New(f.st, tenants.Options{BaseDomain: baseDomain}), platform.New(f.st)
	tok := headscaletest.NewToken()
	f.edge = headscaletest.NewEdge(t, tok)
	tokenFile := filepath.Join(t.TempDir(), "edge_admin_token")
	write(t, tokenFile, tok+"\n")
	if f.loc, err = locator.New(f.ten, f.ss, locator.Options{AdminURL: f.edge.URL(), EdgeTokenFile: tokenFile,
		Logger: log}); err != nil {
		t.Fatal(err)
	}
	f.a, f.b, f.c = f.edge.AddInstance("tenant-a"), f.edge.AddInstance("tenant-b"), f.edge.AddInstance("tenant-c")
	f.ad = &provisioning.Adopter{Tenants: f.ten, Platform: f.plat, Secrets: f.ss, Locator: f.loc,
		Headscale: headscale.Options{Logger: log, Retry: headscale.RetryPolicy{Attempts: 1}}, Audit: f.audit, Log: log}
	return f
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// subject is one tenant of the tests (stable ids, as in the environment files of staging).
type subject struct {
	meta provisioning.Meta
	idp  uuid.UUID
}

func newSubject(slug string, n int32) subject {
	return subject{idp: uuid.Must(uuid.NewV7()), meta: provisioning.Meta{
		TenantID: uuid.New(), InstanceID: uuid.New(), Slug: slug, RunUID: 30000 + n,
		NetCIDR:     netip.MustParsePrefix("10.250.0." + []string{"0", "8", "16", "24", "32"}[n] + "/29"),
		Image:       "docker.io/headscale/headscale@sha256:" + strings.Repeat("1", 64),
		ImageDigest: "sha256:" + strings.Repeat("1", 64), TemplateVersion: "1", ConfigSHA256: strings.Repeat("c", 64),
	}}
}

func (s subject) request(key string) provisioning.AdoptRequest {
	tid := s.meta.TenantID
	return provisioning.AdoptRequest{Meta: s.meta, APIKey: headscale.NewSecret(key), HostName: "host-1",
		NewHost: &platform.HostSpec{Name: "host-1", Region: "lab", RunUIDFirst: 30000, RunUIDLast: 39999,
			TenantNetPool: netip.MustParsePrefix("10.250.0.0/16")},
		TenantName: "Tenant " + s.meta.Slug, BaseDomain: baseDomain,
		IdP: provisioning.KeycloakRealmIdP(s.idp, &tid, s.meta.Slug, baseDomain)}
}

func (f *fixture) count(table string) int {
	f.t.Helper()
	var n int
	if err := f.su.QueryRow(f.t.Context(), "SELECT count(*) FROM "+pgx.Identifier{table}.Sanitize()).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

// rows is a fingerprint of the registry and the SecretStore: a refused adoption must leave it unchanged.
func (f *fixture) rows() string {
	f.t.Helper()
	var s string
	err := f.su.QueryRow(f.t.Context(), `SELECT concat_ws('|',
		(SELECT string_agg(id::text||status||version, ',' ORDER BY id) FROM tenants),
		(SELECT string_agg(id::text||status||version||coalesce(api_key_secret_ref,'-'), ',' ORDER BY id) FROM tenant_instances),
		(SELECT string_agg(id::text||status||version, ',' ORDER BY id) FROM identity_providers),
		(SELECT string_agg(name, ',' ORDER BY id) FROM hosts),
		(SELECT string_agg(name||version::text||(destroyed_at IS NULL)::text, ',' ORDER BY id) FROM secrets))`).Scan(&s)
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}

func keyStates(i *headscaletest.Instance) map[string]bool {
	out := map[string]bool{}
	now := time.Now()
	for _, k := range i.Keys() {
		out[k.Prefix] = k.Valid(now)
	}
	return out
}

func eq(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

// TestAdoptTenantsAAndB — the acceptance of P2-T11: both tenants registered from their meta, the new key of each in
// the SecretStore, every other key of each instance expired (the short-lived Phase 1 key, a long-lived one, one that
// never expires), ForTenant reaching each tenant's own instance; tenant-c untouched (no request, keys unchanged, no row).
func TestAdoptTenantsAAndB(t *testing.T) {
	f := newFixture(t)
	a, b := newSubject("tenant-a", 0), newSubject("tenant-b", 1)
	phase1KeyA, phase1A := f.a.NewKey(time.Hour) // Phase 1: short-lived key used by the P1 tests
	_, longA := f.a.NewKey(30 * day)
	_, foreverA := f.a.NewKey(0)
	_, phase1B := f.b.NewKey(time.Hour)
	f.c.NewKey(time.Hour)
	f.c.NewKey(0)
	before := keyStates(f.c)

	keyA, prefixA := f.a.NewKey(90 * day) // `headscale apikeys create -e 2160h` on each instance
	keyB, prefixB := f.b.NewKey(90 * day)

	resA, err := f.ad.Adopt(t.Context(), a.request(keyA))
	if err != nil {
		t.Fatalf("adopt A: %v", err)
	}
	resB, err := f.ad.Adopt(t.Context(), b.request(keyB))
	if err != nil {
		t.Fatalf("adopt B: %v", err)
	}

	// results
	if !resA.HostCreated || resB.HostCreated || !resA.TenantCreated || !resA.InstanceCreated || !resA.IdPCreated ||
		resA.HeadscaleVersion != "v0.29.7" || resA.KeyPrefix != prefixA || resA.ValidKeys != 1 ||
		resA.SecretRef != "mgsec://"+a.meta.TenantID.String()+"/headscale-api-key#1" || resA.PreviousRef != "" ||
		resA.Activation.TenantFrom != "provisioning" || resA.Activation.InstanceFrom != "starting" {
		t.Errorf("result A: %+v", resA)
	}
	slices.Sort(resA.ExpiredPrefixes)
	want := []string{phase1A, longA, foreverA}
	slices.Sort(want)
	if !slices.Equal(resA.ExpiredPrefixes, want) || !slices.Equal(resB.ExpiredPrefixes, []string{phase1B}) {
		t.Errorf("expired A %v (want %v), B %v (want %v)", resA.ExpiredPrefixes, want, resB.ExpiredPrefixes, phase1B)
	}
	// the instances: only the new key is valid
	if v := f.a.ValidPrefixes(); !slices.Equal(v, []string{prefixA}) {
		t.Errorf("valid keys of A: %v, want only %s", v, prefixA)
	}
	if v := f.b.ValidPrefixes(); !slices.Equal(v, []string{prefixB}) {
		t.Errorf("valid keys of B: %v, want only %s", v, prefixB)
	}
	// tenant-c: never called, keys unchanged
	for _, r := range f.edge.Requests() {
		if r.Slug == "tenant-c" {
			t.Fatalf("a request reached tenant-c: %+v", r)
		}
	}
	if after := keyStates(f.c); !eq(before, after) {
		t.Errorf("tenant-c keys changed: %v → %v", before, after)
	}

	// the registry
	var n int
	if err := f.su.QueryRow(t.Context(), `SELECT count(*) FROM tenants WHERE slug = 'tenant-c'`).Scan(&n); err != nil || n != 0 {
		t.Errorf("tenant-c in the registry: %d %v", n, err)
	}
	for _, s := range []subject{a, b} {
		var tstatus, istatus, ref, prefix, issuer, client, region string
		err := f.su.QueryRow(t.Context(), `SELECT t.status, i.status, i.api_key_secret_ref, i.api_key_prefix, p.issuer,
				p.client_id, t.deployment_region
			FROM tenants t JOIN tenant_instances i ON i.tenant_id = t.id JOIN identity_providers p ON p.tenant_id = t.id
			WHERE t.id = $1 AND i.id = $2 AND p.id = $3 AND p.status = 'active' AND p.driver = 'keycloak'
			  AND i.server_url = 'https://'||t.slug||'.mesh.mg.test' AND i.base_domain = t.slug||'.tail.mg.test'
			  AND i.internal_address = 'hs-'||t.slug||':8080' AND i.headscale_version = 'v0.29.7'`,
			s.meta.TenantID, s.meta.InstanceID, s.idp).Scan(&tstatus, &istatus, &ref, &prefix, &issuer, &client, &region)
		if err != nil {
			t.Fatalf("registry of %s: %v", s.meta.Slug, err)
		}
		if tstatus != "active" || istatus != "running" || issuer != "https://auth.mg.test/realms/"+s.meta.Slug ||
			client != "mg-portal" || region != "lab" || !strings.HasPrefix(ref, "mgsec://"+s.meta.TenantID.String()+"/") {
			t.Errorf("%s: tenant %s instance %s issuer %s client %s region %s ref %s", s.meta.Slug, tstatus, istatus,
				issuer, client, region, ref)
		}
	}

	// ForTenant (production path, fresh registry) reaches each tenant's own instance and never the other
	reg := headscale.NewRegistry(f.loc, headscale.Options{})
	for _, c := range []struct {
		s      subject
		prefix string
		other  string
	}{{a, prefixA, prefixB}, {b, prefixB, prefixA}} {
		inst, err := reg.ForTenant(t.Context(), c.s.meta.TenantID)
		if err != nil {
			t.Fatalf("ForTenant(%s): %v", c.s.meta.Slug, err)
		}
		keys, err := inst.ListAPIKeys(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, k := range keys {
			got = append(got, k.Prefix)
		}
		if !slices.Contains(got, c.prefix) || slices.Contains(got, c.other) {
			t.Errorf("ForTenant(%s) listed %v: want %s and never %s", c.s.meta.Slug, got, c.prefix, c.other)
		}
	}

	// the Phase 1 key no longer opens the instance (401 ⇒ api_key_rejected)
	cand, err := f.loc.Candidate(a.meta.InstanceID, "tenant-a", headscale.NewSecret(phase1KeyA))
	if err != nil {
		t.Fatal(err)
	}
	old, err := headscale.NewRegistry(headscale.StaticLocator{a.meta.TenantID: cand}, headscale.Options{}).
		ForTenant(t.Context(), a.meta.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	var he *headscale.Error
	if _, err := old.ListAPIKeys(t.Context()); !errors.As(err, &he) || he.Kind != headscale.KindAPIKeyRejected {
		t.Errorf("the Phase 1 key after adoption: %v, want api_key_rejected", err)
	}

	// audit: requested then succeeded, paired by operation id
	acts := f.audit.actions()
	if !slices.Equal(acts, []string{"platform.instance.adopt.requested", "platform.instance.adopt.succeeded",
		"platform.instance.adopt.requested", "platform.instance.adopt.succeeded"}) {
		t.Errorf("audit actions %v", acts)
	}
	if ev := f.audit.events; *ev[0].OperationID != *ev[1].OperationID || *ev[0].TenantID != a.meta.TenantID {
		t.Errorf("audit pairing: %+v %+v", ev[0], ev[1])
	}
}

// TestAdoptIsIdempotentAndRotates — running the command again (with another new key) leaves the registry rows as they
// are, stores version 2, erases version 1 and expires the previous platform key.
func TestAdoptIsIdempotentAndRotates(t *testing.T) {
	f := newFixture(t)
	a := newSubject("tenant-a", 0)
	key1, prefix1 := f.a.NewKey(90 * day)
	if _, err := f.ad.Adopt(t.Context(), a.request(key1)); err != nil {
		t.Fatal(err)
	}
	var v1 int64
	if err := f.su.QueryRow(t.Context(), `SELECT version FROM tenants WHERE id = $1`, a.meta.TenantID).Scan(&v1); err != nil {
		t.Fatal(err)
	}
	key2, prefix2 := f.a.NewKey(90 * day)
	res, err := f.ad.Adopt(t.Context(), a.request(key2))
	if err != nil {
		t.Fatalf("second adoption: %v", err)
	}
	if res.TenantCreated || res.InstanceCreated || res.IdPCreated || res.HostCreated ||
		res.Activation != (tenants.Activation{}) || !slices.Equal(res.ExpiredPrefixes, []string{prefix1}) ||
		res.SecretRef != "mgsec://"+a.meta.TenantID.String()+"/headscale-api-key#2" ||
		res.PreviousRef != "mgsec://"+a.meta.TenantID.String()+"/headscale-api-key#1" ||
		!slices.Equal(res.DestroyedRefs, []string{res.PreviousRef}) {
		t.Fatalf("second adoption: %+v", res)
	}
	if v := f.a.ValidPrefixes(); !slices.Equal(v, []string{prefix2}) {
		t.Errorf("valid keys %v, want only %s", v, prefix2)
	}
	var v2 int64
	var destroyed bool
	if err := f.su.QueryRow(t.Context(), `SELECT t.version, s.destroyed_at IS NOT NULL FROM tenants t, secrets s
		WHERE t.id = $1 AND s.tenant_id = t.id AND s.name = 'headscale-api-key' AND s.version = 1`,
		a.meta.TenantID).Scan(&v2, &destroyed); err != nil {
		t.Fatal(err)
	}
	if v2 != v1 || !destroyed {
		t.Errorf("tenant version %d → %d (want unchanged), version 1 destroyed: %v", v1, v2, destroyed)
	}
	if f.count("tenants") != 1 || f.count("tenant_instances") != 1 || f.count("identity_providers") != 1 ||
		f.count("hosts") != 1 {
		t.Error("the second adoption added registry rows")
	}
	// the stored key is the new one
	pt, err := f.ss.Get(t.Context(), secrets.TenantRef(a.meta.TenantID, provisioning.APIKeySecretName, 2))
	if err != nil || string(pt.Bytes()) != key2 {
		t.Fatalf("stored key: %v", err)
	}
}

// TestAdoptRefusals — every refusal leaves the registry, the SecretStore and the keys of the instances unchanged.
func TestAdoptRefusals(t *testing.T) {
	f := newFixture(t)
	a, b := newSubject("tenant-a", 0), newSubject("tenant-b", 1)
	keyA, _ := f.a.NewKey(90 * day)
	if _, err := f.ad.Adopt(t.Context(), a.request(keyA)); err != nil {
		t.Fatal(err)
	}

	type tc struct {
		name string
		req  func() provisioning.AdoptRequest
		want error
		prep func()
	}
	freshA := func() string { k, _ := f.a.NewKey(90 * day); return k }
	freshB := func() string { k, _ := f.b.NewKey(90 * day); return k }
	cases := []tc{
		{name: "second instance for the same tenant", want: provisioning.ErrRefused, req: func() provisioning.AdoptRequest {
			s := a
			s.meta.InstanceID, s.meta.RunUID, s.meta.NetCIDR = uuid.New(), 30005, netip.MustParsePrefix("10.250.0.40/29")
			return s.request(freshA())
		}},
		{name: "slug of another tenant", want: provisioning.ErrRefused, req: func() provisioning.AdoptRequest {
			s := b
			s.meta.Slug = "tenant-a"
			return s.request(freshA())
		}},
		{name: "instance of another tenant", want: provisioning.ErrRefused, req: func() provisioning.AdoptRequest {
			s := b
			s.meta.InstanceID = a.meta.InstanceID
			return s.request(freshB())
		}},
		{name: "identity provider id of another tenant", want: provisioning.ErrRefused, req: func() provisioning.AdoptRequest {
			s := b
			s.idp = a.idp
			return s.request(freshB())
		}},
		{name: "different issuer for the registered IdP", want: provisioning.ErrRefused, req: func() provisioning.AdoptRequest {
			r := a.request(freshA())
			r.IdP.Issuer = "https://auth.other.test/realms/tenant-a"
			return r
		}},
		{name: "instance values changed", want: provisioning.ErrRefused, req: func() provisioning.AdoptRequest {
			s := a
			s.meta.RunUID = 30009
			return s.request(freshA())
		}},
		{name: "host registered with other pools", want: provisioning.ErrRefused, req: func() provisioning.AdoptRequest {
			r := b.request(freshB())
			r.NewHost.Region = "other"
			return r
		}},
		{name: "run_uid outside the host range", want: provisioning.ErrRefused, req: func() provisioning.AdoptRequest {
			s := b
			s.meta.RunUID = 40001
			return s.request(freshB())
		}},
		{name: "unregistered host without its pools", want: provisioning.ErrRefused, req: func() provisioning.AdoptRequest {
			r := b.request(freshB())
			r.HostName, r.NewHost = "host-2", nil
			return r
		}},
		{name: "key expiring within 14 days", want: provisioning.ErrKeyCheck, req: func() provisioning.AdoptRequest {
			k, _ := f.b.NewKey(13 * day)
			return b.request(k)
		}},
		{name: "key created on another instance", want: provisioning.ErrKeyCheck, req: func() provisioning.AdoptRequest {
			return b.request(freshA())
		}},
		{name: "slug unknown to the edge", want: provisioning.ErrKeyCheck, req: func() provisioning.AdoptRequest {
			s := newSubject("tenant-z", 3)
			return s.request(freshB())
		}},
		{name: "not an API key", want: provisioning.ErrRefused, req: func() provisioning.AdoptRequest {
			return b.request("hskey-" + "auth-" + strings.Repeat("a", 12) + "-" + strings.Repeat("b", 64))
		}},
		{name: "suspended tenant", want: provisioning.ErrRefused, prep: func() {
			if _, err := f.su.Exec(t.Context(), `UPDATE tenants SET status = 'suspended' WHERE id = $1`, a.meta.TenantID); err != nil {
				t.Fatal(err)
			}
		}, req: func() provisioning.AdoptRequest { return a.request(freshA()) }},
	}
	for _, c := range cases {
		if c.prep != nil {
			c.prep()
		}
		req := c.req()
		before, keysA, keysB := f.rows(), keyStates(f.a), keyStates(f.b)
		events := len(f.audit.actions())
		_, err := f.ad.Adopt(t.Context(), req)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
			continue
		}
		if f.rows() != before {
			t.Errorf("%s: the registry or the SecretStore changed", c.name)
		}
		if !eq(keysA, keyStates(f.a)) || !eq(keysB, keyStates(f.b)) {
			t.Errorf("%s: keys of an instance changed", c.name)
		}
		if len(f.audit.actions()) != events {
			t.Errorf("%s: an audit event was written for a refusal before any change", c.name)
		}
		if strings.Contains(err.Error(), req.APIKey.Reveal()) {
			t.Errorf("%s: the error carries the key", c.name)
		}
	}

	// an audit store that refuses the .requested event stops the command before any change
	f.audit.fail = true
	defer func() { f.audit.fail = false }()
	before := f.rows()
	if _, err := f.ad.Adopt(t.Context(), b.request(freshB())); err == nil || !strings.Contains(err.Error(), "audit") {
		t.Fatalf("adoption with a failing audit store: %v", err)
	}
	if f.rows() != before {
		t.Error("changes were made although .requested could not be recorded")
	}
}

// TestAdoptVerifyFailureRestores — the key works in the pre-flight but the verification through Registry.ForTenant
// fails: the instance keeps its previous key reference, the new secret version is erased, no key is expired and
// nothing is activated; a later run completes.
func TestAdoptVerifyFailureRestores(t *testing.T) {
	f := newFixture(t)
	a := newSubject("tenant-a", 0)
	_, phase1 := f.a.NewKey(time.Hour)
	key1, _ := f.a.NewKey(90 * day)
	// the first GET /api/v1/apikey (pre-flight) passes, every later one answers 503
	f.edge.SetHook(func(r headscaletest.Request, n int) (int, string, bool) {
		if r.Method == "GET" && r.Path == "/api/v1/apikey" && n >= 1 {
			return 503, "", true
		}
		return 0, "", false
	})
	res, err := f.ad.Adopt(t.Context(), a.request(key1))
	if !errors.Is(err, provisioning.ErrVerify) {
		t.Fatalf("err = %v, want ErrVerify", err)
	}
	var ref *string
	var istatus, tstatus string
	var destroyed bool
	if err := f.su.QueryRow(t.Context(), `SELECT i.api_key_secret_ref, i.status, t.status,
			(SELECT destroyed_at IS NOT NULL FROM secrets WHERE tenant_id = t.id AND version = 1)
		FROM tenant_instances i JOIN tenants t ON t.id = i.tenant_id WHERE i.id = $1`,
		a.meta.InstanceID).Scan(&ref, &istatus, &tstatus, &destroyed); err != nil {
		t.Fatal(err)
	}
	if ref != nil || istatus != "starting" || tstatus != "provisioning" || !destroyed {
		t.Fatalf("after a failed verification: ref %v, instance %s, tenant %s, version 1 destroyed %v (result %+v)",
			ref, istatus, tstatus, destroyed, res)
	}
	if !slices.Contains(f.a.ValidPrefixes(), phase1) {
		t.Fatal("a key was expired although the verification failed")
	}
	if acts := f.audit.actions(); acts[len(acts)-1] != "platform.instance.adopt.failed" {
		t.Errorf("audit %v", acts)
	}

	f.edge.SetHook(nil)
	key2, prefix2 := f.a.NewKey(90 * day)
	res, err = f.ad.Adopt(t.Context(), a.request(key2))
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if res.SecretRef != "mgsec://"+a.meta.TenantID.String()+"/headscale-api-key#2" || res.PreviousRef != "" ||
		!slices.Equal(f.a.ValidPrefixes(), []string{prefix2}) || res.Activation.TenantFrom != "provisioning" {
		t.Fatalf("second run: %+v, valid %v", res, f.a.ValidPrefixes())
	}
}

// TestAdoptExpireFailure — a key that cannot be expired fails the command (ErrExpire) after the new key is registered;
// tenant and instance stay unactivated; a later run finishes the job.
func TestAdoptExpireFailure(t *testing.T) {
	f := newFixture(t)
	a := newSubject("tenant-a", 0)
	_, stuck := f.a.NewKey(time.Hour)
	_, other := f.a.NewKey(time.Hour)
	f.edge.FailExpire(stuck)
	key1, prefix1 := f.a.NewKey(90 * day)
	res, err := f.ad.Adopt(t.Context(), a.request(key1))
	if !errors.Is(err, provisioning.ErrExpire) || !strings.Contains(err.Error(), stuck) {
		t.Fatalf("err = %v, want ErrExpire naming %s", err, stuck)
	}
	if !slices.Equal(res.ExpiredPrefixes, []string{other}) || res.SecretRef == "" {
		t.Fatalf("result %+v", res)
	}
	var tstatus string
	if err := f.su.QueryRow(t.Context(), `SELECT status FROM tenants WHERE id = $1`, a.meta.TenantID).Scan(&tstatus); err != nil ||
		tstatus != "provisioning" {
		t.Fatalf("tenant %s %v (want provisioning)", tstatus, err)
	}
	// the platform already uses the new key
	inst, err := headscale.NewRegistry(f.loc, headscale.Options{}).ForTenant(t.Context(), a.meta.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inst.Health(t.Context()); err != nil {
		t.Fatal(err)
	}

	// once the instance can write again, a run with another new key finishes the job
	f.edge.HealExpire()
	key2, prefix2 := f.a.NewKey(90 * day)
	res, err = f.ad.Adopt(t.Context(), a.request(key2))
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	slices.Sort(res.ExpiredPrefixes)
	want := []string{stuck, prefix1}
	slices.Sort(want)
	if !slices.Equal(res.ExpiredPrefixes, want) || !slices.Equal(f.a.ValidPrefixes(), []string{prefix2}) ||
		res.Activation.TenantFrom != "provisioning" || res.Activation.InstanceFrom != "starting" {
		t.Fatalf("second run: %+v, valid %v", res, f.a.ValidPrefixes())
	}
}
