package hsisolation_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
)

// Tenants and instances of testdata/params-{a,b}.json.
var (
	tenantA   = uuid.MustParse("a1a1a1a1-1111-4111-8111-a1a1a1a1a1a1")
	instanceA = uuid.MustParse("a2a2a2a2-2222-4222-8222-a2a2a2a2a2a2")
	tenantB   = uuid.MustParse("b1b1b1b1-1111-4111-8111-b1b1b1b1b1b1")
	instanceB = uuid.MustParse("b2b2b2b2-2222-4222-8222-b2b2b2b2b2b2")
)

// env is what run.sh prepared: the edge admin listener, the two instances' slugs and API keys, the edge token.
type env struct {
	adminURL     string
	slugA, slugB string
	keyA, keyB   headscale.Secret
	edgeToken    headscale.Secret
}

func setup(t *testing.T) *env {
	t.Helper()
	if os.Getenv("MG_HSISO_ADMIN_URL") == "" {
		t.Skip("isolation environment not set: run tests/isolation/headscale/run.sh (two real Headscale instances)")
	}
	e := &env{adminURL: os.Getenv("MG_HSISO_ADMIN_URL"), slugA: os.Getenv("MG_HSISO_SLUG_A"), slugB: os.Getenv("MG_HSISO_SLUG_B")}
	dir := os.Getenv("MG_HSISO_SECRETS_DIR")
	for name, dst := range map[string]*headscale.Secret{"api_key_a": &e.keyA, "api_key_b": &e.keyB, "edge_token": &e.edgeToken} {
		b, err := os.ReadFile(filepath.Join(dir, name)) //nolint:gosec // G304: directory set by run.sh (test harness)
		if err != nil {
			t.Fatalf("read secret %s: %v", name, err)
		}
		*dst = headscale.NewSecret(strings.TrimSpace(string(b)))
	}
	if e.slugA == "" || e.slugB == "" || e.slugA == e.slugB {
		t.Fatal("MG_HSISO_SLUG_A and MG_HSISO_SLUG_B are required and must differ")
	}
	return e
}

// target is a registry row as the Locator hands it out: instance, routing slug (what internal_address designates
// behind the edge) and API key (what api_key_secret_ref resolves to).
func (e *env) target(instance uuid.UUID, slug string, key headscale.Secret) headscale.Target {
	return headscale.Target{InstanceID: instance, Slug: slug, AdminURL: e.adminURL, APIKey: key, EdgeToken: e.edgeToken}
}

func (e *env) registry(targets map[uuid.UUID]headscale.Target) *headscale.CachingRegistry {
	return headscale.NewRegistry(headscale.StaticLocator(targets), headscale.Options{
		Timeout: 15 * time.Second, Retry: headscale.RetryPolicy{Attempts: 1},
	})
}

// correct is the registry as it must be.
func (e *env) correct() *headscale.CachingRegistry {
	return e.registry(map[uuid.UUID]headscale.Target{
		tenantA: e.target(instanceA, e.slugA, e.keyA), tenantB: e.target(instanceB, e.slugB, e.keyB),
	})
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	t.Cleanup(cancel)
	return c
}

func forTenant(t *testing.T, reg *headscale.CachingRegistry, tenant uuid.UUID) headscale.Instance {
	t.Helper()
	inst, err := reg.ForTenant(ctx(t), tenant)
	if err != nil {
		t.Fatalf("ForTenant(%s): %v", tenant, err)
	}
	return inst
}

// grantsPolicy allows exactly tcp:<port> between all nodes (a document the adapter's validation accepts).
func grantsPolicy(port int) string {
	return fmt.Sprintf(`{"grants":[{"src":["*"],"dst":["*"],"ip":["tcp:%d"]}],"ssh":[]}`, port)
}

func policyHash(t *testing.T, inst headscale.Instance) string {
	t.Helper()
	p, err := inst.GetPolicy(ctx(t))
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	sum := sha256.Sum256([]byte(p.Data))
	return hex.EncodeToString(sum[:])
}

func userNames(t *testing.T, inst headscale.Instance) []string {
	t.Helper()
	users, err := inst.ListUsers(ctx(t), headscale.UserFilter{})
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	var out []string
	for _, u := range users {
		out = append(out, u.Name)
	}
	slices.Sort(out)
	return out
}

func ensureUser(t *testing.T, inst headscale.Instance, name string) {
	t.Helper()
	if slices.Contains(userNames(t, inst), name) {
		return
	}
	if _, err := inst.CreateUser(ctx(t), headscale.CreateUser{Name: name, DisplayName: "isolation " + name}); err != nil {
		t.Fatalf("CreateUser %s: %v", name, err)
	}
}

// markers: one user per instance, so that a call reaching the wrong instance would be visible in what it returns.
const markerA, markerB = "iso-marker-a", "iso-marker-b"

func prepare(t *testing.T, e *env) {
	t.Helper()
	reg := e.correct()
	a, b := forTenant(t, reg, tenantA), forTenant(t, reg, tenantB)
	ensureUser(t, a, markerA)
	ensureUser(t, b, markerB)
	if slices.Contains(userNames(t, a), markerB) || slices.Contains(userNames(t, b), markerA) {
		t.Fatal("the two instances share their users — the environment is wrong")
	}
}

// TestIT06PolicyApplyIsolated — IT-06 (§5.2 boundary 6, adapter level: SetPolicy through Registry.ForTenant): applying
// policies to A leaves the sha256 of B's GetPolicy — and B's users — unchanged, and the other way round.
func TestIT06PolicyApplyIsolated(t *testing.T) {
	e := setup(t)
	prepare(t, e)
	reg := e.correct()
	a, b := forTenant(t, reg, tenantA), forTenant(t, reg, tenantB)
	for inst, doc := range map[headscale.Instance]string{a: grantsPolicy(1100), b: grantsPolicy(1200)} {
		if _, err := inst.SetPolicy(ctx(t), doc); err != nil { // fresh instances have no policy (PL-02)
			t.Fatalf("baseline SetPolicy: %v", err)
		}
	}
	for _, tc := range []struct {
		name           string
		target, victim headscale.Instance
		ports          []int
	}{{"apply on A, B unchanged", a, b, []int{1101, 1102, 1103}}, {"apply on B, A unchanged", b, a, []int{1201, 1202}}} {
		victimHash, victimUsers := policyHash(t, tc.victim), userNames(t, tc.victim)
		for _, port := range tc.ports {
			doc := grantsPolicy(port)
			if _, err := tc.target.SetPolicy(ctx(t), doc); err != nil {
				t.Fatalf("%s: SetPolicy(tcp:%d): %v", tc.name, port, err)
			}
			got, err := tc.target.GetPolicy(ctx(t))
			if err != nil || got.Data != doc {
				t.Fatalf("%s: the target does not hold the applied policy (%v)", tc.name, err)
			}
			if h := policyHash(t, tc.victim); h != victimHash {
				t.Errorf("IT-06 %s: sha256(GetPolicy) of the other instance changed %s → %s after tcp:%d", tc.name, victimHash[:12], h[:12], port)
			}
		}
		if u := userNames(t, tc.victim); !slices.Equal(u, victimUsers) {
			t.Errorf("IT-06 %s: users of the other instance changed %v → %v", tc.name, victimUsers, u)
		}
		t.Logf("IT-06 %s: %d policies applied, sha256(GetPolicy) of the other instance stayed %s…", tc.name, len(tc.ports), victimHash[:16])
	}
}

// readOps are the calls a swapped registry entry is tried with: each must fail, none may return data.
var readOps = map[string]func(context.Context, headscale.Instance) (string, error){
	"ListUsers": func(c context.Context, i headscale.Instance) (string, error) {
		u, err := i.ListUsers(c, headscale.UserFilter{})
		return fmt.Sprint(u), err
	},
	"ListNodes": func(c context.Context, i headscale.Instance) (string, error) {
		n, err := i.ListNodes(c, "")
		return fmt.Sprint(n), err
	},
	"GetPolicy": func(c context.Context, i headscale.Instance) (string, error) {
		p, err := i.GetPolicy(c)
		return p.Data, err
	},
	"ListPreAuthKeys": func(c context.Context, i headscale.Instance) (string, error) {
		k, err := i.ListPreAuthKeys(c)
		return fmt.Sprint(k), err
	},
	"ListAPIKeys": func(c context.Context, i headscale.Instance) (string, error) {
		k, err := i.ListAPIKeys(c)
		return fmt.Sprint(k), err
	},
	"SetPolicy": func(c context.Context, i headscale.Instance) (string, error) {
		p, err := i.SetPolicy(c, grantsPolicy(1999))
		return p.Data, err
	},
}

// refusedEverywhere calls every read op (and one write) for tenant through a registry holding target, each on a fresh
// registry (no breaker carried over): all must fail with api_key_rejected (HTTP 401 after reloading the key) and no
// answer may carry the other instance's marker.
func refusedEverywhere(t *testing.T, e *env, tenant uuid.UUID, target headscale.Target, foreignMarker string) {
	t.Helper()
	for name, op := range readOps {
		reg := e.registry(map[uuid.UUID]headscale.Target{tenant: target})
		inst, err := reg.ForTenant(ctx(t), tenant) // the version check needs no API key
		if err != nil {
			t.Fatalf("ForTenant: %v", err)
		}
		out, err := op(ctx(t), inst)
		var he *headscale.Error
		if !errors.As(err, &he) || he.Kind != headscale.KindAPIKeyRejected || !errors.Is(err, headscale.ErrAPIKeyRejected) {
			t.Errorf("%s: %v, want api_key_rejected (401)", name, err)
		}
		if strings.Contains(out, foreignMarker) || (err != nil && strings.Contains(err.Error(), foreignMarker)) {
			t.Errorf("%s returned data of the other instance (%q)", name, foreignMarker)
		}
	}
}

// TestIT10APIKeyOfAOnInstanceB — IT-10 (§5.2 boundary 10, P2-T15 part): the API key of A presented to instance B (and
// B's to A) is refused with 401 on every call; the right key on the right instance works (control).
func TestIT10APIKeyOfAOnInstanceB(t *testing.T) {
	e := setup(t)
	prepare(t, e)
	refusedEverywhere(t, e, tenantA, e.target(instanceB, e.slugB, e.keyA), markerB)
	refusedEverywhere(t, e, tenantB, e.target(instanceA, e.slugA, e.keyB), markerA)
	reg := e.correct()
	if u := userNames(t, forTenant(t, reg, tenantA)); !slices.Contains(u, markerA) {
		t.Errorf("control: A's key on A lists %v", u)
	}
	t.Logf("IT-10: %d calls with A's key on B and B's key on A, all 401", 2*len(readOps))
}

// TestIT20RegistrySwap — IT-20 (§5.2, registry fault injection) at the adapter level: the registry entries of A and B
// with internal_address swapped (A's entry routes to B's instance with A's key) or api_key_secret_ref swapped (A's
// instance with B's key) — every call through ForTenant fails with 401 and returns nothing of the other tenant.
func TestIT20RegistrySwap(t *testing.T) {
	e := setup(t)
	prepare(t, e)
	t.Run("internal_address swapped", func(t *testing.T) {
		refusedEverywhere(t, e, tenantA, e.target(instanceA, e.slugB, e.keyA), markerB)
		refusedEverywhere(t, e, tenantB, e.target(instanceB, e.slugA, e.keyB), markerA)
	})
	t.Run("api_key_secret_ref swapped", func(t *testing.T) {
		refusedEverywhere(t, e, tenantA, e.target(instanceA, e.slugA, e.keyB), markerB)
		refusedEverywhere(t, e, tenantB, e.target(instanceB, e.slugB, e.keyA), markerA)
	})
	t.Run("both swapped", func(t *testing.T) {
		// Swapping both fields makes A's entry a complete, valid entry of B: the adapter cannot tell. Only the
		// production Locator (P2-T11) refuses it — the secret reference names tenant B, not A (§5.2 boundary 10,
		// P2-T04 "ForTenant kiểm ref.Tenant == tenantID"). This case runs against that Locator once it is merged.
		t.Skip("IT-20 both swapped / foreign secret reference: needs the production Locator of P2-T11 (docs/planning/evidence/P2-T15.md)")
	})
}
