package apikey

// Unit tests of the rotation (no database): the fakes of fakes_test.go around the real adapter (internal/headscale)
// talking HTTP to the fake edge admin listener of headscaletest. Every test ends with the invariants of the task:
// a working key is recorded, no valid key other than it is left unreported, and no key reaches a log, an error, an
// audit or security event, or a result.

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	dto "github.com/prometheus/client_model/go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale/headscaletest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
)

func approx(t *testing.T, got time.Time, want time.Time, tol time.Duration, what string) {
	t.Helper()
	if d := got.Sub(want); d > tol || d < -tol {
		t.Fatalf("%s: %s, want %s ± %s", what, got.UTC().Format(time.RFC3339), want.UTC().Format(time.RFC3339), tol)
	}
}

// TestRotateDue: the flow of §11.4 with the current key — a new 90-day key, verified, stored as version 2, swapped
// with the audit pair, the cache of this process invalidated, the old key expired (401) and its secret version erased;
// a registry of "another process" that cached the old key keeps working (401 ⇒ reload ⇒ new key).
func TestRotateDue(t *testing.T) {
	f := newFixture(t, 10*day, false)
	ctx := context.Background()
	other := headscale.NewRegistry(f.loc, headscale.Options{Retry: headscale.RetryPolicy{Attempts: 1}})
	cached, err := other.ForTenant(ctx, f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cached.ListAPIKeys(ctx); err != nil {
		t.Fatal(err)
	}
	before := len(f.px.requests())
	start := time.Now()
	res, err := f.rotate(Request{Trigger: TriggerSchedule})
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if res.Outcome != OutcomeRotated || res.Mode != ModeAPI || res.PreviousPrefix != f.p0 || len(res.KeyPrefix) != 12 ||
		res.KeyPrefix == f.p0 || res.RefVersion != 2 || res.ValidKeys != 1 || !slices.Equal(res.ExpiredPrefixes, []string{f.p0}) ||
		!slices.Equal(res.DestroyedRefs, []int32{1}) || res.ExpiresAt == nil {
		t.Fatalf("result: %+v", res)
	}
	approx(t, *res.ExpiresAt, start.Add(MaxTTL), time.Minute, "new expiry")
	if v := f.valid(); !slices.Equal(v, []string{res.KeyPrefix}) {
		t.Fatalf("valid keys after: %v", v)
	}
	st := f.be.snapshot()
	want := secrets.TenantRef(f.tenant, SecretName, 2).String()
	if st.Ref != want || st.Prefix != res.KeyPrefix || st.ExpiresAt == nil || !st.ExpiresAt.Equal(*res.ExpiresAt) {
		t.Fatalf("registry after: %+v", st)
	}
	v2, err := f.sec.get(want)
	if err != nil || headscale.APIKeyPrefix(headscale.NewSecret(v2)) != res.KeyPrefix {
		t.Fatalf("stored version 2: %v", err)
	}
	if _, err := f.sec.get(secrets.TenantRef(f.tenant, SecretName, 1).String()); !errors.Is(err, secrets.ErrDestroyed) {
		t.Fatalf("version 1 not destroyed: %v", err)
	}
	if a := f.be.actions(); !slices.Equal(a, []string{ActionRotate + ".requested", ActionRotate + ".succeeded"}) {
		t.Fatalf("audit: %v", a)
	}
	if !strings.Contains(f.be.audits[1].Details, `"key_prefix":"`+res.KeyPrefix+`"`) ||
		!strings.Contains(f.be.audits[1].Details, `"previous_prefix":"`+f.p0+`"`) {
		t.Fatalf("succeeded details: %s", f.be.audits[1].Details)
	}
	if len(f.inv.calls) != 1 || f.inv.calls[0] != f.tenant {
		t.Fatalf("invalidations: %v", f.inv.calls)
	}
	if !f.refused(f.k0) {
		t.Fatal("the old key is still accepted")
	}
	// the request order through the edge: list (old), create (old), verify (new), expire (new), list (new)
	var seq []string
	for _, r := range f.px.requests()[before:] {
		if strings.HasPrefix(r.Path, "/api/v1/apikey") {
			who := "new"
			if r.Bearer == f.p0 {
				who = "old"
			}
			seq = append(seq, r.Method+" "+strings.TrimPrefix(r.Path, "/api/v1/")+" "+who)
		}
	}
	if !slices.Equal(seq, []string{"GET apikey old", "POST apikey old", "GET apikey new", "POST apikey/expire new", "GET apikey new"}) {
		t.Fatalf("call sequence: %v", seq)
	}
	// another process with the old key cached: the first call is refused, reloaded, replayed with the new key
	if _, err := cached.ListAPIKeys(ctx); err != nil {
		t.Fatalf("cached instance after the rotation: %v", err)
	}
	if inst, err := other.ForTenant(ctx, f.tenant); err != nil {
		t.Fatal(err)
	} else if _, err := inst.ListAPIKeys(ctx); err != nil {
		t.Fatalf("registry of another process after the rotation: %v", err)
	}
	if got := metricValue(t, f, MetricRotations, map[string]string{"result": ResultRotated}); got != 1 {
		t.Fatalf("rotations metric: %v", got)
	}
	in := metricValue(t, f, MetricExpiresIn, map[string]string{"instance_id": f.instance.String(), "tenant_id": f.tenant.String()})
	if in < (MaxTTL-time.Hour).Seconds() || in > MaxTTL.Seconds() {
		t.Fatalf("expires_in gauge: %v", in)
	}
	f.working()
	f.noOrphans()
	f.noSecret()
	if len(f.secev.events) != 0 {
		t.Fatalf("security events of a normal rotation: %s", f.secev.dump())
	}
}

// TestNotDueAndForce: a key that expires in 60 days is left alone (no audit, nothing created); --force rotates it.
func TestNotDueAndForce(t *testing.T) {
	f := newFixture(t, 60*day, false)
	res, err := f.rotate(Request{})
	if err != nil || res.Outcome != OutcomeSkipped || res.SkipReason != SkipNotDue || res.KeyPrefix != f.p0 {
		t.Fatalf("not due: %+v %v", res, err)
	}
	if len(f.be.actions()) != 0 || len(f.inst.Keys()) != 1 {
		t.Fatalf("a not-due run changed something: audit %v keys %d", f.be.actions(), len(f.inst.Keys()))
	}
	res, err = f.rotate(Request{Force: true, Trigger: TriggerAdmin})
	if err != nil || res.Outcome != OutcomeRotated || !res.Forced || res.KeyPrefix == f.p0 {
		t.Fatalf("forced: %+v %v", res, err)
	}
	if v := f.valid(); !slices.Equal(v, []string{res.KeyPrefix}) {
		t.Fatalf("valid after forced: %v", v)
	}
	// a key without recorded expiry is due
	f.be.set(func(s *instanceState) { s.ExpiresAt = nil })
	if res, err = f.rotate(Request{}); err != nil || res.Outcome != OutcomeRotated {
		t.Fatalf("no recorded expiry: %+v %v", res, err)
	}
	f.working()
	f.noOrphans()
	f.noSecret()
}

// TestSkipRules: quarantined, removed, stopped, allocated instances, tenants out of reach, a running lifecycle job and
// an instance without a recorded key are skipped without any call to Headscale; a suspended tenant is rotated.
func TestSkipRules(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*instanceState)
		want   string
	}{
		{"quarantined", func(s *instanceState) { s.Status = "quarantined" }, SkipQuarantined},
		{"removed", func(s *instanceState) { s.Status = "removed" }, SkipRemoved},
		{"stopped", func(s *instanceState) { s.Status = "stopped" }, SkipNotRunning},
		{"allocated", func(s *instanceState) { s.Status = "allocated" }, SkipNotRunning},
		{"tenant deleted", func(s *instanceState) { s.TenantStatus = "deleted" }, SkipTenantUnreachable},
		{"tenant deprovisioning", func(s *instanceState) { s.TenantStatus = "deprovisioning" }, SkipTenantUnreachable},
		{"lifecycle job", func(s *instanceState) { s.LifecycleBusy = true }, SkipLifecycleBusy},
		{"no key", func(s *instanceState) { s.Ref, s.Prefix = "", "" }, SkipNoKey},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, 2*day, false)
			f.be.set(c.mutate)
			res, err := f.rotate(Request{Force: true})
			if err != nil || res.Outcome != OutcomeSkipped || res.SkipReason != c.want {
				t.Fatalf("%+v %v", res, err)
			}
			if n := len(f.px.requests()); n != 0 || len(f.be.actions()) != 0 {
				t.Fatalf("skipped run called Headscale %d times, audit %v", n, f.be.actions())
			}
		})
	}
	t.Run("missing", func(t *testing.T) {
		f := newFixture(t, 2*day, false)
		f.be.missing = true
		if res, err := f.rotate(Request{}); err != nil || res.SkipReason != SkipInstanceNotFound {
			t.Fatalf("%+v %v", res, err)
		}
	})
	t.Run("suspended tenant is rotated", func(t *testing.T) {
		f := newFixture(t, 2*day, false)
		f.be.set(func(s *instanceState) { s.TenantStatus = "suspended" })
		if res, err := f.rotate(Request{}); err != nil || res.Outcome != OutcomeRotated {
			t.Fatalf("%+v %v", res, err)
		}
	})
	t.Run("foreign reference", func(t *testing.T) {
		f := newFixture(t, 2*day, false)
		f.be.set(func(s *instanceState) { s.Ref = secrets.TenantRef(uuid.New(), SecretName, 1).String() })
		_, err := f.rotate(Request{})
		if code, perm := codeOf(err); code != CodeForeignRef || !perm || len(f.px.requests()) != 0 {
			t.Fatalf("%v", err)
		}
	})
}

// TestStrayKeys: a valid key the platform does not hold (an earlier run's leftover, or a key someone created) makes a
// rotation happen even when the current key is not due; it is reported (prefix only) and expired with the old key.
func TestStrayKeys(t *testing.T) {
	f := newFixture(t, 60*day, false)
	_, stray := f.inst.NewKey(30 * day)
	res, err := f.rotate(Request{})
	if err != nil || res.Outcome != OutcomeRotated || !slices.Equal(res.StrayPrefixes, []string{stray}) {
		t.Fatalf("%+v %v", res, err)
	}
	got := res.ExpiredPrefixes
	slices.Sort(got)
	want := []string{stray, f.p0}
	slices.Sort(want)
	if !slices.Equal(got, want) || !slices.Equal(f.valid(), []string{res.KeyPrefix}) {
		t.Fatalf("expired %v, valid %v", got, f.valid())
	}
	if p := f.secev.prefixes(EventStray); !slices.Equal(p, []string{stray}) {
		t.Fatalf("stray events: %v", p)
	}
	if f.secev.events[0].Severity != "high" || f.secev.events[0].Source != SecuritySource ||
		f.secev.events[0].DedupeKey != EventStray+":"+f.instance.String()+":"+stray {
		t.Fatalf("stray event: %+v", f.secev.events[0])
	}
	f.working()
	f.noOrphans()
	f.noSecret()
}

// TestFailureSteps: every failure step of the API flow leaves a working recorded key, and no valid key other than it
// unless an apikey.leftover event names it; the audit pair is closed with .failed (before the swap) and the job error
// carries a stable code.
func TestFailureSteps(t *testing.T) {
	const create, list, expire = "/api/v1/apikey", "/api/v1/apikey", "/api/v1/apikey/expire"
	locked := `{"code": 2, "message": "database is locked"}`
	cases := []struct {
		name      string
		setup     func(f *fixture)
		code      string
		permanent bool
		audit     []string
		valid     int  // valid keys of the instance afterwards
		leftover  bool // an apikey.leftover event is expected
		swapped   bool // the new key is recorded
	}{
		{name: "list with the current key fails", setup: func(f *fixture) {
			f.px.add(&rule{method: "GET", path: list, action: "fail", status: 503})
		}, code: CodeInstanceUnavail, valid: 1},
		{name: "create refused", setup: func(f *fixture) {
			f.px.add(&rule{method: "POST", path: create, action: "fail", status: 500, body: locked})
		}, code: CodeCreate, audit: []string{"requested", "failed"}, valid: 1},
		{name: "create answer lost (key created)", setup: func(f *fixture) {
			f.px.add(&rule{method: "POST", path: create, action: "lose"})
		}, code: CodeCreate, audit: []string{"requested", "failed"}, valid: 1},
		{name: "create answer lost and the orphan cannot be expired", setup: func(f *fixture) {
			f.px.add(&rule{method: "POST", path: create, action: "lose"})
			f.px.add(&rule{method: "POST", path: expire, action: "fail", status: 500, body: locked})
		}, code: CodeCreate, audit: []string{"requested", "failed"}, valid: 2, leftover: true},
		{name: "verification with the new key fails", setup: func(f *fixture) {
			f.px.add(&rule{method: "GET", path: list, bearer: "!" + f.p0, action: "fail", status: 503})
		}, code: CodeVerify, audit: []string{"requested", "failed"}, valid: 1},
		{name: "verification fails and the new key cannot be expired", setup: func(f *fixture) {
			f.px.add(&rule{method: "GET", path: list, bearer: "!" + f.p0, action: "fail", status: 503})
			f.px.add(&rule{method: "POST", path: expire, action: "fail", status: 500, body: locked})
		}, code: CodeVerify, audit: []string{"requested", "failed"}, valid: 2, leftover: true},
		{name: "the new key expires earlier than requested", setup: func(f *fixture) {
			early := time.Now().Add(2 * day).UTC().Format(time.RFC3339)
			f.px.add(&rule{method: "POST", path: create, action: "rewrite", body: `{"expiration":"` + early + `"}`})
		}, code: CodeVerify, audit: []string{"requested", "failed"}, valid: 1},
		{name: "SecretStore refuses", setup: func(f *fixture) {
			f.sec.rotateErr = errors.New("secrets: rotate: database unavailable")
		}, code: CodeStore, audit: []string{"requested", "failed"}, valid: 1},
		{name: "registry row changed meanwhile", setup: func(f *fixture) {
			f.be.swapErr = errSwapConflict
		}, code: CodeSwapConflict, audit: []string{"requested", "failed"}, valid: 1},
		{name: "swap failed, row unchanged", setup: func(f *fixture) {
			f.be.swapErr = errors.New("connection reset")
		}, code: CodeSwap, audit: []string{"requested", "failed"}, valid: 1},
		{name: "swap outcome unknown and unreadable", setup: func(f *fixture) {
			f.be.swapErr, f.be.refErr = errors.New("connection reset"), errors.New("database down")
		}, code: CodeSwap, audit: []string{"requested"}, valid: 2, leftover: true},
		{name: "old key cannot be expired", setup: func(f *fixture) {
			f.px.add(&rule{method: "POST", path: expire, bearer: "!" + f.p0, action: "fail", status: 500, body: locked})
		}, code: CodeOldKeyNotExpired, audit: []string{"requested", "succeeded"}, valid: 2, leftover: true, swapped: true},
		{name: "final list with the new key fails (old key already expired)", setup: func(f *fixture) {
			f.px.add(&rule{method: "GET", path: list, bearer: "!" + f.p0, after: 1, action: "fail", status: 503})
		}, code: CodeOldKeyNotExpired, audit: []string{"requested", "succeeded"}, valid: 1, swapped: true},
		{name: "expire and final list with the new key fail", setup: func(f *fixture) {
			f.px.add(&rule{method: "POST", path: expire, bearer: "!" + f.p0, action: "fail", status: 503})
			f.px.add(&rule{method: "GET", path: list, bearer: "!" + f.p0, after: 1, action: "fail", status: 503})
		}, code: CodeOldKeyNotExpired, audit: []string{"requested", "succeeded"}, valid: 2, leftover: true, swapped: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, 5*day, false)
			c.setup(f)
			res, err := f.rotate(Request{})
			code, perm := codeOf(err)
			if code != c.code || perm != c.permanent {
				t.Fatalf("error %v (code %q permanent %v), want %q; result %+v", err, code, perm, c.code, res)
			}
			var got []string
			for _, a := range f.be.actions() {
				got = append(got, strings.TrimPrefix(a, ActionRotate+"."))
			}
			if !slices.Equal(got, c.audit) {
				t.Fatalf("audit %v, want %v", got, c.audit)
			}
			if n := len(f.valid()); n != c.valid {
				t.Fatalf("valid keys %v, want %d", f.valid(), c.valid)
			}
			if left := f.secev.prefixes(EventLeftover); (len(left) > 0) != c.leftover {
				t.Fatalf("leftover events %v, want %v", left, c.leftover)
			}
			if swapped := f.be.snapshot().Prefix != f.p0; swapped != c.swapped {
				t.Fatalf("recorded prefix %s (swapped %v, want %v)", f.be.snapshot().Prefix, swapped, c.swapped)
			}
			f.px.reset()
			f.working()
			f.noOrphans()
			f.noSecret()
			// a retry once the fault is gone converges: one valid key, the recorded one
			f.be.swapErr, f.be.refErr, f.sec.rotateErr = nil, nil, nil
			res, err = f.rotate(Request{})
			if err != nil || !slices.Equal(f.valid(), []string{f.be.snapshot().Prefix}) {
				t.Fatalf("retry: %+v %v, valid %v", res, err, f.valid())
			}
			f.working()
			f.noSecret()
		})
	}
}

// TestBootstrapFallback: an expired or lost current key is re-issued through the agent (every other key expired),
// then verified, stored and swapped; without an agent the run fails clearly and changes nothing.
func TestBootstrapFallback(t *testing.T) {
	t.Run("expired", func(t *testing.T) {
		f := newFixture(t, 5*day, true)
		past := time.Now().Add(-time.Hour)
		f.be.set(func(s *instanceState) { s.ExpiresAt = &past })
		res, err := f.rotate(Request{})
		if err != nil || res.Outcome != OutcomeBootstrapped || res.Mode != ModeBootstrap || res.BootstrapReason != ReasonKeyExpired ||
			res.AgentExpired != 1 || res.RefVersion != 2 {
			t.Fatalf("%+v %v", res, err)
		}
		call := f.agent.calls[0]
		if call.GetKeepPrefix() != "" || call.GetTtl().AsDuration() != MaxTTL || call.GetInstance().GetSlug() != "tenant-a" ||
			call.GetInstance().GetInstanceId() != f.instance.String() {
			t.Fatalf("agent request: %v", call)
		}
		if _, err := uuid.Parse(call.GetJobId()); err != nil {
			t.Fatalf("job id: %q", call.GetJobId())
		}
		if !slices.Equal(f.valid(), []string{res.KeyPrefix}) || !f.refused(f.k0) || f.be.snapshot().Prefix != res.KeyPrefix {
			t.Fatalf("after bootstrap: valid %v", f.valid())
		}
		if a := f.be.actions(); !slices.Equal(a, []string{ActionRotate + ".requested", ActionRotate + ".succeeded"}) ||
			!strings.Contains(f.be.audits[0].Details, `"mode":"bootstrap"`) {
			t.Fatalf("audit: %v %v", a, f.be.audits)
		}
		f.working()
		f.noOrphans()
		f.noSecret()
	})
	t.Run("lost", func(t *testing.T) {
		f := newFixture(t, 5*day, true)
		_ = f.sec.Destroy(context.Background(), secrets.TenantRef(f.tenant, SecretName, 1))
		res, err := f.rotate(Request{JobID: uuid.New()})
		if err != nil || res.Outcome != OutcomeBootstrapped || res.BootstrapReason != ReasonKeyLost {
			t.Fatalf("%+v %v", res, err)
		}
		f.working()
		f.noOrphans()
		f.noSecret()
	})
	t.Run("refused while valid: critical event, no automatic bootstrap", func(t *testing.T) {
		f := newFixture(t, 5*day, true)
		// the SecretStore holds a key the instance does not know (its database replaced: RT-12)
		other, _ := headscaletest.NewEdge(t, f.token).AddInstance("tenant-a").NewKey(day)
		_, _ = f.sec.Rotate(context.Background(), secrets.TenantRef(f.tenant, SecretName, 1), []byte(other))
		f.be.set(func(s *instanceState) { s.Ref = secrets.TenantRef(f.tenant, SecretName, 2).String() })
		_, err := f.rotate(Request{Force: true})
		if code, perm := codeOf(err); code != CodeKeyRejected || !perm || len(f.agent.calls) != 0 {
			t.Fatalf("%v (agent calls %d)", err, len(f.agent.calls))
		}
		if p := f.secev.prefixes(EventRejected); len(p) != 1 || f.secev.events[0].Severity != "critical" {
			t.Fatalf("rejected event: %s", f.secev.dump())
		}
		if len(f.be.actions()) != 0 {
			t.Fatalf("audit: %v", f.be.actions())
		}
		// the operator verified the instance: --allow-bootstrap
		res, err := f.rotate(Request{AllowBootstrap: true, Trigger: TriggerAdmin})
		if err != nil || res.Outcome != OutcomeBootstrapped || res.BootstrapReason != ReasonKeyRejected {
			t.Fatalf("%+v %v", res, err)
		}
		f.working()
		f.noOrphans()
		f.noSecret()
	})
	t.Run("no agent", func(t *testing.T) {
		f := newFixture(t, 5*day, false)
		past := time.Now().Add(-time.Minute)
		f.be.set(func(s *instanceState) { s.ExpiresAt = &past })
		_, err := f.rotate(Request{})
		if code, perm := codeOf(err); code != CodeAgentNotConfigured || !perm || !strings.Contains(err.Error(), "MG_AGENT_SOCKET") {
			t.Fatalf("%v", err)
		}
		if len(f.be.actions()) != 0 || len(f.px.requests()) != 0 || !strings.Contains(f.logs.String(), "not configured") {
			t.Fatalf("no agent: audit %v requests %d", f.be.actions(), len(f.px.requests()))
		}
	})
	t.Run("agent unavailable", func(t *testing.T) {
		f := newFixture(t, 5*day, true)
		past := time.Now().Add(-time.Minute)
		f.be.set(func(s *instanceState) { s.ExpiresAt = &past })
		f.agent.err = status.Error(codes.Unavailable, "connection refused")
		_, err := f.rotate(Request{})
		if code, perm := codeOf(err); code != CodeAgentFailed || perm {
			t.Fatalf("%v", err)
		}
		if a := f.be.actions(); !slices.Equal(a, []string{ActionRotate + ".requested", ActionRotate + ".failed"}) {
			t.Fatalf("audit %v", a)
		}
	})
	t.Run("agent answer unusable", func(t *testing.T) {
		f := newFixture(t, 5*day, true)
		past := time.Now().Add(-time.Minute)
		f.be.set(func(s *instanceState) { s.ExpiresAt = &past })
		f.agent.unusable = true
		_, err := f.rotate(Request{})
		if code, perm := codeOf(err); code != CodeAgentFailed || !perm || len(f.secev.prefixes(EventLeftover)) != 1 {
			t.Fatalf("%v %s", err, f.secev.dump())
		}
		f.noOrphans()
		f.noSecret()
	})
	t.Run("bootstrapped key fails verification", func(t *testing.T) {
		f := newFixture(t, 5*day, true)
		past := time.Now().Add(-time.Minute)
		f.be.set(func(s *instanceState) { s.ExpiresAt = &past })
		f.px.add(&rule{method: "GET", path: "/api/v1/apikey", action: "fail", status: 503})
		_, err := f.rotate(Request{})
		if code, _ := codeOf(err); code != CodeVerify {
			t.Fatalf("%v", err)
		}
		// the candidate could not even list: the new key is expired with itself if possible, else reported
		f.noOrphans()
		f.noSecret()
	})
}

// TestLockSerialisesRotations: concurrent rotations of one instance never interleave (the backend's lock), all end
// with exactly one valid key = the recorded one; a lock that is not acquired in time is lock_busy.
func TestLockSerialisesRotations(t *testing.T) {
	f := newFixture(t, 5*day, false)
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.svc.Rotate(context.Background(), Request{TenantID: f.tenant, InstanceID: f.instance, Force: true})
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Equal(f.valid(), []string{f.be.snapshot().Prefix}) || len(f.secev.events) != 0 {
		t.Fatalf("after 4 concurrent rotations: valid %v, events %s", f.valid(), f.secev.dump())
	}
	// a holder that does not let go
	f.be.sem <- struct{}{}
	_, err := f.rotate(Request{Force: true})
	<-f.be.sem
	if code, perm := codeOf(err); code != CodeLockBusy || perm {
		t.Fatalf("lock busy: %v", err)
	}
	f.noSecret()
}

// TestConfig: the bounds of §7.6/§13.5/§16.3.
func TestConfig(t *testing.T) {
	f := newFixture(t, 5*day, false)
	for name, mut := range map[string]func(*Config){
		"ttl above 90 days":           func(c *Config) { c.TTL = MaxTTL + time.Hour },
		"ttl below a day":             func(c *Config) { c.TTL = time.Hour },
		"rotate later than the alert": func(c *Config) { c.RotateBefore = 13 * day },
		"rotate before >= ttl":        func(c *Config) { c.TTL, c.RotateBefore = 30*day, 30*day },
		"no locator":                  func(c *Config) { c.Locator = nil },
		"no security recorder":        func(c *Config) { c.Security = nil },
	} {
		c := f.config()
		mut(&c)
		if _, err := newService(f.be, c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	c := f.config()
	c.Registerer = nil // f.svc registered the metrics already
	s, err := newService(f.be, c)
	if err != nil || s.cfg.TTL != MaxTTL || s.cfg.RotateBefore != DefaultRotateBefore || s.AgentConfigured() {
		t.Fatalf("defaults: %+v %v", s.cfg, err)
	}
}

// TestSchedule: the expiry gauge follows the registry at every tick; a due instance gets one job per period (dedupe
// key instance:<id>:apikey:<period>), a key further than RotateBefore none; the handler runs one instance and stores
// the result as the job's output.
func TestSchedule(t *testing.T) {
	f := newFixture(t, 60*day, false)
	sc := f.svc.NewScheduler(SchedulerConfig{})
	now := time.Now()
	if n, err := sc.Tick(context.Background(), now); err != nil || n != 0 {
		t.Fatalf("not due: %d %v", n, err)
	}
	exp := f.be.snapshot().ExpiresAt
	if got := f.svc.Expiries()[f.instance]; !got.Equal(*exp) {
		t.Fatalf("gauge %v, want %v", got, exp)
	}
	soon := now.Add(5 * day)
	f.be.set(func(s *instanceState) { s.ExpiresAt = &soon })
	n, err := sc.Tick(context.Background(), now)
	if err != nil || n != 1 || len(f.be.jobs) != 1 || !strings.HasPrefix(f.be.jobs[0], "instance:"+f.instance.String()+":apikey:") {
		t.Fatalf("due: %d %v %v", n, err, f.be.jobs)
	}
	if n, _ := sc.Tick(context.Background(), now); n != 0 {
		t.Fatalf("same period: %d more jobs", n)
	}
	if n, _ := sc.Tick(context.Background(), now.Add(24*time.Hour)); n != 1 || len(f.be.jobs) != 2 {
		t.Fatalf("next period: %d, jobs %v", n, f.be.jobs)
	}
	if got := f.svc.Expiries()[f.instance]; !got.Equal(soon) {
		t.Fatalf("gauge after the registry changed: %v", got)
	}
	// the handler: one instance per job, the result as output
	run := &jobs.Run{ID: uuid.New(), Kind: Kind, TenantID: &f.tenant, InstanceID: &f.instance, Input: []byte(`{"trigger":"schedule"}`)}
	if err := f.svc.run(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	if f.be.snapshot().Prefix == f.p0 {
		t.Fatal("the job did not rotate")
	}
	if err := f.svc.run(context.Background(), &jobs.Run{ID: uuid.New(), Kind: Kind}); err == nil {
		t.Fatal("a job without instance was accepted")
	}
	f.noSecret()
}

func metricValue(t *testing.T, f *fixture, name string, labels map[string]string) float64 {
	t.Helper()
	mfs, err := f.prom.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			if matches(m, labels) {
				if m.GetGauge() != nil {
					return m.GetGauge().GetValue()
				}
				return m.GetCounter().GetValue()
			}
		}
	}
	return -1
}

func matches(m *dto.Metric, labels map[string]string) bool {
	for k, v := range labels {
		found := false
		for _, l := range m.GetLabel() {
			if l.GetName() == k && l.GetValue() == v {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}
