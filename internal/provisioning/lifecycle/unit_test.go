package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/infrastructure/headscale/templates"
	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
)

// TestValidPreAuthKeys: a key can still register a node when it has not expired (no expiration counts as valid) and is
// reusable or unused — exactly the keys the suspension expires (§11.4).
func TestValidPreAuthKeys(t *testing.T) {
	now := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	keys := []headscale.PreAuthKey{
		{ID: 1, Reusable: true, Expiration: now.Add(time.Hour)},
		{ID: 2, Expiration: now.Add(time.Minute)},
		{ID: 3, Used: true, Expiration: now.Add(time.Hour)},
		{ID: 4, Reusable: true, Expiration: now.Add(-time.Second)},
		{ID: 5, Reusable: true, Used: true, Expiration: now.Add(time.Hour)},
		{ID: 6},                  // no expiration: fail closed, expired too
		{ID: 7, Expiration: now}, // expires exactly now: no longer valid
		{ID: 8, Used: true, Tags: []string{"tag:server"}}, // single use, used, no expiration
	}
	var got []uint64
	for _, k := range ValidPreAuthKeys(keys, now) {
		got = append(got, k.ID)
	}
	if want := []uint64{1, 2, 5, 6}; !slices.Equal(got, want) {
		t.Errorf("valid keys %v, want %v", got, want)
	}
	if len(ValidPreAuthKeys(nil, now)) != 0 {
		t.Error("no key, no valid key")
	}
}

// TestCheckStatus: suspend from active only, resume from suspended only, each refusal with its reason.
func TestCheckStatus(t *testing.T) {
	cases := []struct {
		kind, status, reason string
	}{
		{KindSuspend, "active", ""},
		{KindSuspend, "suspended", ReasonAlreadySuspended},
		{KindSuspend, "provisioning", ReasonNotActive},
		{KindSuspend, "failed", ReasonNotActive},
		{KindSuspend, "deprovisioning", ReasonNotActive},
		{KindResume, "suspended", ""},
		{KindResume, "active", ReasonNotSuspended},
		{KindResume, "provisioning", ReasonNotSuspendable},
		{KindResume, "deleted", ReasonNotSuspendable},
	}
	for _, c := range cases {
		err := checkStatus(c.kind, c.status)
		var re *RequestError
		switch {
		case c.reason == "" && err != nil:
			t.Errorf("%s from %s: %v", c.kind, c.status, err)
		case c.reason != "" && (!errors.Is(err, ErrConflict) || !errors.As(err, &re) || re.Reason != c.reason):
			t.Errorf("%s from %s: %v, want conflict %s", c.kind, c.status, err, c.reason)
		}
	}
}

// TestErrorClassification: what the steps retry (transient) and what stops them (permanent).
func TestErrorClassification(t *testing.T) {
	he := func(k headscale.Kind) error {
		return &headscale.Error{Op: headscale.OpListPreAuthKeys, Kind: k, Code: -1}
	}
	for _, c := range []struct {
		err       error
		code      string
		permanent bool
	}{
		{he(headscale.KindUnavailable), "instance_unavailable", false},
		{he(headscale.KindCircuitOpen), "instance_unavailable", false},
		{fmt.Errorf("locate: %w", headscale.ErrNoInstance), "instance_unavailable", false},
		{he(headscale.KindUpstreamRejected), "headscale_upstream_rejected", true},
		{he(headscale.KindAPIKeyRejected), "headscale_api_key_rejected", true},
		{errors.New("dial tcp: refused"), "instance_unavailable", false},
	} {
		got := headscaleErr("op", c.err)
		if jobs.CodeOf(got) != c.code || jobs.IsPermanent(got) != c.permanent {
			t.Errorf("headscaleErr(%v) = %v (code %s, permanent %v), want %s / %v", c.err, got, jobs.CodeOf(got),
				jobs.IsPermanent(got), c.code, c.permanent)
		}
	}
	ae := func(code string) error { return &policies.ApplyError{Code: code, Err: errors.New("x")} }
	_, lintErr := policies.Lint(`{"ssh": []}`)
	for _, c := range []struct {
		err       error
		code      string
		permanent bool
	}{
		{nil, "", false},
		{ae(policies.CodePolicyRejected), policies.CodePolicyRejected, true},
		{ae(policies.CodeNoInstance), policies.CodeNoInstance, true},
		{ae(policies.CodeInstanceUnavailable), policies.CodeInstanceUnavailable, false},
		{ae(policies.CodeOutcomeUnknown), policies.CodeOutcomeUnknown, false},
		{ae(policies.CodeReadbackMismatch), policies.CodeReadbackMismatch, false},
		{lintErr, "policy_lint", true},
		{policies.ErrNoInstance, policies.CodeNoInstance, true},
		{fmt.Errorf("%w: trigger", policies.ErrInvalidRequest), "invalid_request", true},
		{fmt.Errorf("%w: policy", store.ErrLockTimeout), "policy_locked", false},
		{errors.New("connection reset"), "policy_unavailable", false},
	} {
		got := applyErr(c.err)
		if c.err == nil {
			if got != nil {
				t.Errorf("applyErr(nil) = %v", got)
			}
			continue
		}
		if jobs.CodeOf(got) != c.code || jobs.IsPermanent(got) != c.permanent {
			t.Errorf("applyErr(%v) = %v (code %s, permanent %v), want %s / %v", c.err, got, jobs.CodeOf(got),
				jobs.IsPermanent(got), c.code, c.permanent)
		}
	}
	if err := dbErr("x", jobs.Permanent("registry_state", errors.New("y"))); jobs.CodeOf(err) != "registry_state" ||
		!jobs.IsPermanent(err) {
		t.Errorf("dbErr keeps a job error: %v", err)
	}
	if err := dbErr("x", errors.New("boom")); jobs.CodeOf(err) != "registry_unavailable" || jobs.IsPermanent(err) {
		t.Errorf("dbErr of a database error: %v", err)
	}
}

// TestInputAndSteps: the input carries the tenant, the version to restore and the audit operation; the step lists
// follow §11.4 with the status before the keys.
func TestInputAndSteps(t *testing.T) {
	ok := Input{TenantID: uuid.New(), RestoreVersionID: uuid.New(), Operation: audit.Operation{ID: uuid.New(), Action: ActionSuspend}}
	if err := ok.validate(); err != nil {
		t.Errorf("valid input: %v", err)
	}
	for name, in := range map[string]Input{
		"no tenant":    {RestoreVersionID: ok.RestoreVersionID, Operation: ok.Operation},
		"no version":   {TenantID: ok.TenantID, Operation: ok.Operation},
		"no operation": {TenantID: ok.TenantID, RestoreVersionID: ok.RestoreVersionID},
	} {
		if in.validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if !slices.Equal(SuspendSteps, []string{"validate", "policy.suspend", "registry.suspend", "preauthkeys.expire", "notify"}) ||
		!slices.Equal(ResumeSteps, []string{"validate", "policy.resume", "registry.resume", "notify"}) {
		t.Errorf("steps %v / %v", SuspendSteps, ResumeSteps)
	}
	if slices.Index(SuspendSteps, StepRegistrySuspend) > slices.Index(SuspendSteps, StepPreAuthExpire) {
		t.Error("the status must be suspended BEFORE the keys are expired: no key can be issued after the expiry")
	}
	if !jobs.DefaultKinds()[KindSuspend].Compensable || !jobs.DefaultKinds()[KindResume].Compensable ||
		jobs.DefaultKinds()[KindSuspend].Lock != jobs.LockHold || jobs.DefaultKinds()[KindResume].Dedupe != "tenant:{tenant}:lifecycle" {
		t.Errorf("job kinds: %+v %+v", jobs.DefaultKinds()[KindSuspend], jobs.DefaultKinds()[KindResume])
	}
}

// TestNewChecksTheConfiguration: collaborators required; the suspension policy passes the lint (it is the shipped
// template by default) — an allow-all one is refused.
func TestNewChecksTheConfiguration(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("an empty configuration was accepted")
	}
	st := &store.Store{}
	reg := &gatedReg{}
	core := applierFunc(func() {})
	h, err := New(Config{Store: st, Policies: core, Headscale: reg})
	if err != nil || h.cfg.SuspensionPolicy != templates.SuspensionPolicy || h.cfg.StepRetries != 5 ||
		h.cfg.RetryBase != 2*time.Second || h.cfg.RetryMax != time.Minute {
		t.Fatalf("defaults: %+v, %v", h, err)
	}
	if _, err := New(Config{Store: st, Policies: core, Headscale: reg, SuspensionPolicy: `{"ssh": []}`}); err == nil {
		t.Error("a suspension policy without grants (allow-all — L1) was accepted")
	}
	d, err := policies.Lint(templates.SuspensionPolicy)
	if err != nil || d.Applied != "{\n  \"grants\": [],\n  \"ssh\": []\n}" {
		t.Errorf("the suspension template is not deny-all: %q, %v", d.Applied, err)
	}
	for n := 1; n <= 8; n++ {
		if b := h.backoff(n); b < 1600*time.Millisecond || b > 72*time.Second {
			t.Errorf("backoff(%d) = %s", n, b)
		}
	}
}

// applierFunc is a PolicyApplier that is never called (configuration tests).
type applierFunc func()

func (applierFunc) Apply(context.Context, policies.ApplyRequest) (policies.Result, error) {
	return policies.Result{}, errors.New("not called")
}
