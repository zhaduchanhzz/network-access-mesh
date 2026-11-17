package orchestrator

// Unit tests of the state machine (no database): the 17 worker steps in order, every agent RPC typed and in the
// required order (BootstrapPolicy before EnsureEdgeAttachment), the retry policy, permanent failure at every step ⇒
// compensation in reverse order leaving nothing behind, idempotent re-execution of each step, classification of
// errors, and the API key never leaving the agent → SecretStore path.

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/infrastructure/headscale/templates"
	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

type rig struct {
	p      *Provisioner
	r      *fakeRunner
	in     Input
	st     *memStore
	agent  *fakeAgent
	placer *fakePlacer
	sec    *memSecrets
	kc     *fakeIdP
	ext    *fakeIdP
	hs     *fakeHS
	prober *fakeProber
	sec2   *recSecurity
	logs   *bytes.Buffer
}

type recSecurity struct{ events []audit.SecurityEvent }

func (r *recSecurity) RecordSecurityEvent(_ context.Context, ev audit.SecurityEvent) (bool, error) {
	r.events = append(r.events, ev)
	return true, nil
}

func newRig(t *testing.T, mut ...func(*Config, *rig)) *rig {
	t.Helper()
	tenant := uuid.New()
	g := &rig{agent: newFakeAgent(), sec: newMemSecrets(), kc: &fakeIdP{name: DriverKeycloak, realms: map[string]string{}},
		ext: &fakeIdP{name: DriverExternal, realms: map[string]string{}}, hs: &fakeHS{policy: templates.BootstrapPolicy, healthy: true},
		prober: &fakeProber{relay: ProbeResult{OK: true}, edge: ProbeResult{OK: true}}, sec2: &recSecurity{}, logs: &bytes.Buffer{}}
	g.st = newMemStore(TenantRecord{ID: tenant, Slug: "acme", Name: "Acme", Status: tenants.StatusProvisioning})
	g.placer = &fakePlacer{m: g.st, host: uuid.New()}
	g.in = Input{TenantID: tenant, Slug: "acme", Name: "Acme", OwnerEmail: "owner@acme.example",
		IdP:       IdPInput{ID: uuid.New(), Driver: DriverKeycloak},
		Settings:  []byte(`{"node_expiry": 30}`),
		Operation: audit.Operation{ID: uuid.New(), Action: ActionTenantCreate, ActorType: audit.ActorIdentity, ResourceType: "tenant"}}
	cfg := Config{Store: g.st, Agent: g.agent, Placer: g.placer, Secrets: g.sec,
		IdP:       fakeDrivers{DriverKeycloak: g.kc, DriverExternal: g.ext},
		Headscale: fakeRegistry{hs: g.hs}, DNS: StaticDNS{"acme.mesh.example.test": {netip.MustParseAddr("192.0.2.10")}},
		Prober: g.prober, Security: g.sec2, Logger: slog.New(slog.NewJSONHandler(g.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		HeadscaleDigest: "sha256:" + strings.Repeat("d", 64), HeadscaleVersion: "v0.29.7",
		Nameservers: []netip.Addr{netip.MustParseAddr("1.1.1.1")}, EdgeAddress: "10.249.0.2:443",
		RetryBase: time.Millisecond, RetryMax: 4 * time.Millisecond, HealthPoll: time.Millisecond, HealthTimeout: 30 * time.Millisecond}
	for _, m := range mut {
		m(&cfg, g)
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	g.p = p
	g.r = newRunner(g.in)
	return g
}

func (g *rig) run(t *testing.T) error {
	t.Helper()
	return g.p.run(t.Context(), g.r)
}

func (g *rig) instance(t *testing.T) InstanceRecord {
	t.Helper()
	for _, i := range g.st.instances {
		return *i
	}
	t.Fatal("no instance")
	return InstanceRecord{}
}

// workerStepNames are steps 3–19.
var workerStepNames = Steps[2:]

func TestStepTable(t *testing.T) {
	if len(Steps) != 19 || Steps[0] != StepValidate || Steps[18] != StepActivate {
		t.Fatalf("§11.3 has 19 steps from validate to activate, got %d", len(Steps))
	}
	g := newRig(t)
	var names []string
	for _, s := range g.p.workerSteps() {
		names = append(names, s.name)
	}
	if !slices.Equal(names, workerStepNames) {
		t.Fatalf("worker steps %v, want %v", names, workerStepNames)
	}
}

func TestProvisionHappyPath(t *testing.T) {
	g := newRig(t)
	if err := g.run(t); err != nil {
		t.Fatal(err)
	}
	var ran []string
	for _, s := range g.r.steps {
		if s.status != jobs.StepSucceeded || s.attempt != 1 {
			t.Errorf("step %s: %s attempt %d", s.name, s.status, s.attempt)
		}
		ran = append(ran, s.name)
	}
	if !slices.Equal(ran, workerStepNames) {
		t.Fatalf("steps %v", ran)
	}
	// Only typed RPCs, in the order of §11.3 — the policy is set before the edge is attached (PL-02).
	want := []string{"EnsureInstance:TARGET_PHASE_STORAGE", "ValidateConfig", "EnsureInstance:TARGET_PHASE_CONFIG",
		"EnsureInstance:TARGET_PHASE_NETWORK", "EnsureInstance:TARGET_PHASE_CONTAINER", "GetInstanceStatus",
		"BootstrapPolicy", "BootstrapApiKey", "EnsureEdgeAttachment"}
	if got := g.agent.callList(); !slices.Equal(got, want) {
		t.Fatalf("agent calls %v, want %v", got, want)
	}
	inst := g.instance(t)
	switch {
	case g.st.tenant.Status != tenants.StatusActive || inst.Status != tenants.InstanceRunning:
		t.Fatalf("tenant %s instance %s", g.st.tenant.Status, inst.Status)
	case inst.NoiseFingerprint != g.agent.fp || inst.DERPRegionID != DefaultDERPRegionID:
		t.Fatalf("fingerprint %q derp %d", inst.NoiseFingerprint, inst.DERPRegionID)
	case len(g.st.policy) != 1 || g.st.policy[0] != templates.BootstrapPolicy:
		t.Fatal("baseline policy not recorded")
	case g.st.idps[g.in.IdP.ID].Status != tenants.IdPStatusActive || g.kc.realms["acme"] != "enabled":
		t.Fatalf("idp %v realm %q", g.st.idps[g.in.IdP.ID], g.kc.realms["acme"])
	case !g.st.relays["mg-acme"] || len(g.st.invitations) != 1 || string(g.st.settings) != `{"node_expiry":30}`:
		t.Fatalf("relay %v invitations %v settings %s", g.st.relays, g.st.invitations, g.st.settings)
	case !slices.Equal(g.st.audit, []string{ActionTenantCreate + ".succeeded"}):
		t.Fatalf("audit %v", g.st.audit)
	case !slices.Equal(g.st.notification, []string{"tenant.invitation owner@acme.example", "tenant.activated owner@acme.example"}):
		t.Fatalf("notifications %v", g.st.notification)
	}
	// The API key: in the SecretStore under the instance's reference, nowhere else.
	ref, err := g.sec.Latest(t.Context(), g.in.TenantID, provisioning.APIKeySecretName)
	if err != nil || inst.APIKeyRef != ref.String() || !strings.HasPrefix(g.agent.lastKey, "hskey-api-"+inst.APIKeyPrefix+"-") {
		t.Fatalf("api key ref %q (latest %v %v) prefix %q", inst.APIKeyRef, ref, err, inst.APIKeyPrefix)
	}
	if v, _ := g.sec.Get(t.Context(), ref); string(v) != g.agent.lastKey {
		t.Fatal("the stored key is not the agent's")
	}
	assertNoKey(t, g)
	if g.st.apiKeyLocks != 1 {
		t.Fatalf("apikey.bootstrap took the API-key lock %d times, want 1", g.st.apiKeyLocks)
	}
	if len(g.prober.calls) != 2 || g.prober.calls[1] != "edge acme.mesh.example.test mkey:"+g.agent.fp {
		t.Fatalf("prober calls %v", g.prober.calls)
	}
	if g.r.resource != [2]string{"tenant", g.in.TenantID.String()} {
		t.Fatalf("resource %v", g.r.resource)
	}
}

// assertNoKey: no full API key in step details, created_resources, output or logs.
func assertNoKey(t *testing.T, g *rig) {
	t.Helper()
	if g.agent.lastKey == "" {
		return
	}
	secret := g.agent.lastKey[len("hskey-api-pfx000000001-"):]
	for where, text := range map[string]string{"job": g.r.texts(), "logs": g.logs.String()} {
		if strings.Contains(text, g.agent.lastKey) || strings.Contains(text, secret) {
			t.Fatalf("the API key leaked into the %s", where)
		}
	}
}

func TestProvisionIdempotentReexecution(t *testing.T) {
	for _, step := range append(slices.Clone(workerStepNames), "all") {
		t.Run(step, func(t *testing.T) {
			g := newRig(t)
			if err := g.run(t); err != nil {
				t.Fatal(err)
			}
			before, model, live, calls := g.st.snapshot(), g.agent.model(), g.sec.live(), len(g.agent.callList())
			if step == "all" {
				for _, s := range workerStepNames {
					g.r.reset(s)
				}
			} else {
				g.r.reset(step)
			}
			if err := g.run(t); err != nil {
				t.Fatalf("re-executing %s: %v", step, err)
			}
			if after := g.st.snapshot(); after != before {
				t.Fatalf("registry changed by re-executing %s:\nbefore %s\nafter  %s", step, before, after)
			}
			m := g.agent.model()
			if m.dir != model.dir || m.network != model.network || m.container != model.container || m.edge != model.edge ||
				m.activatedBy != model.activatedBy || len(m.keys) != len(model.keys) {
				t.Fatalf("host changed by re-executing %s: %+v → %+v", step, model, m)
			}
			if got := g.sec.live(); !slices.Equal(got, live) {
				t.Fatalf("secrets changed: %v → %v", live, got)
			}
			if g.placer.allocs != 1 || len(g.kc.realms) != 1 {
				t.Fatalf("allocations %d realms %d", g.placer.allocs, len(g.kc.realms))
			}
			if step == StepPlacement || step == "all" {
				if len(g.agent.callList()) < calls {
					t.Fatal("calls")
				}
			}
		})
	}
}

func TestProvisionTransientRetry(t *testing.T) {
	unavailable := status.Error(codes.Unavailable, "agent restarting")
	busy, _ := status.New(codes.Aborted, "busy").WithDetails(&agentv1.Refusal{Reason: agentv1.RefusalReason_REFUSAL_REASON_BUSY})
	t.Run("recovers", func(t *testing.T) {
		g := newRig(t)
		g.agent.fail("EnsureInstance:TARGET_PHASE_NETWORK", unavailable, busy.Err())
		if err := g.run(t); err != nil {
			t.Fatal(err)
		}
		if s := g.r.step(StepNetwork); s.attempt != 3 || s.status != jobs.StepSucceeded {
			t.Fatalf("network step attempt %d %s", s.attempt, s.status)
		}
	})
	t.Run("exhausted", func(t *testing.T) {
		g := newRig(t)
		errs := make([]error, DefaultStepRetries+1)
		for i := range errs {
			errs[i] = unavailable
		}
		g.agent.fail("EnsureInstance:TARGET_PHASE_NETWORK", errs...)
		err := g.run(t)
		if !jobs.IsResumable(err) || jobs.IsPermanent(err) || jobs.CodeOf(err) != "agent_unavailable" {
			t.Fatalf("err %v (code %s)", err, jobs.CodeOf(err))
		}
		s := g.r.step(StepNetwork)
		if s.attempt != DefaultStepRetries+1 || g.r.step(StepStart) != nil {
			t.Fatalf("network attempts %d, next step ran %v", s.attempt, g.r.step(StepStart) != nil)
		}
		// failed_resumable: nothing undone — the directory and config stay, nothing was compensated.
		if m := g.agent.model(); !m.dir || !m.config || m.network {
			t.Fatalf("host %+v", m)
		}
		for _, st := range g.r.steps {
			if st.comp != "" {
				t.Fatal("a failed_resumable job must not compensate")
			}
		}
		// Resuming continues from the failed step only.
		if err := g.run(t); err != nil {
			t.Fatal(err)
		}
		if g.r.step(StepStorage).attempt != 1 || g.r.step(StepNetwork).attempt != DefaultStepRetries+2 {
			t.Fatal("resume did not continue from the failed step")
		}
	})
	t.Run("dns_and_probes", func(t *testing.T) {
		g := newRig(t, func(c *Config, _ *rig) {
			c.DNS = StaticDNS{"acme.mesh.example.test": {netip.MustParseAddr("198.51.100.1")}}
		})
		if err := g.run(t); !jobs.IsResumable(err) || jobs.CodeOf(err) != "dns_mismatch" {
			t.Fatalf("dns mismatch: %v", err)
		}
		g = newRig(t, func(c *Config, _ *rig) { c.DNS = nil })
		if err := g.run(t); err != nil || !strings.Contains(string(g.r.step(StepDNS).detail), "skipped") {
			t.Fatalf("no DNS checker: %v %s", err, g.r.step(StepDNS).detail)
		}
		g = newRig(t, func(c *Config, _ *rig) { c.Prober = nil })
		if err := g.run(t); !jobs.IsResumable(err) || jobs.CodeOf(err) != "prober_not_configured" || g.r.step(StepRelay).attempt != 1 {
			t.Fatalf("no prober: %v", err)
		}
		g = newRig(t)
		g.prober.relay = ProbeResult{OK: false, Checks: []ProbeCheck{{Name: "stun", Code: "timeout"}}}
		if err := g.run(t); !jobs.IsResumable(err) || jobs.CodeOf(err) != "relay_probe_failed" {
			t.Fatalf("relay probe: %v", err)
		}
		g = newRig(t)
		g.prober.edgeErrs = []error{errors.New("prober down")}
		if err := g.run(t); err != nil || g.r.step(StepEdgeVerify).attempt != 2 {
			t.Fatalf("prober down once: %v", err)
		}
	})
}

// permanentAt injects an unrecoverable failure into the dependency used by one step.
var permanentAt = []struct {
	step   string
	code   string
	inject func(g *rig)
}{
	{StepPlacement, "placement_refused", func(g *rig) { g.placer.err = platform.ErrHostnameInUse }},
	{StepSecrets, "tenant_keys_destroyed", func(g *rig) { g.sec.err = secrets.ErrKeyDestroyed }},
	{StepIdP, "idp_conflict", func(g *rig) { g.kc.err = idp.NewError(idp.CodeConflict, "EnsureIssuer", "realm_of_another_idp", nil) }},
	{StepStorage, "agent_unsafe_path", func(g *rig) {
		g.agent.fail("EnsureInstance:TARGET_PHASE_STORAGE", refused(codes.FailedPrecondition, agentv1.RefusalReason_REFUSAL_REASON_UNSAFE_PATH, "symlink"))
	}},
	{StepConfig, "agent_out_of_bounds", func(g *rig) {
		g.agent.fail("ValidateConfig", refused(codes.InvalidArgument, agentv1.RefusalReason_REFUSAL_REASON_OUT_OF_BOUNDS, "limits"))
	}},
	{StepNetwork, "agent_conflict", func(g *rig) {
		g.agent.fail("EnsureInstance:TARGET_PHASE_NETWORK", refused(codes.FailedPrecondition, agentv1.RefusalReason_REFUSAL_REASON_CONFLICT, "subnet overlaps"))
	}},
	{StepStart, "agent_image_not_allowed", func(g *rig) {
		g.agent.fail("EnsureInstance:TARGET_PHASE_CONTAINER", refused(codes.InvalidArgument, agentv1.RefusalReason_REFUSAL_REASON_IMAGE_NOT_ALLOWED, "digest"))
	}},
	{StepWaitHealthy, "instance_unhealthy", func(g *rig) { g.agent.unhealthy = true }},
	{StepPolicyBoot, "agent_state", func(g *rig) {
		g.agent.fail("BootstrapPolicy", refused(codes.FailedPrecondition, agentv1.RefusalReason_REFUSAL_REASON_STATE, "policy read back differs"))
	}},
	{StepAPIKey, "agent_state", func(g *rig) {
		g.agent.fail("BootstrapApiKey", refused(codes.FailedPrecondition, agentv1.RefusalReason_REFUSAL_REASON_STATE, "start guard: fingerprint_mismatch"))
	}},
	{StepEdgeAttach, "agent_conflict", func(g *rig) {
		g.agent.fail("EnsureEdgeAttachment", refused(codes.FailedPrecondition, agentv1.RefusalReason_REFUSAL_REASON_CONFLICT, "alias hs-acme exists"))
	}},
	{StepPolicyVerify, "no_policy", func(g *rig) { g.hs.noPolicy = true }},
	{StepConfigure, "registry_state", func(g *rig) { g.st.failErr["Configure"] = ErrState }},
	{StepEdgeVerify, "edge_exposes_paths", func(g *rig) { g.prober.edge = ProbeResult{Exposed: []string{"/api/v1/node"}} }},
	{StepActivate, "registry_state", func(g *rig) { g.st.failErr["Activate"] = ErrState }},
}

func TestProvisionPermanentFailureCompensates(t *testing.T) {
	for _, c := range permanentAt {
		t.Run(c.step, func(t *testing.T) {
			g := newRig(t)
			c.inject(g)
			err := g.run(t)
			if !jobs.IsPermanent(err) || jobs.CodeOf(err) != c.code {
				t.Fatalf("err %v (code %s), want permanent %s", err, jobs.CodeOf(err), c.code)
			}
			if s := g.r.step(c.step); s == nil || s.status != jobs.StepFailed || s.attempt != 1 {
				t.Fatalf("failing step %s: %+v (a permanent error is not retried)", c.step, s)
			}
			callsBefore := len(g.agent.callList())
			if err := g.p.compensate(t.Context(), g.r, err); err != nil {
				t.Fatalf("compensate: %v", err)
			}
			// Nothing left: host empty, instance removed, secrets of the job destroyed, IdP disabled, invitation
			// revoked, relay rows gone, tenant failed with the audit operation closed.
			m := g.agent.model()
			if m.dir || m.network || m.container || m.edge || m.flag || m.activatedBy != "" {
				t.Fatalf("host left behind: %+v", m)
			}
			for _, i := range g.st.instances {
				if i.Status != tenants.InstanceRemoved {
					t.Fatalf("instance %s", i.Status)
				}
			}
			for _, ref := range g.sec.live() {
				if strings.Contains(ref, provisioning.APIKeySecretName) {
					t.Fatalf("API key version %s left", ref)
				}
			}
			for _, r := range g.st.idps {
				if r.Status != "disabled" {
					t.Fatalf("idp %s", r.Status)
				}
			}
			for _, st := range g.kc.realms {
				if st != string(idp.RemoveDisable) {
					t.Fatalf("realm %s", st)
				}
			}
			for id, s := range g.st.invitations {
				if s != "revoked" {
					t.Fatalf("invitation %s %s", id, s)
				}
			}
			if len(g.st.relays) != 0 || g.st.tenant.Status != tenants.StatusFailed ||
				!slices.Equal(g.st.audit, []string{ActionTenantCreate + ".failed " + c.code}) {
				t.Fatalf("relays %v tenant %s audit %v", g.st.relays, g.st.tenant.Status, g.st.audit)
			}
			// Reverse order on the host: edge first, then container, network, directory.
			order := g.agent.callList()[callsBefore:]
			want := []string{"RemoveEdgeAttachment", "RemoveInstance:DATA_DISPOSITION_KEEP", "RemoveInstance:DATA_DISPOSITION_KEEP",
				"RemoveInstance:DATA_DISPOSITION_DELETE_IF_NEVER_ACTIVATED"}
			var got []string
			for _, o := range order {
				if strings.HasPrefix(o, "Remove") {
					got = append(got, o)
				}
			}
			if !isSuffixOf(got, want) {
				t.Fatalf("compensation on the host %v, want a suffix of %v", got, want)
			}
			// Every step is either compensated or skipped; a second compensation (resumed /rollback) changes nothing.
			for _, s := range g.r.steps {
				if s.comp != jobs.StepSucceeded && s.comp != jobs.StepSkipped {
					t.Fatalf("step %s compensation %q", s.name, s.comp)
				}
			}
			snap := g.st.snapshot()
			if err := g.p.compensate(t.Context(), g.r, err); err != nil || g.st.snapshot() != snap {
				t.Fatalf("second compensation: %v", err)
			}
			assertNoKey(t, g)
		})
	}
}

func isSuffixOf(got, want []string) bool {
	if len(got) > len(want) {
		return false
	}
	return slices.Equal(got, want[len(want)-len(got):])
}

func TestCompensationFailureResumes(t *testing.T) {
	g := newRig(t)
	g.prober.edge = ProbeResult{Exposed: []string{"/metrics"}}
	cause := g.run(t)
	g.agent.fail("RemoveInstance:DATA_DISPOSITION_KEEP", refused(codes.FailedPrecondition,
		agentv1.RefusalReason_REFUSAL_REASON_FOREIGN_OBJECT, "network has a foreign member"))
	err := g.p.compensate(t.Context(), g.r, cause)
	if !jobs.IsPermanent(err) || jobs.CodeOf(err) != "agent_foreign_object" {
		t.Fatalf("compensation: %v", err)
	}
	if s := g.r.step(StepStart); s.comp != jobs.StepFailed || g.r.step(StepEdgeAttach).comp != jobs.StepSucceeded ||
		g.r.step(StepNetwork).comp != "" {
		t.Fatal("compensation status after the failure")
	}
	if g.st.tenant.Status != tenants.StatusProvisioning {
		t.Fatal("the tenant is failed only when the compensation completed")
	}
	removes := strings.Count(strings.Join(g.agent.callList(), " "), "RemoveEdgeAttachment")
	if err := g.p.compensate(t.Context(), g.r, cause); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(strings.Join(g.agent.callList(), " "), "RemoveEdgeAttachment"); n != removes {
		t.Fatal("an already compensated step was undone twice")
	}
	if g.st.tenant.Status != tenants.StatusFailed {
		t.Fatal(g.st.tenant.Status)
	}
}

func TestProvisionClassification(t *testing.T) {
	t.Run("start_guard_is_a_security_event", func(t *testing.T) {
		g := newRig(t)
		g.agent.fail("EnsureEdgeAttachment", refused(codes.FailedPrecondition, agentv1.RefusalReason_REFUSAL_REASON_STATE,
			"start guard: fingerprint_mismatch"))
		if err := g.run(t); !jobs.IsPermanent(err) {
			t.Fatal(err)
		}
		if len(g.sec2.events) != 1 || g.sec2.events[0].Kind != "instance.start_guard_failed" ||
			g.sec2.events[0].Severity != audit.SeverityCritical {
			t.Fatalf("security events %+v", g.sec2.events)
		}
	})
	t.Run("unimplemented_is_permanent", func(t *testing.T) {
		g := newRig(t)
		g.agent.fail("BootstrapPolicy", status.Error(codes.Unimplemented, "old agent"))
		if err := g.run(t); !jobs.IsPermanent(err) || jobs.CodeOf(err) != "agent_error" {
			t.Fatal(err)
		}
	})
	t.Run("config_invalid", func(t *testing.T) {
		g := newRig(t, func(c *Config, g *rig) { c.Agent = invalidConfigAgent{g.agent} })
		if err := g.run(t); !jobs.IsPermanent(err) || jobs.CodeOf(err) != "config_invalid" {
			t.Fatal(err)
		}
	})
	t.Run("edge_key_mismatch", func(t *testing.T) {
		g := newRig(t)
		g.prober.edge = ProbeResult{KeyMismatch: true}
		if err := g.run(t); !jobs.IsPermanent(err) || jobs.CodeOf(err) != "edge_key_mismatch" {
			t.Fatal(err)
		}
	})
	t.Run("headscale_unavailable_retries", func(t *testing.T) {
		g := newRig(t)
		g.hs.err = &headscale.Error{Op: headscale.OpGetPolicy, Kind: headscale.KindUnavailable}
		if err := g.run(t); !jobs.IsResumable(err) || jobs.CodeOf(err) != "instance_unavailable" {
			t.Fatal(err)
		}
	})
	t.Run("no_capacity_stops_without_retry", func(t *testing.T) {
		g := newRig(t)
		g.placer.err = &platform.NoCapacityError{Region: "lab"}
		if err := g.run(t); !jobs.IsResumable(err) || jobs.CodeOf(err) != "no_capacity" || g.r.step(StepPlacement).attempt != 1 {
			t.Fatal(err)
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		g := newRig(t)
		g.r.cancelled = true
		if err := g.run(t); !jobs.IsResumable(err) || jobs.CodeOf(err) != jobs.CodeCancelled || len(g.r.steps) != 0 {
			t.Fatal(err)
		}
	})
}

type invalidConfigAgent struct{ *fakeAgent }

func (a invalidConfigAgent) ValidateConfig(context.Context, *agentv1.ValidateConfigRequest, ...grpc.CallOption) (*agentv1.ValidateConfigResponse, error) {
	return &agentv1.ValidateConfigResponse{Valid: false, ExitCode: 1, Detail: "failed to parse node.expiry"}, nil
}

func TestAPIKeyStepNeverLeaks(t *testing.T) {
	g := newRig(t)
	g.st.failErr["SetAPIKey"] = errors.New("connection reset")
	err := g.run(t)
	if !jobs.IsResumable(err) || jobs.CodeOf(err) != "registry_unavailable" {
		t.Fatalf("err %v", err)
	}
	// Every retry asked the agent with keep_prefix = the (empty) registered prefix: each created a new key and
	// expired the previous one — never two valid keys — and each stored version is erased except the last.
	m := g.agent.model()
	valid := 0
	for _, v := range m.keys {
		if v {
			valid++
		}
	}
	if valid != 1 {
		t.Fatalf("%d valid keys in the instance", valid)
	}
	if strings.Contains(err.Error(), g.agent.lastKey) || strings.Contains(err.Error(), "SSSS") {
		t.Fatal("the key is in the error")
	}
	assertNoKey(t, g)
	delete(g.st.failErr, "SetAPIKey")
	if err := g.run(t); err != nil {
		t.Fatal(err)
	}
	live := 0
	for _, ref := range g.sec.live() {
		if strings.Contains(ref, provisioning.APIKeySecretName) {
			live++
		}
	}
	if live != 1 {
		t.Fatalf("%d live API key versions", live)
	}
	assertNoKey(t, g)
}

func TestExternalIdPPendingSecret(t *testing.T) {
	g := newRig(t, func(_ *Config, g *rig) {
		g.in.IdP = IdPInput{ID: uuid.New(), Driver: DriverExternal, Issuer: "https://login.acme.example", ClientID: "meshguard"}
	})
	pending := secrets.PlatformRef(PendingClientSecretName(g.in.IdP.ID), 1)
	if err := g.sec.Put(t.Context(), pending, []byte("client-secret-value")); err != nil {
		t.Fatal(err)
	}
	g.in.IdP.PendingSecretRef = pending.String()
	g.r = newRunner(g.in)
	if err := g.run(t); err != nil {
		t.Fatal(err)
	}
	own := secrets.TenantRef(g.in.TenantID, idp.ClientSecretName(g.in.IdP.ID), 1)
	if v, err := g.sec.Get(t.Context(), own); err != nil || string(v) != "client-secret-value" {
		t.Fatalf("tenant copy %v", err)
	}
	if _, err := g.sec.Get(t.Context(), pending); !errors.Is(err, secrets.ErrDestroyed) {
		t.Fatalf("pending copy: %v", err)
	}
	if r := g.st.idps[g.in.IdP.ID]; r.ClientSecretRef != own.String() || r.Issuer != "https://login.acme.example" {
		t.Fatalf("idp row %+v", r)
	}
	if strings.Contains(g.r.texts(), "client-secret-value") || strings.Contains(g.logs.String(), "client-secret-value") {
		t.Fatal("the client secret leaked")
	}
	// A wrong pending reference (another IdP's) is refused.
	g2 := newRig(t, func(_ *Config, g *rig) {
		g.in.IdP = IdPInput{ID: uuid.New(), Driver: DriverExternal, Issuer: "https://login.acme.example", ClientID: "x",
			PendingSecretRef: pending.String()}
	})
	if err := g2.run(t); !jobs.IsPermanent(err) || jobs.CodeOf(err) != "invalid_input" {
		t.Fatalf("foreign pending ref: %v", err)
	}
}

func TestSpecAndLimits(t *testing.T) {
	g := newRig(t)
	inst := InstanceRecord{ID: uuid.New(), TenantID: g.in.TenantID, RunUID: 30001, NetCIDR: netip.MustParsePrefix("10.250.0.8/29"),
		PublicEntryIPv4: netip.MustParseAddr("192.0.2.10"), ImageDigest: "sha256:" + strings.Repeat("d", 64)}
	a := &attempt{in: g.in, tenant: TenantRecord{Instance: InstanceLimits{CPUs: 64, MemoryMB: 32, PIDs: 100}}}
	spec, err := g.p.instanceSpec(a, inst)
	if err != nil {
		t.Fatal(err)
	}
	l, h := spec.GetLimits(), spec.GetHeadscale()
	if l.GetCpuMillis() != maxCPUMillis || l.GetMemoryMib() != minMemoryMiB || l.GetPids() != 100 ||
		h.GetDerpRegionId() != DefaultDERPRegionID || h.GetPublicEntryIpv4() != "192.0.2.10" || h.StunPort != nil ||
		h.GetNodeExpiryDays() != DefaultNodeExpiryDays || spec.GetInstance().GetSlug() != "acme" {
		t.Fatalf("spec %v", spec)
	}
	if _, err := g.p.instanceSpec(a, InstanceRecord{}); !jobs.IsPermanent(err) {
		t.Fatal("an instance without public entry must be refused")
	}
	if _, err := New(Config{}); err == nil {
		t.Fatal("empty config accepted")
	}
	bad := []Input{{}, {TenantID: uuid.New(), Slug: "Bad", IdP: IdPInput{ID: uuid.New(), Driver: DriverKeycloak}},
		{TenantID: uuid.New(), Slug: "acme", IdP: IdPInput{ID: uuid.New(), Driver: "ldap"}, Operation: audit.Operation{ID: uuid.New()}}}
	for _, in := range bad {
		if in.validate() == nil {
			t.Errorf("input %+v accepted", in)
		}
	}
}

func TestBaselineIsTheAgentsTemplate(t *testing.T) {
	if BaselineSHA256 != policies.SHA256Hex(templates.BootstrapPolicy) || !strings.Contains(templates.BootstrapPolicy, `"grants": []`) {
		t.Fatal("baseline")
	}
}
