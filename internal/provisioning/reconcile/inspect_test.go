package reconcile

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/agentspec"
)

// rig is one Inspector over the fakes.
type rig struct {
	agent *fakeAgent
	hs    *fakeHS
	in    *Inspector
	d     Desired
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{agent: newFakeAgent(), hs: &fakeHS{}, d: desired()}
	r.in = &Inspector{Agent: r.agent.serve(t), Headscale: fakeRegistry{r.d.TenantID: r.hs}, AgentUID: agentUID,
		AgentGID: agentGID, RotationGrace: DefaultRotationGrace, EventWindow: DefaultEventWindow, AgentTimeout: 5 * time.Second,
		Now: func() time.Time { return now0 }}
	r.agent.set(r.d.InstanceID, goodStatus(r.d), nil)
	r.hs.setKeys(currentKey(), expiredKey())
	return r
}

func (r *rig) run(t *testing.T) (Report, []audit.SecurityEvent) {
	t.Helper()
	rep, evs := r.in.Instance(context.Background(), r.d)
	assertReadOnly(t, r.agent, r.hs)
	if _, err := json.Marshal(rep); err != nil {
		t.Fatal(err)
	}
	return rep, evs
}

func kindsOf(rep Report) []string {
	var out []string
	for _, f := range rep.Findings {
		out = append(out, f.Kind+"/"+f.Severity)
	}
	sort.Strings(out)
	return out
}

func eventsOf(evs []audit.SecurityEvent) []string {
	var out []string
	for _, e := range evs {
		out = append(out, e.Kind+"/"+e.Severity)
	}
	sort.Strings(out)
	return out
}

func checkOf(rep Report, name string) Check {
	for _, c := range rep.Checks {
		if c.Name == name {
			return c
		}
	}
	return Check{}
}

// TestCleanInstance: an instance that matches the registry is clean, raises nothing and is only read.
func TestCleanInstance(t *testing.T) {
	r := newRig(t)
	rep, evs := r.run(t)
	if rep.Status != StatusClean || len(rep.Findings) != 0 || len(evs) != 0 || rep.Schema != ReportSchema || rep.Scope != ScopeInstance ||
		*rep.InstanceID != r.d.InstanceID || !rep.CheckedAt.Equal(now0) {
		t.Fatalf("report %+v, events %v", rep, evs)
	}
	for _, c := range rep.Checks {
		if c.Outcome != OutcomeOK && (c.Name != CheckNoiseKey || c.Reason != ReasonNotReported) {
			t.Errorf("check %+v", c)
		}
	}
	if n := checkOf(rep, CheckAPIKeys).Note; n != "valid=1" {
		t.Errorf("api_keys note %q", n)
	}
	if got := r.agent.calls(); !slices.Equal(got, []string{"GetInstanceStatus"}) {
		t.Errorf("agent calls %v", got)
	}
	if got := r.hs.called(); !slices.Equal(got, []string{"ListAPIKeys"}) {
		t.Errorf("headscale calls %v", got)
	}
}

// TestInstanceDrift: every drift scenario of P3-T12 — the finding (kind + severity), the security event (kind +
// severity, platform scope, dedupe key stable across runs and distinct per subject) — and nothing but reads.
func TestInstanceDrift(t *testing.T) {
	foreign := func(prefix string, created time.Time, exp time.Time) headscale.APIKey {
		return headscale.APIKey{ID: 99, Prefix: prefix, CreatedAt: created, Expiration: exp}
	}
	recent := currentKey()
	recent.CreatedAt = now0.Add(-5 * time.Minute) // a rotation 5 minutes ago
	prev := foreign("prvKEY000001", now0.Add(-40*24*time.Hour), now0.Add(20*24*time.Hour))
	cases := []struct {
		name   string
		mutate func(r *rig)
		kinds  []string // findings kind/severity
		events []string // security events kind/severity
		status string
	}{
		{"foreign API key", func(r *rig) {
			r.hs.setKeys(currentKey(), expiredKey(), foreign("evilKEY00001", now0.Add(-time.Hour), now0.Add(24*time.Hour)))
		}, []string{"api_key_foreign/high"}, []string{"reconcile.api_key_foreign/high"}, StatusDrift},
		{"two foreign keys, one without expiration (Headscale: valid forever)", func(r *rig) {
			r.hs.setKeys(currentKey(), foreign("evilKEY00001", now0.Add(-time.Hour), now0.Add(time.Hour)),
				foreign("evilKEY00002", now0.Add(-2*time.Hour), time.Time{}))
		}, []string{"api_key_foreign/high", "api_key_foreign/high"},
			[]string{"reconcile.api_key_foreign/high", "reconcile.api_key_foreign/high"}, StatusDrift},
		{"rotation in progress: the previous key is tolerated", func(r *rig) { r.hs.setKeys(recent, prev, expiredKey()) },
			nil, nil, StatusClean},
		{"rotation over: the previous key still valid is foreign", func(r *rig) {
			late := recent
			late.CreatedAt = now0.Add(-DefaultRotationGrace - time.Minute)
			r.hs.setKeys(late, prev)
		}, []string{"api_key_foreign/high"}, []string{"reconcile.api_key_foreign/high"}, StatusDrift},
		{"rotation in progress: only ONE previous key, a key created after the current one is foreign", func(r *rig) {
			older := foreign("oldVALID0001", now0.Add(-50*24*time.Hour), now0.Add(10*24*time.Hour))
			newer := foreign("newerKEY0001", now0.Add(-time.Minute), now0.Add(10*24*time.Hour))
			r.hs.setKeys(recent, prev, older, newer)
		}, []string{"api_key_foreign/high", "api_key_foreign/high"},
			[]string{"reconcile.api_key_foreign/high", "reconcile.api_key_foreign/high"}, StatusDrift},
		{"current key absent", func(r *rig) { r.hs.setKeys(expiredKey()) }, []string{"api_key_current_missing/high"}, nil, StatusDrift},
		{"current key expired", func(r *rig) {
			k := currentKey()
			k.Expiration = now0.Add(-time.Minute)
			r.hs.setKeys(k)
		}, []string{"api_key_current_missing/high"}, nil, StatusDrift},
		{"extra network member", func(r *rig) {
			r.agent.status[r.d.InstanceID.String()].Network.Members = []string{"intruder", "mg-edge", "mg-hs-acme"}
		}, []string{"network_extra_member/high"}, []string{"reconcile.network_extra_member/high"}, StatusDrift},
		{"edge not attached", func(r *rig) {
			n := r.agent.status[r.d.InstanceID.String()].Network
			n.Members, n.EdgeAttached = []string{"mg-hs-acme"}, false
		}, []string{"edge_not_attached/medium"}, nil, StatusDrift},
		{"a stranger in place of the edge", func(r *rig) {
			n := r.agent.status[r.d.InstanceID.String()].Network
			n.Members, n.EdgeAttached = []string{"mg-hs-acme", "stranger"}, false
		}, []string{"edge_not_attached/medium", "network_extra_member/high"}, []string{"reconcile.network_extra_member/high"}, StatusDrift},
		{"network not internal", func(r *rig) { r.agent.status[r.d.InstanceID.String()].Network.Internal = false },
			[]string{"network_not_internal/high"}, []string{"reconcile.network_not_internal/high"}, StatusDrift},
		{"network subnet", func(r *rig) { r.agent.status[r.d.InstanceID.String()].Network.Subnet = "10.250.0.16/29" },
			[]string{"network_subnet_mismatch/high"}, nil, StatusDrift},
		{"network absent", func(r *rig) { r.agent.status[r.d.InstanceID.String()].Network = &agentv1.NetworkState{} },
			[]string{"network_absent/high"}, nil, StatusDrift},
		{"running container not on its network", func(r *rig) {
			r.agent.status[r.d.InstanceID.String()].Network.Members = []string{"mg-edge"}
		}, []string{"container_not_on_network/high"}, nil, StatusDrift},
		{"image digest", func(r *rig) { r.agent.status[r.d.InstanceID.String()].ImageDigest = digestB },
			[]string{"image_digest_mismatch/high"}, []string{"reconcile.image_digest_mismatch/high"}, StatusDrift},
		{"image not pinned", func(r *rig) { r.agent.status[r.d.InstanceID.String()].ImageDigest = "" },
			[]string{"image_digest_mismatch/high"}, []string{"reconcile.image_digest_mismatch/high"}, StatusDrift},
		{"config hash", func(r *rig) { r.agent.status[r.d.InstanceID.String()].ConfigSha256 = strings.Repeat("d", 64) },
			[]string{"config_hash_mismatch/high"}, nil, StatusDrift},
		{"config missing", func(r *rig) { r.agent.status[r.d.InstanceID.String()].ConfigSha256 = "" },
			[]string{"config_missing/high"}, nil, StatusDrift},
		{"config version not recorded (Phase 1 instance)", func(r *rig) { r.d.ConfigSHA256 = "" }, nil, nil, StatusClean},
		{"path permissions", func(r *rig) {
			ps := r.agent.status[r.d.InstanceID.String()].Paths
			ps[3].Mode = 0o755                                // data/
			ps[5].Uid = 1000                                  // compose.yaml
			ps[6].Mode = 0o440 | uint32(fs.ModeSymlink)       // config.yaml replaced by a symlink
			ps[9].Exists, ps[9].Uid, ps[9].Mode = false, 0, 0 // meta/instance.json
		}, []string{"path_permissions/high"}, nil, StatusDrift},
		{"container exited", func(r *rig) {
			st := r.agent.status[r.d.InstanceID.String()]
			st.ContainerState, st.Health, st.Network.Members = agentv1.ContainerState_CONTAINER_STATE_EXITED, agentv1.HealthState_HEALTH_STATE_NONE,
				[]string{"mg-edge"}
		}, []string{"container_not_running/high"}, nil, StatusDrift},
		{"container absent", func(r *rig) {
			st := r.agent.status[r.d.InstanceID.String()]
			st.ContainerState, st.ImageDigest, st.Network.Members = agentv1.ContainerState_CONTAINER_STATE_ABSENT, "", []string{"mg-edge"}
		}, []string{"container_absent/high"}, nil, StatusDrift},
		{"container unhealthy", func(r *rig) {
			r.agent.status[r.d.InstanceID.String()].Health = agentv1.HealthState_HEALTH_STATE_UNHEALTHY
		}, []string{"container_unhealthy/medium"}, nil, StatusDrift},
		{"stopped instance, container exited: clean, keys not checked", func(r *rig) {
			r.d.Status = "stopped"
			st := r.agent.status[r.d.InstanceID.String()]
			st.ContainerState, st.Health, st.Network.Members, st.Network.EdgeAttached = agentv1.ContainerState_CONTAINER_STATE_EXITED,
				agentv1.HealthState_HEALTH_STATE_NONE, nil, false
			r.hs.setKeys(foreign("evilKEY00001", now0, time.Time{})) // not read for a stopped instance
		}, nil, nil, StatusClean},
		{"stopped instance whose container runs", func(r *rig) { r.d.Status = "stopped" },
			[]string{"container_running_unexpected/medium"}, nil, StatusDrift},
		{"Noise key fingerprint", func(r *rig) {
			r.d.NoiseKeyFingerprint = strings.Repeat("1", 64)
			r.agent.status[r.d.InstanceID.String()].NoiseKeyFingerprint = strings.Repeat("2", 64)
		}, []string{"noise_key_mismatch/critical"}, []string{"reconcile.noise_key_mismatch/critical"}, StatusDrift},
		{"instance directory missing", func(r *rig) { r.agent.set(r.d.InstanceID, nil, nil); delete(r.agent.status, r.d.InstanceID.String()) },
			[]string{"instance_missing/critical"}, nil, StatusDrift},
		{"guard refuses: foreign object under a derived name", func(r *rig) {
			r.agent.set(r.d.InstanceID, nil, refusal(codes.FailedPrecondition, agentv1.RefusalReason_REFUSAL_REASON_FOREIGN_OBJECT, "instance.slug"))
		}, []string{"guard_refused/high"}, []string{"reconcile.guard_refused/high"}, StatusDrift},
		{"agent unreachable", func(r *rig) {
			r.agent.set(r.d.InstanceID, nil, status.Error(codes.Unavailable, "docker engine unavailable"))
		},
			nil, nil, StatusIncomplete},
		{"Headscale unreachable", func(r *rig) {
			r.hs.err = &headscale.Error{Op: headscale.OpListAPIKeys, Kind: headscale.KindUnavailable, Code: -1}
		},
			nil, nil, StatusIncomplete},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			c.mutate(r)
			rep, evs := r.run(t)
			if got := kindsOf(rep); !slices.Equal(got, c.kinds) || rep.Status != c.status {
				t.Fatalf("findings %v (status %s), want %v (%s)\n%+v", got, rep.Status, c.kinds, c.status, rep)
			}
			if got := eventsOf(evs); !slices.Equal(got, c.events) {
				t.Fatalf("events %v, want %v", got, c.events)
			}
			keys := map[string]bool{}
			for _, e := range evs {
				if e.TenantID != nil || e.Source != SecuritySource || e.DedupeWindow != DefaultEventWindow || keys[e.DedupeKey] ||
					!strings.Contains(e.DedupeKey, r.d.InstanceID.String()) || e.Details["instance_id"] != r.d.InstanceID.String() {
					t.Errorf("event %+v (platform scope, one dedupe key per subject naming the instance)", e)
				}
				keys[e.DedupeKey] = true
			}
			// a second run gives the same dedupe keys: the recorder writes each alert once per window
			_, again := r.in.Instance(context.Background(), r.d)
			for _, e := range again {
				if !keys[e.DedupeKey] {
					t.Errorf("dedupe key changed between runs: %s", e.DedupeKey)
				}
			}
			assertReadOnly(t, r.agent, r.hs)
		})
	}
}

// TestFindingDetails: what the report says (tenant-visible: the output of the tenant's job) and what only the
// platform event says.
func TestFindingDetails(t *testing.T) {
	r := newRig(t)
	r.hs.setKeys(currentKey(), headscale.APIKey{ID: 42, Prefix: "evilKEY00001", CreatedAt: now0.Add(-time.Hour)})
	st := r.agent.status[r.d.InstanceID.String()]
	st.Network.Members = []string{"mg-edge", "mg-hs-acme", "mg-hs-other"}
	st.Paths[3].Mode = 0o755
	st.Paths[6].Mode = 0o440 | uint32(fs.ModeSymlink)
	rep, evs := r.run(t)
	raw, _ := json.Marshal(rep)
	if strings.Contains(string(raw), "mg-hs-other") || strings.Contains(string(raw), "hskey") {
		t.Errorf("the report names another tenant's container or a key: %s", raw)
	}
	for _, f := range rep.Findings {
		switch f.Kind {
		case DriftAPIKeyForeign:
			if f.Subject != "evilKEY00001" || f.Actual != "valid until never" {
				t.Errorf("foreign key finding %+v", f)
			}
		case DriftNetworkExtraMember:
			if f.Count != 1 || f.Actual != "3" || len(f.Items) != 0 {
				t.Errorf("extra member finding %+v", f)
			}
		case DriftPathPermissions:
			if !slices.Equal(f.Items, []string{"config_file:mode=0440,symlink,want=0440", "data_dir:mode=0755,want=0700"}) {
				t.Errorf("path items %v", f.Items)
			}
		}
	}
	for _, e := range evs {
		switch e.Kind {
		case "reconcile.api_key_foreign":
			if e.Details["prefix"] != "evilKEY00001" || e.Details["expires"] != "never" || e.Details["key_id"] != "42" ||
				e.DedupeKey != "reconcile.api_key_foreign:"+r.d.InstanceID.String()+":evilKEY00001" {
				t.Errorf("foreign key event %+v", e)
			}
		case "reconcile.network_extra_member":
			if fmt.Sprint(e.Details["members"]) != "[mg-edge mg-hs-acme mg-hs-other]" || e.Details["extra"] != 1 {
				t.Errorf("extra member event %+v", e)
			}
		}
	}
	if len(evs) != 2 {
		t.Errorf("events %v", eventsOf(evs))
	}
}

// TestNoAgentConfigured: without an agent (dev) every agent check is unavailable, the API keys are still checked and
// nothing fails.
func TestNoAgentConfigured(t *testing.T) {
	r := newRig(t)
	r.in.Agent = nil
	r.hs.setKeys(currentKey(), headscale.APIKey{ID: 9, Prefix: "evilKEY00001", Expiration: now0.Add(time.Hour)})
	rep, evs := r.run(t)
	if c := checkOf(rep, CheckAgent); c.Outcome != OutcomeUnavailable || c.Reason != ReasonAgentNotConfigured {
		t.Errorf("agent check %+v", c)
	}
	if got := kindsOf(rep); !slices.Equal(got, []string{"api_key_foreign/high"}) || len(evs) != 1 {
		t.Errorf("findings %v events %d", got, len(evs))
	}
	r.hs.setKeys(currentKey())
	if rep, _ := r.run(t); rep.Status != StatusIncomplete {
		t.Errorf("status %s, want incomplete", rep.Status)
	}
	host, hevs := r.in.Host(context.Background(), nil)
	if host.Status != StatusIncomplete || len(hevs) != 0 || checkOf(host, CheckInventory).Reason != ReasonAgentNotConfigured {
		t.Errorf("host without agent: %+v", host)
	}
	if n := len(r.agent.calls()); n != 0 {
		t.Errorf("agent called %d times", n)
	}
}

// TestHostDrift: unknown resources are reported (never adopted), removed leftovers, identity mismatches, registered
// instances absent from the host, alias collisions and unknown hs-* names — and the agent only listed.
func TestHostDrift(t *testing.T) {
	d := desired()
	other := Registered{InstanceID: uuid.MustParse("33333333-3333-4333-8333-333333333333"), TenantID: uuid.New(), Slug: "beta", Status: "running"}
	gone := Registered{InstanceID: uuid.MustParse("44444444-4444-4444-8444-444444444444"), TenantID: uuid.New(), Slug: "gone", Status: "removed"}
	lost := Registered{InstanceID: uuid.MustParse("55555555-5555-4555-8555-555555555555"), TenantID: uuid.New(), Slug: "lost", Status: "stopped"}
	quarantined := Registered{InstanceID: uuid.MustParse("66666666-6666-4666-8666-666666666666"), TenantID: uuid.New(), Slug: "qq", Status: "quarantined"}
	regs := []Registered{{InstanceID: d.InstanceID, TenantID: d.TenantID, Slug: d.Slug, Status: "running"}, other, gone, lost, quarantined}
	entry := func(g Registered, dir, ctr, nw bool) *agentv1.InventoryEntry {
		return &agentv1.InventoryEntry{InstanceId: g.InstanceID.String(), TenantId: g.TenantID.String(), Slug: g.Slug, HasDirectory: dir,
			HasContainer: ctr, HasNetwork: nw}
	}
	clean := []*agentv1.InventoryEntry{entry(regs[0], true, true, true), entry(other, true, true, true)}
	aliases := []*agentv1.EdgeAlias{{Network: "mg-t-acme", Container: "mg-hs-acme", Alias: "hs-acme"},
		{Network: "mg-t-beta", Container: "mg-hs-beta", Alias: "hs-beta"}}
	cases := []struct {
		name    string
		entries []*agentv1.InventoryEntry
		aliases []*agentv1.EdgeAlias
		listErr error
		kinds   []string
		events  []string
		status  string
	}{
		{"clean (a quarantined instance with nothing on the host is not reported)", clean, aliases, nil, nil, nil, StatusClean},
		{"unknown instance: a labelled network and a directory without registry row", append(slices.Clone(clean),
			&agentv1.InventoryEntry{InstanceId: "77777777-7777-4777-8777-777777777777", HasNetwork: true, Slug: "ghost"},
			&agentv1.InventoryEntry{InstanceId: "88888888-8888-4888-8888-888888888888", HasDirectory: true}), aliases, nil,
			[]string{"unknown_instance/medium", "unknown_instance/medium"},
			[]string{"reconcile.unknown_instance/medium", "reconcile.unknown_instance/medium"}, StatusDrift},
		{"leftover of a removed instance", append(slices.Clone(clean), entry(gone, true, false, false)), aliases, nil,
			[]string{"removed_instance_leftover/low"}, nil, StatusDrift},
		{"labels of another tenant on a registered instance", []*agentv1.InventoryEntry{entry(regs[0], true, true, true),
			{InstanceId: other.InstanceID.String(), TenantId: uuid.NewString(), Slug: "beta", HasContainer: true}}, aliases, nil,
			[]string{"inventory_identity_mismatch/high"}, []string{"reconcile.inventory_identity_mismatch/high"}, StatusDrift},
		{"registered instance absent from the host", clean[:1], aliases[:1], nil,
			[]string{"registered_instance_missing/high"}, nil, StatusDrift},
		{"alias collision on another network of the edge", clean, append(slices.Clone(aliases),
			&agentv1.EdgeAlias{Network: "mg-t-beta", Container: "rogue", Alias: "hs-acme"}), nil,
			[]string{"alias_collision/high"}, []string{"reconcile.alias_collision/high"}, StatusDrift},
		{"alias collision on the tenant's own network by another container", clean, append(slices.Clone(aliases),
			&agentv1.EdgeAlias{Network: "mg-t-acme", Container: "rogue", Alias: "hs-acme"}), nil,
			[]string{"alias_collision/high"}, []string{"reconcile.alias_collision/high"}, StatusDrift},
		{"hs-* name of no live instance (removed tenant still attached)", clean, append(slices.Clone(aliases),
			&agentv1.EdgeAlias{Network: "mg-t-gone", Container: "mg-hs-gone", Alias: "hs-gone"}), nil,
			[]string{"unknown_alias/medium"}, []string{"reconcile.unknown_alias/medium"}, StatusDrift},
		{"agent unreachable", nil, nil, status.Error(codes.Unavailable, "down"), nil, nil, StatusIncomplete},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := newFakeAgent()
			a.inventory = &agentv1.ListInstancesResponse{Instances: c.entries, EdgeAliases: c.aliases}
			a.listErr = c.listErr
			in := &Inspector{Agent: a.serve(t), Now: func() time.Time { return now0 }, AgentTimeout: 5 * time.Second}
			// lost is stopped: with nothing on the host it is reported (clean expects it present)
			entries := slices.Clone(c.entries)
			if c.name != "agent unreachable" {
				entries = append(entries, entry(lost, true, false, false))
				a.inventory.Instances = entries
			}
			rep, evs := in.Host(context.Background(), regs)
			if got := kindsOf(rep); !slices.Equal(got, c.kinds) || rep.Status != c.status {
				t.Fatalf("findings %v (%s), want %v (%s)\n%+v", got, rep.Status, c.kinds, c.status, rep)
			}
			if got := eventsOf(evs); !slices.Equal(got, c.events) {
				t.Fatalf("events %v, want %v", got, c.events)
			}
			for _, e := range evs {
				if e.TenantID != nil || !strings.HasPrefix(e.DedupeKey, e.Kind+":host:") {
					t.Errorf("event %+v", e)
				}
			}
			assertReadOnly(t, a)
			if got := a.calls(); !slices.Equal(got, []string{"ListInstances"}) {
				t.Errorf("agent calls %v", got)
			}
		})
	}
}

// TestDerivedNamesMatchTheAgent: the names reconcile expects are the agent's own derivation (agentspec.Host.Names).
func TestDerivedNamesMatchTheAgent(t *testing.T) {
	h := &agentspec.Host{TenantsDir: "/opt/meshguard/tenants", BackupsDir: "/opt/meshguard/backups/tenants"}
	for _, slug := range []string{"acme", "tenant-a", "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"} {
		n := h.Names(agentspec.Ref{InstanceID: uuid.New(), TenantID: uuid.New(), Slug: slug})
		if n.Network != networkName(slug) || n.Container != containerName(slug) || n.Alias != aliasName(slug) {
			t.Errorf("%s: agent %s/%s/%s, reconcile %s/%s/%s", slug, n.Network, n.Container, n.Alias, networkName(slug),
				containerName(slug), aliasName(slug))
		}
	}
	if len(pathRules) != 10 || len(severities) != len(DriftKinds) {
		t.Errorf("%d path rules, %d severities for %d kinds", len(pathRules), len(severities), len(DriftKinds))
	}
	for k := range securityKinds {
		if !slices.Contains(DriftKinds, k) {
			t.Errorf("security kind %s is not a drift kind", k)
		}
	}
}
