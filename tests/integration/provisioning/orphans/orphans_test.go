package orphans

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// world is a clean run: tenant a provisioned (instance running, edge attached, one valid key = the stored one), tenant b
// rolled back (instance removed, nothing on the host, its key version destroyed), plus objects of another run.
func world() Inventory {
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	ta, tb, other := uuid.New(), uuid.New(), uuid.New()
	ia, ib, io := uuid.New(), uuid.New(), uuid.New()
	pa, pb := uuid.New(), uuid.New()
	ref := func(t uuid.UUID, name string, v int) string { return fmt.Sprintf("mgsec://%s/%s#%d", t, name, v) }
	return Inventory{
		Scope: Scope{SlugPrefix: "run-", TenantsDir: "/r/tenants", Edge: "run-edge", EdgeNetwork: "run-net", Settled: true},
		Now:   now,
		Registry: Registry{
			Tenants: []Tenant{{ID: ta, Slug: "run-a", Status: "active"}, {ID: tb, Slug: "run-b", Status: "failed"},
				{ID: other, Slug: "zz-other", Status: "active"}},
			Instances: []Instance{
				{ID: ia, TenantID: ta, Slug: "run-a", Status: StatusRunning, APIKeyRef: ref(ta, APIKeySecretName, 2), APIKeyPrefix: "aaaaaaaaaaaa"},
				{ID: ib, TenantID: tb, Slug: "run-b", Status: StatusRemoved},
				{ID: io, TenantID: other, Slug: "zz-other", Status: StatusRunning},
			},
			IdPs: []IdP{{ID: pa, TenantID: ta, Status: "active", ClientSecretRef: ref(ta, "idp."+pa.String()+".client", 1)},
				{ID: pb, TenantID: tb, Status: "disabled", ClientSecretRef: ref(tb, "idp."+pb.String()+".client", 1)}},
			Invitations: []Invitation{{ID: uuid.New(), TenantID: ta, Status: "pending"}, {ID: uuid.New(), TenantID: tb, Status: "revoked"}},
			Relays:      []Relay{{TenantID: ta, Kind: "region", Name: "mg-run-a"}, {TenantID: ta, Kind: "assignment", Name: "x"}},
			Secrets: []Secret{
				{TenantID: ta, Name: APIKeySecretName, Version: 1, Destroyed: true},
				{TenantID: ta, Name: APIKeySecretName, Version: 2},
				{TenantID: ta, Name: "idp." + pa.String() + ".client", Version: 1},
				{TenantID: tb, Name: APIKeySecretName, Version: 1, Destroyed: true},
				{TenantID: tb, Name: "idp." + pb.String() + ".client", Version: 1},
				{TenantID: other, Name: APIKeySecretName, Version: 7},
			},
		},
		Host: Host{
			Containers: []Container{
				{ID: "c1", Name: "mg-hs-run-a", State: "running", Labels: map[string]string{labelInstance: ia.String(), labelTenant: ta.String(), labelRole: "tenant"}},
				{ID: "c2", Name: "mg-hs-zz-other", State: "running", Labels: map[string]string{labelInstance: io.String()}},
				{ID: "c3", Name: "mg-helper-zz-other-configtest-0a1b2c3d", State: "running", Labels: map[string]string{labelRole: roleHelper}},
			},
			Networks: []Network{
				{ID: "n1", Name: "mg-t-run-a", Labels: map[string]string{labelInstance: ia.String(), labelRole: "tenant"}},
				{ID: "n2", Name: "mg-t-zz-other", Labels: map[string]string{labelInstance: io.String()}},
				{ID: "n3", Name: "run-net"},
			},
			EdgeNetworks: []string{"run-net", "mg-t-run-a"},
			Dirs:         []string{ia.String()},
		},
		Keys: []Keys{{InstanceID: ia, Listed: []APIKey{{Prefix: "oldoldoldold", Expiration: now.Add(-time.Hour)},
			{Prefix: "aaaaaaaaaaaa", Expiration: now.Add(90 * 24 * time.Hour)}}, StoredPrefix: "aaaaaaaaaaaa", APIOK: true}},
	}
}

func kinds(fs []Finding) string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Kind)
	}
	return strings.Join(out, ",")
}

func TestCleanWorld(t *testing.T) {
	inv := world()
	if fs := Check(inv); len(fs) != 0 {
		t.Fatalf("clean world: %v", fs)
	}
	if s := inv.Summary(); !strings.Contains(s, "instances live=1 removed=1") || !strings.Contains(s, "valid=1") {
		t.Fatalf("summary %s", s)
	}
}

// TestEachOrphanIsFound: one thing left behind (or missing) per case ⇒ exactly that finding.
func TestEachOrphanIsFound(t *testing.T) {
	inst := func(inv *Inventory, slug string) Instance {
		for _, i := range inv.Registry.Instances {
			if i.Slug == slug {
				return i
			}
		}
		t.Fatalf("no %s", slug)
		return Instance{}
	}
	for name, c := range map[string]struct {
		mut  func(inv *Inventory)
		want string
	}{
		"container of the rolled-back instance": {func(inv *Inventory) {
			inv.Host.Containers = append(inv.Host.Containers, Container{Name: "mg-hs-run-b", State: "exited",
				Labels: map[string]string{labelInstance: inst(inv, "run-b").ID.String()}})
		}, ContainerOfRemoved},
		"helper container of the run": {func(inv *Inventory) {
			inv.Host.Containers = append(inv.Host.Containers, Container{Name: "mg-helper-run-a-fingerprint-00112233", State: "exited",
				Labels: map[string]string{labelRole: roleHelper, labelHelperInstance: inst(inv, "run-a").ID.String()}})
		}, ContainerHelper},
		"container with a derived name, no label": {func(inv *Inventory) {
			inv.Host.Containers = append(inv.Host.Containers, Container{Name: "mg-hs-run-x", State: "created"})
		}, ContainerUnlabelled},
		"container of an unknown instance": {func(inv *Inventory) {
			inv.Host.Containers = append(inv.Host.Containers, Container{Name: "mg-hs-run-y", Labels: map[string]string{labelInstance: uuid.NewString()}})
		}, ContainerUnknown},
		"container renamed": {func(inv *Inventory) {
			inv.Host.Containers[0].Name = "mg-hs-run-a2"
		}, ContainerMisnamed + "," + ContainerMissing},
		"container stopped while running": {func(inv *Inventory) { inv.Host.Containers[0].State = "exited" }, ContainerNotRunning},
		"container gone":                  {func(inv *Inventory) { inv.Host.Containers = inv.Host.Containers[1:] }, ContainerMissing},
		"network of the rolled-back instance": {func(inv *Inventory) {
			inv.Host.Networks = append(inv.Host.Networks, Network{Name: "mg-t-run-b", Labels: map[string]string{labelInstance: inst(inv, "run-b").ID.String()}})
		}, NetworkOfRemoved},
		"network with a derived name, no label": {func(inv *Inventory) {
			inv.Host.Networks = append(inv.Host.Networks, Network{Name: "mg-t-run-z"})
		}, NetworkUnlabelled},
		"network gone": {func(inv *Inventory) {
			inv.Host.Networks = inv.Host.Networks[1:]
		}, NetworkMissing},
		"edge on the network of a removed instance": {func(inv *Inventory) {
			inv.Host.EdgeNetworks = append(inv.Host.EdgeNetworks, "mg-t-run-b")
		}, EdgeAttachedOrphan},
		"edge detached from a running instance": {func(inv *Inventory) { inv.Host.EdgeNetworks = []string{"run-net"} }, EdgeNotAttached},
		"hidden directory of an interrupted create": {func(inv *Inventory) {
			inv.Host.Dirs = append(inv.Host.Dirs, "."+uuid.NewString()+creatingSuffix)
		}, DirHidden},
		"directory of the rolled-back instance (keys inside)": {func(inv *Inventory) {
			inv.Host.Dirs = append(inv.Host.Dirs, inst(inv, "run-b").ID.String())
		}, DirOfRemoved},
		"directory of an unknown instance": {func(inv *Inventory) { inv.Host.Dirs = append(inv.Host.Dirs, uuid.NewString()) }, DirUnknown},
		"foreign entry":                    {func(inv *Inventory) { inv.Host.Dirs = append(inv.Host.Dirs, "lost+found") }, DirForeign},
		"directory gone":                   {func(inv *Inventory) { inv.Host.Dirs = nil }, DirMissing},
		"older key version still live": {func(inv *Inventory) {
			inv.Registry.Secrets[0].Destroyed = false
		}, SecretOrphan},
		"key version of the rolled-back instance still live": {func(inv *Inventory) {
			inv.Registry.Secrets[3].Destroyed = false
		}, SecretOrphan},
		"referenced version destroyed": {func(inv *Inventory) {
			inv.Registry.Secrets[1].Destroyed = true
		}, SecretMissing},
		"IdP secret nobody references": {func(inv *Inventory) {
			inv.Registry.IdPs[1].ClientSecretRef = ""
		}, SecretOrphan},
		"unexpected secret": {func(inv *Inventory) {
			inv.Registry.Secrets = append(inv.Registry.Secrets, Secret{TenantID: inst(inv, "run-a").TenantID, Name: "something", Version: 1})
		}, SecretUnexpected},
		"pending IdP secret not destroyed": {func(inv *Inventory) {
			inv.Registry.Secrets = append(inv.Registry.Secrets, Secret{Name: "idp-pending." + inv.Registry.IdPs[0].ID.String() + ".client", Version: 1})
		}, PendingSecretLeft},
		"a second valid key (created, never stored)": {func(inv *Inventory) {
			inv.Keys[0].Listed = append(inv.Keys[0].Listed, APIKey{Prefix: "orphanorphan"})
		}, APIKeyExtraValid},
		"registered key expired": {func(inv *Inventory) {
			inv.Keys[0].Listed[1].Expiration = inv.Now.Add(-time.Second)
		}, APIKeyRegisteredGone},
		"stored key is another key": {func(inv *Inventory) { inv.Keys[0].StoredPrefix = "bbbbbbbbbbbb" }, APIKeySecretMismatch},
		"stored key unreadable":     {func(inv *Inventory) { inv.Keys[0].StoredErr = "destroyed" }, APIKeySecretUnread},
		"stored key refused":        {func(inv *Inventory) { inv.Keys[0].APIOK, inv.Keys[0].APIErr = false, "401" }, APIKeyRejected},
		"keys not listed":           {func(inv *Inventory) { inv.Keys[0].ListErr = "agent unreachable" }, APIKeyUnlisted},
		"keys not checked":          {func(inv *Inventory) { inv.Keys = nil }, APIKeyUnchecked},
		"valid key, none registered": {func(inv *Inventory) {
			for i := range inv.Registry.Instances {
				if inv.Registry.Instances[i].Slug == "run-a" {
					inv.Registry.Instances[i].APIKeyPrefix, inv.Registry.Instances[i].APIKeyRef = "", ""
				}
			}
			inv.Registry.Secrets[1].Destroyed = true
		}, APIKeyUnregistered},
		"instance left allocated": {func(inv *Inventory) {
			inv.Registry.Instances[1].Status = StatusFailed
		}, InstanceUnsettled},
		"pending invitation of the rolled-back tenant": {func(inv *Inventory) {
			inv.Registry.Invitations = append(inv.Registry.Invitations, Invitation{ID: uuid.New(), TenantID: inst(inv, "run-b").TenantID, Status: "pending"})
		}, InvitationLeft},
		"relay rows of the rolled-back tenant": {func(inv *Inventory) {
			inv.Registry.Relays = append(inv.Registry.Relays, Relay{TenantID: inst(inv, "run-b").TenantID, Kind: "region", Name: "mg-run-b"})
		}, RelayLeft},
		"IdP of the rolled-back tenant still pending": {func(inv *Inventory) {
			inv.Registry.IdPs[1].Status = "pending"
		}, IdPNotDisabled},
		"reconcile host finding": {func(inv *Inventory) {
			inv.Reconcile = []HostFinding{{Kind: "removed_instance_leftover", Subject: inst(inv, "run-b").ID.String()}}
		}, ReconcilePrefix + "removed_instance_leftover"},
	} {
		t.Run(name, func(t *testing.T) {
			inv := world()
			c.mut(&inv)
			if got := kinds(Check(inv)); got != c.want {
				t.Fatalf("findings %s, want %s (%v)", got, c.want, Check(inv))
			}
		})
	}
}

// TestOtherRunsAreIgnored: objects of tenants outside the scope (another run on a shared host) are never findings.
func TestOtherRunsAreIgnored(t *testing.T) {
	inv := world()
	inv.Host.Containers = append(inv.Host.Containers, Container{Name: "mg-hs-zz-ghost", State: "exited",
		Labels: map[string]string{labelInstance: uuid.NewString()}}, Container{Name: "mg-helper-zz-x-fingerprint-00000000",
		Labels: map[string]string{labelRole: roleHelper}})
	inv.Host.Networks = append(inv.Host.Networks, Network{Name: "mg-t-zz-ghost"}, Network{Name: "bridge"})
	inv.Host.EdgeNetworks = append(inv.Host.EdgeNetworks, "mg-t-zz-ghost")
	inv.Registry.Secrets = append(inv.Registry.Secrets, Secret{TenantID: uuid.New(), Name: "anything", Version: 1})
	if fs := Check(inv); len(fs) != 0 {
		t.Fatalf("other runs judged: %v", fs)
	}
	// unsettled states are fine while a job is in flight
	inv.Scope.Settled = false
	inv.Registry.Instances[1].Status = StatusAllocated
	if fs := Check(inv); len(fs) != 0 {
		t.Fatalf("in flight: %v", fs)
	}
}
