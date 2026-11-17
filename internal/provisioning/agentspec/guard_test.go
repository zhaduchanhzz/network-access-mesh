package agentspec

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
)

const (
	rForeign  = agentv1.RefusalReason_REFUSAL_REASON_FOREIGN_OBJECT
	rIdentity = agentv1.RefusalReason_REFUSAL_REASON_IDENTITY_MISMATCH
	rUnsafe   = agentv1.RefusalReason_REFUSAL_REASON_UNSAFE_PATH
	rNotFound = agentv1.RefusalReason_REFUSAL_REASON_NOT_FOUND
	rState    = agentv1.RefusalReason_REFUSAL_REASON_STATE
)

// writeInstance lays out <tenants>/<id>/meta/instance.json like tenant-deploy.sh does (directories 0750/0700, meta
// 0400), with the Phase 1 key set of tools/render_instance.py.
func writeInstance(t *testing.T, h *Host, id, tenant, slug string, uid int, cidr string) string {
	t.Helper()
	dir := filepath.Join(h.TenantsDir, id)
	for _, d := range []struct {
		p    string
		mode os.FileMode
	}{{dir, 0o750}, {filepath.Join(dir, "meta"), 0o700}, {filepath.Join(dir, "data"), 0o700}} {
		if err := os.MkdirAll(d.p, d.mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(d.p, d.mode); err != nil {
			t.Fatal(err)
		}
	}
	meta, _ := json.Marshal(map[string]any{"config_sha256": "0000", "image": repo + "@" + digestA, "instance_id": id,
		"net_cidr": cidr, "run_uid": uid, "slug": slug, "template_version": "1", "tenant_id": tenant})
	f := filepath.Join(dir, "meta", "instance.json")
	if err := os.WriteFile(f, meta, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f, 0o400); err != nil {
		t.Fatal(err)
	}
	return dir
}

func validSpec(t *testing.T, h *Host) InstanceSpec {
	t.Helper()
	s, err := (&Validator{Host: h}).Spec("spec", goodSpec())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type fakeInventory struct {
	nets []NetworkInfo
	ctrs []ContainerInfo
}

func (f *fakeInventory) Networks(context.Context) ([]NetworkInfo, error)     { return f.nets, nil }
func (f *fakeInventory) Containers(context.Context) ([]ContainerInfo, error) { return f.ctrs, nil }

func ownLabels() map[string]string {
	return map[string]string{LabelInstanceID: instanceID, LabelTenantID: tenantID, LabelRole: RoleTenant, LabelComposeProject: "mg-t-acme"}
}

func TestGuardFilesystem(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name   string
		setup  func(t *testing.T, h *Host)
		reason agentv1.RefusalReason // 0 = accepted
		field  string
	}{
		{"fresh instance", func(*testing.T, *Host) {}, 0, ""},
		{"own directory, same identity", func(t *testing.T, h *Host) {
			writeInstance(t, h, instanceID, tenantID, "acme", 30001, "10.250.0.8/29")
		}, 0, ""},
		{"non-uuid entries are ignored", func(t *testing.T, h *Host) {
			if err := os.Mkdir(filepath.Join(h.TenantsDir, "lost+found"), 0o700); err != nil {
				t.Fatal(err)
			}
		}, 0, ""},
		{"own directory of another tenant", func(t *testing.T, h *Host) {
			writeInstance(t, h, instanceID, otherID, "acme", 30001, "10.250.0.8/29")
		}, rIdentity, "spec.instance.tenant_id"},
		{"own directory with another slug", func(t *testing.T, h *Host) {
			writeInstance(t, h, instanceID, tenantID, "globex", 30001, "10.250.0.8/29")
		}, rIdentity, "spec.instance.slug"},
		{"run_uid is immutable", func(t *testing.T, h *Host) {
			writeInstance(t, h, instanceID, tenantID, "acme", 30002, "10.250.0.8/29")
		}, rConflict, "spec.run_uid"},
		{"net_cidr is immutable", func(t *testing.T, h *Host) {
			writeInstance(t, h, instanceID, tenantID, "acme", 30001, "10.250.0.16/29")
		}, rConflict, "spec.net_cidr"},
		{"slug used by another instance", func(t *testing.T, h *Host) {
			writeInstance(t, h, otherID, otherID[:35]+"5", "acme", 30005, "10.250.0.32/29")
		}, rConflict, "spec.instance.slug"},
		{"run_uid used by another instance", func(t *testing.T, h *Host) {
			writeInstance(t, h, otherID, otherID[:35]+"5", "globex", 30001, "10.250.0.32/29")
		}, rConflict, "spec.run_uid"},
		{"subnet used by another instance", func(t *testing.T, h *Host) {
			writeInstance(t, h, otherID, otherID[:35]+"5", "globex", 30005, "10.250.0.8/29")
		}, rConflict, "spec.net_cidr"},
		{"directory without meta (never adopted)", func(t *testing.T, h *Host) {
			if err := os.Mkdir(filepath.Join(h.TenantsDir, instanceID), 0o750); err != nil {
				t.Fatal(err)
			}
		}, rForeign, ""},
		{"another instance without meta fails the scan closed", func(t *testing.T, h *Host) {
			if err := os.Mkdir(filepath.Join(h.TenantsDir, otherID), 0o750); err != nil {
				t.Fatal(err)
			}
		}, rForeign, "inventory"},
		{"meta is a symlink to another instance", func(t *testing.T, h *Host) {
			other := writeInstance(t, h, otherID, otherID[:35]+"5", "globex", 30005, "10.250.0.32/29")
			own := writeInstance(t, h, instanceID, tenantID, "acme", 30001, "10.250.0.8/29")
			f := filepath.Join(own, "meta", "instance.json")
			_ = os.Remove(f)
			if err := os.Symlink(filepath.Join(other, "meta", "instance.json"), f); err != nil {
				t.Fatal(err)
			}
		}, rUnsafe, ""},
		{"instance directory is a symlink outside", func(t *testing.T, h *Host) {
			outside := t.TempDir()
			if err := os.Symlink(outside, filepath.Join(h.TenantsDir, instanceID)); err != nil {
				t.Fatal(err)
			}
		}, rUnsafe, ""},
		{"meta/ is a symlink", func(t *testing.T, h *Host) {
			own := writeInstance(t, h, instanceID, tenantID, "acme", 30001, "10.250.0.8/29")
			_ = os.RemoveAll(filepath.Join(own, "meta"))
			if err := os.Symlink(t.TempDir(), filepath.Join(own, "meta")); err != nil {
				t.Fatal(err)
			}
		}, rUnsafe, ""},
		{"meta writable by the group", func(t *testing.T, h *Host) {
			own := writeInstance(t, h, instanceID, tenantID, "acme", 30001, "10.250.0.8/29")
			if err := os.Chmod(filepath.Join(own, "meta", "instance.json"), 0o660); err != nil { //nolint:gosec // G302: the unsafe mode under test
				t.Fatal(err)
			}
		}, rUnsafe, ""},
		{"instance directory writable by others", func(t *testing.T, h *Host) {
			own := writeInstance(t, h, instanceID, tenantID, "acme", 30001, "10.250.0.8/29")
			if err := os.Chmod(own, 0o777); err != nil { //nolint:gosec // G302: the unsafe mode under test
				t.Fatal(err)
			}
		}, rUnsafe, ""},
		{"meta is a directory", func(t *testing.T, h *Host) {
			own := writeInstance(t, h, instanceID, tenantID, "acme", 30001, "10.250.0.8/29")
			f := filepath.Join(own, "meta", "instance.json")
			_ = os.Remove(f)
			if err := os.Mkdir(f, 0o700); err != nil {
				t.Fatal(err)
			}
		}, rUnsafe, ""},
		{"meta is not JSON", func(t *testing.T, h *Host) {
			own := writeInstance(t, h, instanceID, tenantID, "acme", 30001, "10.250.0.8/29")
			f := filepath.Join(own, "meta", "instance.json")
			_ = os.Chmod(f, 0o600)
			if err := os.WriteFile(f, []byte("slug: acme\n"), 0o400); err != nil {
				t.Fatal(err)
			}
			_ = os.Chmod(f, 0o400)
		}, rUnsafe, ""},
		{"meta names another instance", func(t *testing.T, h *Host) {
			own := writeInstance(t, h, otherID, tenantID, "acme", 30001, "10.250.0.8/29")
			if err := os.Rename(own, filepath.Join(h.TenantsDir, instanceID)); err != nil {
				t.Fatal(err)
			}
		}, rIdentity, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := testHost(t)
			c.setup(t, h)
			err := (&Guard{Host: h}).CheckSpec(ctx, validSpec(t, h))
			if c.reason == 0 {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			wantRefusal(t, err, c.reason, c.field)
		})
	}
	t.Logf("%d guard filesystem cases", len(cases))
}

func TestGuardDocker(t *testing.T) {
	ctx := context.Background()
	ownNet := func() NetworkInfo {
		return NetworkInfo{Name: "mg-t-acme", Labels: map[string]string{LabelInstanceID: instanceID, LabelRole: RoleTenant},
			Subnets: []netip.Prefix{netip.MustParsePrefix("10.250.0.8/29")}, Internal: true}
	}
	cases := []struct {
		name   string
		inv    fakeInventory
		reason agentv1.RefusalReason
		field  string
	}{
		{"nothing exists", fakeInventory{}, 0, ""},
		{"own network and container", fakeInventory{nets: []NetworkInfo{ownNet()},
			ctrs: []ContainerInfo{{Name: "mg-hs-acme", Labels: ownLabels()}}}, 0, ""},
		{"unrelated objects", fakeInventory{
			nets: []NetworkInfo{{Name: "mg-edge", Subnets: []netip.Prefix{netip.MustParsePrefix("10.249.0.0/24")}}},
			ctrs: []ContainerInfo{{Name: "mg-edge"}}}, 0, ""},
		{"network of another instance", fakeInventory{nets: []NetworkInfo{{Name: "mg-t-acme",
			Labels: map[string]string{LabelInstanceID: otherID, LabelRole: RoleTenant}, Internal: true}}}, rForeign, "spec.instance.slug"},
		{"unlabelled network with the derived name", fakeInventory{nets: []NetworkInfo{{Name: "mg-t-acme", Internal: true,
			Subnets: []netip.Prefix{netip.MustParsePrefix("10.250.0.8/29")}}}}, rForeign, "spec.instance.slug"},
		{"own network not internal", fakeInventory{nets: []NetworkInfo{func() NetworkInfo { n := ownNet(); n.Internal = false; return n }()}},
			rConflict, "spec.instance.slug"},
		{"own network with another subnet", fakeInventory{nets: []NetworkInfo{func() NetworkInfo {
			n := ownNet()
			n.Subnets = []netip.Prefix{netip.MustParsePrefix("10.250.0.16/29")}
			return n
		}()}}, rConflict, "spec.net_cidr"},
		{"another network overlaps the subnet", fakeInventory{nets: []NetworkInfo{{Name: "mg-t-globex",
			Labels:  map[string]string{LabelInstanceID: otherID, LabelRole: RoleTenant},
			Subnets: []netip.Prefix{netip.MustParsePrefix("10.250.0.0/28")}}}}, rConflict, "spec.net_cidr"},
		{"this instance's label on another network", fakeInventory{nets: []NetworkInfo{{Name: "mg-t-old-name",
			Labels: map[string]string{LabelInstanceID: instanceID}}}}, rConflict, "spec.instance.instance_id"},
		{"container of another instance", fakeInventory{ctrs: []ContainerInfo{{Name: "mg-hs-acme",
			Labels: map[string]string{LabelInstanceID: otherID, LabelTenantID: tenantID, LabelComposeProject: "mg-t-acme"}}}}, rForeign, "spec.instance.slug"},
		{"unlabelled container with the derived name", fakeInventory{ctrs: []ContainerInfo{{Name: "mg-hs-acme"}}}, rForeign, "spec.instance.slug"},
		{"container of another tenant", fakeInventory{ctrs: []ContainerInfo{{Name: "mg-hs-acme",
			Labels: map[string]string{LabelInstanceID: instanceID, LabelTenantID: otherID, LabelComposeProject: "mg-t-acme"}}}}, rForeign, "spec.instance.slug"},
		{"own labels outside the compose project", fakeInventory{ctrs: []ContainerInfo{{Name: "mg-hs-acme",
			Labels: map[string]string{LabelInstanceID: instanceID, LabelTenantID: tenantID}}}}, rForeign, "spec.instance.slug"},
		{"foreign container inside the project", fakeInventory{ctrs: []ContainerInfo{{Name: "sidecar",
			Labels: map[string]string{LabelComposeProject: "mg-t-acme"}}}}, rForeign, "spec.instance.slug"},
		{"this instance's label on another container", fakeInventory{ctrs: []ContainerInfo{{Name: "mg-hs-renamed",
			Labels: map[string]string{LabelInstanceID: instanceID}}}}, rConflict, "spec.instance.instance_id"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := testHost(t)
			inv := c.inv
			err := (&Guard{Host: h, Inventory: &inv, Edge: "mg-edge"}).CheckSpec(ctx, validSpec(t, h))
			if c.reason == 0 {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			wantRefusal(t, err, c.reason, c.field)
		})
	}
	t.Logf("%d guard docker cases", len(cases))
}

func TestGuardRef(t *testing.T) {
	ctx := context.Background()
	h := testHost(t)
	g := &Guard{Host: h}
	ref := Ref{InstanceID: mustUUID(instanceID), TenantID: mustUUID(tenantID), Slug: "acme"}
	_, err := g.CheckRef(ctx, ref, true)
	wantRefusal(t, err, rNotFound, "instance.instance_id")
	if m, err := g.CheckRef(ctx, ref, false); err != nil || m != nil {
		t.Fatalf("absent, not required: %v %v", m, err)
	}
	writeInstance(t, h, instanceID, tenantID, "acme", 30001, "10.250.0.8/29")
	if m, err := g.CheckRef(ctx, ref, true); err != nil || m.RunUID != 30001 {
		t.Fatalf("own: %+v %v", m, err)
	}
	_, err = g.CheckRef(ctx, Ref{InstanceID: ref.InstanceID, TenantID: mustUUID(otherID), Slug: "acme"}, true)
	wantRefusal(t, err, rIdentity, "instance.tenant_id")
	_, err = g.CheckRef(ctx, Ref{InstanceID: ref.InstanceID, TenantID: ref.TenantID, Slug: "globex"}, true)
	wantRefusal(t, err, rIdentity, "instance.slug")
	// Docker objects named after the slug must be this instance's, with the subnet of its meta
	g.Inventory = &fakeInventory{nets: []NetworkInfo{{Name: "mg-t-acme", Labels: map[string]string{LabelInstanceID: instanceID, LabelRole: RoleTenant},
		Internal: true, Subnets: []netip.Prefix{netip.MustParsePrefix("10.250.0.24/29")}}}}
	_, err = g.CheckRef(ctx, ref, true)
	wantRefusal(t, err, rConflict, "instance")
}

func TestGuardEdgeAttach(t *testing.T) {
	ctx := context.Background()
	h := testHost(t)
	ref := Ref{InstanceID: mustUUID(instanceID), TenantID: mustUUID(tenantID), Slug: "acme"}
	own := func(members ...Member) NetworkInfo {
		return NetworkInfo{Name: "mg-t-acme", Labels: map[string]string{LabelInstanceID: instanceID, LabelRole: RoleTenant}, Internal: true, Members: members}
	}
	hs := Member{Container: "mg-hs-acme", Aliases: []string{"hs-acme"}}
	edge := Member{Container: "mg-edge"}
	cases := []struct {
		name   string
		nets   []NetworkInfo
		reason agentv1.RefusalReason
	}{
		{"ready to attach", []NetworkInfo{own(hs), {Name: "mg-edge", Members: []Member{edge}}}, 0},
		{"already attached", []NetworkInfo{own(hs, edge)}, 0},
		{"alias on another network of the edge", []NetworkInfo{own(hs),
			{Name: "mg-t-evil", Members: []Member{edge, {Container: "mg-hs-evil", Aliases: []string{"hs-evil", "hs-acme"}}}}}, rConflict},
		{"container named like the alias on an edge network", []NetworkInfo{own(hs),
			{Name: "mg-t-evil", Members: []Member{edge, {Container: "hs-acme"}}}}, rConflict},
		{"alias elsewhere but not on an edge network", []NetworkInfo{own(hs),
			{Name: "lab", Members: []Member{{Container: "x", Aliases: []string{"hs-acme"}}}}}, 0},
		{"third member on the tenant network", []NetworkInfo{own(hs, edge, Member{Container: "intruder"})}, rForeign},
		{"no tenant network", []NetworkInfo{{Name: "mg-edge", Members: []Member{edge}}}, rState},
		{"instance not attached", []NetworkInfo{own()}, rState},
		{"tenant network of another instance", []NetworkInfo{func() NetworkInfo {
			n := own(hs)
			n.Labels[LabelInstanceID] = otherID
			return n
		}()}, rForeign},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := (&Guard{Host: h, Inventory: &fakeInventory{nets: c.nets}, Edge: "mg-edge"}).CheckEdgeAttach(ctx, ref)
			if c.reason == 0 {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			wantRefusal(t, err, c.reason, "instance.slug")
		})
	}
}
