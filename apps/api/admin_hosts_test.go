package main

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
)

// testPublicIPv4 stands for the public entry of a host (documentation range, RFC 5737); a real address never appears in
// tests or documents.
const testPublicIPv4 = "203.0.113.77"

// TestParseHostSet — the flags are checked before anything is opened; the address only ever comes from the variable
// named by --public-ipv4-env and no message repeats it.
func TestParseHostSet(t *testing.T) {
	env := map[string]string{"MG_PUBLIC_IPV4": " " + testPublicIPv4 + "\n", "MG_EMPTY": ""}
	getenv := func(k string) string { return env[k] }
	r, msg := parseHostSet([]string{"--name", "mg-staging", "--public-ipv4-env", "MG_PUBLIC_IPV4", "--mode", "vps_gateway",
		"--max-instances", "20", "--status", "active"}, getenv)
	if msg != "" || r.name != "mg-staging" || r.ipv4 != testPublicIPv4 || r.mode != "vps_gateway" || r.maxInstances == nil ||
		*r.maxInstances != 20 || r.status != "active" {
		t.Fatalf("parse: %+v %q", r, msg)
	}
	for name, args := range map[string][]string{
		"no name":         {"--mode", "direct"},
		"nothing to do":   {"--name", "h"},
		"positional":      {"--name", "h", "--status", "active", "extra"},
		"bad mode":        {"--name", "h", "--mode", "tunnel"},
		"bad status":      {"--name", "h", "--status", "maintenance"},
		"bad max":         {"--name", "h", "--max-instances", "many"},
		"address as name": {"--name", "h", "--public-ipv4-env", testPublicIPv4},
		"ipv6 as name":    {"--name", "h", "--public-ipv4-env", "2001:db8::1"},
		"lower-case name": {"--name", "h", "--public-ipv4-env", "mg_public_ipv4"},
		"unset variable":  {"--name", "h", "--public-ipv4-env", "MG_UNSET"},
		"empty variable":  {"--name", "h", "--public-ipv4-env", "MG_EMPTY"},
		"unknown flag":    {"--name", "h", "--public-ipv4", testPublicIPv4},
	} {
		_, msg := parseHostSet(args, getenv)
		if msg == "" {
			t.Errorf("%s: accepted", name)
		}
		if strings.Contains(msg, testPublicIPv4) {
			t.Errorf("%s: the message repeats the address: %s", name, msg)
		}
	}
	if _, msg := parseHostSet([]string{"--name", "h", "--public-ipv4-env", "MG_UNSET"}, getenv); !strings.Contains(msg, `-e "MG_UNSET=$MG_UNSET"`) {
		t.Errorf("unset variable: %q", msg)
	}
}

// TestHostSetPatch — public_entry is replaced as a whole: the key the flags leave alone keeps its current value.
func TestHostSetPatch(t *testing.T) {
	cur := platform.HostView{Host: platform.Host{PublicEntry: netip.MustParseAddr("198.51.100.1"), EntryMode: platform.EntryDirect}}
	p := hostSetRequest{name: "h", mode: platform.EntryVPSGateway}.patch(cur)
	if p.PublicEntry == nil || p.PublicEntry.IPv4 == nil || *p.PublicEntry.IPv4 != "198.51.100.1" || *p.PublicEntry.Mode != "vps_gateway" ||
		p.Status != nil || p.MaxInstances != nil {
		t.Errorf("mode only: %+v", p)
	}
	p = hostSetRequest{name: "h", ipv4Env: "MG_PUBLIC_IPV4", ipv4: testPublicIPv4}.patch(platform.HostView{})
	if p.PublicEntry == nil || *p.PublicEntry.IPv4 != testPublicIPv4 || p.PublicEntry.Mode != nil {
		t.Errorf("address only on a host without entry: %+v", p)
	}
	if p := (hostSetRequest{name: "h", status: "draining"}).patch(cur); p.PublicEntry != nil || p.Status == nil {
		t.Errorf("status only: %+v", p)
	}
}

// TestHostSetCommand — `meshguard admin host-set` end to end on a migrated database with the api's roles: the staging
// case (public entry of a host registered by adopt-instance, from MG_PUBLIC_IPV4), a re-run that changes nothing, the
// refusals (capacity below the live instances, an address inside the tenant pool, an unknown host) that write nothing,
// the audit rows (actor_type system), and the address never in the output.
func TestHostSetCommand(t *testing.T) {
	c := newCLIEnv(t, "", "")
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := c.su.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("fixture: %v\n%s", err, sql)
		}
	}
	// the host as adopt-instance registers it (capacity and public_entry from the DEFAULTs of 0014), two live instances
	host, ten1, ten2 := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	exec(`INSERT INTO hosts (id, name, region, run_uid_range, tenant_net_pool) VALUES ($1, 'mg-staging', 'lab',
		int4range(30000, 40000), '10.250.0.0/16')`, host)
	for i, ten := range []uuid.UUID{ten1, ten2} {
		slug := []string{"tenant-a", "tenant-b"}[i]
		exec(`INSERT INTO tenants (id, slug, name, status) VALUES ($1, $2::text, $2::text, 'active')`, ten, slug)
		exec(`INSERT INTO tenant_instances (tenant_id, host_id, status, headscale_version, image_digest, control_hostname,
				server_url, base_domain, internal_address, run_uid, net_cidr, data_path)
			VALUES ($1, $2, 'running', '0.29.7', 'sha256:'||repeat('a', 64), $3::text||'.mesh.mg.test',
				'https://'||$3::text||'.mesh.mg.test', $3::text||'.tail.mg.test', 'hs-'||$3::text||':8080', $4::int,
				$5::cidr, '/opt/meshguard/tenants/x/data')`, ten, host, slug, 30001+i, []string{"10.250.0.0/29", "10.250.0.8/29"}[i])
	}
	row := func() (string, string) {
		t.Helper()
		var capacity, entry string
		if err := c.su.QueryRow(ctx, `SELECT capacity::text, public_entry::text FROM hosts WHERE id = $1`, host).Scan(&capacity, &entry); err != nil {
			t.Fatal(err)
		}
		return capacity, entry
	}
	if cap0, entry0 := row(); cap0 != `{"max_instances": 100}` || entry0 != `{}` {
		t.Fatalf("fixture host: %s %s", cap0, entry0)
	}
	c.vars["MG_PUBLIC_IPV4"] = testPublicIPv4
	stagingCmd := []string{"host-set", "--name", "mg-staging", "--public-ipv4-env", "MG_PUBLIC_IPV4", "--mode", "vps_gateway"}

	// the staging command
	if code := c.run(nil, stagingCmd...); code != 0 {
		t.Fatalf("host-set: %d\n%s%s", code, c.stdout.String(), c.stderr.String())
	}
	out := c.stdout.String()
	for _, want := range []string{"host-set: host mg-staging (" + host.String() + "), region lab",
		"public_entry.ipv4: value of $MG_PUBLIC_IPV4 (changed; the address is not printed)",
		"public_entry.mode: vps_gateway (changed)", "capacity.max_instances: 100 (unchanged)",
		"instances not removed: 2 of 100", "placement: can choose this host", "audit: platform.host.update (actor_type system", "OK"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if _, entry := row(); entry != `{"ipv4": "`+testPublicIPv4+`", "mode": "vps_gateway"}` {
		t.Errorf("public_entry %s", entry)
	}
	// a re-run changes nothing
	if code := c.run(nil, stagingCmd...); code != 0 || !strings.Contains(c.stdout.String(), "(unchanged; the address is not printed)") {
		t.Errorf("re-run: %d\n%s%s", code, c.stdout.String(), c.stderr.String())
	}
	// capacity, status
	if code := c.run(nil, "host-set", "--name", "mg-staging", "--max-instances", "2", "--status", "draining"); code != 0 ||
		!strings.Contains(c.stdout.String(), "status: active → draining") || !strings.Contains(c.stdout.String(), "placement: skips this host (status draining)") {
		t.Errorf("capacity + status: %d\n%s%s", code, c.stdout.String(), c.stderr.String())
	}
	// refusals: nothing written
	capBefore, entryBefore := row()
	c.vars["MG_INSIDE_POOL"] = "10.250.7.7"
	for name, args := range map[string][]string{
		"capacity below live": {"host-set", "--name", "mg-staging", "--max-instances", "1"},
		"address in the pool": {"host-set", "--name", "mg-staging", "--public-ipv4-env", "MG_INSIDE_POOL"},
		"unknown host":        {"host-set", "--name", "mg-nowhere", "--status", "active"},
	} {
		if code := c.run(nil, args...); code != 1 || !strings.Contains(c.stderr.String(), "nothing was written") {
			t.Errorf("%s: %d\n%s%s", name, code, c.stdout.String(), c.stderr.String())
		}
		if strings.Contains(c.stderr.String(), "10.250.7.7") {
			t.Errorf("%s: the error repeats the address: %s", name, c.stderr.String())
		}
	}
	if capAfter, entryAfter := row(); capAfter != capBefore || entryAfter != entryBefore {
		t.Errorf("refusals wrote: %s %s → %s %s", capBefore, entryBefore, capAfter, entryAfter)
	}
	if !strings.Contains(c.out.String(), "public_entry.ipv4: must lie outside tenant_net_pool") {
		t.Errorf("the refusal does not name the field:\n%s", c.out.String())
	}
	// usage errors before any connection
	if code := c.run(nil, "host-set", "--name", "mg-staging", "--public-ipv4-env", testPublicIPv4); code != 2 {
		t.Errorf("address as an argument: %d", code)
	}
	if strings.Contains(c.out.String(), testPublicIPv4) {
		t.Errorf("the public address appears in the output:\n%s", c.out.String())
	}

	// the audit trail: three updates (staging, re-run, capacity+status), actor_type system, one request id each
	rows, err := c.su.Query(ctx, `SELECT actor_type, actor_identity_id IS NULL, actor_display, request_id, tenant_id IS NULL,
			details::text FROM audit_events WHERE action = 'platform.host.update' AND resource_id = $1 ORDER BY occurred_at, id`,
		host.String())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var n int
	reqs := map[string]bool{}
	for rows.Next() {
		var actorType, display, req, details string
		var noActor, platformScope bool
		if err := rows.Scan(&actorType, &noActor, &display, &req, &platformScope, &details); err != nil {
			t.Fatal(err)
		}
		n++
		reqs[req] = true
		var d map[string]any
		_ = json.Unmarshal([]byte(details), &d)
		if actorType != "system" || !noActor || display != "meshguard admin host-set" || !strings.HasPrefix(req, "admin-") ||
			!platformScope || d["live_instances"] != float64(2) {
			t.Errorf("audit row %d: %s %v %q %s %v %v", n, actorType, noActor, display, req, platformScope, d)
		}
		if n == 1 && (d["before_public_ipv4"] != nil || d["after_public_ipv4"] != testPublicIPv4 || d["after_entry_mode"] != "vps_gateway") {
			t.Errorf("first change: %v", d)
		}
	}
	if n != 3 || len(reqs) != 3 {
		t.Errorf("%d audit rows, %d request ids — want 3 and 3", n, len(reqs))
	}
}
