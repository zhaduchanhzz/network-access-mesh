package compose

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"path"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/agentspec"
)

// The isolation invariants of §11.1 and §11.3 step 8 — checked on the rendered bytes, parsed back as YAML, before
// anything is written. The templates are fixed and the values typed, so a failure here is a template or renderer
// bug; the agent refuses to write rather than run an instance that could fail open.

// ErrInvariant marks a rendered file that breaks an isolation invariant.
var ErrInvariant = errors.New("rendered configuration breaks an isolation invariant")

func invariant(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvariant, fmt.Sprintf(format, args...))
}

// get walks a parsed YAML document: get(doc, "derp", "server", "enabled").
func get(doc map[string]any, keys ...string) (any, bool) {
	var cur any = doc
	for _, k := range keys {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = m[k]; !ok {
			return nil, false
		}
	}
	return cur, true
}

func want(doc map[string]any, v any, keys ...string) error {
	got, ok := get(doc, keys...)
	if !ok || !reflect.DeepEqual(got, v) {
		return invariant("%s must be %v", strings.Join(keys, "."), v)
	}
	return nil
}

func parseYAML(b []byte) (map[string]any, error) {
	var doc map[string]any
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil {
		return nil, invariant("not a YAML mapping: %v", err)
	}
	return doc, nil
}

var (
	expiryRE  = regexp.MustCompile(`^[1-9][0-9]*h$`)
	cgnatV4   = netip.MustParsePrefix("100.64.0.0/10")
	tailnetV6 = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

// checkConfig: config.yaml (§11.1, §11.3 step 8, §14.5) — the values configtest does not catch and that would fail open.
func checkConfig(b []byte, h *agentspec.Host, s agentspec.InstanceSpec) error {
	doc, err := parseYAML(b)
	if err != nil {
		return err
	}
	slug := s.Ref.Slug
	for _, c := range []struct {
		v    any
		keys []string
	}{
		{"https://" + slug + ".mesh." + h.BaseDomain, []string{"server_url"}},
		{false, []string{"grpc_allow_insecure"}},
		{"127.0.0.1:50443", []string{"grpc_listen_addr"}},
		{[]any{s.NetCIDR.String()}, []string{"trusted_proxies"}},
		{"", []string{"tls_cert_path"}},
		{"", []string{"tls_key_path"}},
		{"", []string{"tls_letsencrypt_hostname"}},
		{true, []string{"derp", "server", "enabled"}},
		{true, []string{"derp", "server", "verify_clients"}},
		{int(s.Headscale.DERPRegionID), []string{"derp", "server", "region_id"}},
		{s.Headscale.PublicEntry.String(), []string{"derp", "server", "ipv4"}},
		{"", []string{"derp", "server", "ipv6"}},
		{[]any{}, []string{"derp", "urls"}},
		{[]any{}, []string{"derp", "paths"}},
		{false, []string{"derp", "auto_update_enabled"}},
		{"database", []string{"policy", "mode"}},
		{"", []string{"policy", "path"}},
		{"json", []string{"log", "format"}},
		{true, []string{"disable_check_updates"}},
		{false, []string{"logtail", "enabled"}},
		{true, []string{"dns", "magic_dns"}},
		{true, []string{"dns", "override_local_dns"}},
		{slug + ".tail." + h.BaseDomain, []string{"dns", "base_domain"}},
		{"/etc/headscale-records/extra-records.json", []string{"dns", "extra_records_path"}},
		{"/var/lib/headscale/noise_private.key", []string{"noise", "private_key_path"}},
		{"/var/lib/headscale/derp_server_private.key", []string{"derp", "server", "private_key_path"}},
		{"sqlite", []string{"database", "type"}},
		{"/var/lib/headscale/db.sqlite", []string{"database", "sqlite", "path"}},
		{"/var/run/headscale/headscale.sock", []string{"unix_socket"}},
	} {
		if err := want(doc, c.v, c.keys...); err != nil {
			return err
		}
	}
	if lvl, _ := get(doc, "log", "level"); !slices.Contains([]any{"info", "warn", "error"}, lvl) {
		return invariant("log.level must be info, warn or error")
	}
	if e, _ := get(doc, "node", "expiry"); !expiryRE.MatchString(fmt.Sprint(e)) {
		return invariant("node.expiry must be a positive whole number of hours")
	}
	for k, within := range map[string]netip.Prefix{"v4": cgnatV4, "v6": tailnetV6} {
		v, _ := get(doc, "prefixes", k)
		p, err := netip.ParsePrefix(fmt.Sprint(v))
		if err != nil || !within.Contains(p.Addr()) || p.Bits() < within.Bits() {
			return invariant("prefixes.%s must lie within %s", k, within)
		}
	}
	ns, _ := get(doc, "dns", "nameservers", "global")
	if l, ok := ns.([]any); !ok || len(l) == 0 {
		return invariant("dns.nameservers.global must not be empty (RT-07)")
	}
	// RT-07: the MagicDNS domain is neither the host of server_url nor one of its parents
	if host := slug + ".mesh." + h.BaseDomain; host == slug+".tail."+h.BaseDomain || strings.HasSuffix(host, "."+slug+".tail."+h.BaseDomain) {
		return invariant("dns.base_domain overlaps server_url")
	}
	if _, oidc := doc["oidc"]; oidc {
		return invariant("oidc is not part of template v1 (method C — TD-14)")
	}
	return nil
}

// allowedServiceKeys are the only keys the tenant service may have: no ports, no environment (TS_* — PL-15), no
// privileges, capabilities, devices, host namespaces or extra mounts (§14.5).
var allowedServiceKeys = []string{"cap_drop", "command", "container_name", "cpus", "healthcheck", "image", "labels",
	"logging", "mem_limit", "networks", "pids_limit", "read_only", "restart", "security_opt", "stop_grace_period",
	"tmpfs", "user", "volumes"}

// checkCompose: compose.yaml (§14.5) — names derived from the slug, the image by digest, run_uid, hardening, exactly
// the three bind mounts of the instance's own directory, only the tenant's external network, no published port.
func checkCompose(b []byte, h *agentspec.Host, s agentspec.InstanceSpec) error {
	// outside comment lines (the template's header mentions TS_* to say there is none)
	for _, line := range bytes.Split(b, []byte("\n")) {
		if t := bytes.TrimSpace(line); !bytes.HasPrefix(t, []byte("#")) && (bytes.ContainsRune(t, '$') || bytes.Contains(t, []byte("TS_"))) {
			return invariant("compose.yaml must not contain an interpolation or a TS_* variable")
		}
	}
	doc, err := parseYAML(b)
	if err != nil {
		return err
	}
	n := h.Names(s.Ref)
	uid := fmt.Sprint(s.RunUID)
	if err := want(doc, n.Project, "name"); err != nil {
		return err
	}
	top := make([]string, 0, len(doc))
	for k := range doc {
		top = append(top, k)
	}
	sort.Strings(top)
	if !slices.Equal(top, []string{"name", "networks", "services"}) {
		return invariant("compose.yaml top-level keys must be name, networks, services")
	}
	svcs, _ := doc["services"].(map[string]any)
	svc, ok := svcs[n.Service].(map[string]any)
	if len(svcs) != 1 || !ok {
		return invariant("compose.yaml must have exactly the service %s", n.Service)
	}
	for k := range svc {
		if !slices.Contains(allowedServiceKeys, k) {
			return invariant("service key %q is not allowed", k)
		}
	}
	for _, c := range []struct {
		v    any
		keys []string
	}{
		{s.Image.Reference(), []string{"image"}},
		{n.Container, []string{"container_name"}},
		{[]any{"serve"}, []string{"command"}},
		{uid + ":" + uid, []string{"user"}},
		{true, []string{"read_only"}},
		{[]any{"ALL"}, []string{"cap_drop"}},
		{[]any{"no-new-privileges:true"}, []string{"security_opt"}},
		{"unless-stopped", []string{"restart"}},
		{map[string]any{n.Network: map[string]any{"aliases": []any{n.Alias}}}, []string{"networks"}},
		{map[string]any{agentspec.LabelTenantID: s.Ref.TenantID.String(), agentspec.LabelInstanceID: s.Ref.InstanceID.String(),
			agentspec.LabelRole: agentspec.RoleTenant}, []string{"labels"}},
		{[]any{"/var/run/headscale:size=1m,mode=0700,uid=" + uid + ",gid=" + uid}, []string{"tmpfs"}},
	} {
		if err := want(svc, c.v, c.keys...); err != nil {
			return err
		}
	}
	if err := want(doc, map[string]any{n.Network: map[string]any{"external": true}}, "networks"); err != nil {
		return err
	}
	mounts := map[string]struct {
		target string
		ro     bool
	}{
		n.ConfigDir:  {"/etc/headscale", true},
		n.RecordsDir: {"/etc/headscale-records", true},
		n.DataDir:    {"/var/lib/headscale", false},
	}
	vols, _ := svc["volumes"].([]any)
	if len(vols) != len(mounts) {
		return invariant("exactly %d bind mounts", len(mounts))
	}
	for _, v := range vols {
		m, _ := v.(map[string]any)
		src, _ := m["source"].(string)
		w, ok := mounts[src]
		if !ok || path.Clean(src) != src || m["type"] != "bind" || m["target"] != w.target ||
			!reflect.DeepEqual(m["bind"], map[string]any{"create_host_path": false}) {
			return invariant("bind mount of %s is not one of the instance's own directories", src)
		}
		if ro, _ := m["read_only"].(bool); ro != w.ro {
			return invariant("bind mount of %s: read_only must be %v", src, w.ro)
		}
		delete(mounts, src)
	}
	return nil
}
