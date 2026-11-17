package idp

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The T-21 cases of §18.1 ("issuer trỏ vào IP listener admin của edge, 169.254.169.254, host trả 302 về địa chỉ nội
// bộ, tên rebinding — tất cả bị từ chối; lặp lại với địa chỉ thuộc từng subnet nội bộ (mg-admin, mg-data, mg-obs,
// mg-edge, pool tenant) và dạng IPv4-mapped IPv6"). The subnets are read from the repository — the platform networks
// from infrastructure/host/networks.sh, the tenant pool from tools/render_instance.py, the Docker address pool from
// the daemon.json of the host bootstrap, the edge's static addresses from tools/render_edge.py, LAN and tunnel from
// the staging environment file — exactly what a deployment puts into MG_EGRESS_DENY_CIDRS; nothing is hard-coded here.

func repoFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := fs.ReadFile(os.DirFS(filepath.Join("..", "..")), rel)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

type namedNet struct {
	name   string
	prefix netip.Prefix
}

// platformNetworks returns every internal network of the platform, from the repository's sources of truth.
func platformNetworks(t *testing.T) ([]namedNet, map[string]netip.Addr, map[string]string) {
	t.Helper()
	var out []namedNet
	re := regexp.MustCompile(`(?m)^\s*(?:NETS=")?(mg-[a-z-]+)\s+([0-9.]+/[0-9]+)\s+(?:yes|no)\b`)
	for _, m := range re.FindAllStringSubmatch(repoFile(t, "infrastructure/host/networks.sh"), -1) {
		out = append(out, namedNet{m[1], netip.MustParsePrefix(m[2])})
	}
	if len(out) < 7 {
		t.Fatalf("networks.sh: %d networks parsed, want ≥ 7 (mg-edge … mg-idp-data)", len(out))
	}
	m := regexp.MustCompile(`TENANT_NET_POOL = ipaddress\.ip_network\("([0-9./]+)"\)`).FindStringSubmatch(
		repoFile(t, "tools/render_instance.py"))
	if m == nil {
		t.Fatal("render_instance.py: TENANT_NET_POOL not found")
	}
	out = append(out, namedNet{"tenant pool", netip.MustParsePrefix(m[1])})
	m = regexp.MustCompile(`"base": "([0-9./]+)"`).FindStringSubmatch(
		repoFile(t, "docs/planning/evidence/infrastructure-bootstrap/install_docker.sh"))
	if m == nil {
		t.Fatal("daemon.json: default-address-pools base not found")
	}
	out = append(out, namedNet{"docker default-address-pools", netip.MustParsePrefix(m[1])})
	edge := map[string]netip.Addr{}
	for _, m := range regexp.MustCompile(`"(edge(?:_admin|_obs)?_ip)": "([0-9.]+)"`).FindAllStringSubmatch(
		repoFile(t, "tools/render_edge.py"), -1) {
		edge[m[1]] = netip.MustParseAddr(m[2])
	}
	if len(edge) != 3 {
		t.Fatalf("render_edge.py: EDGE_IPS = %v", edge)
	}
	env := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(repoFile(t, "infrastructure/environments/staging/staging.env")))
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), "="); ok && strings.HasPrefix(k, "MG_") {
			env[k] = strings.TrimSpace(v)
		}
	}
	out = append(out, namedNet{"LAN (MG_LAN_CIDR)", netip.MustParsePrefix(env["MG_LAN_CIDR"])})
	for _, k := range []string{"MG_TUNNEL_HOST_IPV4", "MG_TUNNEL_VPS_IPV4"} {
		a := netip.MustParseAddr(env[k])
		out = append(out, namedNet{"tunnel (" + k + ")", netip.PrefixFrom(a, 32)})
	}
	return out, edge, env
}

// samples: the network address, the gateway (.1), the first static address (.2 — the edge on mg-edge/mg-admin/mg-obs),
// the last host and the broadcast address of an IPv4 network; the address itself for a /32.
func samples(p netip.Prefix) []netip.Addr {
	if p.Bits() == 32 {
		return []netip.Addr{p.Addr()}
	}
	b := p.Addr().As4()
	v := binary.BigEndian.Uint32(b[:]) | (uint32(1)<<(32-p.Bits()) - 1)
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], v)
	last := netip.AddrFrom4(l)
	first := p.Addr().Next()
	return []netip.Addr{p.Addr(), first, first.Next(), last.Prev(), last}
}

func mapped(a netip.Addr) netip.Addr { return netip.AddrFrom16(a.As16()) }

// TestT21PlatformSubnets: every address of every internal subnet — IPv4 and IPv4-mapped IPv6 — is refused, both by
// the built-in ranges alone and with the deployment's deny list, through the full client (resolution included) and
// without any connection.
func TestT21PlatformSubnets(t *testing.T) {
	nets, edge, env := platformNetworks(t)
	var deny []string
	for _, n := range nets {
		deny = append(deny, n.prefix.String())
	}
	deny = append(deny, env["MG_PUBLIC_IPV4"])
	cfg, err := ParsePrefixes(strings.Join(deny, ","))
	if err != nil {
		t.Fatal(err)
	}
	builtin, _ := NewEgressPolicy(nil)
	srv, pool := tlsServer(t, okHandler(`{}`))
	h, res, log := hardenedFor(t, srv, pool, HardenedConfig{Deny: cfg})
	n := 0
	for _, net := range nets {
		for _, a := range samples(net.prefix) {
			for _, form := range []netip.Addr{a, mapped(a)} {
				if builtin.Reason(form) == "" {
					t.Errorf("%s %s: allowed by the built-in ranges", net.name, form)
				}
				if h.Policy().Reason(form) == "" {
					t.Errorf("%s %s: allowed with the deny list", net.name, form)
				}
				host := fmt.Sprintf("issuer-%d.example.com", n)
				n++
				res.set(host, []netip.Addr{form})
				err := getErr(t.Context(), h.Client(), "https://"+host+"/.well-known/openid-configuration")
				wantCode(t, net.name+" "+form.String(), err, CodeDestinationRefused, "")
			}
		}
	}
	// the public entry of the platform is not a special-purpose address: only the deny list refuses it
	pub := netip.MustParseAddr(env["MG_PUBLIC_IPV4"])
	if builtin.Reason(pub) != "" || h.Policy().Reason(pub) != ReasonConfigured {
		t.Errorf("MG_PUBLIC_IPV4: built-in %q, configured %q", builtin.Reason(pub), h.Policy().Reason(pub))
	}
	if got := log.list(); len(got) != 0 {
		t.Fatalf("connections made: %v", got)
	}
	t.Logf("T-21: %d internal addresses (IPv4 + IPv4-mapped) over %d networks refused; edge static IPs %d", n, len(nets), len(edge))
}

// TestT21NamedCases: the named cases of §18.1 through FetchDiscovery, the call the external driver makes.
func TestT21NamedCases(t *testing.T) {
	_, edge, _ := platformNetworks(t)
	doc := func(base string) string {
		return `{"issuer":"` + base + `","authorization_endpoint":"` + base + `/auth","token_endpoint":"` + base +
			`/token","jwks_uri":"` + base + `/jwks","response_types_supported":["code"]}`
	}
	cases := []struct {
		name   string
		answer []netip.Addr
	}{
		{"issuer → admin listener of the edge (mg-admin)", []netip.Addr{edge["edge_admin_ip"]}},
		{"issuer → metrics listener of the edge (mg-obs)", []netip.Addr{edge["edge_obs_ip"]}},
		{"issuer → edge on mg-edge", []netip.Addr{edge["edge_ip"]}},
		{"issuer → cloud metadata 169.254.169.254", addrs("169.254.169.254")},
		{"issuer → IPv4-mapped metadata", addrs("::ffff:169.254.169.254")},
		{"issuer → IPv4-mapped admin listener", []netip.Addr{mapped(edge["edge_admin_ip"])}},
		{"issuer → loopback", addrs("127.0.0.1", "::1")},
	}
	srv, pool := tlsServer(t, okHandler(doc("https://example.com")))
	for _, c := range cases {
		h, res, log := hardenedFor(t, srv, pool, HardenedConfig{})
		res.set("example.com", c.answer)
		_, err := FetchDiscovery(t.Context(), h.Client(), "https://example.com", func(_ context.Context, u *url.URL, _ EndpointKind) error {
			return h.CheckURL(u)
		})
		wantCode(t, c.name, err, CodeDestinationRefused, "")
		if got := log.list(); len(got) != 0 {
			t.Fatalf("%s: dialled %v", c.name, got)
		}
	}
	// a host that answers 302 to an internal address
	redir, rpool := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+edge["edge_admin_ip"].String()+":8081/api/v1/node", http.StatusFound)
	}))
	h, _, log := hardenedFor(t, redir, rpool, HardenedConfig{})
	_, err := FetchDiscovery(t.Context(), h.Client(), "https://example.com", func(_ context.Context, u *url.URL, _ EndpointKind) error {
		return h.CheckURL(u)
	})
	wantCode(t, "302 to the admin listener", err, CodeRedirectRefused, "")
	if got := log.list(); len(got) != 1 {
		t.Fatalf("302: dialled %v — the internal target must not be contacted", got)
	}
	// a rebinding name: the discovery document is served from the public answer, the server closes the connection,
	// and the JWKS request — a new connection, a new single resolution — gets the admin listener: refused.
	rb, rbpool := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, doc("https://example.com"))
	}))
	h, res, log := hardenedFor(t, rb, rbpool, HardenedConfig{})
	res.set("example.com", []netip.Addr{publicIP}, []netip.Addr{edge["edge_admin_ip"]})
	_, err = FetchDiscovery(t.Context(), h.Client(), "https://example.com", func(_ context.Context, u *url.URL, _ EndpointKind) error {
		return h.CheckURL(u)
	})
	wantCode(t, "rebinding name", err, CodeDestinationRefused, "address_"+ReasonPrivate)
	if got := log.list(); len(got) != 1 || got[0] != publicIP.String()+":443" {
		t.Fatalf("rebinding: dialled %v, want only the public answer", got)
	}
}
