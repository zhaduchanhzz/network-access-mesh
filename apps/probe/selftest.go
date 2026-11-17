package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/apps/probe/prober"
	"github.com/zhaduchanhzz/network-access-mesh/apps/probe/stub"
)

// selftest runs every probe kind through the RPC API (Handler + Client, as the worker uses them) against the stub
// STUN responder and the stub edge on loopback: no DNS, no network beyond loopback — the image smoke test of the
// workflow `images` (`docker run --network none … selftest`). One PASS/FAIL line per case; exit 0 when all pass.
func selftest(ctx context.Context, stdout io.Writer) int {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	cases, err := runSelftest(ctx)
	if err != nil {
		_, _ = fmt.Fprintf(stdout, "selftest: setup failed: %v\n", err)
		return 1
	}
	failed := 0
	for _, c := range cases {
		mark := "PASS"
		if !c.ok {
			mark, failed = "FAIL", failed+1
		}
		_, _ = fmt.Fprintf(stdout, "%s %s — %s\n", mark, c.name, c.detail)
	}
	_, _ = fmt.Fprintf(stdout, "selftest: %d/%d cases passed\n", len(cases)-failed, len(cases))
	if failed > 0 {
		return 1
	}
	return 0
}

type selfCase struct {
	name, detail string
	ok           bool
}

func runSelftest(ctx context.Context) ([]selfCase, error) {
	const mesh = "mesh.selftest.invalid"
	st, err := stub.NewSTUN("127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer func() { _ = st.Close() }()
	edge, err := stub.NewEdge("127.0.0.1:0", mesh, "tenant-a", "tenant-b")
	if err != nil {
		return nil, err
	}
	defer func() { _ = edge.Close() }()
	closed, err := freeUDPPort(ctx)
	if err != nil {
		return nil, err
	}
	loop := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	local := prober.New(prober.Options{Allow: loop, RootCAs: edge.CA})
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	srv := &http.Server{Handler: prober.Handler(local, prober.HandlerOptions{Callers: loop}), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()
	c, err := prober.NewClient("http://"+ln.Addr().String(), nil)
	if err != nil {
		return nil, err
	}
	edgeAddr, hostA, hostB := edge.Addr().String(), edge.Host("tenant-a"), edge.Host("tenant-b")
	var out []selfCase
	add := func(name string, ok bool, format string, args ...any) {
		out = append(out, selfCase{name: name, ok: ok, detail: fmt.Sprintf(format, args...)})
	}

	s, err := c.STUN(ctx, prober.STUNRequest{Target: st.Addr().String()})
	seen := st.Seen()
	add("stun: mapped address = the source the responder saw", err == nil && s.OK && len(seen) == 1 &&
		s.Mapped == seen[0].String() && s.Mapped == s.Local, "mapped %s, local %s, seen %v, err %v", s.Mapped, s.Local, seen, err)
	s, err = c.STUN(ctx, prober.STUNRequest{Target: closed, TimeoutMS: 1500})
	add("stun: closed port ⇒ typed error", err == nil && !s.OK && s.Error != nil &&
		(s.Error.Code == prober.CodeRefused || s.Error.Code == prober.CodeTimeout), "error %v", s.Error)
	_, err = c.STUN(ctx, prober.STUNRequest{Target: "192.0.2.1:3478"})
	add("stun: target outside the allow-list ⇒ target_not_allowed", prober.CodeOf(err) == prober.CodeTargetNotAllowed, "%v", err)

	h, err := c.HTTPS(ctx, prober.HTTPSRequest{Address: edgeAddr, SNI: hostA, Path: "/key?v=113",
		Expect: prober.Expect{Status: []int{200}, JSONPresent: []string{"publicKey"}}})
	add("https: /key ⇒ 200 with the tenant's key", err == nil && h.OK && h.JSON["publicKey"] == edge.PublicKeys[hostA],
		"status %d class %s err %v", h.Status, h.Class, err)
	h, err = c.HTTPS(ctx, prober.HTTPSRequest{Address: edgeAddr, SNI: hostA, Path: "/api/v1/apikey",
		Expect: prober.Expect{Status: []int{404}}})
	add("https: forbidden path ⇒ 404 classified not_found", err == nil && h.OK && h.Class == prober.ClassNotFound,
		"status %d class %s", h.Status, h.Class)
	h, err = c.HTTPS(ctx, prober.HTTPSRequest{Address: edgeAddr, SNI: hostA, Host: hostB, Path: "/key?v=113",
		Expect: prober.Expect{Status: []int{421}}})
	add("https: SNI ≠ Host ⇒ 421 classified misdirected", err == nil && h.OK && h.Class == prober.ClassMisdirected,
		"status %d class %s", h.Status, h.Class)
	h, err = c.HTTPS(ctx, prober.HTTPSRequest{Address: edgeAddr, SNI: "foreign.example", Path: "/"})
	add("https: SNI without a certificate ⇒ tls_handshake", err == nil && !h.OK && h.Error != nil &&
		h.Error.Code == prober.CodeTLSHandshake, "error %v", h.Error)
	strict := prober.New(prober.Options{Allow: loop}) // system roots: the stub CA is not trusted
	h, err = strict.HTTPS(ctx, prober.HTTPSRequest{Address: edgeAddr, SNI: hostA, Path: "/key?v=113"})
	add("https: verification on by default (untrusted CA ⇒ tls_verify)", err == nil && !h.OK && h.Error != nil &&
		h.Error.Code == prober.CodeTLSVerify, "error %v", h.Error)

	e, err := c.Edge(ctx, prober.EdgeRequest{Address: edgeAddr, Host: hostB, PublicKey: edge.PublicKeys[hostB]})
	add("edge: /key + every forbidden path ⇒ 404", err == nil && e.OK && e.Blocked == len(prober.DefaultForbidden),
		"blocked %d/%d, key %d", e.Blocked, len(e.Forbidden), e.Key.Status)
	r, err := c.Relay(ctx, prober.RelayRequest{Address: edgeAddr, Host: hostA, STUN: st.Addr().String()})
	add("relay: /derp/probe 200 + STUN answered", err == nil && r.OK, "derp %d, stun ok %v", r.DERP.Status, r.STUN.OK)
	return out, nil
}

// freeUDPPort returns a loopback ip:port where nothing listens (a port just released).
func freeUDPPort(ctx context.Context) (string, error) {
	pc, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	addr := pc.LocalAddr().String()
	return addr, pc.Close()
}
