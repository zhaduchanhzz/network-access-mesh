package prober

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/apps/probe/stub"
)

var loopback = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}

func newSTUN(t *testing.T) *stub.STUN {
	t.Helper()
	s, err := stub.NewSTUN("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// udpSocket is a UDP socket under the test's control (a responder that misbehaves on purpose).
func udpSocket(t *testing.T) *net.UDPConn {
	t.Helper()
	pc, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc.(*net.UDPConn)
}

// The request is byte for byte what tools/stun_probe.py sends (accepted by stund on staging since P1-T13): header with
// length 20, SOFTWARE "tailnode", FINGERPRINT = CRC-32 XOR 0x5354554E.
func TestBindingRequestWireFormat(t *testing.T) {
	var tx txID
	copy(tx[:], "0123456789ab")
	got := hex.EncodeToString(bindingRequest(tx))
	want := "00010014" + "2112a442" + hex.EncodeToString(tx[:]) + "80220008" + hex.EncodeToString([]byte("tailnode")) +
		"80280004"
	if got[:len(want)] != want || len(got) != len(want)+8 {
		t.Fatalf("request = %s, want prefix %s + 4-byte fingerprint", got, want)
	}
	// the fingerprint is the CRC-32 (IEEE) of everything before it, XOR 0x5354554E — computed independently by the stub
	if _, ok := parseStubRequest(bindingRequest(tx)); !ok {
		t.Fatal("the stub (stund rules) ignores our request")
	}
}

// parseStubRequest checks a request the way the stub responder (stund rules) does, by sending it to a stub.
func parseStubRequest(b []byte) (netip.AddrPort, bool) {
	s, err := stub.NewSTUN("127.0.0.1:0")
	if err != nil {
		return netip.AddrPort{}, false
	}
	defer func() { _ = s.Close() }()
	c, err := (&net.Dialer{}).DialContext(context.Background(), "udp", s.Addr().String())
	if err != nil {
		return netip.AddrPort{}, false
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write(b); err != nil {
		return netip.AddrPort{}, false
	}
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		return netip.AddrPort{}, false
	}
	var tx txID
	copy(tx[:], b[8:20])
	ap, ours, perr := parseBindingResponse(buf[:n], tx)
	return ap, ours && perr == nil
}

// Correct port ⇒ the mapped address is exactly the source the responder observed (and, on loopback without NAT, the
// local address of the probe).
func TestSTUNMappedAddressIsObservedSource(t *testing.T) {
	s := newSTUN(t)
	p := New(Options{Allow: loopback})
	res, err := p.STUN(t.Context(), STUNRequest{Target: s.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	seen := s.Seen()
	if !res.OK || res.Error != nil || len(seen) != 1 || res.Mapped != seen[0].String() || res.Mapped != res.Local {
		t.Fatalf("result %+v, responder saw %v", res, seen)
	}
	if res.Attempts != 1 || res.RTTMS <= 0 || res.TotalMS < res.RTTMS || res.CheckedAt.IsZero() || res.Target != s.Addr().String() {
		t.Fatalf("timing/attempts not filled: %+v", res)
	}
}

// Wrong port (nothing listens) ⇒ refused (ICMP port unreachable on a connected UDP socket); a responder that never
// answers ⇒ timeout after the retransmissions. Both are typed results, not Go errors.
func TestSTUNWrongPortAndTimeoutAreTypedErrors(t *testing.T) {
	p := New(Options{Allow: loopback})
	closed := udpSocket(t)
	addr := closed.LocalAddr().String()
	_ = closed.Close()
	res, err := p.STUN(t.Context(), STUNRequest{Target: addr, TimeoutMS: 2000})
	if err != nil || res.OK || res.Error == nil {
		t.Fatalf("closed port: %+v, %v", res, err)
	}
	if runtime.GOOS == "linux" && res.Error.Code != CodeRefused {
		t.Fatalf("closed port on linux: code %q, want %q", res.Error.Code, CodeRefused)
	}

	s := newSTUN(t)
	s.SetSilent(true)
	start := time.Now()
	res, err = p.STUN(t.Context(), STUNRequest{Target: s.Addr().String(), TimeoutMS: 1300})
	took := time.Since(start)
	if err != nil || res.OK || res.Error == nil || res.Error.Code != CodeTimeout {
		t.Fatalf("silent responder: %+v, %v", res, err)
	}
	if res.Attempts < 2 || took < 1200*time.Millisecond || took > 3*time.Second {
		t.Fatalf("silent responder: %d attempts in %v (want retransmissions, ≈ the timeout)", res.Attempts, took)
	}
}

// A datagram that is not the answer to our transaction is ignored; garbage with our transaction ID, a Binding Error
// response and a success without a mapped address are bad answers.
func TestSTUNAnswers(t *testing.T) {
	p := New(Options{Allow: loopback})
	cases := []struct {
		name  string
		reply func(tx txID, src netip.AddrPort) [][]byte
		code  string
	}{
		{"stray datagram first, then the answer", func(tx txID, src netip.AddrPort) [][]byte {
			other := tx
			other[0] ^= 0xff
			return [][]byte{stub.Response(other, netip.MustParseAddrPort("192.0.2.9:9")), []byte("noise"), stub.Response(tx, src)}
		}, ""},
		{"binding error response", func(tx txID, _ netip.AddrPort) [][]byte {
			b := header(0x0111, tx, 8)
			b = append(b, 0x00, 0x09, 0x00, 0x04, 0, 0, 4, 0) // ERROR-CODE 400
			return [][]byte{b}
		}, CodeBadResponse},
		{"success without mapped address", func(tx txID, _ netip.AddrPort) [][]byte {
			return [][]byte{header(0x0101, tx, 0)}
		}, CodeNoMappedAddress},
		{"truncated attribute", func(tx txID, _ netip.AddrPort) [][]byte {
			b := header(0x0101, tx, 4)
			return [][]byte{append(b, 0x00, 0x20, 0x00, 0x08)}
		}, CodeBadResponse},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			conn := udpSocket(t)
			go func() {
				buf := make([]byte, 1500)
				n, src, err := conn.ReadFromUDPAddrPort(buf)
				if err != nil || n < 20 {
					return
				}
				var tx txID
				copy(tx[:], buf[8:20])
				for _, d := range c.reply(tx, src) {
					_, _ = conn.WriteToUDPAddrPort(d, src)
				}
			}()
			res, err := p.STUN(t.Context(), STUNRequest{Target: conn.LocalAddr().String(), TimeoutMS: 2000})
			if err != nil {
				t.Fatal(err)
			}
			if c.code == "" && (!res.OK || res.Mapped != res.Local) {
				t.Fatalf("want the answer after the stray datagrams: %+v", res)
			}
			if c.code != "" && (res.OK || res.Error == nil || res.Error.Code != c.code) {
				t.Fatalf("want %s: %+v", c.code, res)
			}
		})
	}
}

func header(typ uint16, tx txID, length int) []byte {
	b := make([]byte, 20, 20+length)
	binary.BigEndian.PutUint16(b[0:], typ)
	binary.BigEndian.PutUint16(b[2:], uint16(length)) //nolint:gosec // G115: test lengths are tiny
	binary.BigEndian.PutUint32(b[4:], stunMagic)
	copy(b[8:], tx[:])
	return b
}

func TestXORMappedAddressIPv6(t *testing.T) {
	var tx txID
	copy(tx[:], "abcdefghijkl")
	want := netip.MustParseAddrPort("[2001:db8::1234]:41641")
	ap, ours, perr := parseBindingResponse(stub.Response(tx, want), tx)
	if !ours || perr != nil || ap != want {
		t.Fatalf("got %v %v %v, want %v", ap, ours, perr, want)
	}
}

// Invalid targets are refused before anything is sent; a target outside the allow-list too (the responder sees
// nothing).
func TestSTUNRefusesBeforeSending(t *testing.T) {
	s := newSTUN(t)
	p := New(Options{Allow: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}})
	for _, tc := range []struct{ target, code string }{
		{"stun.example.com:3478", CodeInvalidRequest}, {"127.0.0.1", CodeInvalidRequest},
		{"127.0.0.1:0", CodeInvalidRequest}, {"0.0.0.0:3478", CodeInvalidRequest}, {"224.0.0.1:3478", CodeInvalidRequest},
		{s.Addr().String(), CodeTargetNotAllowed}, {"[::ffff:127.0.0.1]:3478", CodeTargetNotAllowed},
	} {
		if _, err := p.STUN(t.Context(), STUNRequest{Target: tc.target}); CodeOf(err) != tc.code {
			t.Errorf("%q: %v, want %s", tc.target, err, tc.code)
		}
	}
	if _, err := New(Options{Allow: loopback}).STUN(t.Context(), STUNRequest{Target: s.Addr().String(), TimeoutMS: 20000}); CodeOf(err) != CodeInvalidRequest {
		t.Errorf("timeout 20 s: %v", err)
	}
	if n := len(s.Seen()) + s.Ignored(); n != 0 {
		t.Fatalf("the responder received %d datagrams from refused probes", n)
	}
	if _, err := New(Options{}).STUN(t.Context(), STUNRequest{Target: s.Addr().String()}); CodeOf(err) != CodeTargetNotAllowed {
		t.Fatalf("empty allow-list must refuse everything: %v", err)
	}
}

// A cancelled caller gets a canceled result quickly.
func TestSTUNCanceled(t *testing.T) {
	s := newSTUN(t)
	s.SetSilent(true)
	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(200*time.Millisecond, cancel)
	start := time.Now()
	res, err := New(Options{Allow: loopback}).STUN(ctx, STUNRequest{Target: s.Addr().String(), TimeoutMS: 10000})
	if err != nil || res.Error == nil || res.Error.Code != CodeCanceled || time.Since(start) > 2*time.Second {
		t.Fatalf("%+v %v after %v", res, err, time.Since(start))
	}
}

func FuzzParseBindingResponse(f *testing.F) {
	var tx txID
	copy(tx[:], "0123456789ab")
	f.Add(stub.Response(tx, netip.MustParseAddrPort("198.51.100.7:3478")))
	f.Add(header(0x0101, tx, 0))
	f.Add([]byte("garbage"))
	f.Fuzz(func(t *testing.T, b []byte) {
		ap, ours, perr := parseBindingResponse(b, tx)
		if ours && perr == nil && !ap.IsValid() {
			t.Fatal("success without an address")
		}
		if !ours && (perr != nil || ap.IsValid()) {
			t.Fatal("a stray datagram must yield nothing")
		}
	})
}
