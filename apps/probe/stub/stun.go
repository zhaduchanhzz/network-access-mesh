// Package stub holds stand-ins for the public entry point of the platform (P3-T03a): a STUN responder that behaves
// like Tailscale's stund and a TLS server that behaves like the edge's public listener (§14.6). They listen on
// loopback, need no DNS and no certificate from outside, and are used by the tests of apps/probe and by
// `meshguard-probe selftest` (the image smoke test of the workflow `images`), so the Prober is exercised in CI without
// the dev/CI stack and without public DNS. This package does not import the prober: the wire formats are implemented
// independently on both sides.
package stub

import (
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"net"
	"net/netip"
	"sync"
)

const (
	stunMagic      = 0x2112A442
	fingerprintXOR = 0x5354554E
)

// STUN answers RFC 5389 Binding Requests the way Tailscale's stund does (tailscale.com/net/stun ParseBindingRequest +
// Response): a request is answered only if it carries SOFTWARE "tailnode" and a valid FINGERPRINT as its last
// attribute; the answer holds XOR-MAPPED-ADDRESS = the source address the request came from. Every source answered
// and every request ignored is recorded.
type STUN struct {
	conn *net.UDPConn
	wg   sync.WaitGroup

	mu      sync.Mutex
	seen    []netip.AddrPort
	ignored int
	silent  bool
}

// NewSTUN listens on addr (e.g. "127.0.0.1:0") and serves until Close.
func NewSTUN(addr string) (*STUN, error) {
	pc, err := (&net.ListenConfig{}).ListenPacket(context.Background(), "udp", addr)
	if err != nil {
		return nil, err
	}
	s := &STUN{conn: pc.(*net.UDPConn)}
	s.wg.Go(s.serve)
	return s, nil
}

// Addr is the address the responder listens on.
func (s *STUN) Addr() netip.AddrPort { return s.conn.LocalAddr().(*net.UDPAddr).AddrPort() }

// Seen lists the sources answered, in order.
func (s *STUN) Seen() []netip.AddrPort {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]netip.AddrPort(nil), s.seen...)
}

// Ignored counts the datagrams that were not a valid Tailscale Binding Request.
func (s *STUN) Ignored() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ignored
}

// SetSilent makes the responder read and drop every request (a responder that never answers).
func (s *STUN) SetSilent(v bool) { s.mu.Lock(); s.silent = v; s.mu.Unlock() }

// Close stops the responder.
func (s *STUN) Close() error {
	err := s.conn.Close()
	s.wg.Wait()
	return err
}

func (s *STUN) serve() {
	buf := make([]byte, 1500)
	for {
		n, src, err := s.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		tx, ok := parseRequest(buf[:n])
		s.mu.Lock()
		silent := s.silent
		if !ok {
			s.ignored++
		} else if !silent {
			s.seen = append(s.seen, src)
		}
		s.mu.Unlock()
		if ok && !silent {
			_, _ = s.conn.WriteToUDPAddrPort(Response(tx, src), src)
		}
	}
}

// parseRequest accepts what stund accepts: a Binding Request (type 0x0001, magic cookie) whose attributes include
// SOFTWARE "tailnode" and end with a FINGERPRINT that matches the message.
func parseRequest(b []byte) (tx [12]byte, ok bool) {
	if len(b) < 20 || binary.BigEndian.Uint16(b[0:]) != 0x0001 || binary.BigEndian.Uint32(b[4:]) != stunMagic {
		return tx, false
	}
	length := int(binary.BigEndian.Uint16(b[2:]))
	if 20+length != len(b) || length%4 != 0 {
		return tx, false
	}
	copy(tx[:], b[8:20])
	software, fingerprint := false, false
	for off := 20; off < len(b); {
		if off+4 > len(b) {
			return tx, false
		}
		at, al := binary.BigEndian.Uint16(b[off:]), int(binary.BigEndian.Uint16(b[off+2:]))
		end := off + 4 + (al+3)&^3
		if end > len(b) {
			return tx, false
		}
		v := b[off+4 : off+4+al]
		switch at {
		case 0x8022:
			software = string(v) == "tailnode"
		case 0x8028:
			fingerprint = al == 4 && end == len(b) &&
				binary.BigEndian.Uint32(v) == crc32.ChecksumIEEE(b[:off])^fingerprintXOR
		}
		off = end
	}
	return tx, software && fingerprint
}

// Response encodes a Binding Success Response for transaction tx with XOR-MAPPED-ADDRESS = mapped (IPv4 or IPv6).
func Response(tx [12]byte, mapped netip.AddrPort) []byte {
	a := mapped.Addr().Unmap()
	family, ip := byte(0x01), a.AsSlice()
	if a.Is6() {
		family = 0x02
	}
	var key [16]byte
	binary.BigEndian.PutUint32(key[:], stunMagic)
	copy(key[4:], tx[:])
	val := make([]byte, 4+len(ip))
	val[1] = family
	binary.BigEndian.PutUint16(val[2:], mapped.Port()^uint16(stunMagic>>16))
	for i := range ip {
		val[4+i] = ip[i] ^ key[i]
	}
	b := make([]byte, 20, 20+4+len(val))
	binary.BigEndian.PutUint16(b[0:], 0x0101)
	binary.BigEndian.PutUint16(b[2:], uint16(4+len(val))) //nolint:gosec // G115: 8 or 20 bytes
	binary.BigEndian.PutUint32(b[4:], stunMagic)
	copy(b[8:], tx[:])
	b = binary.BigEndian.AppendUint16(b, 0x0020)
	b = binary.BigEndian.AppendUint16(b, uint16(len(val))) //nolint:gosec // G115: 8 or 20 bytes
	return append(b, val...)
}
