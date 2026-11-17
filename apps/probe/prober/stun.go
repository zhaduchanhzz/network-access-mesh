package prober

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"net"
	"net/netip"
	"time"
)

// A minimal RFC 5389 client: Binding Request with SOFTWARE + FINGERPRINT, Binding Success Response with
// XOR-MAPPED-ADDRESS (or MAPPED-ADDRESS). Written here rather than imported: tailscale.com/net/stun would bring the
// Tailscale module tree into the main module, pion/stun another dependency, for ~150 lines whose wire format is pinned
// by the tests (and matches tools/stun_probe.py, used against stund on staging since P1-T13).
const (
	stunMagic            = 0x2112A442
	stunHeaderLen        = 20
	stunBindingRequest   = 0x0001
	stunBindingSuccess   = 0x0101
	stunBindingError     = 0x0111
	attrMappedAddress    = 0x0001
	attrErrorCode        = 0x0009
	attrXORMappedAddress = 0x0020
	attrSoftware         = 0x8022
	attrFingerprint      = 0x8028
	fingerprintXOR       = 0x5354554E
	// stunSoftware is what the Tailscale client sends: stund and the embedded DERP's STUN ignore a request without
	// SOFTWARE "tailnode" followed by a valid FINGERPRINT (tailscale.com/net/stun ParseBindingRequest).
	stunSoftware = "tailnode"
)

type txID [12]byte

// bindingRequest encodes a Binding Request: header, SOFTWARE "tailnode", FINGERPRINT (CRC-32 of everything before it,
// with the length field already counting the fingerprint, XOR 0x5354554E — RFC 5389 §15.5).
func bindingRequest(tx txID) []byte {
	b := make([]byte, stunHeaderLen, stunHeaderLen+12+8)
	binary.BigEndian.PutUint16(b[0:], stunBindingRequest)
	binary.BigEndian.PutUint16(b[2:], 12+8) // SOFTWARE (4 + 8) + FINGERPRINT (4 + 4)
	binary.BigEndian.PutUint32(b[4:], stunMagic)
	copy(b[8:], tx[:])
	b = binary.BigEndian.AppendUint16(b, attrSoftware)
	b = binary.BigEndian.AppendUint16(b, uint16(len(stunSoftware)))
	b = append(b, stunSoftware...)
	crc := crc32.ChecksumIEEE(b) ^ fingerprintXOR
	b = binary.BigEndian.AppendUint16(b, attrFingerprint)
	b = binary.BigEndian.AppendUint16(b, 4)
	return binary.BigEndian.AppendUint32(b, crc)
}

// parseBindingResponse decodes the answer to transaction tx and returns the mapped address. ours is false for a
// datagram that is not an answer to tx (wrong magic or transaction ID) — the caller ignores it.
func parseBindingResponse(b []byte, tx txID) (mapped netip.AddrPort, ours bool, perr *Error) {
	if len(b) < stunHeaderLen || binary.BigEndian.Uint32(b[4:]) != stunMagic || txID(b[8:20]) != tx {
		return netip.AddrPort{}, false, nil
	}
	typ, length := binary.BigEndian.Uint16(b[0:]), int(binary.BigEndian.Uint16(b[2:]))
	if b[0]&0xC0 != 0 || length%4 != 0 || stunHeaderLen+length > len(b) {
		return netip.AddrPort{}, true, newError(CodeBadResponse, "malformed STUN message")
	}
	attrs := b[stunHeaderLen : stunHeaderLen+length]
	var xor, plain netip.AddrPort
	errCode := -1
	for len(attrs) > 0 {
		if len(attrs) < 4 {
			return netip.AddrPort{}, true, newError(CodeBadResponse, "truncated STUN attribute")
		}
		at, al := binary.BigEndian.Uint16(attrs[0:]), int(binary.BigEndian.Uint16(attrs[2:]))
		padded := (al + 3) &^ 3
		if 4+padded > len(attrs) {
			return netip.AddrPort{}, true, newError(CodeBadResponse, "truncated STUN attribute")
		}
		v := attrs[4 : 4+al]
		switch at {
		case attrXORMappedAddress:
			if ap, ok := decodeAddress(v, true, tx); ok {
				xor = ap
			}
		case attrMappedAddress:
			if ap, ok := decodeAddress(v, false, tx); ok {
				plain = ap
			}
		case attrErrorCode:
			if len(v) >= 4 {
				errCode = int(v[2]&0x7)*100 + int(v[3])
			}
		}
		attrs = attrs[4+padded:]
	}
	switch typ {
	case stunBindingSuccess:
	case stunBindingError:
		return netip.AddrPort{}, true, newError(CodeBadResponse, fmt.Sprintf("binding error response (code %d)", errCode))
	default:
		return netip.AddrPort{}, true, newError(CodeBadResponse, fmt.Sprintf("unexpected STUN message type 0x%04x", typ))
	}
	switch {
	case xor.IsValid():
		return xor, true, nil
	case plain.IsValid():
		return plain, true, nil
	}
	return netip.AddrPort{}, true, newError(CodeNoMappedAddress, "success response without a mapped address")
}

// decodeAddress decodes a (XOR-)MAPPED-ADDRESS value: 0, family (1 = IPv4, 2 = IPv6), port, address.
func decodeAddress(v []byte, xored bool, tx txID) (netip.AddrPort, bool) {
	if len(v) < 4 {
		return netip.AddrPort{}, false
	}
	port := binary.BigEndian.Uint16(v[2:])
	var key [16]byte
	if xored {
		port ^= stunMagic >> 16
		binary.BigEndian.PutUint32(key[:], stunMagic)
		copy(key[4:], tx[:])
	}
	switch {
	case v[1] == 0x01 && len(v) == 8:
		var ip [4]byte
		for i := range ip {
			ip[i] = v[4+i] ^ key[i]
		}
		return netip.AddrPortFrom(netip.AddrFrom4(ip), port), true
	case v[1] == 0x02 && len(v) == 20:
		var ip [16]byte
		for i := range ip {
			ip[i] = v[4+i] ^ key[i]
		}
		return netip.AddrPortFrom(netip.AddrFrom16(ip), port), true
	}
	return netip.AddrPort{}, false
}

// STUN sends a Binding Request to req.Target and waits for the answer, retransmitting with RTO 500 ms doubled after
// every attempt (RFC 5389 §7.2.1) until the timeout.
func (l *Local) STUN(ctx context.Context, req STUNRequest) (STUNResult, error) {
	target, err := parseTarget("target", req.Target)
	if err != nil {
		return STUNResult{}, err
	}
	limit, err := timeout(req.TimeoutMS, DefaultSTUNTimeout)
	if err != nil {
		return STUNResult{}, err
	}
	if err := checkTarget(l.allow, "target", target); err != nil {
		return STUNResult{}, err
	}
	res := STUNResult{Target: target.String(), CheckedAt: l.now().UTC()}
	start := time.Now()
	res.Error = l.stun(ctx, target, limit, &res)
	res.OK = res.Error == nil
	res.TotalMS = ms(time.Since(start))
	l.log.InfoContext(ctx, "probe", "kind", "stun", "target", res.Target, "ok", res.OK, "code", code(res.Error),
		"mapped", res.Mapped, "attempts", res.Attempts, "total_ms", res.TotalMS)
	return res, nil
}

func (l *Local) stun(ctx context.Context, target netip.AddrPort, limit time.Duration, res *STUNResult) *Error {
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", target.String())
	if err != nil {
		return classify(ctx, err)
	}
	defer func() { _ = c.Close() }()
	res.Local = c.LocalAddr().String()
	stop := context.AfterFunc(ctx, func() { _ = c.SetDeadline(time.Unix(1, 0)) }) // unblock a pending read
	defer stop()

	var tx txID
	_, _ = rand.Read(tx[:])
	msg := bindingRequest(tx)
	deadline, _ := ctx.Deadline()
	buf := make([]byte, 1500)
	for rto := l.stunRTO; ; rto *= 2 {
		sent := time.Now()
		if _, err := c.Write(msg); err != nil {
			return classify(ctx, err)
		}
		res.Attempts++
		wait := sent.Add(rto)
		if wait.After(deadline) {
			wait = deadline
		}
		if err := c.SetReadDeadline(wait); err != nil {
			return classify(ctx, err)
		}
		for {
			n, err := c.Read(buf)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() && ctx.Err() == nil && time.Now().Before(deadline) {
					break // retransmit
				}
				return classify(ctx, err)
			}
			mapped, ours, perr := parseBindingResponse(buf[:n], tx)
			if !ours {
				continue // not ours: keep waiting for the answer
			}
			if perr != nil {
				return perr
			}
			res.RTTMS = ms(time.Since(sent))
			res.Mapped = mapped.String()
			return nil
		}
	}
}
