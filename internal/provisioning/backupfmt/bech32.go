package backupfmt

import (
	"errors"
	"strings"
)

// Bech32 (BIP 173 — the original checksum, as age uses it for recipients and identities). Only what the age X25519
// encodings need: 8-bit data ↔ 5-bit groups, the checksum, one lower-case or upper-case string.

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

var bech32Gen = [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

func bech32Polymod(values []byte) uint32 {
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := range 5 {
			if (top>>uint(i))&1 == 1 {
				chk ^= bech32Gen[i]
			}
		}
	}
	return chk
}

func bech32HRPExpand(hrp string) []byte {
	out := make([]byte, 0, len(hrp)*2+1)
	for i := range len(hrp) {
		out = append(out, hrp[i]>>5)
	}
	out = append(out, 0)
	for i := range len(hrp) {
		out = append(out, hrp[i]&31)
	}
	return out
}

// convertBits regroups bits (8 → 5 with padding, 5 → 8 without).
func convertBits(data []byte, from, to uint, pad bool) ([]byte, error) {
	var acc uint32
	var bits uint
	maxv := uint32(1)<<to - 1
	out := make([]byte, 0, len(data)*int(from)/int(to)+1)
	for _, b := range data {
		if uint32(b)>>from != 0 {
			return nil, errors.New("bech32: invalid data range")
		}
		acc = acc<<from | uint32(b)
		bits += from
		for bits >= to {
			bits -= to
			out = append(out, byte(acc>>bits&maxv)) //nolint:gosec // G115: masked to "to" bits (≤ 8)
		}
	}
	if pad {
		if bits > 0 {
			out = append(out, byte(acc<<(to-bits)&maxv)) //nolint:gosec // G115: masked to "to" bits (≤ 8)
		}
	} else if bits >= from || acc<<(to-bits)&maxv != 0 {
		return nil, errors.New("bech32: invalid padding")
	}
	return out, nil
}

// bech32Encode encodes data under hrp (lower case; age upper-cases identities itself).
func bech32Encode(hrp string, data []byte) (string, error) {
	values, err := convertBits(data, 8, 5, true)
	if err != nil {
		return "", err
	}
	hrp = strings.ToLower(hrp)
	poly := bech32Polymod(append(append(bech32HRPExpand(hrp), values...), 0, 0, 0, 0, 0, 0)) ^ 1
	var b strings.Builder
	b.WriteString(hrp)
	b.WriteByte('1')
	for _, v := range values {
		b.WriteByte(bech32Charset[v])
	}
	for i := range 6 {
		b.WriteByte(bech32Charset[(poly>>uint(5*(5-i)))&31])
	}
	return b.String(), nil
}

// bech32Decode decodes a string that is entirely lower case or entirely upper case and returns its (lower-case) hrp
// and data; the checksum must be valid.
func bech32Decode(s string) (string, []byte, error) {
	if strings.ToLower(s) != s && strings.ToUpper(s) != s {
		return "", nil, errors.New("bech32: mixed case")
	}
	s = strings.ToLower(s)
	pos := strings.LastIndexByte(s, '1')
	if pos < 1 || pos+7 > len(s) {
		return "", nil, errors.New("bech32: invalid separator position")
	}
	hrp := s[:pos]
	for i := range len(hrp) {
		if hrp[i] < 33 || hrp[i] > 126 {
			return "", nil, errors.New("bech32: invalid human-readable part")
		}
	}
	values := make([]byte, 0, len(s)-pos-1)
	for i := pos + 1; i < len(s); i++ {
		v := strings.IndexByte(bech32Charset, s[i])
		if v < 0 {
			return "", nil, errors.New("bech32: invalid character")
		}
		values = append(values, byte(v)) //nolint:gosec // G115: an index of the 32-character charset
	}
	if bech32Polymod(append(bech32HRPExpand(hrp), values...)) != 1 {
		return "", nil, errors.New("bech32: invalid checksum")
	}
	data, err := convertBits(values[:len(values)-6], 5, 8, false)
	if err != nil {
		return "", nil, err
	}
	return hrp, data, nil
}
