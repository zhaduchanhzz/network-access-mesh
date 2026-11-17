//go:build !unix

package compose

import "errors"

// FingerprintNoiseKeyFile is the body of the fingerprint helper; the helper runs in the (Linux) agent image only.
func FingerprintNoiseKeyFile(string) (string, error) {
	return "", errors.New("the fingerprint helper runs on Linux only")
}
