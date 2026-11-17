//go:build unix

package compose

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"syscall"
)

// FingerprintNoiseKeyFile is the body of the fingerprint helper (`meshguard-agent noise-fingerprint`, run as the
// tenant's run_uid with data/ read-only): open with O_NOFOLLOW (a symlink is refused) and O_NONBLOCK (a FIFO cannot
// block), accept only a regular file of the expected size, read it, return the fingerprint.
func FingerprintNoiseKeyFile(path string) (string, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) //nolint:gosec // G304: the fixed NoiseKeyPath inside the helper container
	if errors.Is(err, fs.ErrNotExist) {
		return "", ErrNoiseKeyAbsent
	}
	if errors.Is(err, syscall.ELOOP) {
		return "", ErrNoiseKeyInvalid
	}
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() || fi.Size() < noiseKeyMinBytes || fi.Size() > noiseKeyMaxBytes {
		return "", ErrNoiseKeyInvalid
	}
	buf := make([]byte, noiseKeyMaxBytes+1)
	defer clear(buf)
	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return "", err
	}
	if n > noiseKeyMaxBytes {
		return "", ErrNoiseKeyInvalid
	}
	return NoiseFingerprint(buf[:n])
}
