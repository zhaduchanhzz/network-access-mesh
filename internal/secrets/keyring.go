package secrets

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
)

// Keyring names (§7.6): kek-app is mounted into api and worker and wraps the tenant DEKs and the platform DEK;
// kek-ops is mounted into the worker only and wraps the platform_ops DEK.
const (
	KEKApp = "kek-app"
	KEKOps = "kek-ops"
)

// ActiveFile is the keyring file naming the current kek_id.
const ActiveFile = "ACTIVE"

const maxKeyringFile = 4096

// kekIDRE is the CHECK of tenant_keys.kek_id (0003).
var kekIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// Keyring holds the KEK versions of one keyring. New DEKs are wrapped with the active KEK; a DEK is unwrapped with
// the KEK its row names (tenant_keys.kek_id), so old and new KEKs coexist while DEKs are rewrapped (§7.6). The raw
// key bytes are not kept: only the AES-GCM instances built from them.
type Keyring struct {
	name   string
	active string
	keys   map[string]cipher.AEAD
}

// LoadKeyring reads a keyring directory (§7.6, §14.2): one file per KEK version, named by its kek_id and holding the
// 32-byte key as 64 hexadecimal characters (one line, a trailing newline allowed), plus the file ACTIVE holding the
// kek_id of the current KEK. Example (P2-T04a): `umask 077; openssl rand -hex 32 > kek-app/<kek_id>` and
// `echo <kek_id> > kek-app/ACTIVE`. Entries starting with "." are ignored; any other entry must be a valid key file,
// and a key file that other users may access (mode o+rwx, §14.2 forbids 0444) is refused. Errors name files, never
// their content.
func LoadKeyring(name, dir string) (*Keyring, error) {
	if name != KEKApp && name != KEKOps {
		return nil, fmt.Errorf("secrets: keyring name must be %s or %s", KEKApp, KEKOps)
	}
	fail := func(format string, a ...any) (*Keyring, error) {
		return nil, fmt.Errorf("secrets: keyring %s (%s): %s", name, dir, fmt.Sprintf(format, a...))
	}
	if !filepath.IsAbs(dir) {
		return fail("the directory must be an absolute path")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("secrets: keyring %s: %w", name, err) // *PathError: names the path only
	}
	defer func() { _ = root.Close() }()
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return nil, fmt.Errorf("secrets: keyring %s: %w", name, err)
	}
	kr := &Keyring{name: name, keys: map[string]cipher.AEAD{}}
	for _, e := range entries {
		n := e.Name()
		switch {
		case strings.HasPrefix(n, "."):
			continue
		case n == ActiveFile:
			b, err := readKeyringFile(root, n)
			if err != nil {
				return fail("%s: %v", n, err)
			}
			id := string(trimNewline(b))
			if !kekIDRE.MatchString(id) {
				return fail("%s must hold one kek_id matching %s", n, kekIDRE)
			}
			kr.active = id
		case !kekIDRE.MatchString(n):
			return fail("unexpected entry %q (want <kek_id> files and %s)", n, ActiveFile)
		default:
			b, err := readKeyringFile(root, n)
			if err != nil {
				return fail("key file %s: %v", n, err)
			}
			aead, err := parseKEK(b)
			clear(b)
			if err != nil {
				return fail("key file %s: %v", n, err)
			}
			kr.keys[n] = aead
		}
	}
	switch {
	case len(kr.keys) == 0:
		return fail("no key file")
	case kr.active == "":
		return fail("no %s file", ActiveFile)
	case kr.keys[kr.active] == nil:
		return fail("%s names kek_id %q but there is no key file with that name", ActiveFile, kr.active)
	}
	return kr, nil
}

// readKeyringFile reads one small regular file of the keyring.
func readKeyringFile(root *os.Root, name string) ([]byte, error) {
	f, err := root.Open(name)
	if err != nil {
		return nil, errors.New("cannot open")
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	switch {
	case err != nil:
		return nil, errors.New("cannot stat")
	case !info.Mode().IsRegular():
		return nil, errors.New("not a regular file")
	case runtime.GOOS != "windows" && info.Mode().Perm()&0o007 != 0:
		return nil, fmt.Errorf("mode %04o lets other users access it (want 0440 root:<service group> — §14.2)", info.Mode().Perm())
	case info.Size() > maxKeyringFile:
		return nil, errors.New("too large")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxKeyringFile+1))
	if err != nil || len(b) > maxKeyringFile {
		return nil, errors.New("cannot read")
	}
	return b, nil
}

func trimNewline(b []byte) []byte {
	b = bytes.TrimSuffix(b, []byte("\n"))
	return bytes.TrimSuffix(b, []byte("\r"))
}

// parseKEK decodes 64 hexadecimal characters into an AES-256-GCM instance. The error never quotes the content (a
// hex.InvalidByteError would).
func parseKEK(b []byte) (cipher.AEAD, error) {
	b = trimNewline(b)
	if len(b) != 2*keySize {
		return nil, errors.New("must hold exactly 64 hexadecimal characters (32 bytes)")
	}
	key := make([]byte, keySize)
	defer clear(key)
	if _, err := hex.Decode(key, b); err != nil {
		return nil, errors.New("must hold exactly 64 hexadecimal characters (32 bytes)")
	}
	return newAEAD(key)
}

// Name returns KEKApp or KEKOps.
func (k *Keyring) Name() string { return k.name }

// Active returns the kek_id new DEKs are wrapped with.
func (k *Keyring) Active() string { return k.active }

// IDs returns every kek_id of the keyring, sorted.
func (k *Keyring) IDs() []string {
	ids := make([]string, 0, len(k.keys))
	for id := range k.keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// wrap encrypts a DEK with the active KEK.
func (k *Keyring) wrap(dek, aad []byte) (kekID string, nonce, wrapped []byte, err error) {
	nonce, wrapped, err = seal(k.keys[k.active], dek, aad)
	return k.active, nonce, wrapped, err
}

// unwrap decrypts a DEK wrapped with KEK kekID; the caller clears the result.
func (k *Keyring) unwrap(kekID string, nonce, wrapped, aad []byte) ([]byte, error) {
	aead := k.keys[kekID]
	if aead == nil {
		return nil, fmt.Errorf("%w: kek_id %q is not in keyring %s", ErrUnknownKEK, kekID, k.name)
	}
	dek, err := open(aead, nonce, wrapped, aad)
	if err != nil {
		return nil, err
	}
	if len(dek) != keySize {
		clear(dek)
		return nil, errAuth
	}
	return dek, nil
}
