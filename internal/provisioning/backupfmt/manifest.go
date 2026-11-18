package backupfmt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Format is the value of Manifest.Format of this version.
const Format = "meshguard.instance-backup/v1"

// SignContext prefixes the manifest in the signed message (domain separation: a manifest signature is never a valid
// signature of anything else the key could sign).
const SignContext = "meshguard.instance-backup.manifest.v1\x00"

// Bounds.
const (
	MaxManifestBytes  = 64 << 10
	MaxSignatureBytes = ed25519.SignatureSize
)

// Methods (BackupMethod of agent.proto).
const (
	MethodVacuumInto = "vacuum_into"
	MethodColdCopy   = "cold_copy"
)

// EncryptionAgeV1 names the archive encryption: age v1, X25519 recipients (the data key's and the recovery one).
const EncryptionAgeV1 = "age-v1-x25519"

// Archive file paths (tar entries). Restore v1 swaps data/ only; config/ and records/ are kept for the DR path (the
// agent re-renders them from the registry otherwise).
const (
	PathDB       = "data/db.sqlite"
	PathNoiseKey = "data/noise_private.key"
	PathDERPKey  = "data/derp_server_private.key"
	PathConfig   = "config/config.yaml"
	PathRecords  = "records/extra-records.json"
)

// ArchivePaths are the entries of an archive, in tar order; every one is required.
var ArchivePaths = []string{PathDB, PathNoiseKey, PathDERPKey, PathConfig, PathRecords}

// File is one entry of the archive.
type File struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Archive describes the ciphertext.
type Archive struct {
	SHA256     string `json:"sha256"`
	Size       int64  `json:"size"`
	Encryption string `json:"encryption"`
	// Recipients: "data-key:<age recipient of the data key>" and "recovery:<age recipient>".
	Recipients []string `json:"recipients"`
}

// Manifest is the signed description of one backup.
type Manifest struct {
	Format     string `json:"format"`
	TenantID   string `json:"tenant_id"`
	InstanceID string `json:"instance_id"`
	Slug       string `json:"slug"`
	Sequence   uint64 `json:"sequence"`
	JobID      string `json:"job_id"`
	// CreatedAt: RFC 3339, UTC, nanoseconds — the moment the database copy was taken.
	CreatedAt        string  `json:"created_at"`
	Method           string  `json:"method"`
	Image            string  `json:"image"`
	HeadscaleVersion string  `json:"headscale_version"`
	TemplateVersion  string  `json:"template_version"`
	ConfigSHA256     string  `json:"config_sha256"`
	NoiseFingerprint string  `json:"noise_key_fingerprint"`
	SQLiteVersion    string  `json:"sqlite_version"`
	Files            []File  `json:"files"`
	Archive          Archive `json:"archive"`
	// SigningKey is KeyID of the key that signed this manifest.
	SigningKey string `json:"signing_key"`
}

var (
	hex64RE   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	versionRE = regexp.MustCompile(`^v?(\d{1,4})\.(\d{1,4})\.(\d{1,4})`)
	slugRE    = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}[a-z0-9]$`)
	imageRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9._/:-]{0,254}@sha256:[0-9a-f]{64}$`)
)

// ErrManifest is a manifest that is malformed, not canonical, unsigned or signed by an unknown key, or that does not
// describe the expected backup.
var ErrManifest = errors.New("backupfmt: manifest refused")

func refused(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrManifest, fmt.Sprintf(format, args...))
}

// Encode returns the canonical bytes of m (what is signed and stored).
func (m *Manifest) Encode() ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	out := bytes.TrimSuffix(b.Bytes(), []byte("\n"))
	if len(out) > MaxManifestBytes {
		return nil, refused("larger than %d bytes", MaxManifestBytes)
	}
	return out, nil
}

// Sign returns the signature of the canonical manifest bytes.
func Sign(key ed25519.PrivateKey, manifest []byte) []byte {
	return ed25519.Sign(key, append([]byte(SignContext), manifest...))
}

// Parse verifies the signature of raw with one of keys, then decodes it strictly (no unknown field, no trailing data,
// canonical encoding) and checks its own consistency. Nothing of raw is trusted before the signature verified.
func Parse(raw, sig []byte, keys []ed25519.PublicKey) (*Manifest, error) {
	switch {
	case len(raw) == 0 || len(raw) > MaxManifestBytes:
		return nil, refused("size out of bounds")
	case len(sig) != ed25519.SignatureSize:
		return nil, refused("no Ed25519 signature")
	case len(keys) == 0:
		return nil, refused("no verification key configured")
	}
	msg := append([]byte(SignContext), raw...)
	var signer ed25519.PublicKey
	for _, k := range keys {
		if ed25519.Verify(k, msg, sig) {
			signer = k
			break
		}
	}
	if signer == nil {
		return nil, refused("signature does not verify with any trusted manifest key")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, refused("not a manifest: %v", err)
	}
	if dec.More() {
		return nil, refused("trailing data")
	}
	again, err := m.Encode()
	if err != nil || !bytes.Equal(again, raw) {
		return nil, refused("not in canonical form")
	}
	if m.SigningKey != KeyID(signer) {
		return nil, refused("signing_key does not name the key that signed it")
	}
	if err := m.valid(); err != nil {
		return nil, err
	}
	return &m, nil
}

// valid checks the manifest's own consistency (formats, the fixed file list, sizes).
func (m *Manifest) valid() error {
	if m.Format != Format {
		return refused("format %q is not %q", m.Format, Format)
	}
	for f, v := range map[string]string{"tenant_id": m.TenantID, "instance_id": m.InstanceID, "job_id": m.JobID} {
		id, err := uuid.Parse(v)
		if err != nil || id == uuid.Nil || id.String() != v {
			return refused("%s is not a canonical UUID", f)
		}
	}
	if m.TenantID == m.InstanceID {
		return refused("tenant_id equals instance_id")
	}
	if !slugRE.MatchString(m.Slug) {
		return refused("slug")
	}
	if m.Sequence == 0 {
		return refused("sequence 0")
	}
	if _, err := time.Parse(time.RFC3339Nano, m.CreatedAt); err != nil {
		return refused("created_at")
	}
	if m.Method != MethodVacuumInto && m.Method != MethodColdCopy {
		return refused("method")
	}
	if !imageRE.MatchString(m.Image) {
		return refused("image")
	}
	if !hex64RE.MatchString(m.NoiseFingerprint) || !hex64RE.MatchString(m.Archive.SHA256) || !hex64RE.MatchString(m.SigningKey) {
		return refused("fingerprint or hash")
	}
	if m.Archive.Encryption != EncryptionAgeV1 || m.Archive.Size <= 0 || len(m.Archive.Recipients) != 2 {
		return refused("archive")
	}
	if len(m.Files) != len(ArchivePaths) {
		return refused("file list")
	}
	for i, f := range m.Files {
		if f.Path != ArchivePaths[i] || f.Size < 0 || !hex64RE.MatchString(f.SHA256) {
			return refused("file %d", i)
		}
	}
	return nil
}

// Identity is what a manifest must describe to be restored into an instance.
type Identity struct {
	TenantID, InstanceID uuid.UUID
	Slug                 string
	Sequence             uint64
}

// Check refuses a manifest of another tenant, instance, slug or sequence (T-15, AC-19: an archive of A is never
// restored into B — refused before anything is decrypted).
func (m *Manifest) Check(want Identity) error {
	switch {
	case m.TenantID != want.TenantID.String():
		return refused("tenant_id is not the target tenant")
	case m.InstanceID != want.InstanceID.String():
		return refused("instance_id is not the target instance")
	case m.Slug != want.Slug:
		return refused("slug is not the target instance's")
	case m.Sequence != want.Sequence:
		return refused("sequence is not the requested one")
	}
	return nil
}

// Time is CreatedAt parsed (valid by construction after Parse).
func (m *Manifest) Time() time.Time {
	t, _ := time.Parse(time.RFC3339Nano, m.CreatedAt)
	return t.UTC()
}

// FilesSHA256 is the digest of the file list (path, size, sha256 — in archive order): RestoreResponse
// restored_data_sha256 for the data/ part.
func FilesSHA256(files []File, prefix string) string {
	h := sha256.New()
	for _, f := range files {
		if !strings.HasPrefix(f.Path, prefix) {
			continue
		}
		_, _ = fmt.Fprintf(h, "%s\x00%d\x00%s\n", f.Path, f.Size, f.SHA256)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ---------------------------------------------------------------------------------------------------- names, versions

// File names of one backup (directory backups/tenants/<instance_id>/), derived from the sequence only.
func ArchiveName(seq uint64) string   { return fmt.Sprintf("%020d.tar.age", seq) }
func ManifestName(seq uint64) string  { return fmt.Sprintf("%020d.manifest.json", seq) }
func SignatureName(seq uint64) string { return fmt.Sprintf("%020d.manifest.sig", seq) }

var nameRE = regexp.MustCompile(`^([0-9]{20})\.(tar\.age|manifest\.json|manifest\.sig)(\.partial)?$`)

// ParseName returns the sequence of a backup file name and whether the name is one of a backup at all.
func ParseName(name string) (uint64, bool) {
	m := nameRE.FindStringSubmatch(name)
	if m == nil {
		return 0, false
	}
	seq, err := strconv.ParseUint(m[1], 10, 64)
	return seq, err == nil && seq > 0
}

// Version is a Headscale major.minor.patch.
type Version struct{ Major, Minor, Patch int }

// ParseVersion reads "v0.29.7+mg.1", "0.29.7"…; ok is false for anything else.
func ParseVersion(s string) (Version, bool) {
	m := versionRE.FindStringSubmatch(s)
	if m == nil {
		return Version{}, false
	}
	var v Version
	v.Major, _ = strconv.Atoi(m[1])
	v.Minor, _ = strconv.Atoi(m[2])
	v.Patch, _ = strconv.Atoi(m[3])
	return v, true
}

func (v Version) String() string { return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch) }

// Restorable is the version rule of §17.2 step 2: a backup of the same minor as the running image, or of exactly one
// minor older (Headscale migrates forward and refuses an older binary on a newer schema — RT-10). Unknown versions:
// only the very same image.
func Restorable(backupVersion, backupImage, runningVersion, runningImage string) error {
	b, okb := ParseVersion(backupVersion)
	r, okr := ParseVersion(runningVersion)
	if !okb || !okr {
		if backupImage == runningImage {
			return nil
		}
		return refused("unknown Headscale version and another image: restore through the image of the backup")
	}
	switch {
	case b.Major != r.Major:
		return refused("backup of Headscale %s cannot be restored on %s (another major)", b, r)
	case b.Minor == r.Minor, b.Minor+1 == r.Minor:
		return nil
	case b.Minor > r.Minor:
		return refused("backup of Headscale %s is newer than the running %s (no downgrade — RT-10)", b, r)
	default:
		return refused("backup of Headscale %s is more than one minor older than %s: restore through the pinned intermediate images", b, r)
	}
}

// SortedCopy returns the files sorted by path (helpers of tests and of the worker's report).
func SortedCopy(files []File) []File {
	out := slices.Clone(files)
	slices.SortFunc(out, func(a, b File) int { return strings.Compare(a.Path, b.Path) })
	return out
}
