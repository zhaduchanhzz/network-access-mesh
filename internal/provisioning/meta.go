package provisioning

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"github.com/google/uuid"
)

// Meta is meta/instance.json of a tenant instance, written by tools/render_instance.py (§14.5) and installed root-only
// (0400) by infrastructure/host/tenant-deploy.sh: the input of `meshguard admin adopt-instance`.
type Meta struct {
	TenantID        uuid.UUID
	InstanceID      uuid.UUID
	Slug            string
	RunUID          int32
	NetCIDR         netip.Prefix
	Image           string // <repository>@sha256:<64 hex>
	ImageDigest     string // sha256:<64 hex>
	TemplateVersion string
	ConfigSHA256    string
}

// metaFile is the exact key set render_instance.py writes; any other key is refused (a file this command does not
// understand is not adopted).
type metaFile struct {
	ConfigSHA256    *string `json:"config_sha256"`
	Image           *string `json:"image"`
	InstanceID      *string `json:"instance_id"`
	NetCIDR         *string `json:"net_cidr"`
	RunUID          *int64  `json:"run_uid"`
	Slug            *string `json:"slug"`
	TemplateVersion *string `json:"template_version"`
	TenantID        *string `json:"tenant_id"`
}

const maxMetaFile = 64 << 10

var (
	metaSlugRE   = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}[a-z0-9]$`) // §11.3 step 1, render_instance.py SLUG_RE
	imageRE      = regexp.MustCompile(`^[a-z0-9.\-/]+@(sha256:[0-9a-f]{64})$`)
	sha256RE     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	templateRE   = regexp.MustCompile(`^[A-Za-z0-9._-]{1,32}$`)
	reservedSlug = []string{"app", "admin", "auth", "api", "www", "stun", "mesh", "tail"} // render_instance.py RESERVED
)

// ErrInvalidMeta marks a meta/instance.json that cannot be adopted.
var ErrInvalidMeta = errors.New("invalid meta/instance.json")

// ParseMeta reads meta/instance.json strictly: exactly the keys render_instance.py writes, canonical lower-case UUIDs,
// the slug rule of §14.5, a /29 network, an image pinned by digest. Errors name the field, not its value.
func ParseMeta(r io.Reader) (Meta, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxMetaFile+1))
	if err != nil {
		return Meta{}, fmt.Errorf("%w: unreadable", ErrInvalidMeta)
	}
	if len(raw) > maxMetaFile {
		return Meta{}, fmt.Errorf("%w: larger than %d bytes", ErrInvalidMeta, maxMetaFile)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var f metaFile
	if err := dec.Decode(&f); err != nil {
		return Meta{}, fmt.Errorf("%w: not the JSON object render_instance.py writes (unknown key or wrong type)", ErrInvalidMeta)
	}
	if dec.More() {
		return Meta{}, fmt.Errorf("%w: trailing data after the object", ErrInvalidMeta)
	}
	bad := func(field string) (Meta, error) { return Meta{}, fmt.Errorf("%w: field %s", ErrInvalidMeta, field) }
	if f.ConfigSHA256 == nil || f.Image == nil || f.InstanceID == nil || f.NetCIDR == nil || f.RunUID == nil ||
		f.Slug == nil || f.TemplateVersion == nil || f.TenantID == nil {
		return bad("(missing key)")
	}
	var m Meta
	if m.TenantID, err = canonicalUUID(*f.TenantID); err != nil {
		return bad("tenant_id")
	}
	if m.InstanceID, err = canonicalUUID(*f.InstanceID); err != nil {
		return bad("instance_id")
	}
	if m.TenantID == m.InstanceID {
		return bad("instance_id (equals tenant_id)")
	}
	m.Slug = *f.Slug
	if !metaSlugRE.MatchString(m.Slug) || strings.Contains(m.Slug, "--") || strings.HasPrefix(m.Slug, "xn--") ||
		slices.Contains(reservedSlug, m.Slug) {
		return bad("slug")
	}
	if *f.RunUID <= 0 || *f.RunUID > 1<<31-1 {
		return bad("run_uid")
	}
	m.RunUID = int32(*f.RunUID)
	p, err := netip.ParsePrefix(*f.NetCIDR)
	if err != nil || !p.Addr().Is4() || p.Bits() != 29 || p != p.Masked() {
		return bad("net_cidr")
	}
	m.NetCIDR = p
	mm := imageRE.FindStringSubmatch(*f.Image)
	if mm == nil {
		return bad("image (must be pinned by digest)")
	}
	m.Image, m.ImageDigest = *f.Image, mm[1]
	if !templateRE.MatchString(*f.TemplateVersion) {
		return bad("template_version")
	}
	m.TemplateVersion = *f.TemplateVersion
	if !sha256RE.MatchString(*f.ConfigSHA256) {
		return bad("config_sha256")
	}
	m.ConfigSHA256 = *f.ConfigSHA256
	return m, nil
}

func canonicalUUID(s string) (uuid.UUID, error) {
	id, err := uuid.Parse(s)
	if err != nil || id == uuid.Nil || id.String() != s {
		return uuid.Nil, errors.New("not a canonical UUID")
	}
	return id, nil
}
