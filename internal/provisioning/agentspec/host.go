package agentspec

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// TemplateVersion is the version of the instance templates the agent renders (config.yaml, compose.yaml) — the same
// numbering as tools/render_instance.py (TEMPLATE_VERSION), recorded in instance_config_versions.
const TemplateVersion = 1

// Host is the host-local configuration the agent enforces (MG_AGENT_* — apps/agent). None of it comes from the
// worker: a compromised worker cannot widen a range, add an image or point an instance elsewhere.
type Host struct {
	TenantsDir string // /opt/meshguard/tenants — same path inside and outside the agent container (§14.4)
	BackupsDir string // /opt/meshguard/backups/tenants
	RunUIDs    Range  // hosts.run_uid_range (versions.lock [ids] tenant_run_uid_range)
	TenantPool netip.Prefix
	// STUNPorts is the per-tenant STUN port range of the fallback design (§10.1); nil = shared STUN only (MVP).
	STUNPorts   *Range
	PublicEntry netip.Addr // derp.server.ipv4 of every instance (hosts.public_entry)
	BaseDomain  string     // MG_BASE_DOMAIN: server_url https://<slug>.mesh.<domain>, MagicDNS <slug>.tail.<domain>
	Images      *Allowlist
	// OwnerUID owns every file the agent writes (its effective UID: 0 in production).
	OwnerUID int
}

// Range is an inclusive range of numbers.
type Range struct{ Min, Max uint32 }

// Contains reports whether v is in the range.
func (r Range) Contains(v uint32) bool { return v >= r.Min && v <= r.Max }

func (r Range) String() string { return fmt.Sprintf("%d-%d", r.Min, r.Max) }

// ParseRange reads "min-max".
func ParseRange(s string) (Range, error) {
	lo, hi, ok := strings.Cut(strings.TrimSpace(s), "-")
	var r Range
	if !ok {
		return r, errors.New("want min-max")
	}
	if _, err := fmt.Sscanf(lo+" "+hi, "%d %d", &r.Min, &r.Max); err != nil || fmt.Sprintf("%d-%d", r.Min, r.Max) != strings.TrimSpace(s) {
		return r, errors.New("want min-max with decimal numbers")
	}
	if r.Min > r.Max {
		return r, errors.New("min > max")
	}
	return r, nil
}

// reservedIDs are the UIDs and GIDs of the platform's own services (versions.lock [ids], images.keycloak): a tenant
// container runs as run_uid:run_uid (§6.3), so the run_uid range must never contain one of them — a tenant process
// with GID 20003 (mg-sec-worker) could read the agent token and the worker's database passwords (§14.2).
// TestReservedIDsCoverVersionsLock keeps this list in step with versions.lock.
var reservedIDs = []uint32{0, 999, 1000, 10001, 10007, 20001, 20002, 20003, 20004, 20005, 20006, 20007, 20008, 65532, 65534}

// reservedPorts are the ports the platform itself listens on at the host or the public entry: edge (80, 443, tunnel
// 8080/8443) and the shared STUN responder (3478).
var reservedPorts = []uint32{80, 443, 3478, 8080, 8443}

var domainRE = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// Check validates the host configuration itself; the agent refuses to start otherwise.
func (h *Host) Check() error {
	var errs []error
	for name, dir := range map[string]string{"tenants directory": h.TenantsDir, "backups directory": h.BackupsDir} {
		if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || dir == "/" {
			errs = append(errs, fmt.Errorf("%s must be a clean absolute path other than /", name))
		}
	}
	if h.RunUIDs.Min < 1000 || h.RunUIDs.Max > 1<<31-2 || h.RunUIDs.Min > h.RunUIDs.Max {
		errs = append(errs, errors.New("run_uid range must lie within 1000..2147483646"))
	}
	for _, id := range reservedIDs {
		if h.RunUIDs.Contains(id) {
			errs = append(errs, fmt.Errorf("run_uid range %s contains the platform UID/GID %d (versions.lock [ids])", h.RunUIDs, id))
		}
	}
	if !h.TenantPool.IsValid() || !h.TenantPool.Addr().Is4() || h.TenantPool != h.TenantPool.Masked() ||
		h.TenantPool.Bits() > 29 || h.TenantPool.Bits() < 8 {
		errs = append(errs, errors.New("tenant network pool must be a canonical IPv4 prefix between /8 and /29"))
	}
	if h.STUNPorts != nil {
		if h.STUNPorts.Min < 1024 || h.STUNPorts.Max > 65535 || h.STUNPorts.Min > h.STUNPorts.Max {
			errs = append(errs, errors.New("STUN port range must lie within 1024..65535"))
		}
		for _, p := range reservedPorts {
			if h.STUNPorts.Contains(p) {
				errs = append(errs, fmt.Errorf("STUN port range contains the platform port %d", p))
			}
		}
	}
	if !h.PublicEntry.Is4() || !usableUnicast(h.PublicEntry) || h.TenantPool.Contains(h.PublicEntry) {
		errs = append(errs, errors.New("public entry must be a unicast IPv4 address outside the tenant pool"))
	}
	if !domainRE.MatchString(h.BaseDomain) {
		errs = append(errs, errors.New("base domain is not a valid lower-case domain"))
	}
	if h.Images == nil || h.Images.Len() == 0 {
		errs = append(errs, errors.New("image allowlist is empty"))
	}
	if h.OwnerUID < 0 {
		errs = append(errs, errors.New("owner UID must be the agent's effective UID"))
	}
	return errors.Join(errs...)
}

func usableUnicast(a netip.Addr) bool {
	return a.IsValid() && a.Zone() == "" && !a.IsUnspecified() && !a.IsLoopback() && !a.IsMulticast() &&
		!a.IsLinkLocalUnicast() && !a.IsLinkLocalMulticast() && !a.IsInterfaceLocalMulticast()
}

// reservedSlugs are the names of the platform's own hosts (§14.5, tools/render_instance.py RESERVED); the labels of
// <mesh_domain> are added by Host.slugReserved.
var reservedSlugs = []string{"app", "admin", "auth", "api", "www", "stun", "mesh", "tail"}

func (h *Host) slugReserved(s string) bool {
	return slices.Contains(reservedSlugs, s) || slices.Contains(strings.Split(h.BaseDomain, "."), s)
}

// ---------------------------------------------------------------------------------------------------- allowlist

// AllowedImage is one entry of the allowlist.
type AllowedImage struct{ Repository, Digest string }

// Reference is <repository>@<digest>, the form compose and docker run use.
func (a AllowedImage) Reference() string { return a.Repository + "@" + a.Digest }

// Allowlist maps an image digest to its repository. Only digests listed here can run as a tenant instance; the file
// is generated from versions.lock and is not writable by the worker (§14.4).
type Allowlist struct{ byDigest map[string]AllowedImage }

var (
	digestRE     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	repositoryRE = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*(:[0-9]{1,5})?(/[a-z0-9]+([._-]{1,2}[a-z0-9]+)*)+$`)
)

const maxAllowlist = 256

// ParseAllowlist reads one "<repository>@sha256:<64 hex>" per line; "#" starts a comment, blank lines are ignored.
// Anything else — a tag, an upper-case digest, a duplicate digest — makes the whole file invalid.
func ParseAllowlist(r io.Reader) (*Allowlist, error) {
	a := &Allowlist{byDigest: map[string]AllowedImage{}}
	sc := bufio.NewScanner(io.LimitReader(r, 1<<20))
	n := 0
	for sc.Scan() {
		n++
		line, _, _ := strings.Cut(sc.Text(), "#")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		repo, digest, ok := strings.Cut(line, "@")
		if !ok || !repositoryRE.MatchString(repo) || !digestRE.MatchString(digest) {
			return nil, fmt.Errorf("allowlist line %d: want <repository>@sha256:<64 lower-case hex>", n)
		}
		if _, dup := a.byDigest[digest]; dup {
			return nil, fmt.Errorf("allowlist line %d: duplicate digest", n)
		}
		if len(a.byDigest) == maxAllowlist {
			return nil, fmt.Errorf("allowlist: more than %d images", maxAllowlist)
		}
		a.byDigest[digest] = AllowedImage{Repository: repo, Digest: digest}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("allowlist: %w", err)
	}
	return a, nil
}

// Lookup returns the allowed image with that digest.
func (a *Allowlist) Lookup(digest string) (AllowedImage, bool) {
	if a == nil {
		return AllowedImage{}, false
	}
	img, ok := a.byDigest[digest]
	return img, ok
}

// Len is the number of allowed images.
func (a *Allowlist) Len() int {
	if a == nil {
		return 0
	}
	return len(a.byDigest)
}

// All lists the allowed images sorted by repository then digest.
func (a *Allowlist) All() []AllowedImage {
	if a == nil {
		return nil
	}
	out := make([]AllowedImage, 0, len(a.byDigest))
	for _, img := range a.byDigest {
		out = append(out, img)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Reference() < out[j].Reference() })
	return out
}

// ---------------------------------------------------------------------------------------------------- names

// Docker labels of tenant objects (§14.5; tools/render_instance.py, infrastructure/host/tenant-deploy.sh).
const (
	LabelInstanceID     = "meshguard.instance_id"
	LabelTenantID       = "meshguard.tenant_id"
	LabelRole           = "meshguard.role"
	RoleTenant          = "tenant"
	LabelComposeProject = "com.docker.compose.project"
)

// Names are the paths and Docker names of one instance, derived only from its instance_id and slug (§14.2, §14.5).
type Names struct {
	Dir, ConfigDir, ConfigNextDir, RecordsDir, SecretsDir, DataDir, MetaDir, StagingDir string
	ComposeFile, ConfigFile, PolicyFile, RecordsFile, MetaFile, ActivatedFile           string
	BackupDir                                                                           string
	Project, Network, Container, Service, Alias                                         string
}

// Names derives the names of a validated reference. It panics if a derived path escapes the tenants or backups
// directory — impossible for a validated (canonical UUID) id, so a panic is a programming error.
func (h *Host) Names(ref Ref) Names {
	id := ref.InstanceID.String()
	dir := filepath.Join(h.TenantsDir, id)
	backup := filepath.Join(h.BackupsDir, id)
	if filepath.Dir(dir) != h.TenantsDir || filepath.Dir(backup) != h.BackupsDir {
		panic("agentspec: derived path escapes its root")
	}
	n := Names{
		Dir:           dir,
		ConfigDir:     filepath.Join(dir, "config"),
		ConfigNextDir: filepath.Join(dir, "config.next"),
		RecordsDir:    filepath.Join(dir, "records"),
		SecretsDir:    filepath.Join(dir, "secrets"),
		DataDir:       filepath.Join(dir, "data"),
		MetaDir:       filepath.Join(dir, "meta"),
		StagingDir:    filepath.Join(dir, ".staging"),
		ComposeFile:   filepath.Join(dir, "compose.yaml"),
		ConfigFile:    filepath.Join(dir, "config", "config.yaml"),
		PolicyFile:    filepath.Join(dir, "config", "bootstrap-policy.hujson"),
		RecordsFile:   filepath.Join(dir, "records", "extra-records.json"),
		MetaFile:      filepath.Join(dir, "meta", "instance.json"),
		ActivatedFile: filepath.Join(dir, "meta", "activated"),
		BackupDir:     backup,
		Project:       "mg-t-" + ref.Slug,
		Network:       "mg-t-" + ref.Slug,
		Container:     "mg-hs-" + ref.Slug,
		Service:       "hs-" + ref.Slug,
		Alias:         "hs-" + ref.Slug,
	}
	return n
}
