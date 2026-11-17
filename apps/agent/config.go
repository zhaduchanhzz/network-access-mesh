package main

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/agentclient"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/agentspec"
)

// Config is the agent's configuration: environment variables for values, files for secrets and for the image
// allowlist (generated from versions.lock, root-owned, not writable by the worker — §14.4).
type Config struct {
	Env      string
	LogLevel slog.Level
	// Socket is the only listener (MG_AGENT_SOCKET): a Unix socket; the agent never opens a TCP port and runs with
	// network_mode: none (§14.3).
	Socket string
	// SocketGID (MG_AGENT_SOCKET_GID) is the group of the socket (0660): mg-sec-worker; -1 leaves the agent's group
	// (dev only).
	SocketGID int
	// PeerUIDs / PeerGIDs (MG_AGENT_PEER_UIDS, MG_AGENT_PEER_GIDS) are the kernel-attested credentials (SO_PEERCRED)
	// a client must have: the worker's UID (65532) and, optionally, its primary GID. The agent's own UID is accepted
	// for Health only (container healthcheck).
	PeerUIDs, PeerGIDs []uint32
	// TokenFile (MG_AGENT_TOKEN_FILE) holds the agent token every call must present (root:mg-sec-worker 0440).
	TokenFile string
	// AllowlistFile (MG_AGENT_IMAGE_ALLOWLIST_FILE): one <repository>@sha256:<digest> per line.
	AllowlistFile string
	// Edge (MG_AGENT_EDGE_CONTAINER) is the container name of the shared edge (mg-edge).
	Edge string
	// LockWait (MG_AGENT_LOCK_WAIT) bounds the wait for the per-instance lock before BUSY (§11.5).
	LockWait time.Duration
	Host     agentspec.Host
	// selfUID is the agent's effective UID (set by Prepare): accepted as a peer for Health only.
	selfUID uint32
}

var (
	// same rule as internal/config: a secret never comes from the environment (§7.6, §25.1 rule 9)
	secretName = regexp.MustCompile(`(?i)(PASSWORD|PASSWD|TOKEN|SECRET|_KEY$|_KEY_|APIKEY|CREDENTIAL|KEK)`)
	envs       = map[string]bool{"dev": true, "ci": true, "staging": true, "production": true}
)

// LoadConfig reads the environment. It touches no file (Prepare does). Errors name variables, never values.
func LoadConfig(getenv func(string) string, environ []string) (*Config, error) {
	var errs []error
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(name, "MG_") && secretName.MatchString(name) && !strings.HasSuffix(name, "_FILE") {
			errs = append(errs, fmt.Errorf("%s: secret values must be passed as a file (%s_FILE), not in the environment", name, name))
		}
	}
	get := func(k, def string) string {
		if v := strings.TrimSpace(getenv(k)); v != "" {
			return v
		}
		return def
	}
	c := &Config{
		Env:           get("MG_ENV", "dev"),
		Socket:        get("MG_AGENT_SOCKET", agentclient.DefaultSocket),
		TokenFile:     get("MG_AGENT_TOKEN_FILE", ""),
		AllowlistFile: get("MG_AGENT_IMAGE_ALLOWLIST_FILE", ""),
		Edge:          get("MG_AGENT_EDGE_CONTAINER", "mg-edge"),
		SocketGID:     -1,
	}
	if !envs[c.Env] {
		errs = append(errs, errors.New("MG_ENV must be dev, ci, staging or production"))
	}
	if err := c.LogLevel.UnmarshalText([]byte(get("MG_LOG_LEVEL", "info"))); err != nil {
		errs = append(errs, errors.New("MG_LOG_LEVEL: debug, info, warn or error"))
	}
	// the listener: an absolute, clean path that fits sun_path — nothing else (no host:port, no scheme)
	if !filepath.IsAbs(c.Socket) || filepath.Clean(c.Socket) != c.Socket || len(c.Socket) > 100 || strings.ContainsAny(c.Socket, ":\x00") {
		errs = append(errs, errors.New("MG_AGENT_SOCKET must be a clean absolute path of a Unix socket (at most 100 bytes); the agent has no TCP listener"))
	}
	if s := get("MG_AGENT_SOCKET_GID", ""); s != "" {
		gid, err := strconv.Atoi(s)
		if err != nil || gid < 1 || gid > 1<<31-2 {
			errs = append(errs, errors.New("MG_AGENT_SOCKET_GID must be a numeric GID (mg-sec-worker)"))
		}
		c.SocketGID = gid
	} else if c.Env != "dev" {
		errs = append(errs, errors.New("MG_AGENT_SOCKET_GID is required outside dev (the GID of mg-sec-worker)"))
	}
	var err error
	if c.PeerUIDs, err = ids(get("MG_AGENT_PEER_UIDS", "")); err != nil || len(c.PeerUIDs) == 0 {
		errs = append(errs, errors.New("MG_AGENT_PEER_UIDS: a comma-separated list of the worker's numeric UIDs is required"))
	}
	if slices.Contains(c.PeerUIDs, 0) {
		errs = append(errs, errors.New("MG_AGENT_PEER_UIDS must not contain 0"))
	}
	if c.PeerGIDs, err = ids(get("MG_AGENT_PEER_GIDS", "")); err != nil {
		errs = append(errs, errors.New("MG_AGENT_PEER_GIDS: a comma-separated list of numeric GIDs"))
	}
	for name, p := range map[string]string{"MG_AGENT_TOKEN_FILE": c.TokenFile, "MG_AGENT_IMAGE_ALLOWLIST_FILE": c.AllowlistFile} {
		if !filepath.IsAbs(p) {
			errs = append(errs, fmt.Errorf("%s: an absolute path is required", name))
		}
	}
	if c.LockWait, err = time.ParseDuration(get("MG_AGENT_LOCK_WAIT", "5s")); err != nil || c.LockWait <= 0 || c.LockWait > 5*time.Minute {
		errs = append(errs, errors.New("MG_AGENT_LOCK_WAIT: a duration in (0, 5m]"))
	}
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,62}$`).MatchString(c.Edge) {
		errs = append(errs, errors.New("MG_AGENT_EDGE_CONTAINER: a container name"))
	}
	h := &c.Host
	h.TenantsDir = get("MG_AGENT_TENANTS_DIR", "/opt/meshguard/tenants")
	h.BackupsDir = get("MG_AGENT_BACKUPS_DIR", "/opt/meshguard/backups/tenants")
	if h.RunUIDs, err = agentspec.ParseRange(get("MG_AGENT_RUN_UID_RANGE", "")); err != nil {
		errs = append(errs, errors.New("MG_AGENT_RUN_UID_RANGE: min-max is required (hosts.run_uid_range)"))
	}
	if h.TenantPool, err = netip.ParsePrefix(get("MG_AGENT_TENANT_NET_POOL", "")); err != nil {
		errs = append(errs, errors.New("MG_AGENT_TENANT_NET_POOL: a CIDR is required (hosts.tenant_net_pool)"))
	}
	if s := get("MG_AGENT_STUN_PORT_RANGE", ""); s != "" {
		r, err := agentspec.ParseRange(s)
		if err != nil {
			errs = append(errs, errors.New("MG_AGENT_STUN_PORT_RANGE: min-max"))
		}
		h.STUNPorts = &r
	}
	if h.PublicEntry, err = netip.ParseAddr(get("MG_AGENT_PUBLIC_ENTRY_IPV4", "")); err != nil {
		errs = append(errs, errors.New("MG_AGENT_PUBLIC_ENTRY_IPV4: the IPv4 address of the public entry is required (hosts.public_entry)"))
	}
	h.BaseDomain = strings.ToLower(get("MG_BASE_DOMAIN", ""))
	for _, uid := range c.PeerUIDs {
		if h.RunUIDs.Contains(uid) {
			errs = append(errs, errors.New("MG_AGENT_PEER_UIDS must not overlap MG_AGENT_RUN_UID_RANGE (tenant processes)"))
			break
		}
	}
	return c, errors.Join(errs...)
}

func ids(s string) ([]uint32, error) {
	var out []uint32
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		v, err := strconv.ParseUint(f, 10, 32)
		if err != nil || strconv.FormatUint(v, 10) != f {
			return nil, errors.New("not a numeric id")
		}
		out = append(out, uint32(v))
	}
	return out, nil
}

// Prepare reads the files of the configuration — the token, the allowlist — and checks the host configuration and
// the tenants directory. The agent does not start on any error.
func (c *Config) Prepare() ([]byte, error) {
	euid := os.Geteuid()
	c.Host.OwnerUID = euid
	c.selfUID = uint32(euid) //nolint:gosec // G115: an euid is ≥ 0
	// the token: readable by the agent and the worker's group only — never by others, writable by nobody else
	if err := checkFile(c.TokenFile, euid, 0o027, false); err != nil {
		return nil, fmt.Errorf("MG_AGENT_TOKEN_FILE: %w", err)
	}
	tok, err := agentclient.ReadToken(c.TokenFile)
	if err != nil {
		return nil, err
	}
	// the allowlist: written by the operator only — not writable by the worker's group or anyone else
	if err := checkFile(c.AllowlistFile, euid, 0o022, true); err != nil {
		return nil, fmt.Errorf("MG_AGENT_IMAGE_ALLOWLIST_FILE: %w", err)
	}
	f, err := os.Open(c.AllowlistFile) //nolint:gosec // path from the configuration, checked above
	if err != nil {
		return nil, fmt.Errorf("MG_AGENT_IMAGE_ALLOWLIST_FILE: %w", err)
	}
	c.Host.Images, err = agentspec.ParseAllowlist(f)
	_ = f.Close()
	if err != nil {
		return nil, fmt.Errorf("MG_AGENT_IMAGE_ALLOWLIST_FILE: %w", err)
	}
	if err := c.Host.Check(); err != nil {
		return nil, fmt.Errorf("host configuration: %w", err)
	}
	fi, err := os.Lstat(c.Host.TenantsDir)
	if err != nil || !fi.IsDir() || !ownedBy(fi, euid) || fi.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("MG_AGENT_TENANTS_DIR must be an existing directory owned by the agent, not writable by group or others")
	}
	return []byte(tok), nil
}

// checkFile: a regular file (no symlink), owned by the agent when ownerOnly, none of the forbidden permission bits.
func checkFile(path string, euid int, forbidden fs.FileMode, ownerOnly bool) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return errors.New("not a regular file")
	}
	if fi.Mode().Perm()&forbidden != 0 {
		return fmt.Errorf("mode %o has forbidden permission bits %o", fi.Mode().Perm(), forbidden)
	}
	if ownerOnly && !ownedBy(fi, euid) {
		return errors.New("must be owned by the agent's user")
	}
	return nil
}
