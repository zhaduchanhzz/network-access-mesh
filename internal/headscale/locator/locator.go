// Package locator is the production headscale.Locator (§13.4 rule 2, P2-T11): Registry.ForTenant resolves a tenant
// through the Tenant Registry (tenant_instances, read in the tenant's own scope on the tenant pool), the SecretStore
// (the instance API key, by reference) and the platform configuration (edge admin listener URL and token file).
//
// It is a sub-package of internal/headscale (module `headscale` for the architecture rules of §13.6, which allow
// headscale → tenants, secrets) so that the adapter package itself keeps no dependency on the database: the Headscale
// contract-test module (tests/integration/headscale) builds the adapter without PostgreSQL drivers.
//
// Wiring (P2-T16, apps/*):
//
//	loc, _ := locator.New(tenants.New(st, tenants.Options{BaseDomain: cfg.BaseDomain}), secretStore,
//		locator.Options{AdminURL: edge.URL, EdgeTokenFile: edge.TokenFile, Logger: log})
//	reg := headscale.NewRegistry(loc, headscale.Options{Logger: log})
package locator

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// InstanceDirectory is the part of the Tenant Registry the locator reads (*tenants.Service implements it): the live
// instance of a tenant, read in that tenant's own scope (tenant pool, RLS — §8.8 layers 3–5).
type InstanceDirectory interface {
	LocateInstance(ctx context.Context, tenantID uuid.UUID) (tenants.InstanceRecord, error)
}

// SecretReader resolves the reference of an instance API key (*secrets.Store implements it).
type SecretReader interface {
	Get(ctx context.Context, ref secrets.Ref) (secrets.Plaintext, error)
}

// Options configures a Locator. Every value comes from the platform configuration (internal/config), never from a
// request (§13.4 rule 1).
type Options struct {
	// AdminURL is the base URL of the edge admin listener (MG_EDGE_ADMIN_URL, §14.6): http(s)://host[:port], no path,
	// query or user info. One host in the MVP; with several hosts it moves to the hosts table.
	AdminURL string
	// EdgeTokenFile holds the admin listener's own token (MG_EDGE_ADMIN_TOKEN_FILE — on the host
	// /opt/meshguard/secrets/app/edge_admin_token, root:mg-sec-app 0440). It is read at every Locate, so a rotated
	// token is picked up when the edge first refuses the old one (403 ⇒ CachingRegistry locates again).
	EdgeTokenFile string
	// Timeout per call to the instance (Target.Timeout); 0 = the registry default.
	Timeout time.Duration
	// TenantStatuses are the tenant statuses under which the instance is reachable; nil = DefaultTenantStatuses.
	TenantStatuses []string
	// Logger records integrity failures (never a credential); nil discards.
	Logger *slog.Logger
}

// DefaultTenantStatuses: a tenant being provisioned or serving. A suspended, deprovisioning, failed or deleted tenant
// has no reachable instance (headscale.ErrNoInstance); P3 lifecycle jobs that must still reach the instance of a
// suspended tenant (policy drift, deprovisioning — §11.4) construct their locator with their own list.
var DefaultTenantStatuses = []string{tenants.StatusProvisioning, tenants.StatusActive}

// runnableInstance: an instance that is up — starting (steps 10–18 of §11.3 already call it) or running.
var runnableInstance = []string{tenants.InstanceStarting, tenants.InstanceRunning}

var edgeTokenRE = regexp.MustCompile(`^[A-Za-z0-9]{40}$`)

// Locator resolves a tenant to its instance from the registry. It keeps no cache: headscale.CachingRegistry caches
// the located target and calls Locate again after its TTL and — bypassing the cache — after a 401/403, so a rotated
// API key (adopt-instance, apikey.rotate) or edge token is picked up without a restart.
type Locator struct {
	dir      InstanceDirectory
	secrets  SecretReader
	adminURL string
	token    string
	timeout  time.Duration
	statuses []string
	log      *slog.Logger
}

var _ headscale.Locator = (*Locator)(nil)

// New checks the options and returns the locator.
func New(dir InstanceDirectory, sec SecretReader, o Options) (*Locator, error) {
	if dir == nil || sec == nil {
		return nil, errors.New("locator: the tenant registry and the SecretStore are required")
	}
	u, err := url.Parse(o.AdminURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("locator: the edge admin URL must be http(s)://host[:port] without path, query or user info")
	}
	if o.EdgeTokenFile == "" {
		return nil, errors.New("locator: the edge admin token file is required")
	}
	l := &Locator{dir: dir, secrets: sec, adminURL: u.Scheme + "://" + u.Host, token: o.EdgeTokenFile,
		timeout: o.Timeout, statuses: o.TenantStatuses, log: o.Logger}
	if l.statuses == nil {
		l.statuses = DefaultTenantStatuses
	}
	if l.log == nil {
		l.log = slog.New(slog.DiscardHandler)
	}
	return l, nil
}

// Locate implements headscale.Locator. Errors wrap headscale.ErrNoInstance when the tenant has no instance that may
// be called — unknown tenant, tenant status outside the allowed list, no live instance, instance neither starting nor
// running, no API key registered. Any other error (an unreadable or destroyed secret, a key reference owned by
// another tenant, a bad token file) is a platform fault and does not wrap it.
func (l *Locator) Locate(ctx context.Context, tenantID uuid.UUID) (headscale.Target, error) {
	rec, err := l.dir.LocateInstance(ctx, tenantID)
	if errors.Is(err, tenants.ErrNotFound) {
		return headscale.Target{}, fmt.Errorf("tenant %s: %w", tenantID, headscale.ErrNoInstance)
	}
	if err != nil {
		return headscale.Target{}, fmt.Errorf("tenant %s: read the registry: %w", tenantID, err)
	}
	switch {
	case rec.TenantID != tenantID:
		l.log.Error("headscale locator: the registry returned another tenant", "tenant_id", tenantID.String())
		return headscale.Target{}, fmt.Errorf("tenant %s: the registry returned a record of another tenant", tenantID)
	case !slices.Contains(l.statuses, rec.TenantStatus):
		return headscale.Target{}, fmt.Errorf("tenant %s is %s: %w", tenantID, rec.TenantStatus, headscale.ErrNoInstance)
	case !slices.Contains(runnableInstance, rec.Status):
		return headscale.Target{}, fmt.Errorf("instance %s of tenant %s is %s: %w", rec.InstanceID, tenantID, rec.Status,
			headscale.ErrNoInstance)
	case rec.APIKeyRef == "":
		return headscale.Target{}, fmt.Errorf("instance %s of tenant %s has no API key registered: %w", rec.InstanceID,
			tenantID, headscale.ErrNoInstance)
	}
	ref, err := secrets.ParseRef(rec.APIKeyRef)
	if err != nil {
		return headscale.Target{}, fmt.Errorf("instance %s: API key reference: %w", rec.InstanceID, err)
	}
	if ref.Tenant != tenantID { // boundary 10 of §5.2: the key of a tenant is a secret of that tenant only
		l.log.Error("headscale locator: the API key reference belongs to another owner", "tenant_id", tenantID.String(),
			"instance_id", rec.InstanceID.String(), "ref", ref.String())
		return headscale.Target{}, fmt.Errorf("instance %s: the API key reference does not belong to tenant %s",
			rec.InstanceID, tenantID)
	}
	pt, err := l.secrets.Get(ctx, ref)
	if err != nil {
		return headscale.Target{}, fmt.Errorf("instance %s: API key: %w", rec.InstanceID, err)
	}
	apiKey := headscale.NewSecret(string(pt.Bytes()))
	pt.Wipe()
	token, err := l.edgeToken()
	if err != nil {
		return headscale.Target{}, err
	}
	t := headscale.Target{InstanceID: rec.InstanceID, Slug: rec.TenantSlug, AdminURL: l.adminURL, APIKey: apiKey,
		EdgeToken: token, Timeout: l.timeout}
	if err := headscale.ValidateTarget(t); err != nil {
		return headscale.Target{}, fmt.Errorf("instance %s: %w", rec.InstanceID, err)
	}
	return t, nil
}

// Candidate is the target of an instance that is not registered (yet), with the locator's edge admin listener and
// token and the given key: the pre-flight of `meshguard admin adopt-instance` checks a new API key with it before
// anything is written.
func (l *Locator) Candidate(instanceID uuid.UUID, slug string, apiKey headscale.Secret) (headscale.Target, error) {
	token, err := l.edgeToken()
	if err != nil {
		return headscale.Target{}, err
	}
	t := headscale.Target{InstanceID: instanceID, Slug: slug, AdminURL: l.adminURL, APIKey: apiKey, EdgeToken: token,
		Timeout: l.timeout}
	if err := headscale.ValidateTarget(t); err != nil {
		return headscale.Target{}, fmt.Errorf("locator: candidate target: %w", err)
	}
	return t, nil
}

const maxTokenFile = 4096

// edgeToken reads the token file: one line of 40 characters [A-Za-z0-9] (§14.6), a trailing newline ignored. Errors
// name the file, never its content.
func (l *Locator) edgeToken() (headscale.Secret, error) {
	f, err := os.Open(l.token) //nolint:gosec // the path comes from the platform configuration, not from a request
	if err != nil {
		return headscale.Secret{}, fmt.Errorf("locator: edge admin token file %s: %w", l.token, err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxTokenFile+1))
	if err != nil || len(b) > maxTokenFile {
		clear(b)
		return headscale.Secret{}, fmt.Errorf("locator: edge admin token file %s: unreadable or too large", l.token)
	}
	tok := strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
	clear(b)
	if !edgeTokenRE.MatchString(tok) {
		return headscale.Secret{}, fmt.Errorf("locator: edge admin token file %s must hold 40 characters [A-Za-z0-9]",
			l.token)
	}
	return headscale.NewSecret(tok), nil
}
