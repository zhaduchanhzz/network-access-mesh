package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/devices"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale/locator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/httpx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/monitoring"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// poolConns is the size of each of the two pools of a process (store.Config.MaxConns).
const poolConns = 10

// deps are the dependencies api and worker share, opened from the configuration of the process (P2-T16):
//   - the two pools of the service's own roles (§6.1) — store.Open refuses swapped or over-privileged roles;
//   - the SecretStore with the keyrings of the service (§7.6): kek-app in both, kek-ops in the worker only;
//   - the Tenant Registry, the Locator of P2-T11 (live instance + API key from the SecretStore + edge admin listener)
//     and the Headscale registry over it — the only way to a tenant's Headscale (§13.4);
//   - the two HTTP paths to identity providers (P2-T05a, T-21): the SSRF-hardened client for tenant-supplied issuers
//     and the narrow route to the platform-hosted IdP auth.<domain>.
type deps struct {
	cfg       config.Config
	log       *slog.Logger
	st        *store.Store
	secrets   *secrets.Store
	tenants   *tenants.Service
	headscale *headscale.CachingRegistry
	hardened  *idp.Hardened
	route     *idp.PlatformRoute
	closers   []func()
}

func (d *deps) close() {
	for i := len(d.closers) - 1; i >= 0; i-- {
		d.closers[i]()
	}
}

// openDeps opens the shared dependencies; routePaths are the path prefixes of the platform IdP route the process may
// use (api: the public OIDC endpoints only; worker: plus the Admin REST API of its IdP driver).
func openDeps(ctx context.Context, cfg config.Config, log *slog.Logger, routePaths []string) (_ *deps, err error) {
	d := &deps{cfg: cfg, log: log}
	defer func() {
		if err != nil {
			d.close()
		}
	}()
	app, err := loadKeyring(log, secrets.KEKApp, cfg.KEKAppDir)
	if err != nil {
		return nil, err
	}
	var ops *secrets.Keyring
	if cfg.Service == "worker" {
		if ops, err = loadKeyring(log, secrets.KEKOps, cfg.KEKOpsDir); err != nil {
			return nil, err
		}
	}
	d.st, err = store.Open(ctx, store.Config{
		URL:      cfg.DB.URL,
		Tenant:   store.Credentials{User: cfg.DB.TenantUser, PasswordFile: cfg.DB.TenantPasswordFile},
		Platform: store.Credentials{User: cfg.DB.PlatformUser, PasswordFile: cfg.DB.PlatformPasswordFile},
		MaxConns: poolConns,
		Logger:   log,
	})
	if err != nil {
		return nil, err
	}
	d.closers = append(d.closers, d.st.Close)
	if d.secrets, err = secrets.New(d.st, secrets.Options{App: app, Ops: ops, Logger: log,
		OnIntegrity: integrityReporter(d.st, cfg.Service, log)}); err != nil {
		return nil, err
	}
	d.tenants = tenants.New(d.st, tenants.Options{BaseDomain: cfg.BaseDomain})
	loc, err := locator.New(d.tenants, d.secrets, locator.Options{AdminURL: cfg.Edge.URL, EdgeTokenFile: cfg.Edge.TokenFile,
		Logger: log})
	if err != nil {
		return nil, err
	}
	d.headscale = headscale.NewRegistry(loc, headscale.Options{Logger: log})
	if d.hardened, d.route, err = idpClients(cfg, routePaths); err != nil {
		return nil, err
	}
	return d, nil
}

// idpClients builds the two HTTP paths to identity providers (P2-T05a, T-21; G2 wiring hazard 3): the SSRF-hardened
// client — built-in special ranges plus MG_EGRESS_DENY_CIDRS (every platform pool, the LAN, the tunnel, the public
// entry — required outside dev), and every name under MG_BASE_DOMAIN refused — and the narrow route to the
// platform-hosted IdP auth.<domain> (only that host, only routePaths, dialling MG_IDP_PLATFORM_ADDR).
func idpClients(cfg config.Config, routePaths []string) (*idp.Hardened, *idp.PlatformRoute, error) {
	h, err := idp.NewHardened(idp.HardenedConfig{Deny: cfg.EgressDeny, DenyDomains: []string{cfg.BaseDomain}})
	if err != nil {
		return nil, nil, err
	}
	r, err := idp.NewPlatformRoute(idp.PlatformRouteConfig{Host: cfg.IdPPlatformHost(), Address: cfg.IdPPlatformAddr,
		Paths: routePaths})
	if err != nil {
		return nil, nil, err
	}
	return h, r, nil
}

// edgeOnly lets only the trusted proxies (MG_TRUSTED_PROXIES: the edge's address) talk to the public listener — G2
// wiring hazard 5: the api is a member of mg-edge, mg-data, mg-admin, mg-obs and mg-egress, and any other member of those
// networks could otherwise call it directly (no TLS, no CrowdSec, no edge headers). Other peers get 403 forbidden as
// problem+json; the internal listener (/healthz, /readyz, /metrics) is a separate server and not concerned. Without
// trusted proxies (dev) every peer is accepted.
func edgeOnly(trusted []netip.Prefix, next http.Handler) http.Handler {
	if len(trusted) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if peer, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
			a := peer.Addr().Unmap()
			for _, p := range trusted {
				if p.Contains(a) {
					next.ServeHTTP(w, r)
					return
				}
			}
		}
		w.Header().Set("Content-Type", "application/problem+json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"type":"about:blank","title":"Forbidden","status":403,"code":"forbidden",`+
			`"detail":"The API is served through the edge only."}`+"\n")
	})
}

// loadKeyring reads a keyring once at start-up and logs its public identification (name, active kek_id, key check
// value — P2-T04a: the KCV is public and lets the operator match the running keyring with the ceremony's record).
func loadKeyring(log *slog.Logger, name, dir string) (*secrets.Keyring, error) {
	kr, err := secrets.LoadKeyring(name, dir)
	if err != nil {
		return nil, err
	}
	log.Info("keyring loaded", "keyring", kr.Name(), "active", kr.Active(), "kcv", kr.KCV(kr.Active()),
		"versions", len(kr.IDs()))
	return kr, nil
}

// probes are the readiness checks of §16.2 shared by api and worker: PostgreSQL (both pools), the SecretStore (one DEK
// of each scope and KEK unwrapped — "giải mã thử") and the edge admin listener (reachable, our token accepted).
func (d *deps) probes() map[string]httpx.Probe {
	return map[string]httpx.Probe{
		"postgres":    d.st.Ping,
		"secretstore": d.secrets.Probe,
		"edge_admin":  edgeAdminProbe(d.cfg.Edge.URL, d.cfg.Edge.TokenFile),
	}
}

var edgeTokenRE = regexp.MustCompile(`^[A-Za-z0-9]{40}$`)

// errEdgeToken: the edge refused the token (403) — the copy in mg-sec-app differs from the edge's (rotation half done).
var errEdgeToken = errors.New("edge admin listener: token refused")

// edgeAdminProbe asks the edge admin listener for GET /version without selecting an instance (§14.6): the listener
// answers 404 once the token is accepted (no X-MG-Instance ⇒ no route), 403 when it is not. The token file is read
// at every probe, like the Locator does, so a rotated token is picked up; it is never logged.
func edgeAdminProbe(base, tokenFile string) httpx.Probe {
	client := &http.Client{
		Transport:     &http.Transport{Proxy: nil, DisableKeepAlives: true, ResponseHeaderTimeout: 2 * time.Second},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       2500 * time.Millisecond,
	}
	return func(ctx context.Context) error {
		b, err := os.ReadFile(tokenFile) //nolint:gosec // deployment configuration
		if err != nil {
			return fmt.Errorf("edge admin listener: read the token file %s: %w", tokenFile, errors.Unwrap(err))
		}
		token := strings.TrimSpace(string(b))
		clear(b)
		if !edgeTokenRE.MatchString(token) {
			return fmt.Errorf("edge admin listener: the token file %s does not hold a token", tokenFile)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(base, "/")+"/version", nil)
		if err != nil {
			return err
		}
		req.Header.Set("X-MG-Token", token)
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("edge admin listener: %w", err)
		}
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusNotFound:
			return nil
		case http.StatusForbidden:
			return errEdgeToken
		}
		return fmt.Errorf("edge admin listener: unexpected HTTP %d", resp.StatusCode)
	}
}

// Security event of a SecretStore integrity failure (P2-T08 open item, G2 wiring hazard 10).
const (
	integrityKind   = "secrets.integrity_failure"
	integrityWindow = time.Hour
	integrityWrite  = 5 * time.Second
)

// integrityReporter records every operation the SecretStore refused with ErrIntegrity as a platform security event
// (security_events, severity high, deduplicated per process/operation/reference for an hour) — written in a
// transaction of its own after the SecretStore's transaction ended (secrets.Options.OnIntegrity). The reference names
// the secret, never its value; a failure to record is logged at ERROR.
func integrityReporter(st *store.Store, service string, log *slog.Logger) func(context.Context, secrets.IntegrityFailure) {
	return func(ctx context.Context, f secrets.IntegrityFailure) {
		ref := f.Ref.String()
		if f.Ref.Name == "" {
			ref = "" // probe: a DEK of the process, no reference
		}
		ev := audit.SecurityEvent{Kind: integrityKind, Severity: audit.SeverityHigh, Source: "secrets",
			Details:   audit.Details{"operation": f.Op, "ref": ref, "process": service},
			DedupeKey: integrityKind + ":" + service + ":" + f.Op + ":" + ref, DedupeWindow: integrityWindow}
		wctx, cancel := context.WithTimeout(ctx, integrityWrite)
		defer cancel()
		err := st.WithPlatformTx(wctx, func(q *sqlcdb.Queries) error {
			_, err := audit.RecordSecurityEvent(wctx, q, ev)
			return err
		})
		if err != nil {
			log.ErrorContext(ctx, "secrets: integrity failure NOT recorded as a security event", "operation", f.Op,
				"ref", ref, "error", err.Error())
			return
		}
		log.ErrorContext(ctx, "secrets: integrity failure recorded as a security event", "operation", f.Op, "ref", ref)
	}
}

// idpReader is the part of the Tenant Registry the client-secret source reads (*tenants.Service).
type idpReader interface {
	GetIdP(ctx context.Context, id uuid.UUID) (tenants.IdP, error)
}

// secretReader is the part of the SecretStore it reads (*secrets.Store).
type secretReader interface {
	Get(ctx context.Context, ref secrets.Ref) (secrets.Plaintext, error)
}

// errClientSecretRef: a client_secret_ref that is not the reference of its own IdP's client secret.
var errClientSecretRef = errors.New("identity provider client secret: the reference is not bound to its identity provider")

// clientSecrets resolves identity_providers.client_secret_ref (identity.ClientSecretSource) — never as a pass-through
// of the SecretStore (G2 wiring hazard 4): the reference must be the client secret of one identity provider and bound
// to it before the SecretStore is asked:
//   - its name is the client secret of an IdP under either name the platform writes (G2 round 2, I-7):
//     idp.ClientSecretName(<idp id>) = idp.<id>.client (the keycloak/external drivers) or
//     idp.AdminClientSecretName(<idp id>) = idp-client-secret.<id> (`meshguard admin set-idp-client-secret`) — a
//     reference to any other secret (an API key, the provisioning identity…) is refused;
//   - that identity provider exists and records exactly this reference as its client_secret_ref;
//   - the reference is that IdP's own (idp.Registration.OwnClientSecretRef — the check of the callback and the
//     drivers): owner = the IdP's tenant (a tenant IdP) or the platform (a platform IdP), name = one of its two names.
//
// The identity module reads the reference from the row of the IdP it is completing a login with and checks it with
// the IdP in hand (G2 F3); this source checks it again from the registry side (defence in depth).
func clientSecrets(s secretReader, idps idpReader) identity.ClientSecretSource {
	return identity.ClientSecretFunc(func(ctx context.Context, raw string) (string, error) {
		ref, err := secrets.ParseRef(raw)
		if err != nil {
			return "", err
		}
		idpID, ok := clientSecretIdP(ref.Name)
		if !ok {
			return "", fmt.Errorf("%w: not a client secret name", errClientSecretRef)
		}
		p, err := idps.GetIdP(ctx, idpID)
		if err != nil {
			return "", fmt.Errorf("%w: identity provider %s: %w", errClientSecretRef, idpID, err)
		}
		if p.ClientSecretRef != raw {
			return "", fmt.Errorf("%w: identity provider %s records another reference", errClientSecretRef, idpID)
		}
		reg := idp.Registration{IdPID: p.ID, Scope: idp.Scope(p.Scope), Driver: p.Driver, ClientSecretRef: raw}
		switch {
		case p.Scope == tenants.IdPScopeTenant && p.TenantID == nil, p.Scope != tenants.IdPScopeTenant && p.TenantID != nil:
			return "", fmt.Errorf("%w: identity provider %s: scope and tenant disagree", errClientSecretRef, idpID)
		case p.TenantID != nil:
			reg.TenantID = *p.TenantID
		}
		if _, err := reg.OwnClientSecretRef("runner.clientSecrets"); err != nil {
			return "", fmt.Errorf("%w: owner of the reference is not the identity provider's: %w", errClientSecretRef, err)
		}
		v, err := s.Get(ctx, ref)
		if err != nil {
			return "", err
		}
		defer v.Wipe()
		return string(v.Bytes()), nil
	})
}

// clientSecretIdP returns the IdP id of a client-secret name: idp.<id>.client or idp-client-secret.<id>, with the
// canonical form of the id (anything else is not a client secret name).
func clientSecretIdP(name string) (uuid.UUID, bool) {
	var raw string
	switch {
	case strings.HasPrefix(name, "idp-client-secret."):
		raw = strings.TrimPrefix(name, "idp-client-secret.")
	case strings.HasPrefix(name, "idp.") && strings.HasSuffix(name, ".client"):
		raw = strings.TrimSuffix(strings.TrimPrefix(name, "idp."), ".client")
	default:
		return uuid.Nil, false
	}
	id, err := uuid.Parse(raw)
	if err != nil || id == uuid.Nil || (idp.ClientSecretName(id) != name && idp.AdminClientSecretName(id) != name) {
		return uuid.Nil, false
	}
	return id, true
}

// newDevices builds the device inventory over the Headscale registry (P2-T13) on the store of the process; tags is the
// tenant's tag catalog of PUT /devices/{id}/tags (P4-T15 — the api's; nil in the worker, which never tags a device).
func (d *deps) newDevices(reg prometheus.Registerer, tags devices.TagCatalog) (*devices.Service, error) {
	return devices.New(d.st, devices.Config{Registry: d.headscale, Logger: d.log, Registerer: reg, Tags: tags})
}

// deviceCounter gives monitoring the device figures of a tenant through the devices module (§13.6: monitoring never
// reads the devices' tables; devices.Summary has the same fields as monitoring.DeviceCounts — checked by the compiler).
func deviceCounter(dev *devices.Service) monitoring.DeviceCounter {
	return monitoring.DeviceCounterFunc(func(ctx context.Context, t uuid.UUID) (monitoring.DeviceCounts, error) {
		s, err := dev.Summary(ctx, t)
		return monitoring.DeviceCounts(s), err
	})
}
