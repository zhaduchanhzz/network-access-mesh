package provisioning

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale/locator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// APIKeySecretName is the SecretStore name of an instance API key: mgsec://<tenant_id>/headscale-api-key#<version>.
const APIKeySecretName = "headscale-api-key" //nolint:gosec // G101: the name of a SecretStore entry, not a credential

// DefaultMinKeyTTL: a new API key must live longer than the expiry warning of §16.3 (14 days) — the runbook creates it
// with -e 2160h (90 days, §11.3 step 13).
const DefaultMinKeyTTL = 14 * 24 * time.Hour

// apiKeyRE is the full Headscale API key (hscontrol/db/api_key.go of 0.29.7): hskey-api-<12>-<64>, URL-safe base64.
var apiKeyRE = regexp.MustCompile(`^hskey-api-[A-Za-z0-9_-]{12}-[A-Za-z0-9_-]{64}$`)

// ValidAPIKey reports whether s has the shape of a Headscale API key (RT-12). It never says why, so a caller's error
// cannot echo part of the value.
func ValidAPIKey(s string) bool { return apiKeyRE.MatchString(s) }

// SecretStore is the part of the SecretStore the admin commands use (*secrets.Store implements it).
type SecretStore interface {
	Put(ctx context.Context, ref secrets.Ref, value []byte, opts ...secrets.Option) error
	Rotate(ctx context.Context, ref secrets.Ref, value []byte, opts ...secrets.Option) (secrets.Ref, error)
	Destroy(ctx context.Context, ref secrets.Ref) error
	Latest(ctx context.Context, tenant uuid.UUID, name string) (secrets.Ref, error)
}

// Adopter runs `meshguard admin adopt-instance`.
type Adopter struct {
	Tenants   *tenants.Service
	Platform  *platform.Service
	Secrets   SecretStore
	Locator   *locator.Locator  // the production locator: the verification goes through Registry.ForTenant with it
	Headscale headscale.Options // adapter options (timeout, HTTP client, logger) of every registry built here
	Audit     Auditor           // nil: LogAuditor{Log}
	Log       *slog.Logger      // nil discards
	Now       func() time.Time  // nil: time.Now
	MinKeyTTL time.Duration     // 0: DefaultMinKeyTTL
}

// AdoptRequest is one adoption.
type AdoptRequest struct {
	Meta       Meta
	APIKey     headscale.Secret   // the NEW key, read from stdin by the command — never an argument, env or file
	HostName   string             // hosts.name of the host running the instance
	NewHost    *platform.HostSpec // region and pools when the host is not registered yet; checked when it is
	TenantName string             // display name of a new tenant ("" = the slug)
	BaseDomain string             // MG_BASE_DOMAIN: control hostname, server URL, MagicDNS domain
	IdP        tenants.IdPSpec    // the tenant's identity provider (KeycloakRealmIdP)
}

// AdoptResult describes what an adoption did — no secret: references, public key prefixes and counts only.
type AdoptResult struct {
	TenantID         uuid.UUID
	InstanceID       uuid.UUID
	Slug             string
	HostName         string
	HostCreated      bool
	TenantCreated    bool
	InstanceCreated  bool
	IdPCreated       bool
	RuntimeUpdated   bool
	Activation       tenants.Activation
	HeadscaleVersion string
	KeyPrefix        string
	KeyExpiresAt     time.Time
	SecretRef        string   // reference of the stored key
	PreviousRef      string   // reference the instance held before ("" = none)
	ExpiredPrefixes  []string // other keys of the instance expired by this run
	ValidKeys        int      // keys of the instance still valid afterwards (1: the new key)
	DestroyedRefs    []string // older secret versions erased (their keys are expired)
}

// Errors of an adoption. Each wraps one of these (errors.Is) with a message naming the cause — never a credential.
var (
	// ErrRefused: the input or the registry forbids the adoption; nothing was written.
	ErrRefused = errors.New("adoption refused")
	// ErrKeyCheck: the new API key failed the pre-flight through the edge admin listener; nothing was written.
	ErrKeyCheck = errors.New("API key check failed")
	// ErrVerify: the key was stored but the verification through Registry.ForTenant failed; the registry and the
	// SecretStore were put back as they were (the new secret version is destroyed).
	ErrVerify = errors.New("verification through Registry.ForTenant failed")
	// ErrExpire: the new key works and is registered, but some other key of the instance could not be expired; the
	// tenant/instance were NOT activated — run the command again with another new key.
	ErrExpire = errors.New("expiring the other API keys failed")
)

// Adopt registers a hand-built instance and hands its management over to the platform with a new API key:
//
//  1. checks the input (meta/instance.json, key shape) and the registry (CheckAdoption, host) — conflicts refuse;
//  2. pre-flight: lists the API keys of the instance THROUGH THE EDGE with the new key (slug of the meta, edge token
//     and URL of the configuration) — the key must work on that instance, be listed and live longer than MinKeyTTL;
//  3. records "<adopt>.requested", then registers host, tenant (provisioning), instance (starting) and IdP;
//  4. stores the key in the SecretStore (version 1, or the next version) and points the instance at it;
//  5. verifies through Registry.ForTenant with the production locator (registry + SecretStore + edge) — failure puts
//     everything back;
//  6. expires every other currently valid API key of the instance and lists again: only the new key may be valid;
//  7. activates the instance (running) and the tenant (active), erases older secret versions, records the outcome.
//
// Running it again (with another new key) is idempotent for the registry and rotates the key.
func (a *Adopter) Adopt(ctx context.Context, req AdoptRequest) (res AdoptResult, err error) {
	a.defaults()
	m := req.Meta
	res = AdoptResult{TenantID: m.TenantID, InstanceID: m.InstanceID, Slug: m.Slug, HostName: req.HostName}
	key := req.APIKey.Reveal()
	if !ValidAPIKey(key) {
		return res, fmt.Errorf("%w: stdin does not hold a Headscale API key (hskey-api-<prefix>-<secret>)", ErrRefused)
	}
	res.KeyPrefix = headscale.APIKeyPrefix(req.APIKey)

	// 1. registry pre-checks (read only)
	host, hostExists, err := a.host(ctx, req)
	if err != nil {
		return res, err
	}
	if !host.Contains(m.RunUID, m.NetCIDR) {
		return res, fmt.Errorf("%w: run_uid %d or net_cidr %s is outside the pools of host %s", ErrRefused, m.RunUID,
			m.NetCIDR, req.HostName)
	}
	adoption := a.adoption(req, host)
	if _, err := a.Tenants.CheckAdoption(ctx, adoption); err != nil {
		return res, refusal(err)
	}

	// 2. pre-flight of the new key through the edge admin listener — nothing written yet
	cand, err := a.Locator.Candidate(m.InstanceID, m.Slug, req.APIKey)
	if err != nil {
		return res, fmt.Errorf("%w: %s", ErrRefused, err.Error())
	}
	pre := headscale.NewRegistry(headscale.StaticLocator{m.TenantID: cand}, a.Headscale)
	inst, err := pre.ForTenant(ctx, m.TenantID)
	if err != nil {
		return res, keyCheckError(m.Slug, err)
	}
	keys, err := inst.ListAPIKeys(ctx)
	if err != nil {
		return res, keyCheckError(m.Slug, err)
	}
	now := a.Now()
	mine, ok := findKey(keys, res.KeyPrefix)
	switch {
	case !ok:
		return res, fmt.Errorf("%w: the instance accepted the key but does not list prefix %s", ErrKeyCheck, res.KeyPrefix)
	case mine.Expiration.IsZero() || mine.Expiration.Sub(now) < a.MinKeyTTL:
		return res, fmt.Errorf("%w: the new key expires in less than %s — create it with an explicit -e (e.g. 2160h)",
			ErrKeyCheck, a.MinKeyTTL)
	}
	res.KeyExpiresAt = mine.Expiration.UTC()
	v, ok := pre.CachedVersion(m.TenantID)
	if !ok {
		return res, fmt.Errorf("%w: the instance version was not recorded", ErrKeyCheck)
	}
	res.HeadscaleVersion = v.Raw
	adoption.Instance.HeadscaleVersion = v.Raw

	// 3. audit, then the registry
	op := uuid.New()
	tenantID := m.TenantID
	base := AuditEvent{Action: ActionAdoptInstance, OperationID: &op, TenantID: &tenantID, ResourceType: "instance",
		ResourceID: m.InstanceID.String()}
	if err := a.Audit.Record(ctx, with(base, SuffixRequested, OutcomeSuccess, map[string]any{
		"slug": m.Slug, "host": req.HostName, "key_prefix": res.KeyPrefix, "headscale_version": v.Raw})); err != nil {
		return res, fmt.Errorf("record the audit event before any change: %w", err)
	}
	defer func() {
		ev := with(base, SuffixSucceeded, OutcomeSuccess, res.details())
		if err != nil {
			ev = with(base, SuffixFailed, OutcomeFailure, map[string]any{"error": failureCode(err)})
		}
		if aerr := a.Audit.Record(context.WithoutCancel(ctx), ev); aerr != nil {
			a.Log.Error("adopt-instance: audit event not recorded", "action", ev.Action, "error", aerr.Error())
		}
	}()
	if !hostExists {
		h, existed, err := a.Platform.EnsureHost(ctx, *req.NewHost)
		if err != nil {
			return res, refusal(err)
		}
		res.HostCreated = !existed
		adoption.Instance.HostID = h.ID
	}
	state, err := a.Tenants.Register(ctx, adoption)
	if err != nil {
		return res, refusal(err)
	}
	res.TenantCreated, res.InstanceCreated, res.IdPCreated = !state.TenantExists, !state.InstanceExists, !state.IdPExists
	res.RuntimeUpdated = state.RuntimeUpdated

	// 4. the SecretStore, then the instance row
	ref, err := a.storeKey(ctx, m.TenantID, key)
	if err != nil {
		return res, fmt.Errorf("store the API key in the SecretStore: %w", err)
	}
	res.SecretRef = ref.String()
	exp := res.KeyExpiresAt
	prev, err := a.Tenants.SetInstanceAPIKey(ctx, m.TenantID, m.InstanceID,
		tenants.APIKey{Ref: ref.String(), Prefix: res.KeyPrefix, ExpiresAt: &exp})
	if err != nil {
		a.destroy(ctx, ref)
		return res, fmt.Errorf("record the API key reference: %w", err)
	}
	res.PreviousRef = prev.Ref

	// 5. verification through the production path
	reg := headscale.NewRegistry(a.Locator, a.Headscale)
	live, keys, err := verify(ctx, reg, m.TenantID, res.KeyPrefix)
	if err != nil {
		if _, rerr := a.Tenants.SetInstanceAPIKey(context.WithoutCancel(ctx), m.TenantID, m.InstanceID, prev); rerr != nil {
			a.Log.Error("adopt-instance: could not restore the previous API key reference", "instance_id",
				m.InstanceID.String(), "error", rerr.Error())
		}
		a.destroy(context.WithoutCancel(ctx), ref)
		return res, fmt.Errorf("%w: %s", ErrVerify, err.Error())
	}

	// 6. expire every other valid key, then list again
	now = a.Now()
	var failed []string
	for _, k := range keys {
		if k.Prefix == res.KeyPrefix || !stillValid(k, now) {
			continue
		}
		if k.Prefix == "" {
			failed = append(failed, fmt.Sprintf("key id %d (unreadable prefix)", k.ID))
			continue
		}
		if err := live.ExpireAPIKey(ctx, k.Prefix); err != nil {
			failed = append(failed, k.Prefix+" ("+errorKind(err)+")")
			continue
		}
		res.ExpiredPrefixes = append(res.ExpiredPrefixes, k.Prefix)
	}
	after, err := live.ListAPIKeys(ctx)
	if err != nil {
		return res, fmt.Errorf("%w: list after expiring: %s", ErrExpire, errorKind(err))
	}
	now = a.Now()
	var stillLive []string
	for _, k := range after {
		if stillValid(k, now) {
			res.ValidKeys++
			if k.Prefix != res.KeyPrefix {
				stillLive = append(stillLive, k.Prefix)
			}
		}
	}
	if len(failed) > 0 || len(stillLive) > 0 {
		return res, fmt.Errorf("%w: not expired: %s", ErrExpire, strings.Join(append(failed, stillLive...), ", "))
	}

	// 7. activate, erase older secret versions
	if res.Activation, err = a.Tenants.Activate(ctx, m.TenantID, m.InstanceID); err != nil {
		return res, fmt.Errorf("activate tenant and instance: %w", err)
	}
	res.DestroyedRefs = destroyOlder(ctx, a.Secrets, a.Log, ref, prev.Ref)
	return res, nil
}

func (a *Adopter) defaults() {
	if a.Log == nil {
		a.Log = slog.New(slog.DiscardHandler)
	}
	if a.Audit == nil {
		a.Audit = LogAuditor{Logger: a.Log}
	}
	if a.Now == nil {
		a.Now = time.Now
	}
	if a.MinKeyTTL <= 0 {
		a.MinKeyTTL = DefaultMinKeyTTL
	}
}

// host resolves the host of the request: a registered host (checked against NewHost when given) or the
// specification of a new one (validated; inserted only after the pre-flight).
func (a *Adopter) host(ctx context.Context, req AdoptRequest) (platform.Host, bool, error) {
	if req.NewHost != nil && req.NewHost.Name != req.HostName {
		return platform.Host{}, false, fmt.Errorf("%w: host specification of another host", ErrRefused)
	}
	if req.NewHost != nil {
		h, exists, err := a.Platform.CheckHost(ctx, *req.NewHost)
		if err != nil {
			return h, exists, refusal(err)
		}
		if exists {
			return h, true, nil
		}
		s := *req.NewHost
		return platform.Host{Name: s.Name, Region: s.Region, RunUIDFirst: s.RunUIDFirst, RunUIDLast: s.RunUIDLast,
			TenantNetPool: s.TenantNetPool}, false, nil
	}
	h, err := a.Platform.FindHost(ctx, req.HostName)
	if errors.Is(err, platform.ErrNotFound) {
		return h, false, fmt.Errorf("%w: host %s is not registered — give its region, run_uid range and tenant network pool",
			ErrRefused, req.HostName)
	}
	return h, err == nil, err
}

// adoption builds the registry record of the request (host.ID = uuid.Nil while the host is not registered). The
// addresses follow tools/render_instance.py and tenant-deploy.sh: <slug>.mesh.<domain>, <slug>.tail.<domain>, the
// edge proxies to hs-<slug>:8080, data under /opt/meshguard/tenants/<instance_id>/data (§14.2).
func (a *Adopter) adoption(req AdoptRequest, host platform.Host) tenants.Adoption {
	m := req.Meta
	name := req.TenantName
	if name == "" {
		name = m.Slug
	}
	control := tenants.ControlHostname(m.Slug, req.BaseDomain)
	return tenants.Adoption{
		TenantID: m.TenantID, Slug: m.Slug, Name: name, Region: host.Region, IdP: req.IdP,
		Instance: tenants.InstanceSpec{
			ID: m.InstanceID, HostID: host.ID, HeadscaleVersion: "unverified", ImageDigest: m.ImageDigest,
			ControlHostname: control, ServerURL: "https://" + control,
			BaseDomain: tenants.MagicDNSDomain(m.Slug, req.BaseDomain), InternalAddress: "hs-" + m.Slug + ":8080",
			RunUID: m.RunUID, NetCIDR: m.NetCIDR, DataPath: "/opt/meshguard/tenants/" + m.InstanceID.String() + "/data",
		},
	}
}

// storeKey stores the key as version 1, or as the version after the latest one (also after a run that stored a
// version and died before recording it).
func (a *Adopter) storeKey(ctx context.Context, tenantID uuid.UUID, key string) (secrets.Ref, error) {
	value := []byte(key)
	defer clear(value)
	latest, err := a.Secrets.Latest(ctx, tenantID, APIKeySecretName)
	if errors.Is(err, secrets.ErrNotFound) {
		ref := secrets.TenantRef(tenantID, APIKeySecretName, 1)
		return ref, a.Secrets.Put(ctx, ref, value)
	}
	if err != nil {
		return secrets.Ref{}, err
	}
	return a.Secrets.Rotate(ctx, latest, value)
}

func (a *Adopter) destroy(ctx context.Context, ref secrets.Ref) {
	if err := a.Secrets.Destroy(ctx, ref); err != nil {
		a.Log.Error("adopt-instance: could not destroy a secret version", "ref", ref.String(), "error", err.Error())
	}
}

// destroyOlder erases the secret versions below cur, from the version recorded before (prevRef) or from 1: the
// credentials they hold are replaced (and, for API keys, expired). Versions below prevRef were erased by earlier runs;
// the range also covers versions stored by a run that died before recording them.
func destroyOlder(ctx context.Context, st SecretStore, log *slog.Logger, cur secrets.Ref, prevRef string) []string {
	from := int32(1)
	if prev, err := secrets.ParseRef(prevRef); err == nil && prev.Tenant == cur.Tenant && prev.Name == cur.Name &&
		prev.Version < cur.Version {
		from = prev.Version
	}
	var out []string
	for v := from; v < cur.Version; v++ {
		r := secrets.Ref{Tenant: cur.Tenant, Name: cur.Name, Version: v}
		if err := st.Destroy(ctx, r); err != nil {
			if !errors.Is(err, secrets.ErrNotFound) {
				log.Warn("could not destroy an older secret version", "ref", r.String(), "error", err.Error())
			}
			continue
		}
		out = append(out, r.String())
	}
	return out
}

// verify lists the API keys through Registry.ForTenant (registry + SecretStore + edge) and checks the new key is
// among them.
func verify(ctx context.Context, reg headscale.Registry, tenantID uuid.UUID, prefix string) (headscale.Instance,
	[]headscale.APIKey, error) {
	inst, err := reg.ForTenant(ctx, tenantID)
	if err != nil {
		return nil, nil, fmt.Errorf("ForTenant: %s", errorKind(err))
	}
	keys, err := inst.ListAPIKeys(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("ListAPIKeys: %s", errorKind(err))
	}
	if _, ok := findKey(keys, prefix); !ok {
		return nil, nil, fmt.Errorf("the instance reached through the registry does not list prefix %s", prefix)
	}
	return inst, keys, nil
}

func findKey(keys []headscale.APIKey, prefix string) (headscale.APIKey, bool) {
	i := slices.IndexFunc(keys, func(k headscale.APIKey) bool { return k.Prefix == prefix })
	if i < 0 {
		return headscale.APIKey{}, false
	}
	return keys[i], true
}

// stillValid follows Headscale's rule (hscontrol/db/api_key.go): a key without expiration never expires, a key whose
// expiration is in the past is refused.
func stillValid(k headscale.APIKey, now time.Time) bool {
	return k.Expiration.IsZero() || k.Expiration.After(now)
}

// keyCheckError explains a failed pre-flight without any upstream text.
func keyCheckError(slug string, err error) error {
	var he *headscale.Error
	if errors.As(err, &he) {
		switch he.Kind {
		case headscale.KindAPIKeyRejected:
			return fmt.Errorf("%w: instance hs-%s rejected the key — was it created on this instance (docker exec mg-hs-%s …)?",
				ErrKeyCheck, slug, slug)
		case headscale.KindEdgeRejected:
			return fmt.Errorf("%w: the edge admin listener refused the token (MG_EDGE_ADMIN_TOKEN_FILE)", ErrKeyCheck)
		case headscale.KindUnsupportedVersion:
			return fmt.Errorf("%w: the instance runs an unsupported Headscale version (supported: %s)", ErrKeyCheck,
				headscale.SupportedVersions())
		case headscale.KindUnavailable, headscale.KindCircuitOpen:
			return fmt.Errorf("%w: the edge admin listener cannot reach hs-%s (instance down, edge not attached to its network, or wrong MG_EDGE_ADMIN_URL)",
				ErrKeyCheck, slug)
		}
	}
	return fmt.Errorf("%w: %s", ErrKeyCheck, errorKind(err))
}

// errorKind is a short, credential-free description of an adapter error.
func errorKind(err error) string {
	var he *headscale.Error
	if errors.As(err, &he) {
		s := string(he.Op) + ": " + string(he.Kind)
		if he.Status != 0 {
			s += fmt.Sprintf(" (HTTP %d)", he.Status)
		}
		return s
	}
	if errors.Is(err, headscale.ErrNoInstance) {
		return "no reachable instance in the registry"
	}
	return "internal error"
}

// refusal marks registry contradictions as ErrRefused (nothing written) and passes other errors through.
func refusal(err error) error {
	if errors.Is(err, tenants.ErrConflict) || errors.Is(err, tenants.ErrInvalid) || errors.Is(err, platform.ErrConflict) ||
		errors.Is(err, platform.ErrInvalid) {
		return fmt.Errorf("%w: %s", ErrRefused, err.Error())
	}
	return err
}

// failureCode is the stable code of a failed adoption in its audit event.
func failureCode(err error) string {
	for _, c := range []struct {
		err  error
		code string
	}{{ErrRefused, "refused"}, {ErrKeyCheck, "key_check_failed"}, {ErrVerify, "verify_failed"}, {ErrExpire, "expire_failed"}} {
		if errors.Is(err, c.err) {
			return c.code
		}
	}
	return "internal_error"
}

func with(ev AuditEvent, suffix, outcome string, details map[string]any) AuditEvent {
	ev.Action += suffix
	ev.Outcome = outcome
	ev.Details = details
	return ev
}

func (r AdoptResult) details() map[string]any {
	d := map[string]any{"slug": r.Slug, "host": r.HostName, "key_prefix": r.KeyPrefix,
		"headscale_version": r.HeadscaleVersion, "expired_keys": len(r.ExpiredPrefixes),
		"tenant_created": r.TenantCreated, "instance_created": r.InstanceCreated, "idp_created": r.IdPCreated}
	if ref, err := secrets.ParseRef(r.SecretRef); err == nil {
		d["ref_version"] = ref.Version
	}
	return d
}
