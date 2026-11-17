package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// CreateRequest is the body of POST /platform/tenants (TenantCreate, §13.3).
type CreateRequest struct {
	Slug             string
	Name             string
	PlanKey          string
	DeploymentRegion string
	OwnerEmail       string
	IdP              IdPRequest
	Settings         json.RawMessage // TenantSettings, a JSON object; nil = none
}

// IdPRequest is TenantCreate.identity_provider.
type IdPRequest struct {
	Driver string // keycloak (realm of the platform-hosted IdP, named by the slug) or external
	// External only: the tenant's issuer and client. ClientSecret is write-only: stored in the SecretStore before the
	// job is enqueued; the job, the idempotency record and the audit carry only references.
	Issuer              string
	ClientID            string
	ClientSecret        []byte
	RequiredClaims      map[string]any
	AllowedEmailDomains []string
}

// Idempotency is the Idempotency-Key of the request and the SHA-256 of the request (jobs.RequestHash — computed over
// the body WITHOUT the client secret, see RequestBodyForHash).
type Idempotency struct {
	Key  string
	Hash []byte
}

// Created is the outcome of a creation.
type Created struct {
	Job      jobs.Job
	TenantID uuid.UUID
	Replayed bool // the stored answer of an earlier request with the same Idempotency-Key
}

// CreateError is a refusal of steps 1–2: Kind is ErrInvalid (422), ErrConflict (409) or an idempotency error;
// Reason a stable code, Field the offending field (422).
type CreateError struct {
	Kind       error
	Reason     string
	Field      string
	RetryAfter time.Duration // ErrIdempotencyInProgress
}

func (e *CreateError) Error() string {
	return "orchestrator: create tenant: " + e.Kind.Error() + " (" + e.Reason + ")"
}

func (e *CreateError) Unwrap() error { return e.Kind }

// Refusal kinds of the API side.
var (
	ErrInvalid               = errors.New("orchestrator: invalid request")
	ErrConflict              = errors.New("orchestrator: conflict with the registry")
	ErrIdempotencyInProgress = errors.New("orchestrator: a request with this Idempotency-Key is in progress")
	ErrIdempotencyKeyReuse   = errors.New("orchestrator: Idempotency-Key used for another request")
)

func invalid(field, reason string) error {
	return &CreateError{Kind: ErrInvalid, Reason: reason, Field: field}
}
func conflict(reason string) error { return &CreateError{Kind: ErrConflict, Reason: reason} }

// CreatorConfig are the collaborators of a Creator (the api process).
type CreatorConfig struct {
	Store *store.Store
	// Secrets stores the write-only client secret of an external IdP (a pending platform secret with an expiry).
	Secrets interface {
		Put(ctx context.Context, ref secrets.Ref, value []byte, opts ...secrets.Option) error
		Destroy(ctx context.Context, ref secrets.Ref) error
	}
	// Quota is the pre-check of step 1 (no lock); QuotaTx the locked check inside the registry.create transaction
	// (usage.Checker and usage.TenantCreationTx, wired in apps/* — orchestrator does not import usage, §13.6).
	Quota   tenants.QuotaChecker
	QuotaTx func(ctx context.Context, q *sqlcdb.Queries) (tenants.QuotaStatus, error)
	// BaseDomain (MG_BASE_DOMAIN): <slug>.mesh.<domain>; no slug may equal one of its labels (the agent refuses it).
	BaseDomain string
	Now        func() time.Time
}

// Creator runs steps 1 (validate) and 2 (registry.create) of tenant.provision in the API.
type Creator struct {
	cfg CreatorConfig
}

// NewCreator returns the API side of tenant creation.
func NewCreator(cfg CreatorConfig) (*Creator, error) {
	if cfg.Store == nil || cfg.Quota == nil || cfg.QuotaTx == nil || cfg.BaseDomain == "" {
		return nil, errors.New("orchestrator: creator needs a store, the quota checks and the base domain")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Creator{cfg: cfg}, nil
}

// CreateOperation is the operationId of POST /platform/tenants (Idempotency-Key scope — §13.1).
const CreateOperation = "createPlatformTenant"

// PendingSecretTTL bounds the life of an external IdP's pending client secret (step 6 moves it much sooner).
const PendingSecretTTL = 24 * time.Hour

const idempotencyLock = 30 * time.Second

// ReservedSlugs are the names that are never a tenant slug: the platform's own host labels (§15.4 — render_instance.py
// and the agent refuse them too).
var ReservedSlugs = []string{"app", "admin", "auth", "api", "www", "stun", "mesh", "tail"}

var (
	emailRE  = regexp.MustCompile(`^[^@\s]{1,64}@[^@\s]+\.[^@\s.]+$`)
	regionRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	domainRE = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
)

// validate is the pure part of step 1.
func (c *Creator) validate(req *CreateRequest) error {
	req.Slug = strings.TrimSpace(req.Slug)
	req.Name = strings.TrimSpace(req.Name)
	req.OwnerEmail = strings.TrimSpace(req.OwnerEmail)
	switch {
	case !slugRE.MatchString(req.Slug) || strings.Contains(req.Slug, "--"):
		return invalid("slug", "invalid_slug")
	case slices.Contains(ReservedSlugs, req.Slug) || slices.Contains(strings.Split(c.cfg.BaseDomain, "."), req.Slug):
		return invalid("slug", "reserved_slug")
	case len([]rune(req.Name)) < 1 || len([]rune(req.Name)) > 128:
		return invalid("name", "invalid_name")
	case req.PlanKey == "" || len(req.PlanKey) > 63:
		return invalid("plan_key", "invalid_plan")
	case req.DeploymentRegion != "" && !regionRE.MatchString(req.DeploymentRegion):
		return invalid("deployment_region", "invalid_region")
	case len(req.OwnerEmail) > 320 || !emailRE.MatchString(req.OwnerEmail):
		return invalid("owner_email", "invalid_email")
	}
	if s := bytes.TrimSpace(req.Settings); len(s) > 0 && string(s) != "null" {
		if len(s) > 8192 || s[0] != '{' || !json.Valid(s) {
			return invalid("settings", "invalid_settings")
		}
		req.Settings = s
	} else {
		req.Settings = nil
	}
	p := &req.IdP
	switch p.Driver {
	case DriverKeycloak:
		if p.Issuer != "" || p.ClientID != "" || len(p.ClientSecret) > 0 {
			return invalid("identity_provider", "keycloak_takes_no_issuer")
		}
	case DriverExternal:
		u, err := url.Parse(p.Issuer)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || len(p.Issuer) > 512 {
			return invalid("identity_provider.issuer", "invalid_issuer")
		}
		if p.ClientID == "" || len(p.ClientID) > 255 || strings.ContainsAny(p.ClientID, " \t\r\n") {
			return invalid("identity_provider.client_id", "invalid_client_id")
		}
		if len(p.ClientSecret) > 4096 {
			return invalid("identity_provider.client_secret", "invalid_client_secret")
		}
	default:
		return invalid("identity_provider.driver", "invalid_driver")
	}
	if len(p.AllowedEmailDomains) > 32 {
		return invalid("identity_provider.allowed_email_domains", "invalid_domains")
	}
	for i, d := range p.AllowedEmailDomains {
		d = strings.ToLower(strings.TrimSpace(d))
		if !domainRE.MatchString(d) {
			return invalid("identity_provider.allowed_email_domains", "invalid_domains")
		}
		p.AllowedEmailDomains[i] = d
	}
	if b, err := json.Marshal(p.RequiredClaims); err != nil || len(b) > 4096 {
		return invalid("identity_provider.required_claims", "invalid_claims")
	}
	return nil
}

// Create runs step 1 `validate` then step 2 `registry.create`: ONE platform transaction takes the tenant cap under a
// row lock, creates the tenant (`provisioning`), its subscription, the audit event platform.tenant.create.requested,
// the tenant.provision job (River job included) and the rows of steps 1–2 — all or nothing (§11.3, §13.5). With an
// Idempotency-Key a replay returns the stored answer (§13.1).
func (c *Creator) Create(ctx context.Context, actor uuid.UUID, req CreateRequest, idem *Idempotency) (Created, error) {
	if actor == uuid.Nil {
		return Created{}, errors.New("orchestrator: create tenant: no actor")
	}
	if err := c.validate(&req); err != nil {
		return Created{}, err
	}
	var key *jobs.IdempotencyKey
	if idem != nil {
		key = &jobs.IdempotencyKey{IdentityID: actor, OperationID: CreateOperation, Key: idem.Key}
		replay, err := beginIdempotent(ctx, c.cfg.Store, *key, idem.Hash)
		if err != nil {
			return Created{}, err
		}
		if replay != nil {
			if replay.TenantID == nil {
				return Created{}, errors.New("orchestrator: stored creation response unreadable")
			}
			return Created{Job: *replay, TenantID: *replay.TenantID, Replayed: true}, nil
		}
	}
	out, err := c.create(ctx, actor, req, key, idem)
	if err != nil && key != nil {
		_ = c.cfg.Store.WithPlatformTx(context.WithoutCancel(ctx), func(q *sqlcdb.Queries) error {
			return jobs.FailIdempotent(ctx, q, *key, idem.Hash)
		})
	}
	return out, err
}

func (c *Creator) create(ctx context.Context, actor uuid.UUID, req CreateRequest, key *jobs.IdempotencyKey,
	idem *Idempotency) (Created, error) {
	// Step 1 — the checks that read the registry (repeated under the database constraints in step 2).
	var plan sqlcdb.SubscriptionPlan
	if err := c.cfg.Store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		if plan, err = q.GetActivePlanByKey(ctx, req.PlanKey); errors.Is(err, store.ErrNoRows) {
			return invalid("plan_key", "unknown_plan")
		} else if err != nil {
			return err
		}
		if _, err := q.GetLiveTenantBySlug(ctx, req.Slug); err == nil {
			return conflict("slug_taken")
		} else if !errors.Is(err, store.ErrNoRows) {
			return err
		}
		held, err := q.SlugHeldByDeletedTenant(ctx, req.Slug)
		if err != nil {
			return err
		}
		if held {
			return conflict("slug_not_reusable") // objects of a deleted tenant's instance remain (§11.4)
		}
		if _, err := q.GetLiveInstanceByHostname(ctx, tenants.ControlHostname(req.Slug, c.cfg.BaseDomain)); err == nil {
			return conflict("hostname_in_use")
		} else if !errors.Is(err, store.ErrNoRows) {
			return err
		}
		return nil
	}); err != nil {
		return Created{}, err
	}
	pre, err := c.cfg.Quota.CheckTenantCreation(ctx)
	if err != nil {
		return Created{}, err // *tenants.QuotaExceededError ⇒ 403 quota_exceeded
	}

	idpID := uuid.New()
	in := Input{Slug: req.Slug, Name: req.Name, OwnerEmail: req.OwnerEmail, Settings: req.Settings,
		IdP: IdPInput{ID: idpID, Driver: req.IdP.Driver, Issuer: req.IdP.Issuer, ClientID: req.IdP.ClientID,
			RequiredClaims: req.IdP.RequiredClaims, AllowedEmailDomains: req.IdP.AllowedEmailDomains}}
	var pending *secrets.Ref
	if req.IdP.Driver == DriverExternal && len(req.IdP.ClientSecret) > 0 {
		if c.cfg.Secrets == nil {
			return Created{}, errors.New("orchestrator: no secret store for the client secret")
		}
		ref := secrets.PlatformRef(PendingClientSecretName(idpID), 1)
		if err := c.cfg.Secrets.Put(ctx, ref, req.IdP.ClientSecret, secrets.WithExpiry(c.cfg.Now().Add(PendingSecretTTL))); err != nil {
			return Created{}, fmt.Errorf("orchestrator: store the client secret: %w", err)
		}
		pending = &ref
		in.IdP.PendingSecretRef = ref.String()
	}

	// Step 2 — registry.create, one transaction with the job.
	var out Created
	err = c.cfg.Store.WithPlatformJobTx(ctx, func(tx *store.Tx) error {
		q := tx.Q
		qs, err := c.cfg.QuotaTx(ctx, q)
		if err != nil {
			return err
		}
		t, err := q.CreateTenant(ctx, sqlcdb.CreateTenantParams{Slug: req.Slug, Name: req.Name,
			Status: tenants.StatusProvisioning, DeploymentRegion: optional(req.DeploymentRegion), Settings: []byte(`{}`)})
		if err != nil {
			if store.SQLState(err) == "23505" {
				return conflict("slug_taken")
			}
			return err
		}
		if _, err := q.InsertSubscription(ctx, sqlcdb.InsertSubscriptionParams{TenantID: t.ID, PlanID: plan.ID}); err != nil {
			return err
		}
		op, err := audit.Requested(ctx, q, audit.Event{Action: ActionTenantCreate, ResourceType: "tenant",
			ResourceID: t.ID.String(), Details: audit.Details{"tenant_id": t.ID, "slug": t.Slug, "plan": plan.Key,
				"idp_driver": req.IdP.Driver, "region": req.DeploymentRegion}})
		if err != nil {
			return err
		}
		in.TenantID, in.Operation = t.ID, op
		spec := jobs.Spec{Kind: JobKind, TenantID: &t.ID, Input: in, RequestedBy: &actor,
			Resource: &jobs.Resource{Type: "tenant", ID: t.ID.String()}}
		if idem != nil {
			spec.RequestKey = idem.Key
		}
		enq, err := jobs.Enqueue(ctx, tx, spec)
		if err != nil {
			return err
		}
		tid := t.ID
		if err := jobs.EnqueueFinishedStep(ctx, tx, enq.Job.ID, &tid, StepValidate, jobs.StepSucceeded, map[string]any{
			"plan": plan.Key, "quota_used": qs.Used, "quota_limit": qs.Limit, "quota_precheck_used": pre.Used}); err != nil {
			return err
		}
		if err := jobs.EnqueueFinishedStep(ctx, tx, enq.Job.ID, &tid, StepRegistryCreate, jobs.StepSucceeded,
			map[string]any{"tenant_id": t.ID, "status": t.Status}); err != nil {
			return err
		}
		audit.HandOff(ctx, op)
		j, err := jobs.ProjectTx(ctx, q, enq.Job.ID)
		if err != nil {
			return err
		}
		out = Created{Job: j, TenantID: t.ID}
		if key == nil {
			return nil
		}
		body, err := json.Marshal(j)
		if err != nil {
			return err
		}
		return jobs.CompleteIdempotent(ctx, q, *key, idem.Hash, jobs.StoredResponse{Status: 202, Body: body,
			Resource: &jobs.Resource{Type: "job", ID: j.ID.String()}})
	})
	if err != nil {
		if pending != nil {
			if derr := c.cfg.Secrets.Destroy(context.WithoutCancel(ctx), *pending); derr != nil && !errors.Is(derr, secrets.ErrNotFound) {
				_ = derr // it expires after PendingSecretTTL and DestroyExpired erases it
			}
		}
		return Created{}, err
	}
	return out, nil
}

// RequestBodyForHash is the body hashed for the Idempotency-Key (jobs.RequestHash): the request without the
// write-only client secret — no secret, not even its hash, is stored in idempotency_keys.
func RequestBodyForHash(body map[string]any) map[string]any {
	out := make(map[string]any, len(body))
	for k, v := range body {
		out[k] = v
	}
	if p, ok := body["identity_provider"].(map[string]any); ok {
		cp := make(map[string]any, len(p))
		for k, v := range p {
			if k != "client_secret" {
				cp[k] = v
			}
		}
		out["identity_provider"] = cp
	}
	return out
}

// beginIdempotent takes the Idempotency-Key of a platform request (§13.1) in a transaction of its own: nil = proceed;
// a job = the stored answer of the same request (replay); in progress / another request ⇒ a *CreateError.
func beginIdempotent(ctx context.Context, st *store.Store, key jobs.IdempotencyKey, hash []byte) (*jobs.Job, error) {
	var replay *jobs.Job
	err := st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		d, err := jobs.BeginIdempotent(ctx, q, key, hash, idempotencyLock)
		if err != nil {
			return err
		}
		switch d.Outcome {
		case jobs.IdempotencyReplay:
			var j jobs.Job
			if d.Response == nil || json.Unmarshal(d.Response.Body, &j) != nil || j.ID == uuid.Nil {
				return errors.New("orchestrator: stored response unreadable")
			}
			replay = &j
		case jobs.IdempotencyInProgress:
			return &CreateError{Kind: ErrIdempotencyInProgress, Reason: "idempotency_in_progress", RetryAfter: d.RetryAfter}
		case jobs.IdempotencyKeyReuse:
			return &CreateError{Kind: ErrIdempotencyKeyReuse, Reason: "idempotency_key_reuse"}
		}
		return nil
	})
	return replay, err
}
