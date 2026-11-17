package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"regexp"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
)

// JobKind is the job kind of the provisioning state machine (§13.5).
const JobKind = "tenant.provision"

// The 19 steps of §11.3, in order. Steps 1–2 run in the API (Creator), 3–19 in the worker (Provisioner).
const (
	StepValidate       = "validate"
	StepRegistryCreate = "registry.create"
	StepPlacement      = "placement.allocate"
	StepDNS            = "dns.ensure"
	StepSecrets        = "secrets.generate"
	StepIdP            = "idp.ensure"
	StepStorage        = "storage.create"
	StepConfig         = "config.render"
	StepNetwork        = "network.ensure"
	StepStart          = "instance.start"
	StepWaitHealthy    = "instance.wait_healthy"
	StepPolicyBoot     = "policy.bootstrap"
	StepAPIKey         = "apikey.bootstrap"
	StepEdgeAttach     = "edge.attach"
	StepPolicyVerify   = "policy.verify"
	StepConfigure      = "tenant.configure"
	StepRelay          = "relay.assign"
	StepEdgeVerify     = "edge.verify"
	StepActivate       = "activate"
)

// Steps lists the 19 steps of §11.3 in order.
var Steps = []string{StepValidate, StepRegistryCreate, StepPlacement, StepDNS, StepSecrets, StepIdP, StepStorage,
	StepConfig, StepNetwork, StepStart, StepWaitHealthy, StepPolicyBoot, StepAPIKey, StepEdgeAttach, StepPolicyVerify,
	StepConfigure, StepRelay, StepEdgeVerify, StepActivate}

// Audit actions of the provisioning flow (x-audit-action of api/openapi.yaml).
const (
	ActionTenantCreate = "platform.tenant.create" // paired: .requested (API) → .succeeded (step 19) / .failed (rolled back)
	ActionJobRetry     = "platform.job.retry"
	ActionJobCancel    = "platform.job.cancel"
	ActionJobRollback  = "platform.job.rollback"
)

// IdP drivers accepted by TenantCreate.identity_provider.driver (§13.3).
const (
	DriverKeycloak = idp.DriverKeycloak
	DriverExternal = idp.DriverExternal
)

// IdPInput is the identity provider of the tenant in the job input: identifiers and settings, never a secret — the
// client secret of an external IdP travels as the reference of a pending platform secret the API stored (step 6 moves
// it under the tenant's DEK).
type IdPInput struct {
	ID                  uuid.UUID      `json:"id"` // identity_providers.id, chosen by the API (redirect URI)
	Driver              string         `json:"driver"`
	Issuer              string         `json:"issuer,omitempty"`    // external only
	ClientID            string         `json:"client_id,omitempty"` // external only
	PendingSecretRef    string         `json:"pending_secret_ref,omitempty"`
	RequiredClaims      map[string]any `json:"required_claims,omitempty"`
	AllowedEmailDomains []string       `json:"allowed_email_domains,omitempty"`
}

// Input is the input of a tenant.provision job.
type Input struct {
	TenantID   uuid.UUID       `json:"tenant_id"`
	Slug       string          `json:"slug"`
	Name       string          `json:"name"`
	OwnerEmail string          `json:"owner_email"`
	IdP        IdPInput        `json:"identity_provider"`
	Settings   json.RawMessage `json:"settings,omitempty"` // TenantSettings (§13.3), a JSON object
	// Operation is the audit operation platform.tenant.create opened by the API (.requested); the job closes it.
	Operation audit.Operation `json:"operation"`
	// RetryOf is the rolled_back job this one replaces (/retry after rollback — §11.3: a new job from step 3).
	RetryOf *uuid.UUID `json:"retry_of,omitempty"`
}

var (
	slugRE = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}[a-z0-9]$`) // §11.3 step 1
	hexRE  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func (in Input) validate() error {
	switch {
	case in.TenantID == uuid.Nil, !slugRE.MatchString(in.Slug), in.IdP.ID == uuid.Nil:
		return errors.New("tenant, slug or identity provider missing")
	case in.IdP.Driver != DriverKeycloak && in.IdP.Driver != DriverExternal:
		return errors.New("unknown identity provider driver")
	case in.Operation.ID == uuid.Nil:
		return errors.New("audit operation missing")
	}
	return nil
}

// ---------------------------------------------------------------------------------------------------- collaborators

// Agent is the part of the Host Agent the state machine calls — only typed RPCs (§11.1); the generated
// agentv1.AgentServiceClient (agentclient.Client) implements it.
type Agent interface {
	ValidateConfig(ctx context.Context, in *agentv1.ValidateConfigRequest, opts ...grpc.CallOption) (*agentv1.ValidateConfigResponse, error)
	EnsureInstance(ctx context.Context, in *agentv1.EnsureInstanceRequest, opts ...grpc.CallOption) (*agentv1.EnsureInstanceResponse, error)
	GetInstanceStatus(ctx context.Context, in *agentv1.GetInstanceStatusRequest, opts ...grpc.CallOption) (*agentv1.GetInstanceStatusResponse, error)
	RemoveInstance(ctx context.Context, in *agentv1.RemoveInstanceRequest, opts ...grpc.CallOption) (*agentv1.RemoveInstanceResponse, error)
	BootstrapPolicy(ctx context.Context, in *agentv1.BootstrapPolicyRequest, opts ...grpc.CallOption) (*agentv1.BootstrapPolicyResponse, error)
	BootstrapApiKey(ctx context.Context, in *agentv1.BootstrapApiKeyRequest, opts ...grpc.CallOption) (*agentv1.BootstrapApiKeyResponse, error) //nolint:revive // generated RPC name
	EnsureEdgeAttachment(ctx context.Context, in *agentv1.EnsureEdgeAttachmentRequest, opts ...grpc.CallOption) (*agentv1.EnsureEdgeAttachmentResponse, error)
	RemoveEdgeAttachment(ctx context.Context, in *agentv1.RemoveEdgeAttachmentRequest, opts ...grpc.CallOption) (*agentv1.RemoveEdgeAttachmentResponse, error)
}

// Placer is step 3 and its compensation (*platform.Placer).
type Placer interface {
	Allocate(ctx context.Context, req platform.AllocationRequest) (platform.Allocation, error)
	Release(ctx context.Context, tenantID, instanceID uuid.UUID) (bool, error)
}

// SecretStore is the part of the SecretStore the steps use (*secrets.Store).
type SecretStore interface {
	EnsureDEK(ctx context.Context, owner secrets.Owner) (int32, error)
	Put(ctx context.Context, ref secrets.Ref, value []byte, opts ...secrets.Option) error
	Get(ctx context.Context, ref secrets.Ref) (secrets.Plaintext, error)
	Rotate(ctx context.Context, ref secrets.Ref, value []byte, opts ...secrets.Option) (secrets.Ref, error)
	Destroy(ctx context.Context, ref secrets.Ref) error
	Latest(ctx context.Context, tenant uuid.UUID, name string) (secrets.Ref, error)
}

// IdPDrivers selects the IdP driver of a registration (*idp.Registry).
type IdPDrivers interface {
	Driver(name string) (idp.IdPDriver, error)
}

// DNSResult is the outcome of the step-4 check.
type DNSResult struct {
	Addresses []netip.Addr // what the name resolved to
	OK        bool         // the expected address is among them
}

// DNSChecker is step 4 in wildcard mode: does the tenant's control hostname resolve to the public entry? Real:
// Resolver (net.Resolver, optionally a configured server); CI: a fake.
type DNSChecker interface {
	Check(ctx context.Context, hostname string, want netip.Addr) (DNSResult, error)
}

// ProbeCheck is one check of a probe as reported in the step detail.
type ProbeCheck struct {
	Name   string `json:"name"`             // the path or "stun"
	OK     bool   `json:"ok"`               // passed
	Status int    `json:"status,omitempty"` // HTTP status when one was received
	Code   string `json:"code,omitempty"`   // the prober's error code (timeout, refused, tls_verify…) when it failed
}

// ProbeResult is the outcome of a relay or edge probe (apps/probe, P3-T03a).
type ProbeResult struct {
	OK     bool         `json:"ok"`
	Checks []ProbeCheck `json:"checks"`
	// KeyMismatch: /key answered a public key other than the expected one (edge probe).
	KeyMismatch bool `json:"key_mismatch,omitempty"`
	// Exposed: a forbidden path answered something other than 404 — the edge publishes a path it must not (§14.6).
	Exposed []string `json:"exposed,omitempty"`
}

// RelayProbe asks the prober for step 17: GET /derp/probe through the edge's public listener + STUN of the entry.
type RelayProbe struct {
	Address string // the edge's public listener, ip:port
	Host    string // the control hostname
	STUN    string // the shared STUN responder of the public entry, ip:port
}

// EdgeProbe asks the prober for step 18: GET /key?v=<capver> = the instance's Noise key, every forbidden path 404.
type EdgeProbe struct {
	Address   string
	Host      string
	PublicKey string // mkey:<64 hex>
}

// Prober runs the probes of steps 17 and 18 (apps/probe RPC client in the worker; prober.Local + stubs in CI). An
// error means the probe could not run (prober unreachable, target not allowed); a probe that ran and failed is a
// result with OK = false.
type Prober interface {
	Relay(ctx context.Context, p RelayProbe) (ProbeResult, error)
	Edge(ctx context.Context, p EdgeProbe) (ProbeResult, error)
}

// SecurityRecorder records security events (a start-guard refusal of the agent — §11.4).
type SecurityRecorder interface {
	RecordSecurityEvent(ctx context.Context, ev audit.SecurityEvent) (bool, error)
}

// ---------------------------------------------------------------------------------------------------- configuration

// Config are the collaborators and settings of a Provisioner.
type Config struct {
	Store     Store
	Agent     Agent
	Placer    Placer
	Secrets   SecretStore
	IdP       IdPDrivers
	Headscale headscale.Registry
	DNS       DNSChecker       // nil: step 4 records "skipped by configuration" (dev/ci only — Validate)
	Prober    Prober           // nil: steps 17/18 stop with prober_not_configured (failed_resumable)
	Security  SecurityRecorder // nil: start-guard refusals are only logged
	Logger    *slog.Logger

	// HeadscaleDigest (sha256:<64 hex>) and HeadscaleVersion are the runtime of new instances ([images.mg-headscale]).
	HeadscaleDigest  string
	HeadscaleVersion string
	// Instance parameters (§14.5); plan limits (PlanLimits.instance) override the resource defaults.
	NodeExpiryDays uint32       // default 90 (2160h)
	Nameservers    []netip.Addr // required (override_local_dns — RT-07)
	DERPRegionID   uint32       // default 901 (every tailnet has its own DERP map — §10.1)
	LogLevel       agentv1.LogLevel
	MemoryMiB      uint32 // default 512
	CPUMillis      uint32 // default 1000
	PIDs           uint32 // default 256
	APIKeyTTL      time.Duration
	// EdgeAddress is the edge's public listener as the prober reaches it (ip:port); STUNPort the shared STUN port of
	// the public entry (default 3478).
	EdgeAddress string
	STUNPort    uint16

	// Timing (§11.3). Zero values take the defaults.
	StepRetries   int           // 5
	RetryBase     time.Duration // 2 s
	RetryMax      time.Duration // 60 s
	HealthTimeout time.Duration // 90 s
	HealthPoll    time.Duration // 2 s
	CallTimeout   time.Duration // one agent / Headscale / prober call: 2 min
	Now           func() time.Time
}

// Defaults of the instance parameters and of the timing.
const (
	DefaultNodeExpiryDays = 90
	DefaultDERPRegionID   = 901
	DefaultMemoryMiB      = 512
	DefaultCPUMillis      = 1000
	DefaultPIDs           = 256
	DefaultAPIKeyTTL      = 2160 * time.Hour
	DefaultSTUNPort       = 3478
	DefaultStepRetries    = 5
	DefaultHealthTimeout  = 90 * time.Second
)

var digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func (c *Config) defaults() error {
	if c.NodeExpiryDays == 0 {
		c.NodeExpiryDays = DefaultNodeExpiryDays
	}
	if c.DERPRegionID == 0 {
		c.DERPRegionID = DefaultDERPRegionID
	}
	if c.LogLevel == agentv1.LogLevel_LOG_LEVEL_UNSPECIFIED {
		c.LogLevel = agentv1.LogLevel_LOG_LEVEL_INFO
	}
	if c.MemoryMiB == 0 {
		c.MemoryMiB = DefaultMemoryMiB
	}
	if c.CPUMillis == 0 {
		c.CPUMillis = DefaultCPUMillis
	}
	if c.PIDs == 0 {
		c.PIDs = DefaultPIDs
	}
	if c.APIKeyTTL == 0 {
		c.APIKeyTTL = DefaultAPIKeyTTL
	}
	if c.STUNPort == 0 {
		c.STUNPort = DefaultSTUNPort
	}
	if c.StepRetries == 0 {
		c.StepRetries = DefaultStepRetries
	}
	if c.RetryBase == 0 {
		c.RetryBase = 2 * time.Second
	}
	if c.RetryMax == 0 {
		c.RetryMax = time.Minute
	}
	if c.HealthTimeout == 0 {
		c.HealthTimeout = DefaultHealthTimeout
	}
	if c.HealthPoll == 0 {
		c.HealthPoll = 2 * time.Second
	}
	if c.CallTimeout == 0 {
		c.CallTimeout = 2 * time.Minute
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}
	var errs []error
	if c.Store == nil || c.Agent == nil || c.Placer == nil || c.Secrets == nil || c.IdP == nil || c.Headscale == nil {
		errs = append(errs, errors.New("store, agent, placer, secret store, IdP drivers and Headscale registry are required"))
	}
	if !digestRE.MatchString(c.HeadscaleDigest) || c.HeadscaleVersion == "" {
		errs = append(errs, errors.New("the Headscale image digest (sha256:<64 hex>) and version are required"))
	}
	if len(c.Nameservers) == 0 || len(c.Nameservers) > 8 {
		errs = append(errs, errors.New("1–8 nameservers are required (override_local_dns — RT-07)"))
	}
	if c.APIKeyTTL%time.Hour != 0 || c.APIKeyTTL < 24*time.Hour || c.APIKeyTTL > 8760*time.Hour {
		errs = append(errs, errors.New("the API key TTL must be whole hours within 24h–8760h"))
	}
	if c.StepRetries < 0 || c.RetryMax < c.RetryBase {
		errs = append(errs, errors.New("invalid retry settings"))
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("orchestrator: %w", err)
	}
	return nil
}
