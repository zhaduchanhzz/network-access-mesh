package headscale

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Probe reasons: the stable codes of an instance that is not healthy (Probe.Reason). They never carry Headscale's
// own message; the adapter error with the details goes to the internal log only.
const (
	ProbeDatabaseUnreachable = "database_unreachable" // GET /api/v1/health answered: no database connectivity
	ProbeInstanceUnavailable = "instance_unavailable" // transport error, timeout, 502/503/504, the edge cannot route
	ProbeCircuitOpen         = "circuit_open"         // the adapter's breaker for the instance is open: not called
	ProbeUnsupportedVersion  = "unsupported_version"  // GET /version reports a version outside SupportedVersions
	ProbeAPIKeyRejected      = "api_key_rejected"     // the instance refused the platform API key (§13.4)
	ProbeEdgeRejected        = "edge_rejected"        // the edge admin listener refused its token
	ProbeNotLocated          = "not_located"          // the locator has no instance for the tenant (ErrNoInstance)
	ProbeUpstreamRejected    = "upstream_rejected"    // any other answer that is not a healthy one
	ProbeInternal            = "internal"             // our side: invalid target, locator failure
)

// Probe is one health check of a tenant's instance through the adapter (§16.2 "GET /api/v1/health qua adapter (key +
// DB)"): the version the instance reports (GET /version, checked against SupportedVersions), its database
// connectivity (GET /api/v1/health, which also proves the platform API key), and the state of the instance's circuit
// breaker after the calls. A Probe is a result, never an error: a failed check is what it reports.
type Probe struct {
	InstanceID uuid.UUID     // the instance the locator resolved; uuid.Nil when none could be resolved
	Version    string        // GET /version ("" when not reached)
	Database   *bool         // GET /api/v1/health database connectivity (nil when not reached)
	Breaker    BreakerState  // state of the instance's breaker after the probe ("" when no instance was resolved)
	Err        error         // the adapter error that ended the probe (nil when every call answered)
	Duration   time.Duration // wall time of the probe
}

// Healthy reports whether every check passed: the version is supported and the database is reachable.
func (p Probe) Healthy() bool { return p.Reason() == "" }

// Reason is the stable code of a probe that is not healthy, "" when it is.
func (p Probe) Reason() string {
	if p.Err == nil {
		if p.Database != nil && *p.Database {
			return ""
		}
		if p.Database != nil {
			return ProbeDatabaseUnreachable
		}
		return ProbeInternal // nothing failed and nothing was learnt: not a healthy probe
	}
	e, ok := AsError(p.Err)
	if !ok {
		return ProbeInternal
	}
	switch e.Kind {
	case KindUnavailable:
		if errors.Is(e, ErrNoInstance) {
			return ProbeNotLocated
		}
		return ProbeInstanceUnavailable
	case KindCircuitOpen:
		return ProbeCircuitOpen
	case KindUnsupportedVersion:
		return ProbeUnsupportedVersion
	case KindAPIKeyRejected:
		return ProbeAPIKeyRejected
	case KindEdgeRejected:
		return ProbeEdgeRejected
	case KindInternal:
		return ProbeInternal
	default:
		return ProbeUpstreamRejected
	}
}

// Probe checks the instance of a tenant: the target is taken from the registry's cache while it is fresh, else from
// the Locator (the cache is not filled: a probe changes nothing but the breaker's counters), then GET /version and
// GET /api/v1/health go through the same transport as every other call — credentials reloaded once on 401/403, safe
// GETs retried with backoff, failures counted by the instance's breaker. It honours ctx; a probe cut short by its
// caller reports the context error and says nothing about the instance.
func (r *CachingRegistry) Probe(ctx context.Context, tenantID uuid.UUID) Probe {
	start := r.now()
	p := r.probe(ctx, tenantID)
	p.Duration = r.now().Sub(start)
	return p
}

func (r *CachingRegistry) probe(ctx context.Context, tenantID uuid.UUID) (p Probe) {
	if tenantID == uuid.Nil {
		return Probe{Err: localError(OpForTenant, KindInternal, "nil tenant id")}
	}
	target, base, err := r.probeTarget(ctx, tenantID)
	if err != nil {
		return Probe{Err: err}
	}
	c := r.newConn(tenantID, target, base)
	p.InstanceID = target.InstanceID
	defer func() { p.Breaker = c.breaker.State() }()
	raw, err := c.version(ctx)
	if err != nil {
		p.Err = err
		return p
	}
	p.Version = raw
	v, err := ParseVersion(raw)
	if err != nil {
		p.Err = localError(OpVersion, KindUnsupportedVersion, err.Error())
		return p
	}
	impl, ok := implFor(v)
	if !ok {
		p.Err = localError(OpVersion, KindUnsupportedVersion,
			fmt.Sprintf("instance reports %s; supported: %s", v.Raw, SupportedVersions()))
		return p
	}
	h, err := impl.construct(c).Health(ctx)
	if err != nil {
		p.Err = err
		return p
	}
	db := h.DatabaseConnectivity
	p.Database = &db
	return p
}

// probeTarget returns the cached target of the tenant while it is fresh, else asks the Locator.
func (r *CachingRegistry) probeTarget(ctx context.Context, tenantID uuid.UUID) (Target, string, error) {
	r.mu.Lock()
	e := r.entries[tenantID]
	if e != nil && r.now().Sub(e.at) < r.ttl {
		t, base := e.target, e.base
		r.mu.Unlock()
		return t, base, nil
	}
	r.mu.Unlock()
	return r.locate(ctx, tenantID)
}
