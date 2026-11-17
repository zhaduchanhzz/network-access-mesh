package idpconsoleapi

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp/console"
)

// GatePath is the path of the gate on the api's public listener — outside /api/v1: the public sites of the edge
// route only /api/* to the api, so no browser reaches it; the edge calls it as forward_auth (and the listener answers
// only the edge's address — edgeOnly of apps/internal/runner).
const GatePath = "/internal/edge/idp-console"

// Audit actions of the gate (platform events).
const (
	ActionConsoleAccess = "idp.console.access" // a refused console request (denied, reason in details)
	ActionConsoleOpen   = "idp.console.open"   // the first request let through in a console session (success)
)

// Grants reads the console sessions of a person (*console.Store).
type Grants interface {
	Grants(ctx context.Context, identity uuid.UUID, now time.Time) ([]console.Grant, error)
}

// Authorizer decides whether the caller still holds platform.idp:console (*authz.Authorizer).
type Authorizer interface {
	Require(ctx context.Context, tenantID uuid.UUID, req authz.Requirement) (authz.Decision, error)
}

// Auditor writes the gate's audit and security events (*audit.Logger).
type Auditor interface {
	RecordDetached(ctx context.Context, ev audit.Event) error
	RecordCommitted(ctx context.Context, ev audit.Event) error
	RecordSecurityEvent(ctx context.Context, ev audit.SecurityEvent) (bool, error)
}

// Gate is the forward_auth of the console (GET /internal/edge/idp-console). It runs behind the session hook of the
// public API (httpapi.Options.Internal): the identity middleware resolved the Platform Console session of the Host
// (admin.<domain>), the chain computed the client address from the edge's X-Forwarded-For.
type Gate struct {
	grants Grants
	authz  Authorizer
	audit  Auditor
	log    *slog.Logger
	now    func() time.Time

	mu     sync.Mutex
	seen   map[string]time.Time // throttle of the audit of refusals (key → last written) and of the session openings
	opened map[uuid.UUID]time.Time
}

// GateConfig configures NewGate.
type GateConfig struct {
	Grants Grants
	Authz  Authorizer
	Audit  Auditor
	Logger *slog.Logger
	Now    func() time.Time
}

// NewGate returns the gate.
func NewGate(cfg GateConfig) *Gate {
	g := &Gate{grants: cfg.Grants, authz: cfg.Authz, audit: cfg.Audit, log: cfg.Logger, now: cfg.Now,
		seen: map[string]time.Time{}, opened: map[uuid.UUID]time.Time{}}
	if g.log == nil {
		g.log = slog.New(slog.DiscardHandler)
	}
	if g.now == nil {
		g.now = time.Now
	}
	return g
}

// refusalThrottle: one audit event per (person or address, reason) and minute — a console page loads dozens of assets.
const refusalThrottle = time.Minute

// ServeHTTP answers 204 (the edge lets the request through) or 401/403 (the edge returns this answer to the browser).
func (g *Gate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	now := g.now()
	ip := httpapi.ClientIP(ctx)
	uri := r.Header.Get("X-Forwarded-Uri")
	path := uriPath(uri)
	if r.Method != http.MethodGet || uri == "" {
		g.refuse(ctx, w, http.StatusForbidden, nil, ip, "not_forward_auth", path, now)
		return
	}
	s, ok := identity.SessionFromContext(ctx)
	if !ok || s.Origin != identity.OriginAdmin || s.Scope != identity.ScopePlatform {
		g.refuse(ctx, w, http.StatusUnauthorized, nil, ip, "no_platform_session", path, now)
		return
	}
	who := s.IdentityID
	if console.IsImpersonation(uri) {
		_, _ = g.audit.RecordSecurityEvent(context.WithoutCancel(ctx), audit.SecurityEvent{
			Kind: console.KindImpersonationAttempt, Severity: audit.SeverityCritical, Source: "idp.console_gate",
			Details: audit.Details{"identity_id": who, "method": token(r.Header.Get("X-Forwarded-Method")),
				"path": clip(path), "ip": ip},
			DedupeKey:    console.KindImpersonationAttempt + ":" + who.String() + ":" + now.UTC().Format("200601021504"),
			DedupeWindow: time.Minute})
		g.refuse(ctx, w, http.StatusForbidden, &who, ip, console.ReasonImpersonation, path, now)
		return
	}
	p := authz.Principal{IdentityID: who, Scope: authz.ScopePlatform, Origin: authz.OriginAdmin}
	if _, err := g.authz.Require(authz.WithPrincipal(ctx, p), uuid.Nil,
		authz.Requirement{Permission: console.Permission, ReadOnly: true}); err != nil {
		g.refuse(ctx, w, http.StatusForbidden, &who, ip, console.ReasonNoPlatformUser, path, now)
		return
	}
	grants, err := g.grants.Grants(ctx, who, now)
	if err != nil {
		g.log.ErrorContext(ctx, "idp console gate: grants unreadable", "error", err.Error())
		writeText(w, http.StatusServiceUnavailable, "The console gate cannot decide right now.")
		return
	}
	d := console.Decide(grants, who, ip, now)
	if !d.Allowed {
		g.refuse(ctx, w, http.StatusForbidden, &who, ip, d.Reason, path, now)
		return
	}
	g.opening(ctx, who, ip, *d.Grant, now)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// opening writes idp.console.open for the first request let through in a console session (once per session and
// process; a restarted api writes it again — still bounded).
func (g *Gate) opening(ctx context.Context, who uuid.UUID, ip netip.Addr, gr console.Grant, now time.Time) {
	g.mu.Lock()
	_, done := g.opened[gr.ApprovalID]
	if !done {
		g.opened[gr.ApprovalID] = gr.EndsAt
		for id, end := range g.opened {
			if now.After(end) {
				delete(g.opened, id)
			}
		}
	}
	g.mu.Unlock()
	if done {
		return
	}
	id := who
	if err := g.audit.RecordCommitted(context.WithoutCancel(ctx), audit.Event{Action: ActionConsoleOpen,
		ActorIdentityID: &id, ActorIP: ip, ResourceType: "approval", ResourceID: gr.ApprovalID.String(),
		Details: audit.Details{"approval_id": gr.ApprovalID, "approved_by_identity_id": gr.ApprovedBy,
			"source_cidr": gr.Payload.SourceCIDR, "starts_at": gr.StartsAt, "ends_at": gr.EndsAt}}); err != nil {
		g.log.ErrorContext(ctx, "idp console gate: opening not audited", "error", err.Error())
	}
}

// refuse answers a refusal and audits it (detached path, throttled per person or address and reason).
func (g *Gate) refuse(ctx context.Context, w http.ResponseWriter, status int, who *uuid.UUID, ip netip.Addr, reason,
	path string, now time.Time,
) {
	key := ip.String() + "|" + reason
	if who != nil {
		key = who.String() + "|" + reason
	}
	g.mu.Lock()
	last, seen := g.seen[key]
	write := !seen || now.Sub(last) >= refusalThrottle
	if write {
		g.seen[key] = now
		if len(g.seen) > 4096 {
			for k, t := range g.seen {
				if now.Sub(t) >= refusalThrottle {
					delete(g.seen, k)
				}
			}
		}
	}
	g.mu.Unlock()
	if write {
		if err := g.audit.RecordDetached(context.WithoutCancel(ctx), audit.Event{Action: ActionConsoleAccess,
			ActorIdentityID: who, ActorIP: ip, ResourceType: "idp.console", Outcome: audit.OutcomeDenied,
			Details: audit.Details{"reason": reason, "path": clip(path)}}); err != nil {
			g.log.ErrorContext(ctx, "idp console gate: refusal not audited", "error", err.Error())
		}
	}
	g.log.InfoContext(ctx, "idp console gate: refused", "reason", reason, "status", status)
	msg := "The Keycloak administration console needs an approved console session (Platform Console → IdP console)."
	if status == http.StatusUnauthorized {
		msg = "Sign in to the Platform Console first; the Keycloak administration console needs an approved console session."
	}
	writeText(w, status, msg)
}

func writeText(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, msg+"\n")
}

// uriPath is the path of the original request (X-Forwarded-Uri) without its query — which may carry an OAuth code or
// state of the console's login, never written anywhere.
func uriPath(uri string) string {
	u, err := url.Parse(uri)
	if err != nil || !strings.HasPrefix(u.Path, "/") {
		return ""
	}
	return u.Path
}

func clip(s string) string {
	if len(s) > 200 {
		return s[:200]
	}
	return s
}

// token keeps a short HTTP method name, nothing else.
func token(s string) string {
	if len(s) > 0 && len(s) <= 16 && strings.Trim(s, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") == "" {
		return s
	}
	return "other"
}
