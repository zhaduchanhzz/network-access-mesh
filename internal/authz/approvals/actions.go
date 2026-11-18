package approvals

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
)

// Spec describes one action that runs only after a second person approved it (§8.5/§8.6 2P cells, §8.6 tenant-scope
// approvals).
type Spec struct {
	// Name is approval_requests.action — the dotted action of the operation ("platform.instance.restore",
	// "platform.tenant.delete", "tenant.settings.disable_four_eyes" …).
	Name string
	// Scope is the scope of its requests: platform (/platform/approvals) or tenant (/tenants/{t}/approvals).
	Scope authz.Scope
	// ResourceType is approval_requests.resource_type: what ResourceID names (tenant, instance, backup, settings…).
	ResourceType string
	// Permission is the permission of the operation itself: the approver must hold it besides :decide (§8.6 "người
	// duyệt phải có tenant.approval:decide và permission của chính thao tác được duyệt"); the requester held it when the
	// operation turned into a request.
	Permission authz.Permission
	// DecideConditions are the conditions of a :decide grant under which this action may still be decided — the
	// conditional cell "chỉ cho restore" of §8.5 (authz.CondRestoreOnly) lets a Platform Operator decide restores only.
	DecideConditions []string
	// ApproverConditions are the conditions of a grant of Permission that the approval itself satisfies — the Super
	// Admin's platform.idp:manage carries tenant_idp_dual_control ("a tenant row needs 2P"): the second Super Admin of
	// such a request holds the permission under exactly that condition (P4-T03a). Without it a conditional grant of
	// Permission is refused to the decider.
	ApproverConditions []string
}

// Execution is what an approved action runs on: the request and its payload, exactly as approved — the bytes whose
// SHA-256 was checked against payload_sha256 just before (the only input of the action, §6.3).
type Execution struct {
	Request Request
	Payload json.RawMessage
}

// Action is the executor of one kind of request (registry of P3-T04a; deprovision P3-T09, restore P3-T11, release
// P3-T18 … register theirs). Validate runs when the request is created and again before execution; Execute runs inside
// the transaction that marks the request executed — it must do its effect there (typically jobs.Enqueue on tx) and
// return the job it enqueued, or nil when the action needs no job. An error rolls everything back: the request stays
// approved and the approver may retry.
type Action interface {
	Spec() Spec
	Validate(payload json.RawMessage) error
	Execute(ctx context.Context, tx *store.Tx, e Execution) (*uuid.UUID, error)
}

// Validator is implemented by a typed payload that checks its own fields.
type Validator interface{ Validate() error }

// Typed returns the Action of spec whose payload is P: decoded strictly (unknown fields refused, one JSON object), then
// checked by P.Validate when P implements Validator; run receives the decoded payload.
func Typed[P any](spec Spec, run func(ctx context.Context, tx *store.Tx, e Execution, p P) (*uuid.UUID, error)) Action {
	return typed[P]{spec: spec, run: run}
}

type typed[P any] struct {
	spec Spec
	run  func(ctx context.Context, tx *store.Tx, e Execution, p P) (*uuid.UUID, error)
}

func (a typed[P]) Spec() Spec { return a.spec }

func (a typed[P]) decode(raw json.RawMessage) (P, error) {
	var p P
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return p, fmt.Errorf("%w: %w", ErrPayload, err)
	}
	if dec.More() {
		return p, fmt.Errorf("%w: trailing data", ErrPayload)
	}
	if v, ok := any(&p).(Validator); ok {
		if err := v.Validate(); err != nil {
			return p, fmt.Errorf("%w: %w", ErrPayload, err)
		}
	} else if v, ok := any(p).(Validator); ok {
		if err := v.Validate(); err != nil {
			return p, fmt.Errorf("%w: %w", ErrPayload, err)
		}
	}
	return p, nil
}

func (a typed[P]) Validate(raw json.RawMessage) error {
	_, err := a.decode(raw)
	return err
}

func (a typed[P]) Execute(ctx context.Context, tx *store.Tx, e Execution) (*uuid.UUID, error) {
	p, err := a.decode(e.Payload)
	if err != nil {
		return nil, err
	}
	return a.run(ctx, tx, e, p)
}

var (
	actionRE       = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`) // CHECK of 0009
	resourceTypeRE = regexp.MustCompile(`^[a-z][a-z_]{0,31}$`)                   // CHECK of 0009
)

// Registry is the closed set of actions this process can execute. An approval request whose action is not in it can
// be read and rejected, never approved (nothing would run it).
type Registry struct{ actions map[string]Action }

// NewRegistry checks the specs and returns the registry: a valid name, scope, resource type and permission of the
// scope; every decide condition a known condition of §8.5/§8.6; no duplicate name.
func NewRegistry(actions ...Action) (*Registry, error) {
	r := &Registry{actions: map[string]Action{}}
	var errs []error
	known := []string{authz.CondSelfEnroll, authz.CondExcludesSuperAdmin, authz.CondTenantIdPDualControl, authz.CondRestoreOnly}
	for _, a := range actions {
		s := a.Spec()
		switch {
		case len(s.Name) > 100 || !actionRE.MatchString(s.Name):
			errs = append(errs, fmt.Errorf("action %q: not a dotted lowercase action", s.Name))
		case s.Scope != authz.ScopePlatform && s.Scope != authz.ScopeTenant:
			errs = append(errs, fmt.Errorf("action %s: scope %q", s.Name, s.Scope))
		case !resourceTypeRE.MatchString(s.ResourceType):
			errs = append(errs, fmt.Errorf("action %s: resource type %q", s.Name, s.ResourceType))
		case s.Permission.Scope() != s.Scope:
			errs = append(errs, fmt.Errorf("action %s: permission %q is not a %s permission", s.Name, s.Permission, s.Scope))
		case r.actions[s.Name] != nil:
			errs = append(errs, fmt.Errorf("action %s: registered twice", s.Name))
		default:
			for _, c := range append(slices.Clone(s.DecideConditions), s.ApproverConditions...) {
				if !slices.Contains(known, c) {
					errs = append(errs, fmt.Errorf("action %s: unknown decide condition %q", s.Name, c))
				}
			}
			r.actions[s.Name] = a
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("approvals: registry: %w", err)
	}
	return r, nil
}

// Lookup returns the action named name.
func (r *Registry) Lookup(name string) (Action, bool) {
	if r == nil {
		return nil, false
	}
	a, ok := r.actions[name]
	return a, ok
}

// Names lists the registered actions, sorted.
func (r *Registry) Names() []string {
	if r == nil {
		return nil
	}
	out := make([]string, 0, len(r.actions))
	for n := range r.actions {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
