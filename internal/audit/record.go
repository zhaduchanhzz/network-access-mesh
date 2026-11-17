package audit

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Record writes ev in the business transaction q (the queries of store.WithTenantTx / WithPlatformTx): the event of a
// successful operation then commits or rolls back with the change it describes (§6.1). Unset fields come from the
// request scope of ctx — action, actor, tenant of the path, resource, request id, client address. RLS checks the
// tenant: a tenant transaction accepts only events of its own tenant, a platform transaction only platform events.
func Record(ctx context.Context, q *sqlcdb.Queries, ev Event) error {
	r := RequestFrom(ctx)
	fill(ctx, &ev, r, true)
	if err := appendTx(ctx, q, &ev); err != nil {
		return err
	}
	r.markRecorded()
	return nil
}

// appendTx normalizes ev and appends it through q.
func appendTx(ctx context.Context, q *sqlcdb.Queries, ev *Event) error {
	if q == nil {
		return errors.New("audit: no transaction")
	}
	if err := ev.normalize(); err != nil {
		return err
	}
	p, err := ev.params()
	if err != nil {
		return err
	}
	if err := q.AppendAuditEvent(ctx, p); err != nil {
		return fmt.Errorf("audit: append %s: %w", ev.Action, err)
	}
	return nil
}

// Operation is an operation that calls Headscale or runs as a job (§6.1): "<Action>.requested" is committed before the
// external call, then exactly one "<Action>.succeeded" or "<Action>.failed" carries the same ID — a process that dies
// halfway leaves the request for reconcile (Logger.OpenOperations). It is plain data: a job carries it in its input
// (JSON) to finish the pair. The outcome events repeat the actor, tenant, resource and request id of the request.
type Operation struct {
	ID              uuid.UUID  `json:"id"`
	Action          string     `json:"action"` // base action, without suffix
	TenantID        *uuid.UUID `json:"tenant_id,omitempty"`
	ActorType       string     `json:"actor_type"`
	ActorIdentityID *uuid.UUID `json:"actor_identity_id,omitempty"`
	SupportGrantID  *uuid.UUID `json:"support_grant_id,omitempty"`
	ActorDisplay    string     `json:"actor_display,omitempty"`
	ActorIP         netip.Addr `json:"actor_ip"`
	ResourceType    string     `json:"resource_type"`
	ResourceID      string     `json:"resource_id,omitempty"`
	RequestID       string     `json:"request_id,omitempty"`
}

// Requested starts an operation: it writes "<ev.Action>.requested" with a new operation id in the business transaction
// q and returns the operation. Commit q before the external call — or enqueue the job that runs the operation in q and
// HandOff the operation to it. ev.Action is the base action (x-audit-action, default from the request scope).
func Requested(ctx context.Context, q *sqlcdb.Queries, ev Event) (Operation, error) {
	r := RequestFrom(ctx)
	fill(ctx, &ev, r, true)
	if pairSuffix(ev.Action) != "" {
		return Operation{}, fmt.Errorf("%w: Requested takes the base action, got %q", ErrInvalidEvent, ev.Action)
	}
	id, err := uuid.NewV7()
	if err != nil {
		return Operation{}, err
	}
	base := ev.Action
	ev.Action, ev.Outcome, ev.OperationID = base+SuffixRequested, OutcomeSuccess, &id
	if err := appendTx(ctx, q, &ev); err != nil {
		return Operation{}, err
	}
	op := Operation{
		ID: id, Action: base, TenantID: ev.TenantID, ActorType: ev.ActorType, ActorIdentityID: ev.ActorIdentityID,
		SupportGrantID: ev.SupportGrantID, ActorDisplay: ev.ActorDisplay, ActorIP: ev.ActorIP,
		ResourceType: ev.ResourceType, ResourceID: ev.ResourceID, RequestID: ev.RequestID,
	}
	r.track(op)
	return op, nil
}

// event is the outcome event of o.
func (o Operation) event(suffix, outcome, reason string, details Details) (Event, error) {
	if o.ID == uuid.Nil || o.Action == "" {
		return Event{}, fmt.Errorf("%w: not an operation returned by Requested", ErrInvalidEvent)
	}
	if reason != "" {
		d := make(Details, len(details)+1)
		for k, v := range details {
			d[k] = v
		}
		d["reason"] = reason
		details = d
	}
	id := o.ID
	return Event{
		TenantID: o.TenantID, ActorType: o.ActorType, ActorIdentityID: o.ActorIdentityID, SupportGrantID: o.SupportGrantID,
		ActorDisplay: o.ActorDisplay, ActorIP: o.ActorIP, Action: o.Action + suffix, ResourceType: o.ResourceType,
		ResourceID: o.ResourceID, RequestID: o.RequestID, OperationID: &id, Outcome: outcome, Details: details,
	}, nil
}

// Succeeded writes "<action>.succeeded" in the business transaction q that applies the outcome (cache update…).
func (o Operation) Succeeded(ctx context.Context, q *sqlcdb.Queries, details Details) error {
	ev, err := o.event(SuffixSucceeded, OutcomeSuccess, "", details)
	if err != nil {
		return err
	}
	return appendTx(ctx, q, &ev)
}

// Failed writes "<action>.failed" in transaction q — when a transaction commits the failure (a job recording its
// failed state). reason is a stable code (e.g. upstream_rejected), never an upstream message.
func (o Operation) Failed(ctx context.Context, q *sqlcdb.Queries, reason string, details Details) error {
	ev, err := o.event(SuffixFailed, OutcomeFailure, reason, details)
	if err != nil {
		return err
	}
	return appendTx(ctx, q, &ev)
}

// FailedDetached writes "<action>.failed" on the detached path of l — when no transaction will commit.
func (o Operation) FailedDetached(ctx context.Context, l *Logger, reason string, details Details) error {
	ev, err := o.event(SuffixFailed, OutcomeFailure, reason, details)
	if err != nil {
		return err
	}
	return l.RecordDetached(ctx, ev)
}

// HandOff tells the request scope of ctx that the job enqueued with o (in the transaction of Requested) finishes the
// pair: Logger.Finish then neither fails the operation nor reports it open.
func HandOff(ctx context.Context, o Operation) {
	RequestFrom(ctx).handOff(o.ID)
}
