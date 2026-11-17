package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// compensate undoes a failed provisioning (§11.3): every completed step — and every step interrupted after it
// recorded created_resources — in REVERSE order, each compensation idempotent and retried in place like a step; then
// the tenant ends `failed` (kept for audit) and the audit operation platform.tenant.create closes with .failed. A
// compensation that fails leaves the job failed_resumable (compensation_failed): /rollback resumes it where it stopped.
//
// Steps without a compensation (§11.3 "—"): 4 dns.ensure (wildcard mode creates nothing), 5 secrets.generate (the
// tenant DEK stays: /retry of a rolled_back job provisions again from step 3 with it; crypto-shredding is Deprovision's —
// §11.4), 8 config.render (a new instance has no previous version to restore; its files go with step 7), 11, 12, 15
// (read-only or replaced with the instance), 18, 19.
func (p *Provisioner) compensate(ctx context.Context, r runner, cause error) error {
	a := &attempt{r: r}
	if err := r.Input(&a.in); err != nil {
		return jobs.Permanent("invalid_input", err)
	}
	if err := a.in.validate(); err != nil {
		return jobs.Permanent("invalid_input", err)
	}
	fns := map[string]jobs.CompensateFunc{
		StepRelay:      p.retried(a, p.undoRelay),
		StepConfigure:  p.retried(a, p.undoConfigure),
		StepEdgeAttach: p.retried(a, p.undoEdgeAttach),
		StepAPIKey:     p.retried(a, p.undoAPIKey),
		StepStart:      p.retried(a, p.undoStart),
		StepNetwork:    p.retried(a, p.undoNetwork),
		StepStorage:    p.retried(a, p.undoStorage),
		StepIdP:        p.retried(a, p.undoIdP),
		StepPlacement:  p.retried(a, p.undoPlacement),
	}
	if err := r.CompensateSteps(ctx, fns); err != nil {
		return err
	}
	reason := jobs.CodeOf(cause)
	if err := p.cfg.Store.Fail(ctx, a.in.TenantID, a.in.Operation, reason,
		audit.Details{"job_id": r.JobID(), "slug": a.in.Slug, "rolled_back": true}); err != nil {
		return storeErr("mark the tenant failed", err)
	}
	return nil
}

// retried wraps a compensation with the retry policy of the steps (transient errors retried in place with backoff).
func (p *Provisioner) retried(a *attempt, fn func(ctx context.Context, a *attempt, s jobs.CompensationStep) error) jobs.CompensateFunc {
	return func(ctx context.Context, s jobs.CompensationStep) error {
		for try := 0; ; try++ {
			err := fn(ctx, a, s)
			switch {
			case err == nil:
				return nil
			case jobs.IsPermanent(err), ctx.Err() != nil, try >= p.cfg.StepRetries:
				return err
			}
			if werr := sleep(ctx, p.backoff(try+1)); werr != nil {
				return err
			}
		}
	}
}

// ref of the instance named in a step's resources (or the instance of step 3).
func (p *Provisioner) compInstance(ctx context.Context, a *attempt, id uuid.UUID) (InstanceRecord, bool, error) {
	if id == uuid.Nil {
		var err error
		if id, err = a.instanceID(ctx); err != nil {
			return InstanceRecord{}, false, nil //nolint:nilerr // no instance was ever placed: nothing to undo
		}
	}
	inst, err := p.cfg.Store.Instance(ctx, a.in.TenantID, id)
	if errors.Is(err, ErrNotFound) {
		return inst, false, nil
	}
	if err != nil {
		return inst, false, storeErr("load the instance", err)
	}
	return inst, true, nil
}

func (p *Provisioner) undoRelay(ctx context.Context, a *attempt, s jobs.CompensationStep) error {
	var res relayResources
	if found, err := s.Decode(&res); err != nil || !found {
		return err
	}
	if err := p.cfg.Store.RemoveRelay(ctx, a.in.TenantID, res.InstanceID, res.Code); err != nil {
		return storeErr("remove the relay rows", err)
	}
	return nil
}

func (p *Provisioner) undoConfigure(ctx context.Context, a *attempt, s jobs.CompensationStep) error {
	var res configureResources
	if found, err := s.Decode(&res); err != nil || !found || res.InvitationID == uuid.Nil {
		return err
	}
	if err := p.cfg.Store.RevokeInvitation(ctx, a.in.TenantID, res.InvitationID); err != nil {
		return storeErr("revoke the Owner invitation", err)
	}
	return nil
}

func (p *Provisioner) undoEdgeAttach(ctx context.Context, a *attempt, _ jobs.CompensationStep) error {
	inst, ok, err := p.compInstance(ctx, a, uuid.Nil)
	if err != nil || !ok {
		return err
	}
	cctx, cancel := p.call(ctx)
	defer cancel()
	// Removes the edge_attach flag first, then detaches; meta/activated goes only if THIS job wrote it (job_id).
	_, err = p.cfg.Agent.RemoveEdgeAttachment(cctx, &agentv1.RemoveEdgeAttachmentRequest{Instance: instRef(a, inst),
		JobId: a.r.JobID().String(), Reason: agentv1.EdgeDetachReason_EDGE_DETACH_REASON_COMPENSATION})
	if err != nil && !notFoundAtAgent(err) {
		return agentErr("RemoveEdgeAttachment", err)
	}
	return nil
}

// undoAPIKey destroys the secret versions this job stored and clears the registry fields that point at them. The key
// inside the instance dies with the instance: step 7's compensation removes the whole directory (data/ included) of an
// instance that was never activated — which step 14's compensation guarantees for this job. Expiring it through the
// API is not possible any more at that point: the edge was detached first (reverse order).
func (p *Provisioner) undoAPIKey(ctx context.Context, a *attempt, s jobs.CompensationStep) error {
	return p.underAPIKeyLock(ctx, a, func(ctx context.Context) error { return p.undoAPIKeyLocked(ctx, a, s) })
}

func (p *Provisioner) undoAPIKeyLocked(ctx context.Context, a *attempt, s jobs.CompensationStep) error {
	var res apiKeyResources
	if found, err := s.Decode(&res); err != nil || !found {
		return err
	}
	from := int32(0)
	if res.FromRef != "" {
		if r, err := secrets.ParseRef(res.FromRef); err == nil {
			from = r.Version
		}
	}
	latest, err := p.cfg.Secrets.Latest(ctx, a.in.TenantID, res.SecretName)
	switch {
	case errors.Is(err, secrets.ErrNotFound):
		latest = secrets.Ref{}
	case err != nil:
		return jobs.Transient("secret_store_unavailable", err)
	}
	inst, ok, err := p.compInstance(ctx, a, uuid.Nil)
	if err != nil {
		return err
	}
	if ok && inst.APIKeyRef != "" {
		if r, perr := secrets.ParseRef(inst.APIKeyRef); perr == nil && r.Name == res.SecretName && r.Version > from {
			if err := p.cfg.Store.SetAPIKey(ctx, a.in.TenantID, inst.ID, "", "", nil); err != nil {
				return storeErr("clear the API key reference", err)
			}
		}
	}
	for v := from + 1; v <= latest.Version; v++ {
		ref := secrets.TenantRef(a.in.TenantID, res.SecretName, v)
		if err := p.cfg.Secrets.Destroy(ctx, ref); err != nil && !errors.Is(err, secrets.ErrNotFound) {
			return jobs.Transient("secret_store_unavailable", fmt.Errorf("destroy %s: %w", ref, err))
		}
	}
	return nil
}

// undoStart: compose down (data kept), then the instance → failed so placement can release it.
func (p *Provisioner) undoStart(ctx context.Context, a *attempt, s jobs.CompensationStep) error {
	var res agentResources
	if _, err := s.Decode(&res); err != nil {
		return err
	}
	inst, ok, err := p.compInstance(ctx, a, res.InstanceID)
	if err != nil || !ok {
		return err
	}
	if err := p.remove(ctx, a, inst, agentv1.DataDisposition_DATA_DISPOSITION_KEEP); err != nil {
		return err
	}
	if _, err := p.cfg.Store.TransitionInstance(ctx, a.in.TenantID, inst.ID,
		[]string{tenants.InstanceStarting, tenants.InstanceRunning}, tenants.InstanceFailed); err != nil {
		return storeErr("mark the instance failed", err)
	}
	return nil
}

// undoNetwork: RemoveInstance(KEEP) removes the container and the network, keeps the directory (§11.5).
func (p *Provisioner) undoNetwork(ctx context.Context, a *attempt, s jobs.CompensationStep) error {
	var res agentResources
	if _, err := s.Decode(&res); err != nil {
		return err
	}
	inst, ok, err := p.compInstance(ctx, a, res.InstanceID)
	if err != nil || !ok {
		return err
	}
	return p.remove(ctx, a, inst, agentv1.DataDisposition_DATA_DISPOSITION_KEEP)
}

// undoStorage: the whole directory, only if it was never activated (the agent refuses otherwise — §11.3 step 7).
func (p *Provisioner) undoStorage(ctx context.Context, a *attempt, s jobs.CompensationStep) error {
	var res agentResources
	if _, err := s.Decode(&res); err != nil {
		return err
	}
	inst, ok, err := p.compInstance(ctx, a, res.InstanceID)
	if err != nil || !ok {
		return err
	}
	return p.remove(ctx, a, inst, agentv1.DataDisposition_DATA_DISPOSITION_DELETE_IF_NEVER_ACTIVATED)
}

func (p *Provisioner) remove(ctx context.Context, a *attempt, inst InstanceRecord, d agentv1.DataDisposition) error {
	cctx, cancel := p.call(ctx)
	defer cancel()
	_, err := p.cfg.Agent.RemoveInstance(cctx, &agentv1.RemoveInstanceRequest{Instance: instRef(a, inst),
		JobId: a.r.JobID().String(), Data: d})
	if err != nil && !notFoundAtAgent(err) {
		return agentErr("RemoveInstance("+d.String()+")", err)
	}
	return nil
}

// undoIdP disables the issuer this job created (a realm that carries the job's IdP id) and the registry row.
func (p *Provisioner) undoIdP(ctx context.Context, a *attempt, s jobs.CompensationStep) error {
	var res idpResources
	if found, err := s.Decode(&res); err != nil || !found {
		return err
	}
	cur, exists, err := p.cfg.Store.IdP(ctx, a.in.TenantID, res.IdPID)
	if err != nil {
		return storeErr("load the identity provider", err)
	}
	drv, err := p.cfg.IdP.Driver(res.Driver)
	if err != nil {
		return jobs.Permanent("idp_unknown_driver", err)
	}
	reg := idp.Registration{IdPID: res.IdPID, Scope: idp.ScopeTenant, TenantID: a.in.TenantID, Driver: res.Driver,
		Issuer: a.in.IdP.Issuer, ClientID: a.in.IdP.ClientID}
	if exists {
		reg.Issuer, reg.ClientID, reg.DriverRef, reg.ClientSecretRef = cur.Issuer, cur.ClientID, cur.DriverRef, cur.ClientSecretRef
	} else if res.Driver == DriverKeycloak {
		reg.DriverRef = res.Realm
	}
	if reg.DriverRef != "" || res.Driver == DriverExternal {
		cctx, cancel := p.call(ctx)
		defer cancel()
		if _, err := drv.RemoveIssuer(cctx, reg, idp.RemoveDisable); err != nil && idp.CodeOf(err) != idp.CodeNotFound {
			return idpErr("RemoveIssuer", err)
		}
	}
	if exists {
		for _, from := range []string{"pending", tenants.IdPStatusActive} {
			if _, err := p.cfg.Store.SetIdPStatus(ctx, a.in.TenantID, res.IdPID, from, "disabled"); err != nil {
				return storeErr("disable the identity provider", err)
			}
		}
	}
	return nil
}

func (p *Provisioner) undoPlacement(ctx context.Context, a *attempt, s jobs.CompensationStep) error {
	var res placementResources
	if found, err := s.Decode(&res); err != nil || !found || res.InstanceID == uuid.Nil {
		return err
	}
	_, err := p.cfg.Placer.Release(ctx, a.in.TenantID, res.InstanceID)
	if errors.Is(err, platform.ErrConflict) {
		// Still starting/running (step 10 never recorded what it started): failed first, then release.
		if _, terr := p.cfg.Store.TransitionInstance(ctx, a.in.TenantID, res.InstanceID,
			[]string{tenants.InstanceStarting, tenants.InstanceRunning}, tenants.InstanceFailed); terr != nil {
			return storeErr("mark the instance failed", terr)
		}
		_, err = p.cfg.Placer.Release(ctx, a.in.TenantID, res.InstanceID)
	}
	switch {
	case err == nil, errors.Is(err, platform.ErrNotFound): // released, or never registered
		return nil
	case errors.Is(err, platform.ErrConflict):
		return jobs.Permanent("registry_state", fmt.Errorf("release the instance: %w", err))
	}
	return jobs.Transient("registry_unavailable", fmt.Errorf("release the instance: %w", err))
}

// notFoundAtAgent: the agent has nothing of the instance any more (an idempotent compensation that ran before).
func notFoundAtAgent(err error) bool { return status.Code(err) == codes.NotFound }

// sleep waits d or until ctx ends.
func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
