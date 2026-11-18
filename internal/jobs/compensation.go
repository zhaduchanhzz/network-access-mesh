package jobs

// Steps of a lifecycle job seen from its compensation (§11.3): created_resources recorded before each resource was
// created, and compensation_status per step — so a compensation that stops halfway (failure, worker stop) resumes at
// the step where it stopped, and never undoes a step twice.

import (
	"context"
	"encoding/json"
	"errors"
	"sort"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// StepResources decodes into v the created_resources of the job's step name (recorded by RecordCreated — in this
// attempt or an earlier one): found = false when the step never recorded any. Later steps read what an earlier step
// created (the instance ID chosen by placement.allocate) even when that step is skipped because it succeeded before.
func (r *Run) StepResources(ctx context.Context, name string, v any) (bool, error) {
	var raw []byte
	err := r.w.bookkeep(ctx, func(bctx context.Context, tx *store.Tx) error {
		row, err := tx.Q.GetJobStep(bctx, sqlcdb.GetJobStepParams{JobID: r.ID, Name: name})
		if errors.Is(err, store.ErrNoRows) {
			return nil
		}
		raw = row.CreatedResources
		return err
	})
	if err != nil {
		return false, Transient("step_bookkeeping", errorf("step %s: sqlstate %q", name, store.SQLState(err)))
	}
	if len(raw) == 0 || string(raw) == "null" {
		return false, nil
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return false, Permanent("invalid_step", errorf("step %s: created_resources unreadable", name))
	}
	return true, nil
}

// CompensationStep is one step of the job handed to its compensation function.
type CompensationStep struct {
	Name   string
	Status string // StepSucceeded, StepFailed or StepRunning (a step interrupted after it recorded resources)
	// Resources is the step's created_resources (JSON; nil when it recorded none).
	Resources json.RawMessage
}

// Decode decodes the step's created_resources into v; found = false when the step recorded none.
func (c CompensationStep) Decode(v any) (bool, error) {
	if len(c.Resources) == 0 || string(c.Resources) == "null" {
		return false, nil
	}
	if err := json.Unmarshal(c.Resources, v); err != nil {
		return false, Permanent("invalid_step", errorf("step %s: created_resources unreadable", c.Name))
	}
	return true, nil
}

// CompensateFunc undoes one step. It must be idempotent: a compensation that failed or was interrupted runs again
// (/rollback) from the step where it stopped.
type CompensateFunc func(ctx context.Context, s CompensationStep) error

// CompensateSteps undoes the job's steps in REVERSE order (§11.3): every step that succeeded, and every step that
// failed or was interrupted after recording created_resources (it may have created part of what it recorded). A step
// without a function in fns, or one that did nothing, is marked compensation `skipped`; a step already compensated
// (succeeded or skipped — an earlier, interrupted compensation) is not touched again. The worker's StepGate is consulted
// before each step that would be undone (its refusal stops the compensation like a failure). The first failure stops the
// compensation: the step is marked compensation `failed` with the redacted error in its detail, and the error is
// returned (the job then ends failed_resumable with compensation_failed — the operator decides).
func (r *Run) CompensateSteps(ctx context.Context, fns map[string]CompensateFunc) error {
	var steps []sqlcdb.ProvisioningJobStep
	if err := r.w.bookkeep(ctx, func(bctx context.Context, tx *store.Tx) error {
		var err error
		steps, err = tx.Q.ListJobSteps(bctx, []uuid.UUID{r.ID})
		return err
	}); err != nil {
		return Transient("step_bookkeeping", errorf("list steps: sqlstate %q", store.SQLState(err)))
	}
	sort.Slice(steps, func(i, j int) bool { return steps[i].Seq > steps[j].Seq })
	for _, st := range steps {
		if cs := st.CompensationStatus; cs != nil && (*cs == StepSucceeded || *cs == StepSkipped) {
			continue
		}
		fn := fns[st.Name]
		acted := st.Status == StepSucceeded ||
			((st.Status == StepFailed || st.Status == StepRunning) && len(st.CreatedResources) > 0 && string(st.CreatedResources) != "null")
		if fn == nil || !acted {
			if err := r.markCompensation(ctx, st.Name, StepSkipped, nil); err != nil {
				return err
			}
			continue
		}
		// the step gate (quarantine — P3-T18) holds a compensation too: nothing of a quarantined instance is undone
		var gated error
		if err := r.w.bookkeep(ctx, func(bctx context.Context, tx *store.Tx) error {
			gated = r.gate(bctx, tx.Q)
			return nil
		}); err != nil {
			return Transient("step_bookkeeping", errorf("step %s compensation: sqlstate %q", st.Name, store.SQLState(err)))
		}
		if gated != nil {
			return gated
		}
		if err := r.markCompensation(ctx, st.Name, StepRunning, nil); err != nil {
			return err
		}
		cerr := call(ctx, func(ctx context.Context, _ *Run) error {
			return fn(ctx, CompensationStep{Name: st.Name, Status: st.Status, Resources: st.CreatedResources})
		}, r)
		if cerr != nil {
			_, _, msg := classify(cerr)
			detail := withKey(st.Detail, "compensation_error", msg)
			if err := r.markCompensation(context.WithoutCancel(ctx), st.Name, StepFailed, detail); err != nil {
				return errors.Join(cerr, err)
			}
			return cerr
		}
		if err := r.markCompensation(ctx, st.Name, StepSucceeded, nil); err != nil {
			return err
		}
	}
	return nil
}

func (r *Run) markCompensation(ctx context.Context, name, status string, detail []byte) error {
	if err := r.w.bookkeep(ctx, func(bctx context.Context, tx *store.Tx) error {
		return tx.Q.SetJobStepCompensation(bctx, sqlcdb.SetJobStepCompensationParams{CompensationStatus: status,
			Detail: detail, JobID: r.ID, Name: name})
	}); err != nil {
		return Transient("step_bookkeeping", errorf("step %s compensation: sqlstate %q", name, store.SQLState(err)))
	}
	return nil
}

// withKey adds one redacted string to a step's raw detail.
func withKey(detail []byte, key, msg string) []byte {
	m := map[string]any{}
	if len(detail) > 0 {
		_ = json.Unmarshal(detail, &m)
	}
	m[key] = scrub(msg)
	b, _ := json.Marshal(m)
	return b
}
