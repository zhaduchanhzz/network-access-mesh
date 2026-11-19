package main

// `meshguard-worker admin policy-drift-check` — check a tenant's policy drift now (P4-T10, §7.3, §13.5): the command
// enqueues one policy.drift_check job (dedupe tenant:<id>:policy.drift:cli-<time>) that the running worker executes with
// its own wiring (registries, Host Agent for the edge detach), waits for it and prints its outcome — for the runbook
// (after a suspected out-of-band change, before the next scheduled check) and the functional tests:
//
//	docker compose -p mg-app exec -T worker /usr/local/bin/meshguard admin policy-drift-check --tenant <uuid|slug>
//
// Output: one JSON object — job id, job status, the job's output (state in_sync | drift | no_policy |
// api_key_rejected | skipped, the sha256 compared, the repair job, the security events raised) and its error code. No
// policy text, no secret. Exit status: 0 in sync (or nothing to check); 3 a drift was found (repair enqueued) or an
// incident raised (no policy, API key refused); 1 the job did not finish or could not be enqueued; 2 usage or
// configuration error.

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

const policyDriftUsage = `usage: meshguard-worker admin policy-drift-check --tenant <uuid|slug> [--wait <duration>]
  enqueues policy.drift_check for the running worker and waits for it (default 2m)
  runs inside the worker container: docker compose -p mg-app exec -T worker /usr/local/bin/meshguard admin policy-drift-check …
`

// policyDriftOutput is the command's output.
type policyDriftOutput struct {
	Tenant    string          `json:"tenant_id"`
	JobID     string          `json:"job_id,omitempty"`
	Status    string          `json:"status"`
	Output    json.RawMessage `json:"output,omitempty"`
	ErrorCode string          `json:"error_code,omitempty"`
}

// policyDriftEnv is what the command needs from the process (replaced in tests).
type policyDriftEnv struct {
	getenv  func(string) string
	environ []string
	open    func(ctx context.Context, cfg config.Config) (driftChecker, func(), error)
}

// driftChecker enqueues a drift check and reads its job.
type driftChecker interface {
	ResolveTenant(ctx context.Context, ref string) (uuid.UUID, error)
	Enqueue(ctx context.Context, tenantID uuid.UUID) (uuid.UUID, error)
	Job(ctx context.Context, tenantID, jobID uuid.UUID) (status string, output, errJSON []byte, err error)
}

func policyDriftCheck(ctx context.Context, args []string, stdout, stderr io.Writer, env policyDriftEnv) int {
	fset := flag.NewFlagSet("policy-drift-check", flag.ContinueOnError)
	fset.SetOutput(io.Discard) // flag errors may quote a value
	tenant := fset.String("tenant", "", "")
	wait := fset.Duration("wait", 2*time.Minute, "")
	if err := fset.Parse(args); err != nil || fset.NArg() != 0 || *wait <= 0 || *wait > 10*time.Minute {
		_, _ = io.WriteString(stderr, "meshguard-worker admin policy-drift-check: invalid flags\n"+policyDriftUsage)
		return 2
	}
	if _, err := uuid.Parse(*tenant); err != nil && !slugRE.MatchString(*tenant) {
		_, _ = io.WriteString(stderr, "meshguard-worker admin policy-drift-check: --tenant takes a tenant UUID or slug\n"+policyDriftUsage)
		return 2
	}
	cfg, err := config.Load("worker", env.getenv, env.environ)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshguard-worker admin policy-drift-check: invalid configuration:\n%v\n", err)
		return 2
	}
	if !cfg.Wired {
		_, _ = io.WriteString(stderr, "meshguard-worker admin policy-drift-check: the worker is not configured (MG_DB_URL)\n")
		return 2
	}
	ctx, cancel := context.WithTimeout(ctx, *wait+30*time.Second)
	defer cancel()
	c, closeC, err := env.open(ctx, cfg)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshguard-worker admin policy-drift-check: FAILED: %s\n", logx.RedactString(err.Error()))
		return 1
	}
	defer closeC()
	tenantID, err := c.ResolveTenant(ctx, *tenant)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshguard-worker admin policy-drift-check: tenant %q: %s\n", *tenant, logx.RedactString(err.Error()))
		return 2
	}
	out := policyDriftOutput{Tenant: tenantID.String(), Status: "not_enqueued"}
	id, err := c.Enqueue(ctx, tenantID)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshguard-worker admin policy-drift-check: FAILED: %s\n", logx.RedactString(err.Error()))
		return printDrift(stdout, out, 1)
	}
	out.JobID = id.String()
	deadline := time.Now().Add(*wait)
	for {
		status, output, errJSON, err := c.Job(ctx, tenantID, id)
		if err == nil {
			out.Status = status
			if len(output) > 0 {
				out.Output = output
			}
			var e struct {
				Code string `json:"code"`
			}
			if len(errJSON) > 0 && json.Unmarshal(errJSON, &e) == nil {
				out.ErrorCode = e.Code
			}
		}
		switch out.Status {
		case jobs.StatusSucceeded:
			var o policies.DriftOutput
			if json.Unmarshal(out.Output, &o) == nil && o.State == policies.DriftDrift {
				return printDrift(stdout, out, 3)
			}
			return printDrift(stdout, out, 0)
		case jobs.StatusFailed, jobs.StatusCancelled:
			if out.ErrorCode == "no_policy" || out.ErrorCode == "database_replaced" {
				return printDrift(stdout, out, 3)
			}
			return printDrift(stdout, out, 1)
		}
		if time.Now().After(deadline) {
			_, _ = io.WriteString(stderr, "meshguard-worker admin policy-drift-check: the job did not finish in time — is the "+
				"worker running (and not in maintenance)?\n")
			return printDrift(stdout, out, 1)
		}
		select {
		case <-ctx.Done():
			return printDrift(stdout, out, 1)
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func printDrift(w io.Writer, out policyDriftOutput, code int) int {
	b, _ := json.Marshal(out)
	_, _ = fmt.Fprintf(w, "%s\n", b)
	return code
}

// realDriftChecker is driftChecker over the worker's store.
type realDriftChecker struct {
	st      *store.Store
	tenants *tenants.Service
}

func openDriftChecker(ctx context.Context, cfg config.Config) (driftChecker, func(), error) {
	st, err := store.Open(ctx, store.Config{URL: cfg.DB.URL,
		Tenant:   store.Credentials{User: cfg.DB.TenantUser, PasswordFile: cfg.DB.TenantPasswordFile},
		Platform: store.Credentials{User: cfg.DB.PlatformUser, PasswordFile: cfg.DB.PlatformPasswordFile}, MaxConns: 2})
	if err != nil {
		return nil, nil, err
	}
	return &realDriftChecker{st: st, tenants: tenants.New(st, tenants.Options{BaseDomain: cfg.BaseDomain})}, st.Close, nil
}

func (r *realDriftChecker) ResolveTenant(ctx context.Context, ref string) (uuid.UUID, error) {
	return (&realPolicyCore{tenants: r.tenants}).ResolveTenant(ctx, ref)
}

// Enqueue writes the job (and its queue row) in one tenant transaction; the slot names this command and the time.
func (r *realDriftChecker) Enqueue(ctx context.Context, tenantID uuid.UUID) (uuid.UUID, error) {
	var id uuid.UUID
	err := r.st.WithTenantJobTx(ctx, tenantID, func(tx *store.Tx) error {
		e, err := jobs.Enqueue(ctx, tx, jobs.Spec{Kind: policies.KindDriftCheck, TenantID: &tenantID,
			Slot: "cli-" + strconv.FormatInt(time.Now().UnixNano(), 10)})
		id = e.Job.ID
		return err
	})
	return id, err
}

func (r *realDriftChecker) Job(ctx context.Context, tenantID, jobID uuid.UUID) (string, []byte, []byte, error) {
	var (
		status       string
		output, errs []byte
	)
	err := r.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		j, err := q.GetJob(ctx, jobID)
		if err != nil {
			return err
		}
		if j.TenantID == nil || *j.TenantID != tenantID {
			return errors.New("not this tenant's job")
		}
		status, output, errs = j.Status, j.Output, j.Error
		return nil
	})
	return status, output, errs, err
}
