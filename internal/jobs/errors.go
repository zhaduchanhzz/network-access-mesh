package jobs

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"regexp"
	"time"
)

// Error codes set by the framework. Handlers add their own with Transient / Permanent; every code matches
// ^[a-z][a-z0-9_]{0,63}$ (CHECK of provisioning_jobs.error and provisioning_job_steps.error_code).
const (
	CodeTimeout            = "timeout"             // the job exceeded timeout_at (seen by the worker running it)
	CodeWorkerLost         = "worker_lost"         // job.reaper: still running past timeout_at — the worker died or hung
	CodeQueueLost          = "queue_lost"          // job.reaper: the queue dropped the job (discarded, cancelled, deleted)
	CodeHandlerError       = "handler_error"       // an error without a code
	CodeHandlerPanic       = "handler_panic"       // the handler panicked (never retried)
	CodeInterrupted        = "interrupted"         // the worker stopped mid-job: the job resumes after restart
	CodeRetriesExhausted   = "retries_exhausted"   // delivered again after its last attempt (rescue)
	CodeCompensationFailed = "compensation_failed" // compensation after a permanent error failed
	CodeCancelled          = "cancelled"           // /cancel: the job stopped after its current step (§11.3)
)

var codeRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// Error is a handler error with a stable code: the tenant sees only the code (§13.3); the message, redacted, is kept
// for GET /platform/jobs/{id}.
type Error struct {
	Code      string
	Permanent bool // not recoverable: no retry; a lifecycle job with a Compensator rolls back (§11.3)
	// Stop: recoverable, but the queue must not retry it — the handler ran its own retries (or was cancelled): the job
	// ends failed_resumable (lifecycle group: no compensation, resources kept, /retry resumes from the failed step) or
	// failed.
	Stop bool
	Err  error
}

func (e *Error) Error() string {
	if e.Err == nil {
		return e.Code
	}
	return e.Code + ": " + e.Err.Error()
}

func (e *Error) Unwrap() error { return e.Err }

// Transient wraps err as a recoverable failure: retried with backoff while attempts remain; when they run out the job
// ends failed — failed_resumable for the lifecycle group (§11.3).
func Transient(code string, err error) error { return &Error{Code: code, Err: err} }

// Permanent wraps err as a failure that no retry can fix.
func Permanent(code string, err error) error { return &Error{Code: code, Permanent: true, Err: err} }

// Resumable wraps err as a recoverable failure that the queue must not retry: the handler already spent its own
// retries (the provisioning steps retry 5 times with backoff — §11.3), or the operator cancelled the job. The job stops
// without compensation — failed_resumable for the lifecycle group, failed otherwise.
func Resumable(code string, err error) error { return &Error{Code: code, Stop: true, Err: err} }

// IsPermanent reports whether err (or an error it wraps) is a Permanent failure.
func IsPermanent(err error) bool {
	var je *Error
	return errors.As(err, &je) && je.Permanent
}

// IsResumable reports whether err (or an error it wraps) is a Resumable failure.
func IsResumable(err error) bool {
	var je *Error
	return errors.As(err, &je) && je.Stop
}

// CodeOf returns the stable code of a handler error (CodeHandlerError when it has none).
func CodeOf(err error) string {
	code, _, _ := classify(err)
	return code
}

// classify returns the code, permanence and redacted message of a handler error.
func classify(err error) (code string, permanent bool, msg string) {
	code = CodeHandlerError
	var je *Error
	if errors.As(err, &je) {
		if codeRE.MatchString(je.Code) {
			code = je.Code
		}
		permanent = je.Permanent
	}
	return code, permanent, scrub(err.Error())
}

// secretRE matches Headscale API keys, pre-auth keys and web-auth IDs (RT-12, ID-05) — the same patterns kit/logx
// redacts in logs.
var secretRE = regexp.MustCompile(`hskey-(?:api|auth|authreq)-[A-Za-z0-9_-]+`)

const maxMessage = 512

// scrub redacts credentials and bounds the length of an error message before it is stored or logged. Handlers must
// not put secrets in errors (§11.3); this is the second line of defence.
func scrub(s string) string {
	s = secretRE.ReplaceAllString(s, "[REDACTED]")
	if len(s) > maxMessage {
		s = s[:maxMessage] + "…"
	}
	return s
}

// jobError is the stored provisioning_jobs.error: {code, message?}.
func jobError(code, msg string) []byte {
	if !codeRE.MatchString(code) {
		code = CodeHandlerError
	}
	v := map[string]string{"code": code}
	if msg != "" {
		v["message"] = scrub(msg)
	}
	b, _ := json.Marshal(v)
	return b
}

// backoff is the delay before the next attempt after `attempt` failures: exponential from base, capped at max, with
// ±20 % jitter (§11.3: 2 s → 60 s + jitter).
func backoff(attempt int, base, maxDelay time.Duration) time.Duration {
	d := base
	for i := 1; i < attempt && d < maxDelay; i++ {
		d *= 2
	}
	d = min(d, maxDelay)
	return jitter(d, 0.2)
}

// jitter spreads d uniformly over [d·(1−f), d·(1+f)].
func jitter(d time.Duration, f float64) time.Duration {
	return time.Duration(float64(d) * (1 - f + 2*f*rand.Float64())) //nolint:gosec // scheduling jitter, not security
}

// randUpTo returns a uniform duration in [0, d).
func randUpTo(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(d))) //nolint:gosec // scheduling jitter, not security
}

func errorf(format string, args ...any) error { return fmt.Errorf("jobs: "+format, args...) }
