package jobs

import (
	"context"
	"fmt"
	"time"
)

// minPeriodicInterval bounds RegisterPeriodic: a module job every few seconds would only load the queue.
const minPeriodicInterval = time.Minute

// periodic is one periodic job registered by a module (RegisterPeriodic).
type periodic struct {
	kind  string
	every time.Duration
}

// RegisterPeriodic registers fn as the handler of a platform-scope kind and schedules it every interval as a River
// periodic job, like the built-in maintenance jobs: each run records its own provisioning_jobs row (dedupe key
// <kind>:<slot>), and the first run happens when the worker starts, after a random 0–StartJitter (River's OSS schedule
// is not durable — ST-01, §13.5). It implements identity.PeriodicRegistrar (session.gc — P2-T16): modules schedule
// their maintenance through this method because jobs imports no business module (§13.6). Call it before Start.
func (w *Worker) RegisterPeriodic(kind string, interval time.Duration, fn func(ctx context.Context) error) error {
	k, ok := w.cfg.Kinds[kind]
	switch {
	case fn == nil:
		return errorf("register periodic %s: no function", kind)
	case !ok:
		return fmt.Errorf("jobs: register periodic %q: %w", kind, ErrUnknownKind)
	case k.Scope != ScopePlatform:
		return errorf("register periodic %s: only platform-scope kinds run on a schedule", kind)
	case interval < minPeriodicInterval:
		return errorf("register periodic %s: interval below %s", kind, minPeriodicInterval)
	}
	if err := w.Register(kind, HandlerFunc(func(ctx context.Context, _ *Run) error { return fn(ctx) })); err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.periodics = append(w.periodics, periodic{kind: kind, every: interval})
	return nil
}
