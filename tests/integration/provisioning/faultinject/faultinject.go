// Package faultinject injects failures at the boundary of the provisioning state machine (P3-T07, §11.3): decorators
// of the collaborators of orchestrator.Config — the Host Agent RPCs, the registry (Store), the Headscale adapter, the
// prober, the placer, the SecretStore and the IdP drivers — that make one named call fail, before or after the real
// call, a given number of times, deterministically (counted per call, never random).
//
// Nothing in the production code knows about it: the harness of tests/integration/provisioning builds the real
// orchestrator with these decorators around the real collaborators; the production wiring (apps/internal/runner) never
// imports this package (TestNotImportedByProduction). There is no hook, flag or build tag in the orchestrator: a fault is
// an ordinary error (or answer) returned across an interface the orchestrator already depends on, so the state machine
// classifies it exactly like the same failure of the real collaborator:
//
//	layer      Permanent                                   Transient
//	agent      FAILED_PRECONDITION + Refusal STATE         UNAVAILABLE                  (agentclient.Retryable)
//	store      orchestrator.ErrState  ⇒ registry_state      a database error ⇒ registry_unavailable
//	headscale  headscale.Error upstream_rejected            headscale.Error unavailable
//	prober     Edge: the probe answers a forbidden path      the prober is unreachable ⇒ prober_unavailable
//	placer     platform.ErrConflict ⇒ placement_refused     a database error ⇒ registry_unavailable
//	secrets    secrets.ErrKeyDestroyed (EnsureDEK)           a database error ⇒ secret_store_unavailable
//	idp        idp.Error conflict                            idp.Error unavailable
//
// After = true runs the real call first and then fails: its effect exists (a directory, a container, an API key in
// Headscale, a registry row) while the state machine only sees the failure — the "answer lost" case. Kill (always
// after) makes the process die (SIGKILL) right after the real call returned: nothing after it runs, not even the
// bookkeeping of the step — the "worker died mid-step" case.
package faultinject

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
)

// Mode is how a matching call fails.
type Mode string

// Modes.
const (
	Permanent Mode = "permanent" // classified permanent by the state machine ⇒ compensation in reverse order
	Transient Mode = "transient" // classified transient ⇒ retried in place, then failed_resumable
	Kill      Mode = "kill"      // the process dies after the real call (After implied)
)

// Calls are the call names a fault may name, with the step of §11.3 that makes them (some steps make several).
var Calls = map[string]string{
	"placer.Allocate":                "placement.allocate",
	"placer.Release":                 "placement.allocate (compensation)",
	"secrets.EnsureDEK":              "secrets.generate",
	"idp.EnsureIssuer":               "idp.ensure",
	"idp.EnsureClient":               "idp.ensure",
	"agent.EnsureInstance:STORAGE":   "storage.create",
	"agent.ValidateConfig":           "config.render",
	"agent.EnsureInstance:CONFIG":    "config.render",
	"agent.EnsureInstance:NETWORK":   "network.ensure",
	"agent.EnsureInstance:CONTAINER": "instance.start",
	"agent.GetInstanceStatus":        "instance.wait_healthy",
	"agent.BootstrapPolicy":          "policy.bootstrap",
	"agent.BootstrapApiKey":          "apikey.bootstrap",
	"agent.EnsureEdgeAttachment":     "edge.attach",
	"agent.RemoveEdgeAttachment":     "edge.attach (compensation); edge.detach (deprovision — P3-T09)",
	"agent.RemoveInstance":           "storage/network/start (compensation); instance.remove, storage.remove (deprovision)",
	"agent.Backup":                   "backup.final (deprovision — P3-T09: the final backup, instance.backup's path)",
	"headscale.ExpireNode":           "nodes.expire (deprovision — P3-T09: the point of no return)",
	"headscale.GetPolicy":            "policy.verify",
	"headscale.Version":              "policy.verify",
	"headscale.Health":               "edge.verify",
	"store.RecordConfig":             "config.render",
	"store.SetFingerprint":           "instance.wait_healthy",
	"store.SetAPIKey":                "apikey.bootstrap",
	"store.RecordBaselinePolicy":     "policy.verify",
	"store.Configure":                "tenant.configure",
	"store.AssignRelay":              "relay.assign",
	"store.Activate":                 "activate",
	"prober.Relay":                   "relay.assign",
	"prober.Edge":                    "edge.verify",
}

// Fault is one injected failure.
type Fault struct {
	Call  string `json:"call"`            // a key of Calls
	Mode  Mode   `json:"mode"`            // Permanent, Transient or Kill
	After bool   `json:"after,omitempty"` // fail after the real call (Kill: always)
	Times int    `json:"times,omitempty"` // matching calls that fail; 0 = every one
	Skip  int    `json:"skip,omitempty"`  // matching calls let through before the first failure
}

func (f Fault) String() string {
	when := "before"
	if f.After || f.Mode == Kill {
		when = "after"
	}
	n := "every call"
	if f.Times > 0 {
		n = fmt.Sprintf("%d call(s)", f.Times)
	}
	return fmt.Sprintf("%s %s %s (%s, skip %d)", f.Call, f.Mode, when, n, f.Skip)
}

// Plan is the set of faults of one worker process.
type Plan []Fault

// ParsePlan decodes and validates a JSON plan ("" = no fault).
func ParsePlan(s string) (Plan, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var p Plan
	dec := json.NewDecoder(strings.NewReader(s))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("faultinject: plan: %w", err)
	}
	return p, p.Validate()
}

// Encode returns the JSON of the plan (the worker process reads it from its environment).
func (p Plan) Encode() string {
	b, _ := json.Marshal(p)
	return string(b)
}

// Validate refuses unknown calls and modes and combinations that have no meaning.
func (p Plan) Validate() error {
	var errs []error
	for i, f := range p {
		if _, ok := Calls[f.Call]; !ok {
			errs = append(errs, fmt.Errorf("fault %d: unknown call %q", i, f.Call))
		}
		switch f.Mode {
		case Permanent, Transient, Kill:
		default:
			errs = append(errs, fmt.Errorf("fault %d: unknown mode %q", i, f.Mode))
		}
		if f.Times < 0 || f.Skip < 0 {
			errs = append(errs, fmt.Errorf("fault %d: negative times or skip", i))
		}
		if f.Mode == Permanent && f.Call == "prober.Relay" {
			// The state machine treats every relay probe failure as transient (§11.3 step 17): there is no permanent
			// failure of this call to inject — store.AssignRelay is the permanent failure of step 17.
			errs = append(errs, fmt.Errorf("fault %d: prober.Relay has no permanent failure", i))
		}
		if f.Mode == Kill && f.Times != 1 {
			errs = append(errs, fmt.Errorf("fault %d: kill fires once (times = 1)", i))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("faultinject: %w", err)
	}
	return nil
}

// Event is one call that matched a fault.
type Event struct {
	Call  string `json:"call"`
	Mode  Mode   `json:"mode"`
	After bool   `json:"after"`
	N     int    `json:"n"`     // the n-th matching call (1-based)
	Fired bool   `json:"fired"` // the failure was injected (false: let through by Skip or Times)
}

// Injector decides, call by call, whether a fault fires. It is safe for concurrent use.
type Injector struct {
	mu     sync.Mutex
	plan   Plan
	seen   []int
	fired  []int
	calls  map[string]int
	events []Event
	kill   func()
	notify func(Event)
}

// Options of an Injector.
type Options struct {
	// Kill ends the process (the worker: SIGKILL to itself). It must not return; if it does, the call fails as if the
	// process had died (an UNAVAILABLE-like transient error), which keeps unit tests deterministic.
	Kill func()
	// Notify is told about every matching call (the worker logs it before a kill, so the log shows the kill point).
	Notify func(Event)
}

// New returns an injector for plan (nil plan: no fault ever fires).
func New(plan Plan, o Options) (*Injector, error) {
	if err := plan.Validate(); err != nil {
		return nil, err
	}
	if o.Kill == nil {
		o.Kill = func() {}
	}
	return &Injector{plan: plan, seen: make([]int, len(plan)), fired: make([]int, len(plan)), calls: map[string]int{},
		kill: o.Kill, notify: o.Notify}, nil
}

// decide counts one call at one point (before or after the real call) and returns the fault that fires, if any.
func (in *Injector) decide(call string, after bool) (Fault, bool) {
	in.mu.Lock()
	if !after {
		in.calls[call]++
	}
	var (
		hit   Fault
		fired bool
		ev    *Event
	)
	for i, f := range in.plan {
		if f.Call != call || (f.After || f.Mode == Kill) != after {
			continue
		}
		in.seen[i]++
		e := Event{Call: call, Mode: f.Mode, After: after, N: in.seen[i]}
		if in.seen[i] > f.Skip && (f.Times == 0 || in.fired[i] < f.Times) && !fired {
			in.fired[i]++
			e.Fired, hit, fired = true, f, true
		}
		in.events = append(in.events, e)
		ev = &e
	}
	notify := in.notify
	in.mu.Unlock()
	if ev != nil && notify != nil {
		notify(*ev)
	}
	return hit, fired
}

// Calls returns how many times each call was made (counted before the real call).
func (in *Injector) Calls() map[string]int {
	in.mu.Lock()
	defer in.mu.Unlock()
	out := make(map[string]int, len(in.calls))
	for k, v := range in.calls {
		out[k] = v
	}
	return out
}

// Events returns the matching calls in order.
func (in *Injector) Events() []Event {
	in.mu.Lock()
	defer in.mu.Unlock()
	return slices.Clone(in.events)
}

// Fired returns the number of failures injected per fault (in plan order).
func (in *Injector) Fired() []int {
	in.mu.Lock()
	defer in.mu.Unlock()
	return slices.Clone(in.fired)
}

// Summary is a stable one-line description of the calls and the faults that fired (for test logs).
func (in *Injector) Summary() string {
	calls := in.Calls()
	names := make([]string, 0, len(calls))
	for k := range calls {
		names = append(names, k)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, n := range names {
		parts = append(parts, fmt.Sprintf("%s×%d", n, calls[n]))
	}
	fired := in.Fired()
	fp := make([]string, 0, len(in.plan))
	for i, f := range in.plan {
		fp = append(fp, fmt.Sprintf("%s: fired %d", f, fired[i]))
	}
	return "calls [" + strings.Join(parts, " ") + "] faults [" + strings.Join(fp, "; ") + "]"
}

// before is consulted before the real call: a non-nil error is returned instead of making it.
func (in *Injector) before(l layer, call string) error {
	f, ok := in.decide(call, false)
	if !ok {
		return nil
	}
	return l.err(call, f.Mode)
}

// after is consulted after a real call that succeeded: a non-nil error replaces its answer.
func (in *Injector) after(l layer, call string) error {
	f, ok := in.decide(call, true)
	if !ok {
		return nil
	}
	if f.Mode == Kill {
		in.kill()
		// Kill returned (unit tests): the caller sees what a dead peer would leave — no answer.
		return l.err(call, Transient)
	}
	return l.err(call, f.Mode)
}

// ErrInjected marks every error this package returns (errors.Is), so a test can tell an injected failure from a real
// one in a log or an error chain.
var ErrInjected = errors.New("fault injected by the test harness")
