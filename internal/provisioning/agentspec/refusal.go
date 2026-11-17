package agentspec

import (
	"errors"
	"fmt"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
)

// Refusal is the typed error of every refused request: the reason, the path of the offending field and a short
// message. Neither carries the refused value (it may be a secret, huge, or crafted for the logs).
type Refusal struct {
	Reason agentv1.RefusalReason
	Field  string
	Msg    string
}

func (r *Refusal) Error() string {
	if r.Field == "" {
		return fmt.Sprintf("refused (%s): %s", r.Reason, r.Msg)
	}
	return fmt.Sprintf("refused (%s) %s: %s", r.Reason, r.Field, r.Msg)
}

// Proto returns the wire form of the refusal (the detail of the gRPC status).
func (r *Refusal) Proto() *agentv1.Refusal {
	return &agentv1.Refusal{Reason: r.Reason, Field: r.Field, Message: r.Msg}
}

// AsRefusal extracts the refusal of err, if any.
func AsRefusal(err error) (*Refusal, bool) {
	var r *Refusal
	if errors.As(err, &r) {
		return r, true
	}
	return nil, false
}

func refuse(reason agentv1.RefusalReason, field, format string, args ...any) *Refusal {
	return &Refusal{Reason: reason, Field: field, Msg: fmt.Sprintf(format, args...)}
}

func malformed(field, format string, args ...any) *Refusal {
	return refuse(agentv1.RefusalReason_REFUSAL_REASON_MALFORMED, field, format, args...)
}

func outOfBounds(field, format string, args ...any) *Refusal {
	return refuse(agentv1.RefusalReason_REFUSAL_REASON_OUT_OF_BOUNDS, field, format, args...)
}

func tooLarge(field string, n, max int) *Refusal {
	return refuse(agentv1.RefusalReason_REFUSAL_REASON_TOO_LARGE, field, "%d items or bytes, at most %d", n, max)
}

func missing(field string) *Refusal { return malformed(field, "required") }

// join builds a field path: join("spec", "instance") = "spec.instance".
func join(parent, name string) string {
	if parent == "" {
		return name
	}
	return parent + "." + name
}

func index(parent string, i int) string { return fmt.Sprintf("%s[%d]", parent, i) }
