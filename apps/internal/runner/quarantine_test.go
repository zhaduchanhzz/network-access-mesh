package runner

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/quarantine"
)

// TestReleaseAction — the wiring of P3-T18: the api's registry of approved actions executes the release of a
// quarantined instance (§8.5 platform.instance:release, 2P for every role — no decide condition: a Platform Operator,
// whose :decide is restore_only, never approves it); the payload is the typed one, unknown fields refused.
func TestReleaseAction(t *testing.T) {
	r, err := approvalActions(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(r.Names(), quarantine.ReleaseApprovalAction) {
		t.Fatalf("registry %v", r.Names())
	}
	a, _ := r.Lookup(quarantine.ReleaseApprovalAction)
	s := a.Spec()
	if s.Scope != authz.ScopePlatform || s.Permission != "platform.instance:release" || s.ResourceType != "instance" ||
		len(s.DecideConditions) != 0 {
		t.Fatalf("spec %+v", s)
	}
	ok, _ := json.Marshal(quarantine.ReleasePayload{InstanceID: uuid.New(), TenantID: uuid.New()})
	if err := a.Validate(ok); err != nil {
		t.Fatalf("valid payload: %v", err)
	}
	for _, bad := range []string{`{}`, `{"instance_id":"` + uuid.NewString() + `"}`,
		`{"instance_id":"` + uuid.NewString() + `","tenant_id":"` + uuid.NewString() + `","extra":1}`} {
		if a.Validate(json.RawMessage(bad)) == nil {
			t.Errorf("payload %s accepted", bad)
		}
	}
}
