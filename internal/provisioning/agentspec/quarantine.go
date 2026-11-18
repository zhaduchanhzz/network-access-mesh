package agentspec

import (
	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
)

// Release is a validated ReleaseInstanceRequest (§11.4 Quarantine, P3-T18): the instance, the job and the sha256 of the
// policy the released instance must serve (the applied policy of the registry).
type Release struct {
	Call
	ExpectedPolicySHA256 string
}

// QuarantineInstance validates a QuarantineInstanceRequest: an instance and a job, nothing else.
func (v *Validator) QuarantineInstance(r *agentv1.QuarantineInstanceRequest) (Call, error) {
	return v.Call(r)
}

// ReleaseInstance validates a ReleaseInstanceRequest: an instance, a job and a 64-hex policy sha256 (required — a
// release never starts an instance without knowing the policy it must serve).
func (v *Validator) ReleaseInstance(r *agentv1.ReleaseInstanceRequest) (Release, error) {
	c, err := v.Call(r)
	if err != nil {
		return Release{}, err
	}
	if err := sha256Hex("expected_policy_sha256", r.GetExpectedPolicySha256()); err != nil {
		return Release{}, err
	}
	return Release{Call: c, ExpectedPolicySHA256: r.GetExpectedPolicySha256()}, nil
}
