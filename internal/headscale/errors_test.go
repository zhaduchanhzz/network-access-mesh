package headscale

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// testAuthID builds a well-formed Auth ID at run time (a literal would trip the secret scanner — .gitleaks.toml).
func testAuthID(fill string) string { return "hskey-" + "authreq-" + strings.Repeat(fill, 24) }

// gw builds a grpc-gateway error body in the exact layout 0.29.7 sends (protojson, ", " separators).
func gw(code int, msg string) string {
	m, _ := json.Marshal(msg)
	return fmt.Sprintf(`{"code":%d, "message":%s, "details":[]}`, code, m)
}

// TestClassifyTable is the error-mapping table of §13.4 (P2-T09 verification). Bodies marked "observed" were
// returned by Headscale v0.29.7 in the contract run of P2-T10 (docs/planning/evidence/P2-T10.md); the others come
// from reading hscontrol/grpcv1.go at the tag.
func TestClassifyTable(t *testing.T) {
	cases := []struct {
		name      string
		op        Op
		status    int
		body      string
		kind      Kind
		outcome   Outcome
		transient bool
	}{
		// --- edge admin listener (non-JSON answers, §14.6)
		{"edge: X-MG-Token wrong", OpListUsers, 403, "", KindEdgeRejected, 0, false},
		{"edge: cannot route (unknown slug, stopped instance)", OpListUsers, 404, "", KindUnavailable, 0, true},
		{"edge: bad gateway", OpGetNode, 502, "", KindUnavailable, 0, true},
		{"edge: gateway timeout", OpGetNode, 504, "", KindUnavailable, 0, true},
		{"edge: rate limited", OpGetNode, 429, "", KindUnavailable, 0, false},
		{"observed: API key invalid/expired (auth middleware text)", OpListUsers, 401, "Unauthorized", KindAPIKeyRejected, 0, false},
		{"plain 500 text", OpListUsers, 500, "boom", KindUpstreamRejected, 0, false},
		// --- gateway codes
		{"observed: route unknown on this version", OpListUsers, 404, gw(5, "Not Found"), KindUpstreamRejected, 0, false},
		{"observed: GetNode unknown id", OpGetNode, 404, gw(5, "node not found"), KindNotFound, 0, false},
		{"DeleteNode unknown id", OpDeleteNode, 404, gw(5, "node not found"), KindNotFound, 0, false},
		{"SetTags unknown node", OpSetTags, 404, gw(5, "node not found"), KindNotFound, 0, false},
		{"already exists", OpCreateUser, 409, gw(6, "already exists"), KindConflict, 0, false},
		{"unavailable 503", OpListNodes, 503, gw(14, "authentication capacity reached; retry later"), KindUnavailable, 0, true},
		{"unauthenticated code", OpListNodes, 401, gw(16, "unauthenticated"), KindAPIKeyRejected, 0, false},
		{"permission denied → upstream rejected", OpListNodes, 403, gw(7, "denied"), KindUpstreamRejected, 0, false},
		// --- users
		{"observed: CreateUser duplicate (code 13)", OpCreateUser, 500,
			gw(13, "creating user: creating user: constraint failed: UNIQUE constraint failed: users.name (2067)"), KindConflict, 0, false},
		{"observed: RenameUser unknown id", OpRenameUser, 500, gw(2, "user not found"), KindNotFound, 0, false},
		{"RenameUser OIDC user", OpRenameUser, 500, gw(2, "cannot edit OIDC user"), KindConflict, 0, false},
		{"observed: RenameUser to a taken name", OpRenameUser, 500,
			gw(2, "updating user: constraint failed: UNIQUE constraint failed: users.name (2067)"), KindConflict, 0, false},
		{"observed: DeleteUser unknown id", OpDeleteUser, 500, gw(2, "user not found"), KindNotFound, 0, false},
		{"observed: DeleteUser with nodes", OpDeleteUser, 500, gw(2, "user not empty: node(s) found"), KindConflict, 0, false},
		{"observed: ListNodes unknown user", OpListNodes, 500, gw(2, "user not found"), KindNotFound, 0, false},
		// --- nodes
		{"SetTags empty list", OpSetTags, 400,
			gw(3, "cannot remove all tags from a node - tagged nodes must have at least one tag"), KindValidation, 0, false},
		{"observed: SetTags bad format (code 2!)", OpSetTags, 500, gw(2, "tag must start with the string 'tag:'"), KindValidation, 0, false},
		{"observed: SetTags tag not in policy", OpSetTags, 400,
			gw(3, "requested tags [tag:ct-undeclared] are invalid or not permitted"), KindValidation, 0, false},
		{"observed: SetApprovedRoutes unknown node (wrapped as 400)", OpSetApprovedRoutes, 400,
			gw(3, "node no longer exists in NodeStore: 999999"), KindNotFound, 0, false},
		{"observed: SetApprovedRoutes bad prefix", OpSetApprovedRoutes, 500, gw(2, `parsing route: netip.ParsePrefix("x"): no '/'`), KindValidation, 0, false},
		{"ExpireNode out of range", OpExpireNode, 400, gw(3, "key expiry is outside the years 0 to 9999 in UTC: x"), KindValidation, 0, false},
		{"observed: ExpireNode unparseable expiry", OpExpireNode, 400,
			gw(3, `parsing field "expiry": parsing time "10000-01-01T00:00:00Z" as "2006-01-02T15:04:05.999999999Z07:00": cannot parse "0-01-01T00:00:00Z" as "-"`), KindValidation, 0, false},
		{"observed: ExpireNode unknown node", OpExpireNode, 500, gw(2, "node no longer exists in NodeStore: 999999"), KindNotFound, 0, false},
		{"observed: RenameNode unknown node", OpRenameNode, 500, gw(2, "node no longer exists in NodeStore: 999999"), KindNotFound, 0, false},
		{"observed: RenameNode invalid label", OpRenameNode, 500,
			gw(2, `renaming node: "Bad_Name" is not a valid DNS label: "Bad_Name" is not a valid DNS label: contains invalid character '_'`), KindValidation, 0, false},
		{"observed: RenameNode name taken", OpRenameNode, 500, gw(2, "node name is not unique: ct-err-node2"), KindConflict, 0, false},
		// --- keys
		{"CreatePreAuthKey bad tag", OpCreatePreAuthKey, 400, gw(3, "tag must start with the string 'tag:'"), KindValidation, 0, false},
		{"observed: CreatePreAuthKey unknown user", OpCreatePreAuthKey, 500, gw(2, "user not found"), KindNotFound, 0, false},
		{"observed: ExpireAPIKey unknown prefix", OpExpireAPIKey, 500, gw(2, "record not found"), KindNotFound, 0, false},
		// --- web auth (§13.4: an Auth ID that is not pending is validation_failed)
		{"observed: AuthRegister not pending", OpAuthRegister, 500, gw(2, "node not found in registration cache"), KindValidation, 0, false},
		{"observed: AuthRegister bad prefix", OpAuthRegister, 500, gw(2, `auth ID has invalid prefix: expected prefix "hskey-authreq-"`), KindValidation, 0, false},
		{"observed: AuthRegister unknown user", OpAuthRegister, 500, gw(2, "looking up user: user not found"), KindNotFound, 0, false},
		{"observed: AuthApprove not pending", OpAuthApprove, 404, gw(5, "no pending auth session for auth_id "+testAuthID("q")), KindValidation, 0, false},
		{"observed: AuthApprove malformed", OpAuthApprove, 400,
			gw(3, `invalid auth_id: auth ID has invalid prefix: expected prefix "hskey-authreq-"`), KindValidation, 0, false},
		{"AuthReject malformed", OpAuthReject, 400, gw(3, "invalid auth_id: auth ID has invalid length: expected 38, got 5"), KindValidation, 0, false},
		// --- V-26 on the patched build (P2-T10a): AuthRegister with the Auth ID of an SSH-check session
		{"observed (patched): AuthRegister SSH-check Auth ID", OpAuthRegister, 400, gw(3, "auth session is not for node registration"), KindValidation, 0, false},
		{"patched: same text under another code", OpAuthRegister, 500, gw(2, "auth session is not for node registration"), KindValidation, 0, false},
		{"observed (official 0.29.7): the instance exits, the edge cannot route", OpAuthRegister, 404, "", KindUnavailable, 0, true},
		// --- a handler panic recovered by the patched build (patch 0002): a write may have been applied
		{"patched: recovered panic on a write", OpCreateUser, 500, gw(13, "internal error: request handler panicked"), KindUpstreamRejected, OutcomeUnknown, false},
		{"patched: recovered panic on AuthRegister", OpAuthRegister, 500, gw(13, "internal error: request handler panicked"), KindUpstreamRejected, OutcomeUnknown, false},
		{"patched: recovered panic on SetPolicy", OpSetPolicy, 500, gw(13, "internal error: request handler panicked"), KindUpstreamRejected, OutcomeUnknown, false},
		{"patched: recovered panic on a read", OpListNodes, 500, gw(13, "internal error: request handler panicked"), KindUpstreamRejected, OutcomeNotApplied, false},
		{"another internal error is not a recovered panic", OpCreateUser, 500, gw(13, "internal error"), KindUpstreamRejected, OutcomeNotApplied, false},
		// --- policy
		{"observed: GetPolicy none stored", OpGetPolicy, 500, gw(2, "loading ACL from database: acl policy not found"), KindNoPolicy, 0, false},
		{"observed: CheckPolicy rejected", OpCheckPolicy, 400, gw(3, `parsing policy: group not defined in policy: "group:nope"`), KindPolicyRejected, 0, false},
		{"observed: CheckPolicy failing tests", OpCheckPolicy, 400,
			gw(3, "test(s) failed:\nct-observer@ -> ct-observer@:1000: expected ALLOWED, got DENIED"), KindPolicyRejected, 0, false},
		{"observed: SetPolicy rejected before swap", OpSetPolicy, 500, gw(2, `setting policy: parsing policy: unknown field: "postures"`),
			KindPolicyRejected, OutcomeNotApplied, false},
		{"observed: SetPolicy failing tests", OpSetPolicy, 500,
			gw(2, "setting policy: test(s) failed:\nct-observer@ -> ct-observer@:1000: expected ALLOWED, got DENIED"),
			KindPolicyRejected, OutcomeNotApplied, false},
		{"observed: SetPolicy duplicate key", OpSetPolicy, 500,
			gw(2, `setting policy: parsing policy: parsing policy from bytes: jsontext: duplicate object member name "Grants"`),
			KindPolicyRejected, OutcomeNotApplied, false},
		{"SetPolicy SSH verification after swap (V-26)", OpSetPolicy, 500, gw(2, "verifying SSH rules: compiling SSH policy: x"),
			KindPolicyRejected, OutcomeUnknown, false},
		{"observed: SetPolicy storage failure after swap (V-26)", OpSetPolicy, 500, gw(2, "database or disk is full (13)"),
			KindPolicyRejected, OutcomeUnknown, false},
		{"storage failure on another write", OpCreateUser, 500, gw(2, "database or disk is full (13)"), KindUnavailable, 0, false},
		{"SetPolicy file mode", OpSetPolicy, 500, gw(2, "update is disabled for modes other than 'database'"),
			KindUpstreamRejected, OutcomeNotApplied, false},
		// --- instance storage
		{"Health database failure", OpHealth, 500, gw(2, "pinging database: database is locked"), KindUnavailable, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := classify(tc.op, tc.status, []byte(tc.body))
			if e.Kind != tc.kind {
				t.Fatalf("kind = %s, want %s (%v)", e.Kind, tc.kind, e)
			}
			if e.Outcome != tc.outcome {
				t.Fatalf("outcome = %s, want %s", e.Outcome, tc.outcome)
			}
			if got := transient(e); got != tc.transient {
				t.Fatalf("transient = %v, want %v", got, tc.transient)
			}
			if e.Status != tc.status || e.Op != tc.op {
				t.Fatalf("status/op not recorded: %+v", e)
			}
		})
	}
}

func TestProblemCodes(t *testing.T) {
	want := map[Kind]string{
		KindValidation: "validation_failed", KindNotFound: "not_found", KindConflict: "conflict",
		KindPolicyRejected: "upstream_rejected", KindNoPolicy: "upstream_rejected", KindUpstreamRejected: "upstream_rejected",
		KindUnavailable: "instance_unavailable", KindCircuitOpen: "instance_unavailable",
		KindAPIKeyRejected: "instance_unavailable", KindEdgeRejected: "instance_unavailable",
		KindUnsupportedVersion: "instance_unavailable", KindInternal: "internal_error",
	}
	for k, code := range want {
		e := &Error{Op: OpGetNode, Kind: k, Code: -1, Upstream: "SECRET-UPSTREAM-TEXT"}
		if e.ProblemCode() != code {
			t.Errorf("%s → %s, want %s", k, e.ProblemCode(), code)
		}
		if !errors.Is(e, kindSentinel[k]) {
			t.Errorf("errors.Is(%s) does not match its sentinel", k)
		}
		if strings.Contains(e.Detail(), "SECRET-UPSTREAM-TEXT") || e.Detail() == "" {
			t.Errorf("Detail of %s leaks or is empty: %q", k, e.Detail())
		}
	}
	if len(want) != len(kindSentinel) {
		t.Fatalf("every kind needs a sentinel and a problem code: %d vs %d", len(want), len(kindSentinel))
	}
	if errors.Is(&Error{Kind: KindNotFound}, ErrConflict) {
		t.Fatal("an error matched the sentinel of another kind")
	}
}

// TestSSHCheckAuthIDProblem: the refusal of the patched build (P2-T10a) reaches a tenant as validation_failed with the
// generic detail — never Headscale's text nor the Auth ID.
func TestSSHCheckAuthIDProblem(t *testing.T) {
	id := testAuthID("s")
	e := classify(OpAuthRegister, 400, []byte(gw(3, "auth session is not for node registration for "+id)))
	if e.ProblemCode() != ProblemValidationFailed || !errors.Is(e, ErrValidation) || e.Outcome != OutcomeNotApplied {
		t.Fatalf("problem %s, outcome %s, kind %s", e.ProblemCode(), e.Outcome, e.Kind)
	}
	for _, leak := range []string{"auth session", "registration", id, "hskey-"} {
		if strings.Contains(e.Detail(), leak) {
			t.Errorf("Detail %q leaks %q", e.Detail(), leak)
		}
	}
}

func TestRetryClasses(t *testing.T) {
	safe := []Op{OpHealth, OpVersion, OpListUsers, OpListNodes, OpGetNode, OpListPreAuthKeys, OpGetPolicy, OpListAPIKeys, OpCheckPolicy}
	idem := []Op{OpSetPolicy, OpExpireNode, OpSetApprovedRoutes, OpSetTags, OpExpirePreAuthKey, OpDeleteNode, OpDeletePreAuthKey}
	never := []Op{OpCreateUser, OpCreatePreAuthKey, OpCreateAPIKey, OpAuthRegister} // §13.4 rule 3
	for _, op := range safe {
		if op.RetryClass() != RetrySafe {
			t.Errorf("%s should be safe", op)
		}
	}
	for _, op := range idem {
		if op.RetryClass() != RetryIdempotentWrite {
			t.Errorf("%s should be an idempotent write", op)
		}
	}
	for _, op := range never {
		if op.RetryClass() != RetryNever {
			t.Errorf("%s must never be retried", op)
		}
	}
}

func TestErrorStringCarriesContext(t *testing.T) {
	e := classify(OpGetNode, 404, []byte(gw(5, "node not found")))
	s := e.Error()
	for _, want := range []string{"GetNode", "not_found", "http 404", "code 5", "node not found"} {
		if !strings.Contains(s, want) {
			t.Errorf("Error() = %q, missing %q", s, want)
		}
	}
	long := classify(OpGetNode, 500, []byte(strings.Repeat("x", 4000)))
	if len(long.Upstream) > maxUpstreamMessage+len("…") {
		t.Errorf("upstream message not truncated: %d bytes", len(long.Upstream))
	}
}
