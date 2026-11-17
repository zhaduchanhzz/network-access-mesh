//go:build mgtestfixture

package authzmatrix_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/tests/security/sessionfixture"
)

// Hosts of the two origins (the fixture's defaults).
const (
	hostApp   = sessionfixture.AppHost
	hostAdmin = sessionfixture.AdminHost
)

type actorKind string

const (
	kindPlatform    actorKind = "platform"     // a platform role, its session on admin
	kindTenant      actorKind = "tenant"       // a tenant role in A or B, its session on app
	kindAnonymous   actorKind = "anonymous"    // no session
	kindCrossOrigin actorKind = "cross-origin" // a session presented on the other origin (never attached: 401)
	kindCrossSite   actorKind = "cross-site"   // a state-changing request with a foreign Origin (refused before routing)
)

// actor is one client of the matrix.
type actor struct {
	name    string
	kind    actorKind
	role    string
	fx      *sessionfixture.Actor   // nil for anonymous clients
	session *sessionfixture.Session // nil for anonymous clients
	host    string
}

func (a *actor) tenantName() string {
	if a.fx == nil || a.fx.Tenant == nil {
		return ""
	}
	return a.fx.Tenant.Name
}

// decisionKind is what layer 1 must have decided for a request.
type decisionKind int

const (
	decNone  decisionKind = iota // refused before authorization (identity middleware) — no decision
	decGrant                     // authorized
	decDeny                      // refused by authorization
)

// expectation of one request.
type expectation struct {
	status   int
	code     gen.ProblemCode
	accepted bool // any answer that is not a refusal (mounted handler, own object)
	decision decisionKind
	denyKind error
	reason   string // authz.Denial.Reason
	ownOnly  bool
	pending  bool // 501: the handler set of the operation is not mounted yet
}

// call is one request of the matrix and, once sent, its answer.
type call struct {
	actor      *actor
	op         authz.Operation
	recipe     recipe
	host       string
	session    *sessionfixture.Session
	tenantCase string    // own, other, missing ("" for operations outside /tenants/{tenantId})
	pathTenant uuid.UUID // {tenantId} of a tenant route
	objectCase string    // see objectFor
	objectID   uuid.UUID
	victim     string // tenant ("A"/"B") whose data the call targets without being a member of it
	loginSlug  string
	state      string
	exp        expectation

	rec  *httptest.ResponseRecorder
	reqs string // X-Request-Id of the answer
}

func (c *call) String() string {
	s := fmt.Sprintf("%s %s %s", c.actor.name, c.op.Method, c.op.ID)
	if c.tenantCase != "" {
		s += " tenant=" + c.tenantCase
	}
	if c.objectCase != "" {
		s += " object=" + c.objectCase
	}
	return s
}

// matrix holds the world, the actors and the calls.
type matrix struct {
	*matrixWorld
	actors    []*actor
	byFixture map[*sessionfixture.Actor]*actor
	throwaway []*sessionfixture.Session // sessions minted for calls that end them or that revoke them
	calls     []*call
}

func other(w *sessionfixture.World, t *sessionfixture.Tenant) *sessionfixture.Tenant {
	if t == w.A {
		return w.B
	}
	return w.A
}

func newMatrix(t *testing.T) *matrix {
	t.Helper()
	m := &matrix{matrixWorld: newMatrixWorld(t), byFixture: map[*sessionfixture.Actor]*actor{}}
	var sessionActors []*actor
	for _, role := range sessionfixture.PlatformRoles {
		fx := m.Actor(t, role, nil)
		sessionActors = append(sessionActors, &actor{name: fx.String(), kind: kindPlatform, role: role, fx: fx, host: hostAdmin})
	}
	for _, ten := range []*sessionfixture.Tenant{m.A, m.B} {
		for _, role := range sessionfixture.TenantRoles {
			fx := m.Actor(t, role, ten)
			sessionActors = append(sessionActors, &actor{name: fx.String(), kind: kindTenant, role: role, fx: fx, host: hostApp})
		}
	}
	for _, a := range sessionActors {
		a.session = m.Login(t, a.fx)
		m.byFixture[a.fx] = a
	}
	m.actors = append(m.actors, sessionActors...)
	m.actors = append(m.actors,
		&actor{name: "anonymous@app", kind: kindAnonymous, host: hostApp, session: m.Anonymous("app")},
		&actor{name: "anonymous@admin", kind: kindAnonymous, host: hostAdmin, session: m.Anonymous("admin")})
	for _, a := range sessionActors {
		otherHost := hostAdmin
		if a.host == hostAdmin {
			otherHost = hostApp
		}
		m.actors = append(m.actors,
			&actor{name: a.name + "→" + otherHost, kind: kindCrossOrigin, role: a.role, fx: a.fx, host: otherHost,
				session: a.session.OnHost(otherHost)},
			&actor{name: a.name + "+foreign-origin", kind: kindCrossSite, role: a.role, fx: a.fx, host: a.host, session: a.session})
	}
	m.actors = append(m.actors, &actor{name: "anonymous@app+foreign-origin", kind: kindCrossSite, host: hostApp,
		session: m.Anonymous("app")})
	return m
}

// mint returns a throwaway session of a (for a call that ends or revokes it).
func (m *matrix) mint(t *testing.T, a *sessionfixture.Actor) *sessionfixture.Session {
	t.Helper()
	s := m.Login(t, a)
	m.throwaway = append(m.throwaway, s)
	return s
}

// generate builds every call of the matrix with its expectation. Throwaway sessions are minted here, before any
// snapshot of a victim tenant is taken.
func (m *matrix) generate(t *testing.T) {
	t.Helper()
	for _, op := range authz.Operations() {
		rcp := recipes[op.ID]
		for _, a := range m.actors {
			unsafe := op.Method != http.MethodGet && op.Method != http.MethodHead
			if a.kind == kindCrossSite && !unsafe {
				continue // CORS is off and GET is never state-changing: the Origin check applies to unsafe methods
			}
			for _, tc := range m.tenantCases(op, a) {
				for _, oc := range m.objectCases(op, a, tc) {
					c := &call{actor: a, op: op, recipe: rcp, host: a.host, session: a.session, tenantCase: tc, objectCase: oc}
					m.place(t, c)
					c.exp = m.expect(c)
					m.calls = append(m.calls, c)
				}
			}
		}
	}
}

// tenantCases: a tenant member is tried on its own tenant, the other tenant and a tenant that does not exist;
// everyone else on A, B and a missing tenant (members of neither: platform staff without grant, anonymous clients).
func (m *matrix) tenantCases(op authz.Operation, a *actor) []string {
	if !op.TenantScoped() {
		return []string{""}
	}
	switch a.kind {
	case kindCrossSite:
		return []string{"A"}
	case kindTenant:
		return []string{"own", "other", "missing"}
	}
	return []string{"A", "B", "missing"}
}

// objectCases lists the objects tried for the object parameter of the path.
func (m *matrix) objectCases(op authz.Operation, a *actor, tenantCase string) []string {
	kind, ok := objectKindOf(op)
	if !ok {
		return []string{""}
	}
	if a.kind == kindCrossSite {
		return []string{firstCase(kind)}
	}
	if op.TenantScoped() && tenantCase != "own" {
		if tenantCase == "missing" {
			return []string{"missing"}
		}
		return []string{"as-path"} // a consistent object of the path's tenant: the refusal is the tenant's
	}
	switch kind {
	case objDevice:
		return []string{"eu-own", "eu-tagged", "other-member", "other-tenant", "missing"}
	case objMembership, objJob:
		if op.TenantScoped() {
			return []string{"own", "other-tenant", "missing"}
		}
		return []string{"existing", "missing"}
	case objInstance, objTenant, objHost:
		return []string{"existing", "missing"}
	case objSession:
		if a.session == nil || a.fx == nil || a.kind == kindCrossOrigin {
			return []string{"missing"}
		}
		return []string{"own", "other-user", "missing"}
	case objIdP:
		return []string{"own", "missing"}
	}
	return []string{""}
}

func firstCase(k objectKind) string {
	switch k {
	case objDevice:
		return "eu-own"
	case objSession:
		return "missing"
	case objInstance, objTenant, objHost:
		return "existing"
	}
	return "own"
}

// objectKindOf returns the kind of the object parameter of the operation (the {tenantId} context of a tenant route
// is not an object).
func objectKindOf(op authz.Operation) (objectKind, bool) {
	var kinds []objectKind
	for _, p := range pathParams(op.Path) {
		if p == "tenantId" && op.TenantScoped() {
			continue
		}
		kinds = append(kinds, paramObjects[p])
	}
	if len(kinds) == 0 {
		return "", false
	}
	return kinds[0], true // TestEveryOperationHasAnExpectation guarantees a known kind; one object per path today
}

// place fills the path tenant, the object, the session of the call and its victim.
func (m *matrix) place(t *testing.T, c *call) {
	t.Helper()
	w := m.World
	var pathTenant *sessionfixture.Tenant
	switch c.tenantCase {
	case "own":
		pathTenant = c.actor.fx.Tenant
	case "other":
		pathTenant = other(w, c.actor.fx.Tenant)
	case "A":
		pathTenant = w.A
	case "B":
		pathTenant = w.B
	case "missing":
		c.pathTenant = uuid.New()
	}
	if pathTenant != nil {
		c.pathTenant = pathTenant.ID
		if c.actor.tenantName() != pathTenant.Name {
			c.victim = pathTenant.Name
		}
	}
	// the tenant a tenant-scoped object belongs to, relative to the path
	owner := pathTenant
	if c.objectCase == "other-tenant" && pathTenant != nil {
		owner = other(w, pathTenant)
		if c.actor.tenantName() != owner.Name {
			c.victim = owner.Name
		}
	}
	kind, _ := objectKindOf(c.op)
	switch {
	case c.objectCase == "" || c.objectCase == "missing":
		c.objectID = uuid.New()
	case kind == objDevice:
		c.objectID = map[string]map[string]uuid.UUID{
			"eu-own": m.obj.devEU, "eu-tagged": m.obj.devEUTagged, "other-member": m.obj.devOther,
			"other-tenant": m.obj.devEU, "as-path": m.obj.devEU,
		}[c.objectCase][owner.Name]
	case kind == objMembership:
		c.objectID = m.Actor(t, authz.RoleTenantViewer, owner).MembershipID
	case kind == objJob && c.op.TenantScoped():
		c.objectID = m.obj.job[owner.Name]
	case kind == objJob:
		c.objectID = m.obj.platformJob
	case kind == objInstance:
		c.objectID = m.obj.instance["A"]
	case kind == objTenant:
		c.objectID = w.A.ID
	case kind == objHost:
		c.objectID = m.obj.host
	case kind == objIdP:
		c.objectID = c.ownIdP(w)
	case kind == objSession && c.objectCase == "own":
		c.objectID = m.mint(t, c.actor.fx).PublicID
	case kind == objSession && c.objectCase == "other-user":
		// a live session of another identity: the Tenant Owner of the other tenant (of A for platform staff)
		victimTenant := w.A
		if c.actor.fx.Tenant != nil {
			victimTenant = other(w, c.actor.fx.Tenant)
		}
		c.objectID = m.mint(t, m.Actor(t, authz.RoleTenantOwner, victimTenant)).PublicID
		c.victim = victimTenant.Name
	}
	if c.recipe.endsSession && c.actor.fx != nil && c.actor.kind != kindCrossOrigin && c.actor.kind != kindCrossSite {
		c.session = m.mint(t, c.actor.fx)
	}
	c.loginSlug = w.A.Slug
	if c.actor.fx != nil && c.actor.fx.Tenant != nil {
		c.loginSlug = c.actor.fx.Tenant.Slug
	}
	raw := make([]byte, 32)
	copy(raw, uuid.New().String())
	c.state = base64.RawURLEncoding.EncodeToString(raw)
}

// ownIdP is the IdP of the actor's login (tenant IdP, platform IdP; tenant A's or the platform's for anonymous).
func (c *call) ownIdP(w *sessionfixture.World) uuid.UUID {
	switch {
	case c.actor.fx != nil:
		return c.actor.fx.IdPID
	case c.host == hostAdmin:
		return w.PlatformIdP
	}
	return w.A.IdP
}

// path is the request path below /api/v1.
func (c *call) path() string {
	p := c.op.Path
	for _, name := range pathParams(p) {
		v := c.objectID.String()
		if name == "tenantId" && c.op.TenantScoped() {
			v = c.pathTenant.String()
		}
		p = strings.ReplaceAll(p, "{"+name+"}", v)
	}
	if c.recipe.query != nil {
		p += "?" + c.recipe.query(c)
	}
	return p
}

// expect derives the expected answer from §8.5/§8.6 (master_test.go), the request and the mounted handler sets.
func (m *matrix) expect(c *call) expectation {
	op, a := c.op, c.actor
	refused := func(status int, code gen.ProblemCode, kind error, reason string) expectation {
		return expectation{status: status, code: code, decision: decDeny, denyKind: kind, reason: reason}
	}
	if a.kind == kindCrossSite {
		return expectation{status: http.StatusForbidden, code: gen.ProblemCodeForbidden, decision: decNone}
	}
	hasSession := a.kind == kindPlatform || a.kind == kindTenant
	switch op.Permission {
	case authz.Public:
		return expectation{status: c.recipe.public.status, code: c.recipe.public.code, decision: decGrant}
	case authz.Internal:
		return refused(http.StatusForbidden, gen.ProblemCodeForbidden, authz.ErrForbidden, "internal_route")
	}
	if !hasSession {
		return refused(http.StatusUnauthorized, gen.ProblemCodeUnauthenticated, authz.ErrUnauthenticated, "no_principal")
	}
	if op.Permission == authz.Authenticated {
		return m.handlerAnswer(c, false)
	}
	cell := cellOf(op.Permission, a.role)
	switch op.Permission.Scope() {
	case authz.ScopeTenant:
		if a.kind == kindPlatform {
			return refused(http.StatusForbidden, gen.ProblemCodeForbidden, authz.ErrForbidden, "no_support_grant")
		}
		if c.tenantCase != "own" {
			return refused(http.StatusNotFound, gen.ProblemCodeNotFound, authz.ErrNotFound, "not_a_member")
		}
	case authz.ScopePlatform:
		if a.kind == kindTenant {
			return refused(http.StatusForbidden, gen.ProblemCodeForbidden, authz.ErrForbidden, "not_platform_principal")
		}
	}
	switch cell {
	case Y, P2:
		return m.handlerAnswer(c, false)
	case O:
		if !op.OwnResource {
			return refused(http.StatusForbidden, gen.ProblemCodeForbidden, authz.ErrForbidden, "own_scope_on_shared_operation")
		}
		return m.handlerAnswer(c, true)
	case N:
		return refused(http.StatusForbidden, gen.ProblemCodeForbidden, authz.ErrForbidden, "no_grant")
	}
	if cond, ok := conditions[cell]; ok { // no operation declares it enforces a condition yet (Requirement.Conditions)
		return refused(http.StatusForbidden, gen.ProblemCodeForbidden, authz.ErrForbidden, "condition_not_enforced:"+cond)
	}
	panic("matrix: no expectation for cell " + cell + " of " + string(op.Permission)) // TestHandTablesMatchTheMaster
}

// handlerAnswer is the answer to a granted request: 501 while the handler set is not mounted; once it is, the own
// object (or no object) is accepted and anything else — another member's object under an own-only grant, another
// tenant's object, a missing one, another identity's session — is 404 (layer 2, §8.8; §8.4 invariants 3b and 6).
func (m *matrix) handlerAnswer(c *call, ownOnly bool) expectation {
	e := expectation{decision: decGrant, ownOnly: ownOnly}
	if !m.mounted[goName(c.op.ID)] {
		e.status, e.code, e.pending = http.StatusNotImplemented, gen.ProblemCodeNotImplemented, true
		return e
	}
	switch c.objectCase {
	case "", "own", "existing", "eu-own":
	case "eu-tagged", "other-member":
		if ownOnly {
			e.status, e.code = http.StatusNotFound, gen.ProblemCodeNotFound
			return e
		}
	default: // other-tenant, missing, other-user
		e.status, e.code = http.StatusNotFound, gen.ProblemCodeNotFound
		return e
	}
	if c.recipe.ok.status != 0 {
		e.status, e.code = c.recipe.ok.status, c.recipe.ok.code
		return e
	}
	e.accepted = true
	return e
}

// send runs one call through the composed API.
func (m *matrix) send(c *call) {
	var body io.Reader
	if c.recipe.body != "" {
		body = strings.NewReader(c.recipe.body)
	}
	r := c.session.Request(context.Background(), c.op.Method, c.path(), body)
	if c.recipe.idempotent {
		r.Header.Set("Idempotency-Key", "matrix-"+uuid.NewString())
	}
	if c.actor.kind == kindCrossSite {
		r.Header.Set("Origin", "https://evil.example")
	}
	rec := httptest.NewRecorder()
	m.API.ServeHTTP(rec, r)
	c.rec, c.reqs = rec, rec.Header().Get("X-Request-Id")
}

// problemOf decodes a problem answer ("" code when the body is not a problem).
func problemOf(rec *httptest.ResponseRecorder) (gen.Problem, bool) {
	var p gen.Problem
	if !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/problem+json") {
		return p, false
	}
	return p, json.Unmarshal(rec.Body.Bytes(), &p) == nil
}

// check returns what is wrong with the answer of c (nothing ⇒ nil).
func (m *matrix) check(t *testing.T, c *call) []string {
	t.Helper()
	var bad []string
	add := func(format string, a ...any) { bad = append(bad, fmt.Sprintf(format, a...)) }
	rec, e := c.rec, c.exp
	p, isProblem := problemOf(rec)
	switch {
	case e.accepted:
		if slices.Contains([]int{401, 403, 404, 500, 501}, rec.Code) {
			add("HTTP %d %s, want an accepted answer (granted, own object, mounted handler)", rec.Code, p.Code)
		}
	case rec.Code != e.status || (e.code != "" && (!isProblem || p.Code != e.code)) || (e.code == "" && isProblem):
		add("HTTP %d %q, want %d %q", rec.Code, p.Code, e.status, e.code)
	}
	if isProblem {
		if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			add("problem without X-Content-Type-Options: nosniff")
		}
		if p.RequestId != c.reqs {
			add("problem request_id %q, X-Request-Id %q", p.RequestId, c.reqs)
		}
		if p.Code == gen.ProblemCodeNotImplemented && (p.Detail == nil || !strings.Contains(*p.Detail, goName(c.op.ID))) {
			add("501 detail %v does not name %s", p.Detail, goName(c.op.ID))
		}
	}
	// layer 1: what the authorizer decided
	d, found := m.rec.get(c.reqs)
	switch e.decision {
	case decNone:
		if found {
			add("the request reached authorization (%v, %v), want a refusal before it", d.decision.Permission, d.err)
		}
	case decGrant:
		if !found || d.err != nil {
			add("authorization: %v (found %v), want a grant", d.err, found)
			break
		}
		bad = append(bad, m.checkGrant(c, d)...)
	case decDeny:
		var denial *authz.Denial
		if !found || !errors.Is(d.err, e.denyKind) || !errors.As(d.err, &denial) || denial.Reason != e.reason {
			add("authorization: %v (found %v), want %v (%s)", d.err, found, e.denyKind, e.reason)
		}
	}
	// the access log line of the request
	line := m.AccessLine(t, c.reqs)
	if st, _ := line["status"].(float64); int(st) != rec.Code {
		add("access line status %v, answer %d", line["status"], rec.Code)
	}
	if e.decision != decNone && line["operation"] != goName(c.op.ID) {
		add("access line operation %v", line["operation"])
	}
	wantIdentity := ""
	if c.session != nil && c.session.Actor != nil && (c.actor.kind == kindPlatform || c.actor.kind == kindTenant) {
		wantIdentity = c.session.Actor.IdentityID.String()
	}
	if got, _ := line["identity"].(string); got != wantIdentity {
		add("access line identity %q, want %q", got, wantIdentity)
	}
	return bad
}

// checkGrant checks the obligations a granted decision hands to the service.
func (m *matrix) checkGrant(c *call, d decisionRecord) []string {
	var bad []string
	add := func(format string, a ...any) { bad = append(bad, fmt.Sprintf(format, a...)) }
	dec, op := d.decision, c.op
	if dec.Permission != op.Permission {
		add("decision permission %s, want %s", dec.Permission, op.Permission)
	}
	if op.Permission == authz.Public {
		return bad
	}
	if dec.Principal.IdentityID != c.actor.fx.IdentityID {
		add("decision principal %s, want %s", dec.Principal.IdentityID, c.actor.fx.IdentityID)
	}
	if op.Permission == authz.Authenticated {
		return bad
	}
	if dec.RoleKey != c.actor.role || dec.OwnOnly != c.exp.ownOnly || dec.DualControl != op.DualControl {
		add("decision role %s ownOnly %v dualControl %v, want %s %v %v", dec.RoleKey, dec.OwnOnly, dec.DualControl,
			c.actor.role, c.exp.ownOnly, op.DualControl)
	}
	if op.TenantScoped() && (dec.TenantID != c.pathTenant || dec.MembershipID != c.actor.fx.MembershipID) {
		add("decision tenant %s membership %s, want %s %s", dec.TenantID, dec.MembershipID, c.pathTenant, c.actor.fx.MembershipID)
	}
	if !op.TenantScoped() && dec.PlatformUserID != c.actor.fx.PlatformUserID {
		add("decision platform user %s, want %s", dec.PlatformUserID, c.actor.fx.PlatformUserID)
	}
	return bad
}

// run sends the calls (in parallel) and returns them in their original order.
func (m *matrix) run(calls []*call) {
	ch := make(chan *call)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for c := range ch {
				m.send(c)
			}
		})
	}
	for _, c := range calls {
		ch <- c
	}
	close(ch)
	wg.Wait()
}

// TestAuthzMatrix — IT-02 (§5.2) and the authorization matrix of P2-T15: every operation × every client × tenant of
// the path × object of the path through the composed API, answers and layer-1 decisions as §8.5/§8.6 say, no side
// effect in the tenant probed from outside (snapshot before/after), every denial audited in the actor's scope only,
// no secret in any answer or log line (IT-10, response scan). Coverage must be 100% of the operations of the spec.
func TestAuthzMatrix(t *testing.T) {
	start := time.Now()
	m := newMatrix(t)
	m.generate(t)
	byVictim := map[string][]*call{}
	for _, c := range m.calls {
		byVictim[c.victim] = append(byVictim[c.victim], c)
	}
	// Probes of A from outside, then of B: the victim's rows must not change (IT-02 "không side effect").
	for _, victim := range []string{"A", "B"} {
		ten := m.A
		if victim == "B" {
			ten = m.B
		}
		before := m.snapshot(t, ten.ID)
		m.run(byVictim[victim])
		after := m.snapshot(t, ten.ID)
		for table, sum := range before {
			if after[table] != sum {
				t.Errorf("IT-02: %d probes of tenant %s from outside changed its rows in %s (%s → %s)",
					len(byVictim[victim]), victim, table, sum, after[table])
			}
		}
	}
	m.run(byVictim[""])

	failures := map[string][]string{}
	var nFail int
	for _, c := range m.calls {
		if bad := m.check(t, c); len(bad) > 0 {
			nFail++
			if len(failures[c.op.ID]) < 6 {
				failures[c.op.ID] = append(failures[c.op.ID], c.String()+": "+strings.Join(bad, "; "))
			}
		}
	}
	ids := make([]string, 0, len(failures))
	for id := range failures {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		for _, f := range failures[id] {
			t.Error(f)
		}
	}
	if nFail > 0 {
		t.Errorf("%d of %d requests do not match §8.5/§8.6", nFail, len(m.calls))
	}
	m.checkAudit(t)
	m.scan(t)
	covered := m.report(t, failures, time.Since(start))
	if total := len(authz.Operations()); covered != total {
		t.Errorf("coverage %d/%d operations", covered, total)
	}
}

// snapshot fingerprints every row of a tenant in every table with a tenant_id column (and the tenant row, its
// identities' sessions): md5 of the rows as text, per table.
func (m *matrix) snapshot(t *testing.T, tenant uuid.UUID) map[string]string {
	t.Helper()
	out := map[string]string{}
	var tables []string
	var list string
	m.Scan(t, `SELECT string_agg(table_name, ',' ORDER BY table_name) FROM information_schema.columns
		WHERE table_schema = 'public' AND column_name = 'tenant_id'`, nil, &list)
	tables = strings.Split(list, ",")
	for _, table := range tables {
		var sum string
		m.Scan(t, `SELECT count(*)::text || ':' || coalesce(md5(string_agg(x::text, '|' ORDER BY x::text)), '') FROM `+
			table+` x WHERE tenant_id = $1`, []any{tenant}, &sum)
		out[table] = sum
	}
	for name, sql := range map[string]string{
		"tenants":  `SELECT coalesce(md5(string_agg(x::text, '|')), '') FROM tenants x WHERE id = $1`,
		"sessions": `SELECT count(*)::text || ':' || coalesce(md5(string_agg(s::text, '|' ORDER BY s::text)), '') FROM sessions s JOIN identities i ON i.id = s.identity_id WHERE i.tenant_id = $1`,
	} {
		var sum string
		m.Scan(t, sql, []any{tenant}, &sum)
		out[name] = sum
	}
	var jobs string
	m.Scan(t, `SELECT count(*)::text FROM river.river_job`, nil, &jobs)
	out["river.river_job"] = jobs
	return out
}

// checkAudit — every request refused with a principal (outside /auth/*, which the identity module audits itself) left
// exactly one denied event, in the actor's scope (its tenant, or platform for staff), never in the probed tenant
// (§8.8, P2-T08): refusals of authorization (layer 1) and, since the handler sets are mounted, the 404 of a granted
// request on an object that is not the caller's (layer 2) — whose reason is not_own_resource when an own-only grant
// meets another member's or a tagged device (§8.4 invariant 3b).
func (m *matrix) checkAudit(t *testing.T) {
	t.Helper()
	var rows string
	m.Scan(t, `SELECT coalesce(json_agg(json_build_object('r', request_id, 't', tenant_id, 'o', outcome,
			'why', details ->> 'reason')), '[]')::text
		FROM audit_events WHERE request_id IS NOT NULL`, nil, &rows)
	var events []struct {
		R   string     `json:"r"`
		T   *uuid.UUID `json:"t"`
		O   string     `json:"o"`
		Why string     `json:"why"`
	}
	if err := json.Unmarshal([]byte(rows), &events); err != nil {
		t.Fatal(err)
	}
	byReq := map[string][]int{}
	for i, e := range events {
		byReq[e.R] = append(byReq[e.R], i)
	}
	var checked, layer2, bad int
	for _, c := range m.calls {
		if c.actor.fx == nil || c.actor.kind == kindCrossOrigin || strings.HasPrefix(c.op.Path, "/auth/") {
			continue
		}
		refusedByHandler := c.exp.decision == decGrant && c.exp.status == http.StatusNotFound
		if c.exp.decision != decDeny && !refusedByHandler {
			continue
		}
		checked++
		wantWhy := ""
		if refusedByHandler {
			layer2++
			if c.exp.ownOnly && (c.objectCase == "eu-tagged" || c.objectCase == "other-member") {
				wantWhy = "not_own_resource"
			}
		}
		idx := byReq[c.reqs]
		want := (*uuid.UUID)(nil)
		if c.actor.fx.Tenant != nil {
			want = &c.actor.fx.Tenant.ID
		}
		ok := len(idx) == 1 && events[idx[0]].O == "denied" &&
			((want == nil && events[idx[0]].T == nil) || (want != nil && events[idx[0]].T != nil && *events[idx[0]].T == *want)) &&
			(wantWhy == "" || events[idx[0]].Why == wantWhy)
		if !ok {
			bad++
			if bad <= 10 {
				t.Errorf("audit of %s: %d events %v, want one denied event in the scope of %s (reason %q)", c, len(idx), idx,
					c.actor.name, wantWhy)
			}
		}
	}
	t.Logf("audit: %d denials checked (%d refused by a handler — layer 2), %d wrong", checked, layer2, bad)
}

// report logs the coverage table (and writes it as Markdown to $MG_AUTHZ_MATRIX_REPORT when set) and returns the
// number of operations fully covered: every client kind sent and every answer as expected.
func (m *matrix) report(t *testing.T, failures map[string][]string, took time.Duration) int {
	t.Helper()
	type stat struct {
		n, pending int
		byStatus   map[int]int
		kinds      map[actorKind]bool
	}
	stats := map[string]*stat{}
	byStatus := map[int]int{}
	for _, c := range m.calls {
		s := stats[c.op.ID]
		if s == nil {
			s = &stat{byStatus: map[int]int{}, kinds: map[actorKind]bool{}}
			stats[c.op.ID] = s
		}
		s.n++
		s.byStatus[c.rec.Code]++
		s.kinds[c.actor.kind] = true
		byStatus[c.rec.Code]++
		if c.exp.pending {
			s.pending++
		}
	}
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "| operation | x-permission | handler | requests | answers by status | clients |\n|---|---|---|---|---|---|\n")
	covered := 0
	for _, op := range authz.Operations() {
		s := stats[op.ID]
		if s == nil {
			fmt.Fprintf(&buf, "| `%s` | `%s` | — | 0 | — | — |\n", op.ID, op.Permission)
			continue
		}
		need := []actorKind{kindPlatform, kindTenant, kindAnonymous, kindCrossOrigin}
		if op.Method != http.MethodGet {
			need = append(need, kindCrossSite)
		}
		all := true
		for _, k := range need {
			all = all && s.kinds[k]
		}
		if all && len(failures[op.ID]) == 0 {
			covered++
		}
		codes := make([]int, 0, len(s.byStatus))
		for code := range s.byStatus {
			codes = append(codes, code)
		}
		sort.Ints(codes)
		var parts []string
		for _, code := range codes {
			parts = append(parts, fmt.Sprintf("%d×%d", code, s.byStatus[code]))
		}
		handler := "mounted"
		if !m.mounted[goName(op.ID)] {
			handler = "501 (not mounted)"
		}
		fmt.Fprintf(&buf, "| `%s` | `%s` | %s | %d | %s | %d kinds |\n", op.ID, op.Permission, handler, s.n,
			strings.Join(parts, " "), len(s.kinds))
	}
	summary := fmt.Sprintf("coverage %d/%d operations; %d requests (%d clients, %d throwaway sessions) in %s; by status %v",
		covered, len(authz.Operations()), len(m.calls), len(m.actors), len(m.throwaway), took.Round(time.Millisecond), byStatus)
	t.Log(summary)
	t.Log("\n" + buf.String())
	if path := os.Getenv("MG_AUTHZ_MATRIX_REPORT"); path != "" {
		if err := os.WriteFile(path, []byte(summary+"\n\n"+buf.String()), 0o600); err != nil { //nolint:gosec // G703: path chosen by whoever runs the test
			t.Errorf("write the report: %v", err)
		}
	}
	return covered
}
