package networkapi

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz/approvals"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/network"
)

// fakeSvc records the calls of the handlers and answers what the test set.
type fakeSvc struct {
	Service
	ifMatch  string
	route    network.RouteChangeInput
	idem     *network.Idempotency
	result   network.RouteResult
	resIn    network.ResourceInput
	patch    network.ResourcePatch
	recordID uuid.UUID
	err      error
}

func (f *fakeSvc) ApproveRoutes(_ context.Context, _ uuid.UUID, _ network.Actor, ifMatch string, in network.RouteChangeInput, idem *network.Idempotency) (network.RouteResult, error) {
	f.ifMatch, f.route, f.idem = ifMatch, in, idem
	return f.result, f.err
}

func (f *fakeSvc) DeleteDNSRecord(_ context.Context, _, id uuid.UUID, _ network.Actor, ifMatch string) (network.DNSRecordChange, error) {
	f.recordID, f.ifMatch = id, ifMatch
	return network.DNSRecordChange{Job: jobs.Job{ID: uuid.New(), Kind: network.KindDNSRecordsWrite, Status: "queued"}}, f.err
}

func (f *fakeSvc) CreateResource(_ context.Context, _ uuid.UUID, _ network.Actor, in network.ResourceInput, idem *network.Idempotency) (network.ResourceChange, error) {
	f.resIn, f.idem = in, idem
	return network.ResourceChange{Resource: network.Resource{ID: uuid.New(), Name: in.Name, Kind: in.Kind,
		Address: netip.MustParsePrefix("10.0.0.5/32"), Protocol: network.ProtocolAny, Version: 1}}, f.err
}

func (f *fakeSvc) UpdateResource(_ context.Context, _, _ uuid.UUID, _ network.Actor, ifMatch string, p network.ResourcePatch) (network.ResourceChange, error) {
	f.ifMatch, f.patch = ifMatch, p
	return network.ResourceChange{Resource: network.Resource{ID: uuid.New(), Version: 2, Address: netip.MustParsePrefix("10.0.0.0/24")}}, f.err
}

type fakeAppr struct {
	in   approvals.NewRequest
	idem approvals.Idempotency
	act  approvals.Actor
}

func (a *fakeAppr) RequestIdempotent(_ context.Context, actor approvals.Actor, in approvals.NewRequest, idem approvals.Idempotency) (approvals.Request, error) {
	a.act, a.in, a.idem = actor, in, idem
	t := in.TenantID
	return approvals.Request{ID: uuid.New(), TenantID: &t, Scope: authz.ScopeTenant, Action: in.Action, Status: "pending"}, nil
}

func handlers(svc *fakeSvc, appr *fakeAppr) *Handlers {
	h := New(svc, appr)
	h.actor = func(context.Context) (caller, error) {
		return caller{identityID: uuid.New(), authTime: time.Now()}, nil
	}
	return h
}

// TestApproveRoutes: the If-Match, the Idempotency-Key with the hash of the request, the body; 200 carries the new
// routes_etag; a four-eyes result becomes a tenant approval request (202 + Location) with the payload as approved.
func TestApproveRoutes(t *testing.T) {
	ctx := context.Background()
	tenant, device := uuid.New(), uuid.New()
	confirm := true
	req := gen.ApproveTenantRoutesRequestObject{TenantId: tenant, Params: gen.ApproveTenantRoutesParams{IfMatch: ptr(`"e1"`),
		IdempotencyKey: routeKey}, Body: &gen.RouteChange{DeviceId: device, Prefixes: []string{"0.0.0.0/0"}, ConfirmExitNode: &confirm}}
	svc := &fakeSvc{result: network.RouteResult{Device: &network.RouteDevice{DeviceID: device, ETag: `"e2"`}}}
	appr := &fakeAppr{}
	res, err := handlers(svc, appr).ApproveTenantRoutes(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	ok, isOK := res.(gen.ApproveTenantRoutes200JSONResponse)
	if !isOK || ok.Headers.ETag != `"e2"` || svc.ifMatch != `"e1"` || !svc.route.ConfirmExitNode || svc.route.DeviceID != device ||
		svc.idem == nil || svc.idem.Key != routeKey || len(svc.idem.Hash) != 32 {
		t.Fatalf("200: %#v %+v", res, svc)
	}
	svc.result = network.RouteResult{Approval: &network.RouteApprovalPayload{DeviceID: device, Prefixes: []string{"0.0.0.0/0", "::/0"},
		Approved: []string{"0.0.0.0/0", "::/0"}, IfMatch: `"e1"`, ExitNode: true}}
	res, err = handlers(svc, appr).ApproveTenantRoutes(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	acc, isAcc := res.(gen.ApproveTenantRoutes202JSONResponse)
	if !isAcc || acc.Headers.Location == "" || appr.in.Action != network.RouteApprovalAction || appr.in.ResourceID != device.String() ||
		appr.in.TenantID != tenant || appr.idem.Operation != "approveTenantRoutes" || appr.idem.Key != routeKey ||
		appr.act.Scope != authz.ScopeTenant {
		t.Fatalf("202: %#v %+v", res, appr)
	}
}

// TestRequestsMapped: DELETE of a record passes If-Match; a resource create maps protocol, tags, owner; PATCH maps only
// the fields sent.
func TestRequestsMapped(t *testing.T) {
	ctx := context.Background()
	svc := &fakeSvc{}
	h := handlers(svc, &fakeAppr{})
	rec := uuid.New()
	res, err := h.DeleteTenantDnsRecord(ctx, gen.DeleteTenantDnsRecordRequestObject{TenantId: uuid.New(), RecordId: rec,
		Params: gen.DeleteTenantDnsRecordParams{IfMatch: ptr(`"r1"`)}})
	if _, ok := res.(gen.DeleteTenantDnsRecord202JSONResponse); err != nil || !ok || svc.recordID != rec || svc.ifMatch != `"r1"` {
		t.Fatalf("delete record: %#v %v", res, err)
	}
	proto, tags, group := gen.NetworkResourceProtocolTcp, []string{"tag:server"}, uuid.New()
	_, err = h.CreateTenantResource(ctx, gen.CreateTenantResourceRequestObject{TenantId: uuid.New(),
		Params: gen.CreateTenantResourceParams{IdempotencyKey: resourceKey}, Body: &gen.NetworkResourceCreate{Name: "web",
			Kind: gen.NetworkResourceKindService, Address: "10.0.0.5", Ports: &[]string{"443"}, Protocol: &proto, Tags: &tags,
			OwnerGroupId: &group}})
	if err != nil || svc.resIn.Protocol != network.ProtocolTCP || svc.resIn.Kind != network.KindService || svc.resIn.OwnerGroupID == nil ||
		*svc.resIn.OwnerGroupID != group || len(svc.resIn.Tags) != 1 || svc.idem == nil {
		t.Fatalf("create resource: %+v %v", svc.resIn, err)
	}
	empty := ""
	_, err = h.UpdateTenantResource(ctx, gen.UpdateTenantResourceRequestObject{TenantId: uuid.New(), ResourceId: uuid.New(),
		Params: gen.UpdateTenantResourceParams{IfMatch: ptr(`"1"`)}, Body: &gen.NetworkResourceUpdate{OwnerGroupId: &empty}})
	if err != nil || svc.ifMatch != `"1"` || svc.patch.OwnerGroupID == nil || *svc.patch.OwnerGroupID != "" || svc.patch.Name != nil ||
		svc.patch.Kind != nil {
		t.Fatalf("patch: %+v %v", svc.patch, err)
	}
}

// TestProblemOf: every code of the module maps to its Problem; a field refusal names the field; not_found carries the
// authorization reason for the audit middleware (never sent); anything else is internal.
func TestProblemOf(t *testing.T) {
	for _, c := range []struct {
		err  error
		code gen.ProblemCode
	}{
		{&network.Error{Code: network.CodeNotFound, Reason: network.ReasonNoDevice}, gen.ProblemCodeNotFound},
		{&network.Error{Code: network.CodeValidationFailed, Reason: "route_not_advertised", Field: "prefixes", Detail: "x"}, gen.ProblemCodeValidationFailed},
		{&network.Error{Code: network.CodePreconditionReq}, gen.ProblemCodePreconditionRequired},
		{&network.Error{Code: network.CodePreconditionFailed}, gen.ProblemCodePreconditionFailed},
		{&network.Error{Code: network.CodeConflict, RetryAfter: time.Second}, gen.ProblemCodeConflict},
		{&network.Error{Code: network.CodeIdempotencyKeyReuse}, gen.ProblemCodeIdempotencyKeyReuse},
		{&network.Error{Code: network.CodeInstanceUnavailable}, gen.ProblemCodeInstanceUnavailable},
		{&network.Error{Code: network.CodeUpstreamRejected}, gen.ProblemCodeUpstreamRejected},
		{&network.Error{Code: network.CodeInternal}, gen.ProblemCodeInternalError},
		{errors.New("boom"), gen.ProblemCodeInternalError},
	} {
		var p *problem.Error
		if !errors.As(problemOf(c.err), &p) || p.Code != c.code {
			t.Errorf("%v ⇒ %+v, want %s", c.err, p, c.code)
			continue
		}
		switch c.code {
		case gen.ProblemCodeValidationFailed:
			if len(p.Fields) != 1 || p.Fields[0].Field != "prefixes" || p.Fields[0].Code != "route_not_advertised" {
				t.Errorf("fields %+v", p.Fields)
			}
		case gen.ProblemCodeNotFound:
			var d *authz.Denial
			if !errors.As(p.Cause, &d) || d.Reason != network.ReasonNoDevice {
				t.Errorf("not_found cause %v", p.Cause)
			}
		case gen.ProblemCodeInstanceUnavailable:
			if p.RetryAfter == 0 {
				t.Error("instance_unavailable without Retry-After")
			}
		}
	}
}

func ptr[T any](v T) *T { return &v }

// Idempotency-Keys of the requests (built, not literal: they are not secrets).
var (
	routeKey    = strings.Repeat("r", 12)
	resourceKey = strings.Repeat("s", 12)
)
