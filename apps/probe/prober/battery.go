package prober

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var publicKeyRE = regexp.MustCompile(`^mkey:[0-9a-f]{64}$`)

// forbiddenConcurrency bounds the parallel GETs of an edge check (the whole check stays well under the RPC timeout).
const forbiddenConcurrency = 4

// Edge runs the check of provisioning step 18 (edge.verify, §11.3) through the edge's public listener: GET
// /key?v=<capver> answers 200 with a Noise public key ("mkey:…", equal to req.PublicKey when given) and every forbidden
// path answers 404 — the edge's allow-list (§14.6).
func (l *Local) Edge(ctx context.Context, req EdgeRequest) (EdgeResult, error) {
	host := strings.ToLower(strings.TrimSpace(req.Host))
	base := HTTPSRequest{Address: req.Address, SNI: host, Host: host, TimeoutMS: req.TimeoutMS}
	if req.CapVer == 0 {
		req.CapVer = DefaultCapVer
	}
	if req.CapVer < 1 || req.CapVer > 10000 {
		return EdgeResult{}, newError(CodeInvalidRequest, "capver must be 1-10000")
	}
	if req.PublicKey != "" && !publicKeyRE.MatchString(req.PublicKey) {
		return EdgeResult{}, newError(CodeInvalidRequest, "public_key must be mkey:<64 hex digits>")
	}
	forbidden := req.Forbidden
	if forbidden == nil {
		forbidden = DefaultForbidden
	}
	if len(forbidden) == 0 || len(forbidden) > maxForbidden {
		return EdgeResult{}, newError(CodeInvalidRequest, "forbidden must list 1-64 paths")
	}
	keyReq := base
	keyReq.Path = "/key?v=" + strconv.Itoa(req.CapVer)
	keyReq.Expect = Expect{Status: []int{200}, JSONPresent: []string{"publicKey"}}
	if req.PublicKey != "" {
		keyReq.Expect.JSONEquals = map[string]string{"publicKey": req.PublicKey}
	}
	keyPlan, err := planHTTPS(keyReq)
	if err != nil {
		return EdgeResult{}, err
	}
	if err := checkTarget(l.allow, "address", keyPlan.addr); err != nil {
		return EdgeResult{}, err
	}
	plans := make([]httpsPlan, len(forbidden))
	for i, path := range forbidden {
		r := base
		r.Path, r.Expect = path, Expect{Status: []int{404}}
		if plans[i], err = planHTTPS(r); err != nil {
			return EdgeResult{}, err
		}
	}

	res := EdgeResult{Host: host, CheckedAt: l.now().UTC(), Forbidden: make([]HTTPSResult, len(plans))}
	start := time.Now()
	res.Key = l.https(ctx, keyPlan)
	if k := res.Key.JSON["publicKey"]; res.Key.Error == nil && res.Key.Status == 200 && !publicKeyRE.MatchString(k) {
		res.Key.Failures = append(res.Key.Failures, Failure{Check: "json:publicKey", Want: "mkey:<64 hex digits>", Got: bounded(k, 80)})
		res.Key.OK = false
	}
	sem := make(chan struct{}, forbiddenConcurrency)
	var wg sync.WaitGroup
	for i, p := range plans {
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
			res.Forbidden[i] = l.https(ctx, p)
		})
	}
	wg.Wait()
	res.OK = res.Key.OK
	for _, f := range res.Forbidden {
		if f.OK {
			res.Blocked++
		}
	}
	res.OK = res.OK && res.Blocked == len(res.Forbidden)
	res.TotalMS = ms(time.Since(start))
	l.log.InfoContext(ctx, "probe", "kind", "edge", "address", res.Key.Address, "host", host, "ok", res.OK,
		"key_status", res.Key.Status, "key_code", code(res.Key.Error), "blocked", res.Blocked, "forbidden", len(res.Forbidden),
		"total_ms", res.TotalMS)
	return res, nil
}

// Relay runs the check of provisioning step 17 (relay.assign, §11.3): GET /derp/probe of the tenant through the edge
// answers 200 (the instance's embedded DERP) and the shared STUN responder answers a Binding Request.
func (l *Local) Relay(ctx context.Context, req RelayRequest) (RelayResult, error) {
	host := strings.ToLower(strings.TrimSpace(req.Host))
	derpPlan, err := planHTTPS(HTTPSRequest{Address: req.Address, SNI: host, Host: host, Path: "/derp/probe",
		TimeoutMS: req.TimeoutMS, Expect: Expect{Status: []int{200}}})
	if err != nil {
		return RelayResult{}, err
	}
	stunTarget, err := parseTarget("stun", req.STUN)
	if err != nil {
		return RelayResult{}, err
	}
	stunLimit, err := timeout(req.TimeoutMS, DefaultSTUNTimeout)
	if err != nil {
		return RelayResult{}, err
	}
	if err := checkTarget(l.allow, "address", derpPlan.addr); err != nil {
		return RelayResult{}, err
	}
	if err := checkTarget(l.allow, "stun", stunTarget); err != nil {
		return RelayResult{}, err
	}
	res := RelayResult{Host: host, CheckedAt: l.now().UTC()}
	start := time.Now()
	var wg sync.WaitGroup
	wg.Go(func() { res.DERP = l.https(ctx, derpPlan) })
	wg.Go(func() {
		s := STUNResult{Target: stunTarget.String(), CheckedAt: res.CheckedAt}
		t0 := time.Now()
		s.Error = l.stun(ctx, stunTarget, stunLimit, &s)
		s.OK, s.TotalMS = s.Error == nil, ms(time.Since(t0))
		res.STUN = s
	})
	wg.Wait()
	res.OK = res.DERP.OK && res.STUN.OK
	res.TotalMS = ms(time.Since(start))
	l.log.InfoContext(ctx, "probe", "kind", "relay", "address", res.DERP.Address, "host", host, "ok", res.OK,
		"derp_status", res.DERP.Status, "derp_code", code(res.DERP.Error), "stun", res.STUN.Target,
		"stun_code", code(res.STUN.Error), "total_ms", res.TotalMS)
	return res, nil
}
