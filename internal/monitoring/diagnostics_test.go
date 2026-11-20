package monitoring

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func checkMap(cs []Check) map[string]Check {
	out := map[string]Check{}
	for _, c := range cs {
		out[c.ID] = c
	}
	return out
}

func diagDevice(ip string, online bool) DiagDevice {
	return DiagDevice{ID: uuid.New(), Name: "host-" + ip, GivenName: "host", Addresses: []netip.Addr{netip.MustParseAddr(ip)},
		Owner: uuid.New(), Tags: []string{}, Online: online, Revocation: "none"}
}

// TestChecksAndVerdict pins the control-plane checks of a diagnosis and the verdict rule: a failed check ⇒ blocked;
// the policy undecided (no applied policy, unresolved principals) ⇒ unknown; warnings (unhealthy instance or relay,
// stale register, a later failed application) never change an allowance — the data plane does not need them.
func TestChecksAndVerdict(t *testing.T) {
	now := time.Date(2026, 11, 20, 8, 0, 0, 0, time.UTC)
	past, future := now.Add(-time.Hour), now.Add(time.Hour)
	ts := tenantState{tenant: "active", now: now, instance: InstanceDiag{Health: InstanceHealth{Status: StatusHealthy}}}
	applied := now.Add(-10 * time.Minute)
	allow := DiagPolicy{Applied: true, AppliedAt: &applied, Access: &AccessVerdict{Decision: "allowed"}}
	relays := []DiagRelay{{Code: "mg-a", Status: "active", Health: StatusHealthy}}
	base := func() ConnectivityReport {
		src, dst := diagDevice("100.64.0.1", true), diagDevice("100.64.0.2", true)
		src.SyncedAt, dst.SyncedAt = now.Add(-time.Minute), now.Add(-time.Minute)
		return ConnectivityReport{Source: src, Target: Target{Device: &dst}, Policy: allow}
	}
	type mod func(*tenantState, *ConnectivityReport, *[]DiagRelay)
	for name, c := range map[string]struct {
		mod     mod
		verdict string
		id      string
		status  string
		reason  string
	}{
		"all good": {func(*tenantState, *ConnectivityReport, *[]DiagRelay) {}, VerdictAllowed, CheckPolicyGrant, CheckPass, ""},
		"tenant suspended": {func(s *tenantState, _ *ConnectivityReport, _ *[]DiagRelay) { s.tenant = "suspended" },
			VerdictBlocked, CheckTenantActive, CheckFail, "tenant_suspended"},
		"instance unhealthy is a warning": {func(s *tenantState, _ *ConnectivityReport, _ *[]DiagRelay) {
			s.instance.Health.Status = StatusUnhealthy
		}, VerdictAllowed, CheckInstanceHealthy, CheckWarn, reasonInstanceUnhealth},
		"stale register": {func(_ *tenantState, r *ConnectivityReport, _ *[]DiagRelay) { r.Source.SyncedAt = now.Add(-time.Hour) },
			VerdictAllowed, CheckInventoryFresh, CheckWarn, reasonStaleInventory},
		"source offline": {func(_ *tenantState, r *ConnectivityReport, _ *[]DiagRelay) { r.Source.Online = false },
			VerdictBlocked, CheckSourceOnline, CheckFail, reasonOffline},
		"target expired": {func(_ *tenantState, r *ConnectivityReport, _ *[]DiagRelay) { r.Target.Device.Expiry = &past },
			VerdictBlocked, CheckTargetNotExpired, CheckFail, reasonExpired},
		"expiry in the future": {func(_ *tenantState, r *ConnectivityReport, _ *[]DiagRelay) { r.Target.Device.Expiry = &future },
			VerdictAllowed, CheckTargetNotExpired, CheckPass, ""},
		"source revocation pending": {func(_ *tenantState, r *ConnectivityReport, _ *[]DiagRelay) { r.Source.Revocation = "pending" },
			VerdictBlocked, CheckSourceNotRevoked, CheckFail, "revocation_pending"},
		"policy denies": {func(_ *tenantState, r *ConnectivityReport, _ *[]DiagRelay) {
			r.Policy.Access = &AccessVerdict{Decision: "denied", Reason: "port_not_allowed"}
		}, VerdictBlocked, CheckPolicyGrant, CheckFail, "port_not_allowed"},
		"policy undecided": {func(_ *tenantState, r *ConnectivityReport, _ *[]DiagRelay) {
			r.Policy.Access = &AccessVerdict{Decision: "unknown", Reason: "unresolved_principals"}
		}, VerdictUnknown, CheckPolicyGrant, CheckUnknown, "unresolved_principals"},
		"no applied policy": {func(_ *tenantState, r *ConnectivityReport, _ *[]DiagRelay) { r.Policy = DiagPolicy{} },
			VerdictUnknown, CheckPolicyApplied, CheckUnknown, ReasonNeverApplied},
		"later application failed": {func(_ *tenantState, r *ConnectivityReport, _ *[]DiagRelay) {
			r.Policy.LatestState, r.Policy.LatestAt = "failed", &now
		}, VerdictAllowed, CheckPolicyApplied, CheckWarn, reasonLatestFailed},
		"relay unhealthy is a warning": {func(_ *tenantState, _ *ConnectivityReport, rs *[]DiagRelay) { (*rs)[0].Health = StatusUnhealthy },
			VerdictAllowed, CheckRelayHealthy, CheckWarn, reasonUnhealthyRelay},
		"relay not active": {func(_ *tenantState, _ *ConnectivityReport, rs *[]DiagRelay) { (*rs)[0].Status = "disabled" },
			VerdictAllowed, CheckRelayHealthy, CheckUnknown, reasonNoRelayHealth},
	} {
		s, r, rs := ts, base(), slices.Clone(relays)
		c.mod(&s, &r, &rs)
		checks := checksOf(s, r, rs)
		got := checkMap(checks)[c.id]
		if v := verdictOf(checks); v != c.verdict || got.Status != c.status || got.Reason != c.reason {
			t.Errorf("%s: verdict %s, %s = %+v; want %s, %s/%s", name, v, c.id, got, c.verdict, c.status, c.reason)
		}
		if len(checks) != 13 {
			t.Errorf("%s: %d checks, want the 13 of the fixed order", name, len(checks))
		}
	}
}

// TestRouteChecks: a resource behind an approved subnet route of an online router passes; no router ⇒ fail; every
// covering router offline ⇒ fail; an address of the tailnet needs no route.
func TestRouteChecks(t *testing.T) {
	now := time.Now()
	ts := tenantState{tenant: "active", now: now, instance: InstanceDiag{Health: InstanceHealth{Status: StatusHealthy}}}
	src := diagDevice("100.64.0.1", true)
	src.SyncedAt = now
	res := &DiagResource{Name: "db", Address: netip.MustParsePrefix("10.77.0.5/32")}
	tailnet := &DiagResource{Name: "ts", Address: netip.MustParsePrefix("100.64.0.9/32")}
	router := DiagRouter{Name: "r1", Online: true, Approved: []netip.Prefix{netip.MustParsePrefix("10.77.0.0/24")}}
	offline := router
	offline.Online = false
	for name, c := range map[string]struct {
		target Target
		status string
		reason string
	}{
		"approved route":  {Target{Resource: res, Routers: []DiagRouter{router}}, CheckPass, ""},
		"no route":        {Target{Resource: res}, CheckFail, reasonNoRoute},
		"router offline":  {Target{Resource: res, Routers: []DiagRouter{offline}}, CheckFail, reasonRouterOffline},
		"tailnet address": {Target{Resource: tailnet}, CheckNotApplicable, reasonTailnetAddress},
	} {
		r := ConnectivityReport{Source: src, Target: c.target, Policy: DiagPolicy{Applied: true, Access: &AccessVerdict{Decision: "allowed"}}}
		got := checkMap(checksOf(ts, r, nil))[CheckRouteApproved]
		if got.Status != c.status || got.Reason != c.reason {
			t.Errorf("%s: %+v", name, got)
		}
	}
}

// TestChecklist: the commands per OS with the target's address filled in — a real TCP check per OS (nc,
// Test-NetConnection), curl on web ports only, the relay's code for `debug derp`, --accept-routes on Linux for a
// subnet resource, a placeholder for a subnet without a single host, the router as the `ping` target of a resource.
func TestChecklist(t *testing.T) {
	dst := diagDevice("100.64.0.2", true)
	cs := Checklist(Target{Device: &dst}, 443, "mg-acme")
	byOS := map[string][]string{}
	for _, c := range cs {
		byOS[c.OS] = append(byOS[c.OS], c.Command)
		if c.RunOn != RunOnSource && c.ID != CmdListen {
			t.Errorf("%s runs on %s", c.ID, c.RunOn)
		}
	}
	for _, want := range []string{"tailscale status", "tailscale ping --c 5 100.64.0.2", "tailscale netcheck",
		"tailscale debug derp mg-acme", "nc -vz -w 5 100.64.0.2 443",
		`curl -sS -o /dev/null -w "%{http_code}\n" --connect-timeout 5 https://100.64.0.2:443/`, "ss -ltn 'sport = :443'"} {
		if !slices.Contains(byOS[OSLinux], want) {
			t.Errorf("linux checklist %q missing %q", byOS[OSLinux], want)
		}
	}
	for _, want := range []string{"Test-NetConnection -ComputerName 100.64.0.2 -Port 443", "Get-NetTCPConnection -State Listen -LocalPort 443"} {
		if !slices.Contains(byOS[OSWindows], want) {
			t.Errorf("windows checklist %q missing %q", byOS[OSWindows], want)
		}
	}
	if !slices.Equal(commandIDs(cs), []string{CmdStatus, CmdPing, CmdNetcheck, CmdDebugDERP, CmdTCP, CmdHTTP, CmdListen}) {
		t.Errorf("ids %v", commandIDs(cs))
	}
	// no port: no TCP step; no relay: no debug derp; not a web port: no curl
	if ids := commandIDs(Checklist(Target{Device: &dst}, 0, "")); slices.Contains(ids, CmdTCP) || slices.Contains(ids, CmdDebugDERP) {
		t.Errorf("no port / no relay: %v", ids)
	}
	if ids := commandIDs(Checklist(Target{Device: &dst}, 22, "x")); slices.Contains(ids, CmdHTTP) {
		t.Errorf("port 22: %v", ids)
	}
	// a subnet resource: placeholder host, the router is pinged, Linux needs --accept-routes
	router := DiagRouter{Addresses: []netip.Addr{netip.MustParseAddr("100.64.0.7")}}
	subnet := &DiagResource{Name: "lab", Address: netip.MustParsePrefix("10.78.0.0/24")}
	cs = Checklist(Target{Resource: subnet, Routers: []DiagRouter{router}}, 5432, "")
	var linux []string
	for _, c := range cs {
		if c.OS == OSLinux {
			linux = append(linux, c.Command)
		}
		if c.ID == CmdListen {
			t.Errorf("listen check on a resource: %+v", c)
		}
		if c.ID == CmdAcceptRoutes && c.OS != OSLinux {
			t.Errorf("accept-routes on %s", c.OS)
		}
	}
	if !slices.Contains(linux, "tailscale ping --c 5 100.64.0.7") || !slices.Contains(linux, "sudo tailscale set --accept-routes") ||
		!slices.Contains(linux, "nc -vz -w 5 "+PlaceholderHost+" 5432") {
		t.Errorf("subnet checklist %q", linux)
	}
	// a device without an address in the register: its MagicDNS name
	bare := DiagDevice{GivenName: "printer"}
	if cs := Checklist(Target{Device: &bare}, 9100, ""); !slices.ContainsFunc(cs, func(c Command) bool {
		return c.ID == CmdTCP && strings.HasSuffix(c.Command, "printer 9100")
	}) {
		t.Errorf("bare device: %+v", cs)
	}
	for _, c := range cs {
		if strings.Contains(c.Command, "\n") && c.ID != CmdHTTP {
			t.Errorf("multi-line command %q", c.Command)
		}
	}
}

func TestAPIKeyAndEdge(t *testing.T) {
	now := time.Now()
	for _, c := range []struct {
		exp  *time.Time
		want string
	}{{nil, APIKeyUnknown}, {ptrT(now.Add(-time.Minute)), APIKeyExpired}, {ptrT(now.Add(24 * time.Hour)), APIKeyExpiring},
		{ptrT(now.Add(60 * 24 * time.Hour)), APIKeyValid}} {
		if got := apiKeyState(c.exp, now); got.Status != c.want {
			t.Errorf("api key %v: %s, want %s", c.exp, got.Status, c.want)
		}
	}
	at := now.Add(-time.Minute)
	for name, c := range map[string]struct {
		relays []DiagRelay
		status string
		reason string
	}{
		"no relay":       {nil, StatusUnknown, ReasonNoRelay},
		"derp ok":        {[]DiagRelay{{Status: "active", Health: StatusHealthy, CheckedAt: &at, DERP: &DiagCheck{OK: true}}}, DiagReachable, ""},
		"derp failed":    {[]DiagRelay{{Status: "active", Health: StatusUnhealthy, CheckedAt: &at, DERP: &DiagCheck{Code: "timeout"}}}, DiagUnreachable, "timeout"},
		"stale":          {[]DiagRelay{{Status: "active", Health: StatusUnknown, Reason: "stale", DERP: &DiagCheck{OK: true}}}, StatusUnknown, "stale"},
		"never probed":   {[]DiagRelay{{Status: "active", Health: StatusUnknown}}, StatusUnknown, ReasonNeverChecked},
		"only disabled":  {[]DiagRelay{{Status: "disabled", Health: StatusHealthy, DERP: &DiagCheck{OK: true}}}, StatusUnknown, ReasonNoRelay},
		"stun only fail": {[]DiagRelay{{Status: "active", Health: StatusUnhealthy, CheckedAt: &at, DERP: &DiagCheck{OK: true}, STUN: &DiagCheck{}}}, DiagReachable, ""},
	} {
		if got := edgeOf(c.relays); got.Status != c.status || got.Reason != c.reason {
			t.Errorf("%s: %+v", name, got)
		}
	}
}

func ptrT(t time.Time) *time.Time { return &t }

func TestNotFoundReason(t *testing.T) {
	err := NotFound(ReasonNotOwnResource)
	if NotFoundReason(err) != ReasonNotOwnResource || NotFoundReason(ErrDiagNotFound) != "" {
		t.Errorf("reasons %q %q", NotFoundReason(err), NotFoundReason(ErrDiagNotFound))
	}
	if !errors.Is(err, ErrDiagNotFound) {
		t.Error("NotFound is not ErrDiagNotFound")
	}
}
