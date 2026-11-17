package contract

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
)

// Phase 1 — a freshly started instance (rendered config, no policy yet).

func TestP1_FreshInstance(t *testing.T) {
	e := setup(t)
	inst := e.inst(t)
	c := ctx(t)
	v, err := inst.Version(c)
	if err != nil || v != "v0.29.7" {
		t.Fatalf("Version = %q, %v", v, err)
	}
	h, err := inst.Health(c)
	if err != nil || !h.DatabaseConnectivity {
		t.Fatalf("Health = %+v, %v", h, err)
	}
	_, commit := e.versionInfo(t)
	if commit != e.expectCommit {
		t.Fatalf("GET /version commit = %s, want the patched build's %s", commit, e.expectCommit)
	}
	e.record(t, "version", "GET /version qua listener admin", fmt.Sprintf("version=%s commit=%s (bản vá P2-T10a; image chính thức: %s); supported range %s; health databaseConnectivity=%v",
		v, commit, e.officialCommit, headscale.SupportedVersions(), h.DatabaseConnectivity),
		"ForTenant kiểm version trước khi chọn implementation; ngoài dải ⇒ unsupported_version — bản vá giữ version v0.29.7, dấu bản vá nằm ở commit")

	_, firstRead := inst.GetPolicy(c)
	if !errors.Is(firstRead, headscale.ErrNoPolicy) {
		t.Fatalf("GetPolicy on a new instance: %v", firstRead)
	}
	e.ensureUser(t, inst, userAlice)
	e.ensureUser(t, inst, userBob)
	obsUser := e.ensureUser(t, inst, userObserver)
	o := newFakeNode("ct-observer")
	e.registerWithKey(t, o, e.userKey(t, inst, obsUser.ID), time.Time{})
	before := filterSummary(e.firstMap(t, o))
	if before != "allow-all" {
		t.Fatalf("new instance without policy: filter %s, want allow-all (PL-02)", before)
	}
	if _, err := inst.SetPolicy(c, portPolicy(1000)); err != nil {
		t.Fatalf("SetPolicy P(tcp:1000): %v", err)
	}
	after := filterSummary(e.firstMap(t, o))
	if after != "ports=1000" {
		t.Fatalf("filter after SetPolicy = %s", after)
	}
	e.record(t, "PL-02", "instance mới (policy.mode database) trước SetPolicy đầu tiên",
		fmt.Sprintf("GetPolicy ⇒ %s; filter của node = %s; sau SetPolicy P(tcp:1000): filter = %s", describe(firstRead), before, after),
		"GetPolicy trả ErrNoPolicy (no_policy) — job drift coi là Critical (§13.4)")
	s := e.loadState(t)
	s.Nodes["observer"] = o
	e.saveState(t, s)
}

// TestP1_DBCreatedByOfficialImage: before phase 1 the runner started the OFFICIAL image on the empty data volume (it
// created and migrated the database and the user ct-boot), then replaced it with the patched build (P2-T10a).
func TestP1_DBCreatedByOfficialImage(t *testing.T) {
	e := setup(t)
	inst := e.inst(t)
	users, err := inst.ListUsers(ctx(t), headscale.UserFilter{Name: userBoot})
	if err != nil || len(users) != 1 {
		t.Fatalf("user created by the official image: %v %+v", err, users)
	}
	e.record(t, "P2-T10a", "DB do image CHÍNH THỨC tạo, bản vá mở",
		fmt.Sprintf("user %s (id %d, tạo bằng CLI của image chính thức) đọc được qua bản vá; instance healthy", users[0].Name, users[0].ID), "")
}

func TestP1_EdgeHeaderScheme(t *testing.T) {
	e := setup(t)
	type edgeCase struct {
		name   string
		req    rawReq
		status int
	}
	cases := []edgeCase{
		{"đúng token + slug + API key", rawReq{method: "GET", path: "/api/v1/user"}, 200},
		{"thiếu X-MG-Token", rawReq{method: "GET", path: "/api/v1/user", header: map[string]string{headscale.HeaderEdgeToken: ""}}, 403},
		{"X-MG-Token sai", rawReq{method: "GET", path: "/api/v1/user", header: map[string]string{headscale.HeaderEdgeToken: strings.Repeat("Z", 40)}}, 403},
		{"X-MG-Instance sai định dạng", rawReq{method: "GET", path: "/api/v1/user", header: map[string]string{headscale.HeaderInstance: "Bad_Slug"}}, 404},
		{"X-MG-Instance hợp lệ nhưng không tồn tại", rawReq{method: "GET", path: "/api/v1/user", header: map[string]string{headscale.HeaderInstance: "nosuchtenant"}}, 404},
		{"path ngoài allow-list (/swagger)", rawReq{method: "GET", path: "/swagger"}, 404},
		{"path ngoài allow-list (/key)", rawReq{method: "GET", path: "/key", query: url.Values{"v": {"113"}}}, 404},
		{"POST /version", rawReq{method: "POST", path: "/version"}, 404},
		{"GET /version không cần API key", rawReq{method: "GET", path: "/version", header: map[string]string{"Authorization": ""}}, 200},
		{"API key sai", rawReq{method: "GET", path: "/api/v1/user", header: map[string]string{"Authorization": "Bearer nope"}}, 401},
	}
	var obs []string
	for _, tc := range cases {
		status, body := e.raw(t, tc.req)
		if status != tc.status {
			t.Errorf("%s: http %d (%s), want %d", tc.name, status, truncate(body, 100), tc.status)
		}
		obs = append(obs, fmt.Sprintf("%s ⇒ %s", tc.name, gatewayBody(status, body)))
	}
	// The adapter's classification of the same answers.
	_, errTok := e.instWith(t, func(tg *headscale.Target) { tg.EdgeToken = headscale.NewSecret(strings.Repeat("Z", 40)) })
	_, errSlug := e.instWith(t, func(tg *headscale.Target) { tg.Slug = "nosuchtenant" })
	badKey, err := e.instWith(t, func(tg *headscale.Target) { tg.APIKey = headscale.NewSecret("nope") })
	if err != nil {
		t.Fatalf("version probe does not need the API key: %v", err)
	}
	_, errKey := badKey.ListUsers(ctx(t), headscale.UserFilter{})
	if kindOf(errTok) != "edge_rejected" || kindOf(errSlug) != "unavailable" || kindOf(errKey) != "api_key_rejected" {
		t.Fatalf("adapter kinds: token=%s slug=%s key=%s", kindOf(errTok), kindOf(errSlug), kindOf(errKey))
	}
	e.record(t, "§14.6", "header scheme của listener admin (Caddyfile.tmpl thật, Caddy 2.11.9)", strings.Join(obs, "; "),
		fmt.Sprintf("adapter: token sai ⇒ %s; slug không tồn tại ⇒ %s; API key sai ⇒ %s", kindOf(errTok), kindOf(errSlug), kindOf(errKey)))
}

func TestP1_AllOperations(t *testing.T) {
	e := setup(t)
	inst := e.inst(t)
	c := ctx(t)
	var done []string
	step := func(name string, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		done = append(done, name)
	}

	u, err := inst.CreateUser(c, headscale.CreateUser{Name: "ct-ops", DisplayName: "Contract ops"})
	step("CreateUser", err)
	users, err := inst.ListUsers(c, headscale.UserFilter{Name: "ct-ops"})
	if err == nil && (len(users) != 1 || users[0].ID != u.ID) {
		err = fmt.Errorf("ListUsers(name) = %+v", users)
	}
	step("ListUsers(name)", err)
	users, err = inst.ListUsers(c, headscale.UserFilter{ID: u.ID})
	if err == nil && len(users) != 1 {
		err = fmt.Errorf("ListUsers(id) = %+v", users)
	}
	step("ListUsers(id)", err)
	ru, err := inst.RenameUser(c, u.ID, "ct-ops.renamed")
	if err == nil && ru.Name != "ct-ops.renamed" {
		err = fmt.Errorf("RenameUser = %+v", ru)
	}
	step("RenameUser", err)
	_, err = inst.RenameUser(c, u.ID, "ct-ops")
	step("RenameUser(back)", err)

	exp := time.Now().Add(10 * time.Minute).Truncate(time.Second)
	k, err := inst.CreatePreAuthKey(c, headscale.PreAuthKeyOpts{User: u.ID, Expiration: exp})
	if err == nil && (!k.Expiration.Equal(exp) || k.Key.IsZero() || k.KeyPrefix == "" || k.User == nil || k.User.ID != u.ID) {
		err = fmt.Errorf("CreatePreAuthKey = %+v (expiration %s)", k, k.Expiration)
	}
	step("CreatePreAuthKey(user)", err)
	tk, err := inst.CreatePreAuthKey(c, headscale.PreAuthKeyOpts{Tags: []string{"tag:ct-ci"}, Expiration: exp})
	if err == nil && (tk.User != nil || len(tk.Tags) != 1) {
		err = fmt.Errorf("tag-only key = %+v", tk)
	}
	step("CreatePreAuthKey(tag-only)", err)
	keys, err := inst.ListPreAuthKeys(c)
	found := false
	for _, x := range keys {
		if x.ID == k.ID {
			found = x.KeyPrefix == k.KeyPrefix && x.Key.IsZero()
		}
	}
	if err == nil && !found {
		err = fmt.Errorf("ListPreAuthKeys does not show key %d with its prefix only", k.ID)
	}
	step("ListPreAuthKeys", err)

	n := newFakeNode("ct-ops-node")
	n.Routes = []netip.Prefix{netip.MustParsePrefix("10.98.0.0/24")}
	e.registerWithKey(t, n, k.Key.Reveal(), time.Time{})
	nodes, err := inst.ListNodes(c, "ct-ops")
	if err == nil && (len(nodes) != 1 || nodes[0].RegisterMethod != headscale.RegisterMethodAuthKey || nodes[0].PreAuthKeyID != k.ID) {
		err = fmt.Errorf("ListNodes(user) = %+v", nodes)
	}
	step("ListNodes(user)", err)
	id := e.nodeOf(t, inst, n).ID
	g, err := inst.GetNode(c, id)
	if err == nil && g.NodeKey != n.Node.Public().String() {
		err = fmt.Errorf("GetNode = %+v", g)
	}
	step("GetNode", err)
	rn, err := inst.RenameNode(c, id, "ct-ops-renamed")
	if err == nil && rn.GivenName != "ct-ops-renamed" {
		err = fmt.Errorf("RenameNode = %+v", rn)
	}
	step("RenameNode", err)
	_, stop := e.mapSession(t, n) // announce 10.98.0.0/24
	ar, err := inst.SetApprovedRoutes(c, id, []netip.Prefix{netip.MustParsePrefix("10.98.0.0/24")})
	if err == nil && (len(ar.ApprovedRoutes) != 1 || ar.ApprovedRoutes[0].String() != "10.98.0.0/24") {
		err = fmt.Errorf("SetApprovedRoutes = %s", routes(ar))
	}
	step("SetApprovedRoutes", err)
	ar, err = inst.SetApprovedRoutes(c, id, nil)
	if err == nil && len(ar.ApprovedRoutes) != 0 {
		err = fmt.Errorf("SetApprovedRoutes([]) = %s", routes(ar))
	}
	step("SetApprovedRoutes([] = revoke all)", err)
	stop()
	future := time.Now().Add(48 * time.Hour).Truncate(time.Second)
	en, err := inst.ExpireNode(c, id, &future)
	if err == nil && (en.Expiry == nil || !en.Expiry.Equal(future)) {
		err = fmt.Errorf("ExpireNode(future) expiry = %s", expiryString(en.Expiry))
	}
	step("ExpireNode(explicit future time)", err)
	en, err = inst.ExpireNode(c, id, nil)
	if err == nil && (en.Expiry == nil || en.Expiry.After(time.Now())) {
		err = fmt.Errorf("ExpireNode(now) expiry = %s", expiryString(en.Expiry))
	}
	step("ExpireNode(now)", err)

	n2 := newFakeNode("ct-ops-tagme")
	e.registerWithKey(t, n2, e.userKey(t, inst, u.ID), time.Time{})
	id2 := e.nodeOf(t, inst, n2).ID
	tn, err := inst.SetTags(c, id2, []string{"tag:ct-tagged"})
	if err == nil && (len(tn.Tags) != 1 || tn.Tags[0] != "tag:ct-tagged") {
		err = fmt.Errorf("SetTags = %+v", tn.Tags)
	}
	step("SetTags", err)
	step("DeleteNode(tagged)", inst.DeleteNode(c, id2))
	step("DeleteNode", inst.DeleteNode(c, id))
	step("ExpirePreAuthKey", inst.ExpirePreAuthKey(c, k.ID))
	keys, _ = inst.ListPreAuthKeys(c)
	for _, x := range keys {
		if x.ID == k.ID && x.Expiration.After(time.Now()) {
			t.Fatalf("pre-auth key %d not expired: %s", k.ID, x.Expiration)
		}
	}
	step("DeletePreAuthKey", inst.DeletePreAuthKey(c, tk.ID))

	// Web authentication: AuthRegister and AuthReject.
	w := newFakeNode("ct-ops-web")
	nc := e.noise(t, w)
	_, authID := e.startInteractive(t, nc, w, time.Time{})
	wn, err := inst.AuthRegister(c, "ct-ops", authID)
	if err == nil && (wn.RegisterMethod != headscale.RegisterMethodCLI || owner(wn) != "ct-ops") {
		err = fmt.Errorf("AuthRegister node = method %s owner %s", wn.RegisterMethod, owner(wn))
	}
	step("AuthRegister", err)
	step("DeleteNode(web)", inst.DeleteNode(c, wn.ID))
	r := newFakeNode("ct-ops-reject")
	ncr := e.noise(t, r)
	_, rid := e.startInteractive(t, ncr, r, time.Time{})
	step("AuthReject", inst.AuthReject(c, rid))

	// Policy and API keys.
	stored, err := inst.GetPolicy(c)
	if err == nil && stored.Data != portPolicy(1000) {
		err = fmt.Errorf("GetPolicy = %s", stored.Data)
	}
	step("GetPolicy", err)
	step("CheckPolicy", inst.CheckPolicy(c, portPolicy(1000)))
	_, err = inst.SetPolicy(c, portPolicy(1000))
	step("SetPolicy (same document)", err)
	newKey, err := inst.CreateAPIKey(c, time.Now().Add(time.Hour))
	step("CreateAPIKey", err)
	prefix := headscale.APIKeyPrefix(newKey)
	aks, err := inst.ListAPIKeys(c)
	var display bool
	for _, x := range aks {
		display = display || x.Prefix == prefix
	}
	if err == nil && !display {
		err = fmt.Errorf("ListAPIKeys does not show the new prefix")
	}
	step("ListAPIKeys", err)
	step("ExpireAPIKey(display form hskey-api-<prefix>-***)", inst.ExpireAPIKey(c, "hskey-api-"+prefix+"-***"))
	st, _ := e.raw(t, rawReq{method: "GET", path: "/api/v1/user", header: map[string]string{"Authorization": "Bearer " + newKey.Reveal()}})
	if st != http.StatusUnauthorized {
		t.Fatalf("expired API key still accepted: http %d", st)
	}
	step("DeleteUser", inst.DeleteUser(c, u.ID))
	e.record(t, "§13.4", "mọi operation của Instance trên 0.29.7", strings.Join(done, ", ")+" — tất cả thành công",
		"v029 cài đủ 26 operation; ExpireAPIKey nhận cả prefix trần lẫn dạng hiển thị")
}

func TestP1_ErrorMapping(t *testing.T) {
	e := setup(t)
	inst := e.inst(t)
	c := ctx(t)
	errUser := e.ensureUser(t, inst, "ct-err")
	other := e.ensureUser(t, inst, "ct-err2")
	n := newFakeNode("ct-err-node")
	e.registerWithKey(t, n, e.userKey(t, inst, errUser.ID), time.Time{})
	node := e.nodeOf(t, inst, n)
	n2 := newFakeNode("ct-err-node2")
	e.registerWithKey(t, n2, e.userKey(t, inst, other.ID), time.Time{})
	node2 := e.nodeOf(t, inst, n2)
	pending := newFakeNode("ct-err-pending")
	_, pendingID := e.startInteractive(t, e.noise(t, pending), pending, time.Time{})
	future := time.Now().Add(time.Hour)
	const missing = 999999

	type ec struct {
		name string
		call func() error
		want string // adapter kind ("" = success)
		raw  rawReq
	}
	body := func(v any) string { return mustJSON(v) }
	cases := []ec{
		{"GetNode id không tồn tại", func() error { _, err := inst.GetNode(c, missing); return err }, "not_found",
			rawReq{method: "GET", path: "/api/v1/node/999999"}},
		{"DeleteNode id không tồn tại", func() error { return inst.DeleteNode(c, missing) }, "not_found",
			rawReq{method: "DELETE", path: "/api/v1/node/999999"}},
		{"RenameNode id không tồn tại", func() error { _, err := inst.RenameNode(c, missing, "ct-x"); return err }, "not_found",
			rawReq{method: "POST", path: "/api/v1/node/999999/rename/ct-x"}},
		{"RenameNode trùng tên node khác", func() error { _, err := inst.RenameNode(c, node.ID, node2.GivenName); return err }, "conflict",
			rawReq{method: "POST", path: fmt.Sprintf("/api/v1/node/%d/rename/%s", node.ID, node2.GivenName)}},
		{"SetTags node không tồn tại", func() error { _, err := inst.SetTags(c, missing, []string{"tag:ct-tagged"}); return err }, "not_found",
			rawReq{method: "POST", path: "/api/v1/node/999999/tags", body: body(map[string]any{"tags": []string{"tag:ct-tagged"}})}},
		{"SetTags tag không có trong policy", func() error { _, err := inst.SetTags(c, node.ID, []string{"tag:ct-undeclared"}); return err }, "validation",
			rawReq{method: "POST", path: fmt.Sprintf("/api/v1/node/%d/tags", node.ID), body: body(map[string]any{"tags": []string{"tag:ct-undeclared"}})}},
		{"SetApprovedRoutes node không tồn tại", func() error {
			_, err := inst.SetApprovedRoutes(c, missing, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")})
			return err
		}, "not_found", rawReq{method: "POST", path: "/api/v1/node/999999/approve_routes", body: body(map[string]any{"routes": []string{"10.0.0.0/24"}})}},
		{"ExpireNode node không tồn tại", func() error { _, err := inst.ExpireNode(c, missing, &future); return err }, "not_found",
			rawReq{method: "POST", path: "/api/v1/node/999999/expire", query: url.Values{"expiry": {future.UTC().Format(time.RFC3339)}}}},
		{"CreateUser trùng tên", func() error { _, err := inst.CreateUser(c, headscale.CreateUser{Name: "ct-err"}); return err }, "conflict",
			rawReq{method: "POST", path: "/api/v1/user", body: body(map[string]any{"name": "ct-err"})}},
		{"RenameUser id không tồn tại", func() error { _, err := inst.RenameUser(c, missing, "ct-zz"); return err }, "not_found",
			rawReq{method: "POST", path: "/api/v1/user/999999/rename/ct-zz"}},
		{"RenameUser sang tên đã có", func() error { _, err := inst.RenameUser(c, errUser.ID, "ct-err2"); return err }, "conflict",
			rawReq{method: "POST", path: fmt.Sprintf("/api/v1/user/%d/rename/ct-err2", errUser.ID)}},
		{"DeleteUser id không tồn tại", func() error { return inst.DeleteUser(c, missing) }, "not_found",
			rawReq{method: "DELETE", path: "/api/v1/user/999999"}},
		{"DeleteUser còn node", func() error { return inst.DeleteUser(c, errUser.ID) }, "conflict",
			rawReq{method: "DELETE", path: fmt.Sprintf("/api/v1/user/%d", errUser.ID)}},
		{"ListNodes user không tồn tại", func() error { _, err := inst.ListNodes(c, "ct-nobody"); return err }, "not_found",
			rawReq{method: "GET", path: "/api/v1/node", query: url.Values{"user": {"ct-nobody"}}}},
		{"CreatePreAuthKey user không tồn tại", func() error {
			_, err := inst.CreatePreAuthKey(c, headscale.PreAuthKeyOpts{User: missing, Expiration: future})
			return err
		}, "not_found", rawReq{method: "POST", path: "/api/v1/preauthkey", body: body(map[string]any{"user": "999999", "expiration": future.UTC().Format(time.RFC3339)})}},
		{"ExpirePreAuthKey id không tồn tại (idempotent)", func() error { return inst.ExpirePreAuthKey(c, missing) }, "",
			rawReq{method: "POST", path: "/api/v1/preauthkey/expire", body: `{"id":"999999"}`}},
		{"DeletePreAuthKey id không tồn tại (idempotent)", func() error { return inst.DeletePreAuthKey(c, missing) }, "",
			rawReq{method: "DELETE", path: "/api/v1/preauthkey", query: url.Values{"id": {"999999"}}}},
		{"AuthRegister Auth ID không có trong cache", func() error { _, err := inst.AuthRegister(c, "ct-err", unknownAuthID()); return err }, "validation",
			rawReq{method: "POST", path: "/api/v1/auth/register", body: body(map[string]any{"user": "ct-err", "authId": unknownAuthID()})}},
		{"AuthRegister user không tồn tại", func() error { _, err := inst.AuthRegister(c, "ct-ghost", pendingID); return err }, "not_found",
			rawReq{method: "POST", path: "/api/v1/auth/register", body: body(map[string]any{"user": "ct-ghost", "authId": pendingID})}},
		{"AuthApprove Auth ID không có trong cache", func() error { return inst.AuthApprove(c, unknownAuthID()) }, "validation",
			rawReq{method: "POST", path: "/api/v1/auth/approve", body: body(map[string]any{"authId": unknownAuthID()})}},
		{"AuthReject Auth ID không có trong cache", func() error { return inst.AuthReject(c, unknownAuthID()) }, "validation",
			rawReq{method: "POST", path: "/api/v1/auth/reject", body: body(map[string]any{"authId": unknownAuthID()})}},
		{"ExpireAPIKey prefix không tồn tại", func() error { return inst.ExpireAPIKey(c, "AAAAAAAAAAAA") }, "not_found",
			rawReq{method: "POST", path: "/api/v1/apikey/expire", body: `{"prefix":"AAAAAAAAAAAA"}`}},
		{"CheckPolicy tham chiếu group chưa khai báo", func() error {
			return inst.CheckPolicy(c, `{"grants":[{"src":["group:nope"],"dst":["*"],"ip":["*"]}]}`)
		}, "policy_rejected", rawReq{method: "POST", path: "/api/v1/policy/check",
			body: body(map[string]any{"policy": `{"grants":[{"src":["group:nope"],"dst":["*"],"ip":["*"]}]}`})}},
	}
	for _, tc := range cases {
		err := tc.call()
		got := kindOf(err)
		status, rb := e.raw(t, tc.raw)
		if got != tc.want {
			t.Errorf("%s: adapter kind %q, want %q (%s); raw %s", tc.name, got, tc.want, describe(err), gatewayBody(status, rb))
		}
		e.record(t, "error-map", tc.name, gatewayBody(status, rb), describe(err))
	}
	// Answers the adapter never provokes (blocked locally) — recorded for the mapping table.
	const blocked = "chặn cục bộ: validation_failed, không gọi Headscale"
	rawOnly := []struct {
		name, adapter string
		req           rawReq
	}{
		{"SetTags tag sai định dạng", blocked, rawReq{method: "POST", path: fmt.Sprintf("/api/v1/node/%d/tags", node.ID), body: `{"tags":["Tag:Bad"]}`}},
		{"RenameNode tên không phải nhãn DNS", blocked, rawReq{method: "POST", path: fmt.Sprintf("/api/v1/node/%d/rename/Bad_Name", node.ID)}},
		{"AuthRegister Auth ID sai định dạng", blocked, rawReq{method: "POST", path: "/api/v1/auth/register", body: `{"user":"ct-err","authId":"x"}`}},
		{"AuthApprove Auth ID sai định dạng", blocked, rawReq{method: "POST", path: "/api/v1/auth/approve", body: `{"authId":"x"}`}},
		{"SetApprovedRoutes prefix sai", blocked, rawReq{method: "POST", path: fmt.Sprintf("/api/v1/node/%d/approve_routes", node.ID), body: `{"routes":["x"]}`}},
		{"ExpireNode năm 10000", blocked, rawReq{method: "POST", path: fmt.Sprintf("/api/v1/node/%d/expire", node.ID), query: url.Values{"expiry": {"10000-01-01T00:00:00Z"}}}},
		{"route không tồn tại trên version này", "code 5 + message đúng \"Not Found\" ⇒ upstream_rejected (không phải not_found)",
			rawReq{method: "GET", path: "/api/v1/nosuchroute"}},
		{"CreateUser tên vi phạm ID-08 (REST không kiểm)", blocked, rawReq{method: "POST", path: "/api/v1/user", body: `{"name":"1 bad/name"}`}},
	}
	for _, r := range rawOnly {
		status, rb := e.raw(t, r.req)
		e.record(t, "error-map", r.name, gatewayBody(status, rb), r.adapter)
	}
	// Clean the invalid user if Headscale accepted it (ID-08: REST does not check names).
	if us, err := inst.ListUsers(c, headscale.UserFilter{}); err == nil {
		for _, u := range us {
			if u.Name == "1 bad/name" {
				_, _ = e.raw(t, rawReq{method: "DELETE", path: "/api/v1/user/" + strconv.FormatUint(u.ID, 10)})
			}
		}
	}
}

func TestP1_V06_PreAuthKeyWithoutExpiration(t *testing.T) {
	e := setup(t)
	inst := e.inst(t)
	u := e.ensureUser(t, inst, "ct-v06")
	status, body := e.raw(t, rawReq{method: "POST", path: "/api/v1/preauthkey", body: fmt.Sprintf(`{"user":"%d","reusable":false}`, u.ID)})
	var out struct {
		PreAuthKey struct {
			Key        string `json:"key"`
			Expiration string `json:"expiration"`
		} `json:"preAuthKey"`
	}
	if status != 200 || json.Unmarshal([]byte(body), &out) != nil || out.PreAuthKey.Key == "" {
		t.Fatalf("raw create without expiration: http %d", status)
	}
	n := newFakeNode("ct-v06-noexp")
	resp, rstatus, rbody := e.register(t, e.noise(t, n), n, tailcfg.RegisterRequest{Auth: &tailcfg.RegisterResponseAuth{AuthKey: out.PreAuthKey.Key}})
	if rstatus == 200 && resp.Error == "" && resp.MachineAuthorized {
		t.Fatal("a key created without expiration registered a node")
	}
	_, aerr := inst.CreatePreAuthKey(ctx(t), headscale.PreAuthKeyOpts{User: u.ID})
	if kindOf(aerr) != "validation" {
		t.Fatalf("adapter accepted a key without expiration: %v", aerr)
	}
	exp := time.Now().Add(5 * time.Minute).Truncate(time.Second)
	k, err := inst.CreatePreAuthKey(ctx(t), headscale.PreAuthKeyOpts{User: u.ID, Expiration: exp})
	if err != nil || !k.Expiration.Equal(exp) {
		t.Fatalf("explicit expiration not stored: %v %s", err, k.Expiration)
	}
	e.record(t, "V-06", "CreatePreAuthKey không kèm expiration",
		fmt.Sprintf("HTTP %d, key được tạo với expiration=%s; đăng ký bằng key đó ⇒ http %d %q (error %q)",
			status, out.PreAuthKey.Expiration, rstatus, truncate(rbody, 120), resp.Error),
		fmt.Sprintf("adapter từ chối cục bộ (%s); luôn gửi expiration tường minh — key +5m lưu đúng %s", kindOf(aerr), k.Expiration.UTC().Format(time.RFC3339)))
}

func TestP1_V06_APIKeyWithoutExpiration(t *testing.T) {
	e := setup(t)
	inst := e.inst(t)
	status, body := e.raw(t, rawReq{method: "POST", path: "/api/v1/apikey", body: `{}`})
	var out struct {
		APIKey string `json:"apiKey"`
	}
	if status != 200 || json.Unmarshal([]byte(body), &out) != nil || out.APIKey == "" {
		t.Fatalf("raw API key without expiration: http %d", status)
	}
	prefix := headscale.APIKeyPrefix(headscale.NewSecret(out.APIKey))
	var expiration string
	aks, _ := inst.ListAPIKeys(ctx(t))
	for _, k := range aks {
		if k.Prefix == prefix {
			expiration = k.Expiration.UTC().Format(time.RFC3339)
		}
	}
	use, _ := e.raw(t, rawReq{method: "GET", path: "/api/v1/user", header: map[string]string{"Authorization": "Bearer " + out.APIKey}})
	if use != http.StatusUnauthorized {
		t.Fatalf("API key without expiration was accepted: http %d", use)
	}
	del, delBody := e.raw(t, rawReq{method: "DELETE", path: "/api/v1/apikey/" + prefix})
	_, aerr := inst.CreateAPIKey(ctx(t), time.Time{})
	if kindOf(aerr) != "validation" {
		t.Fatalf("adapter accepted an API key without expiration: %v", aerr)
	}
	e.record(t, "V-06", "CreateApiKey không kèm expiration",
		fmt.Sprintf("HTTP %d, key được tạo với expiration=%s; dùng key ⇒ http %d (đã hết hạn ngay); DeleteApiKey(prefix) ⇒ %s",
			status, expiration, use, gatewayBody(del, delBody)),
		"adapter từ chối cục bộ (validation) và luôn gửi expiration tường minh")
}

func TestP1_V06_KeyEndpointCapver(t *testing.T) {
	e := setup(t)
	cur := strconv.Itoa(int(tailcfg.CurrentCapabilityVersion))
	cases := []struct {
		q      string
		status int
	}{{"", 400}, {"?v=abc", 400}, {"?v=112", 400}, {"?v=113", 200}, {"?v=" + cur, 200}}
	var obs []string
	for _, tc := range cases {
		status, body := e.control(t, "/key"+tc.q)
		if status != tc.status {
			t.Errorf("/key%s: http %d (%s), want %d", tc.q, status, body, tc.status)
		}
		if status == 200 {
			var k struct {
				PublicKey key.MachinePublic `json:"publicKey"`
			}
			if err := json.Unmarshal([]byte(body), &k); err != nil || k.PublicKey.IsZero() {
				t.Errorf("/key%s: body %s", tc.q, body)
			}
			body = "publicKey mkey:…"
		}
		obs = append(obs, fmt.Sprintf("/key%s ⇒ %d %q", tc.q, status, body))
	}
	e.record(t, "V-06", "GET /key cần ?v=<capver> (RT-02a)", strings.Join(obs, "; ")+fmt.Sprintf(" (capver hiện hành của tailscale.com v1.104.7 = %s)", cur),
		"adapter không gọi /key (listener admin trả 404); probe sức khỏe phải gọi /key?v=<capver ≥ 113>")
}

func TestP1_V06_SetPolicyErrors(t *testing.T) {
	e := setup(t)
	inst := e.inst(t)
	s := e.loadState(t)
	o := s.Nodes["observer"]
	before := e.storedPolicy(t, inst)
	liveBefore := filterSummary(e.firstMap(t, o))
	bad := []struct{ name, doc string }{
		{"khóa top-level lạ", `{"grants":[],"postures":{}}`},
		{"group chưa khai báo", `{"grants":[{"src":["group:nope"],"dst":["*"],"ip":["*"]}]}`},
		{"lỗi cú pháp HuJSON", `{"grants":[`},
		{"tests thất bại", `{"grants":[],"tests":[{"src":"ct-observer@","accept":["ct-observer@:1000"]}]}`},
	}
	var obs []string
	for _, b := range bad {
		status, body := e.raw(t, rawReq{method: "PUT", path: "/api/v1/policy", body: mustJSON(map[string]string{"policy": b.doc})})
		cs, cb := e.raw(t, rawReq{method: "POST", path: "/api/v1/policy/check", body: mustJSON(map[string]string{"policy": b.doc})})
		if status < 400 {
			t.Errorf("%s: SetPolicy accepted (http %d)", b.name, status)
		}
		obs = append(obs, fmt.Sprintf("%s: SetPolicy ⇒ %s, CheckPolicy ⇒ %s", b.name, gatewayBody(status, body), gatewayBody(cs, cb)))
	}
	after := e.storedPolicy(t, inst)
	liveAfter := filterSummary(e.firstMap(t, o))
	if after != before || liveAfter != liveBefore {
		t.Fatalf("a rejected SetPolicy changed the policy: stored %s→%s live %s→%s", e.policyName(before), e.policyName(after), liveBefore, liveAfter)
	}
	_, aerr := inst.SetPolicy(ctx(t), bad[1].doc)
	he, _ := headscale.AsError(aerr)
	if he == nil || he.Kind != headscale.KindPolicyRejected || he.Outcome != headscale.OutcomeNotApplied || he.Op != headscale.OpCheckPolicy {
		t.Fatalf("adapter SetPolicy on a rejected policy: %s", describe(aerr))
	}
	e.record(t, "V-06", "mã lỗi HTTP của SetPolicy / CheckPolicy", strings.Join(obs, "; "),
		"SetPolicy luôn chạy CheckPolicy trước ⇒ policy_rejected (upstream_rejected), outcome not_applied, không PUT")
	e.record(t, "V-26", "trạng thái policy sau khi SetPolicy bị từ chối (lỗi trước hoán đổi)",
		fmt.Sprintf("stored %s ⇒ %s; live %s ⇒ %s (không đổi)", e.policyName(before), e.policyName(after), liveBefore, liveAfter),
		"outcome not_applied cho lỗi \"setting policy: …\"")
}

func TestP1_V06_PolicyDecoderLeniency(t *testing.T) {
	e := setup(t)
	inst := e.inst(t)
	s := e.loadState(t)
	o := s.Nodes["observer"]
	docs := []struct{ name, doc, want string }{
		{"\"Grants\" (khác kiểu chữ)", `{"Grants":[{"src":["*"],"dst":["*"],"ip":["tcp:1101"]}]}`, "ports=1101"},
		{"\"GRANTS\"", `{"GRANTS":[{"src":["*"],"dst":["*"],"ip":["tcp:1102"]}]}`, "ports=1102"},
		{"chỉ có \"#grants\"", `{"#grants":[{"src":["*"],"dst":["*"],"ip":["tcp:1103"]}]}`, "allow-all"},
		{"\"#grants\" cạnh \"grants\"", `{"grants":[{"src":["*"],"dst":["*"],"ip":["tcp:1104"]}],"#grants":[{"src":["*"],"dst":["*"],"ip":["*"]}]}`, "ports=1104"},
		{"khóa \"#src\" trong một grant", `{"grants":[{"#src":["x"],"src":["*"],"dst":["*"],"ip":["tcp:1106"]}]}`, "ports=1106"},
		{"\"grants\": null", `{"grants":null}`, "allow-all"},
		{"\"grants\": [] (đối chứng)", `{"grants":[]}`, "deny-all"},
		{"\"grants\" và \"Grants\" cùng lúc", `{"grants":[],"Grants":[{"src":["*"],"dst":["*"],"ip":["tcp:1105"]}]}`, ""},
	}
	for _, d := range docs {
		status, body := e.raw(t, rawReq{method: "PUT", path: "/api/v1/policy", body: mustJSON(map[string]string{"policy": d.doc})})
		live := "(không áp dụng)"
		if status == 200 {
			live = filterSummary(e.firstMap(t, o))
			if d.want != "" && live != d.want {
				t.Errorf("%s: live filter %s, want %s", d.name, live, d.want)
			}
		} else if d.want != "" {
			t.Errorf("%s: rejected (%s), expected accepted", d.name, gatewayBody(status, body))
		}
		guard := headscale.ValidatePolicyDocument(d.doc)
		accepted := d.doc == `{"grants":[]}`
		if (guard == nil) != accepted {
			t.Errorf("%s: adapter guard = %v", d.name, guard)
		}
		adapter := "guard chấp nhận"
		if guard != nil {
			adapter = "guard từ chối cục bộ: " + guard.Error()
		}
		e.record(t, "V-06", "decoder policy: "+d.name, fmt.Sprintf("SetPolicy ⇒ %s; filter thực thi = %s", gatewayBody(status, body), live), adapter)
	}
	if _, err := inst.SetPolicy(ctx(t), portPolicy(1000)); err != nil {
		t.Fatalf("restore P(tcp:1000): %v", err)
	}
}

func TestP1_V21_PreAuthDefaultExpiry(t *testing.T) {
	e := setup(t)
	inst := e.inst(t)
	u := e.ensureUser(t, inst, "ct-v21")
	n := newFakeNode("ct-v21-default")
	e.registerWithKey(t, n, e.userKey(t, inst, u.ID), time.Time{})
	node := e.nodeOf(t, inst, n)
	if node.Expiry == nil {
		t.Fatal("node registered on a config with node.expiry has no expiry")
	}
	want := node.CreatedAt.Add(e.nodeExpiry)
	delta := node.Expiry.Sub(want)
	if !within(*node.Expiry, want, 2*time.Minute) {
		t.Fatalf("expiry %s, want created_at + %s = %s", expiryString(node.Expiry), e.nodeExpiry, want)
	}
	mr := e.firstMap(t, n)
	if !within(mr.Node.KeyExpiry, *node.Expiry, time.Second) {
		t.Fatalf("map KeyExpiry %s != %s", mr.Node.KeyExpiry, expiryString(node.Expiry))
	}
	_, clamp := headscale.ExpiryClamp(node, node.CreatedAt, e.nodeExpiry)
	if clamp {
		t.Fatal("ExpiryClamp flags a default expiry")
	}
	e.record(t, "V-21", "pre-auth key, RegisterRequest.Expiry rỗng (config render có node.expiry)",
		fmt.Sprintf("expiry = created_at + %s %+.3fs (created_at %s, expiry %s); KeyExpiry trong map khớp", e.nodeExpiry, delta.Seconds(),
			node.CreatedAt.UTC().Format(time.RFC3339), expiryString(node.Expiry)),
		"ExpiryClamp: không cần kẹp (sai lệch < 1 phút cho phép)")
}

func TestP1_V21_ClientRequestedExpiry(t *testing.T) {
	e := setup(t)
	inst := e.inst(t)
	c := ctx(t)
	u := e.ensureUser(t, inst, "ct-v21")
	far := time.Now().Add(10 * 365 * 24 * time.Hour).UTC().Truncate(time.Second)

	n := newFakeNode("ct-v21-far")
	e.registerWithKey(t, n, e.userKey(t, inst, u.ID), far)
	node := e.nodeOf(t, inst, n)
	if node.Expiry == nil || !node.Expiry.Equal(far) {
		t.Fatalf("pre-auth path: expiry %s, client asked %s", expiryString(node.Expiry), far)
	}
	e.record(t, "V-21", "pre-auth key, RegisterRequest.Expiry = now + 10 năm",
		fmt.Sprintf("expiry = %s (đúng giá trị client yêu cầu; node.expiry %s bị bỏ qua)", expiryString(node.Expiry), e.nodeExpiry), "")

	w := newFakeNode("ct-v21-web")
	far2 := time.Now().Add(5 * 365 * 24 * time.Hour).UTC().Truncate(time.Second)
	_, authID := e.startInteractive(t, e.noise(t, w), w, far2)
	wn, err := inst.AuthRegister(c, "ct-v21", authID)
	if err != nil || wn.Expiry == nil || !wn.Expiry.Equal(far2) {
		t.Fatalf("web-auth path: %v expiry %s, client asked %s", err, expiryString(wn.Expiry), far2)
	}
	e.record(t, "V-21", "web-auth (AuthRegister), RegisterRequest.Expiry = now + 5 năm",
		fmt.Sprintf("expiry = %s (client thắng cả trên đường AuthRegister)", expiryString(wn.Expiry)), "")

	short := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	sn := newFakeNode("ct-v21-short")
	e.registerWithKey(t, sn, e.userKey(t, inst, u.ID), short)
	snode := e.nodeOf(t, inst, sn)
	if snode.Expiry == nil || !snode.Expiry.Equal(short) {
		t.Fatalf("short expiry: %s", expiryString(snode.Expiry))
	}
	max9999 := time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)
	mn := newFakeNode("ct-v21-9999")
	resp, status, body := e.register(t, e.noise(t, mn), mn, tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{AuthKey: e.userKey(t, inst, u.ID)}, Expiry: max9999})
	maxObs := gatewayBody(status, body)
	if status == 200 && resp.Error == "" {
		maxObs = "chấp nhận, expiry = " + expiryString(e.nodeOf(t, inst, mn).Expiry)
	}
	e.record(t, "V-21", "RegisterRequest.Expiry ngắn hơn (now + 1h) và cực đại (9999-12-31)",
		fmt.Sprintf("+1h ⇒ expiry %s; 9999-12-31 ⇒ %s", expiryString(snode.Expiry), maxObs), "kẹp chỉ áp khi vượt hạn của tenant; hạn ngắn hơn được giữ")

	// The platform's clamp (§13.4 "Kẹp hạn node").
	at, need := headscale.ExpiryClamp(node, node.CreatedAt, e.nodeExpiry)
	if !need {
		t.Fatal("ExpiryClamp did not flag a 10-year expiry")
	}
	cn, err := inst.ExpireNode(c, node.ID, &at)
	if err != nil || cn.Expiry == nil || !cn.Expiry.Equal(at) {
		t.Fatalf("clamp ExpireNode: %v %s want %s", err, expiryString(cn.Expiry), at)
	}
	mr := e.firstMap(t, n)
	if !within(mr.Node.KeyExpiry, at, time.Second) {
		t.Fatalf("map KeyExpiry %s after clamp, want %s", mr.Node.KeyExpiry, at)
	}
	e.record(t, "V-21", "nền tảng kẹp hạn sau đăng ký",
		fmt.Sprintf("ExpireNode(expiry=created_at+%s) ⇒ node.expiry %s; KeyExpiry gửi xuống node %s", e.nodeExpiry, expiryString(cn.Expiry),
			mr.Node.KeyExpiry.UTC().Format(time.RFC3339)),
		"ExpiryClamp(node, registered_at, node_expiry) + ExpireNode(at); security_event do module devices ghi (P2-T13)")

	// Parameter placement: an expiry sent in a JSON body is ignored and the node expires immediately.
	monthAhead := time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)
	st, rb := e.raw(t, rawReq{method: "POST", path: fmt.Sprintf("/api/v1/node/%d/expire", node.ID), body: `{"expiry":"` + monthAhead + `"}`})
	after, _ := inst.GetNode(c, node.ID)
	if st != 200 || after.Expiry == nil || after.Expiry.After(time.Now().Add(time.Minute)) {
		t.Fatalf("expiry-in-body: http %d %s, expiry %s", st, truncate(rb, 100), expiryString(after.Expiry))
	}
	e.record(t, "V-06", "tham số query: ExpireNode với expiry trong BODY",
		fmt.Sprintf("HTTP %d; body bị bỏ qua ⇒ node hết hạn NGAY (expiry %s) thay vì %s", st, expiryString(after.Expiry), monthAhead),
		"adapter luôn gửi expiry ở query string, thời điểm tường minh")
	if _, err := inst.ExpireNode(c, node.ID, &at); err != nil {
		t.Fatal(err)
	}
}

func TestP1_V26_AuthApproveOnRegistrationID(t *testing.T) {
	e := setup(t)
	inst := e.inst(t)
	c := ctx(t)
	for _, verdict := range []string{"AuthApprove", "AuthReject"} {
		n := newFakeNode("ct-v26-" + strings.ToLower(verdict))
		nc := e.noise(t, n)
		authURL, authID := e.startInteractive(t, nc, n, time.Time{})
		type fu struct {
			resp   tailcfg.RegisterResponse
			status int
			body   string
		}
		ch := make(chan fu, 1)
		fctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		go func() {
			r, s, b := e.followup(fctx, nc, n, authURL)
			ch <- fu{r, s, b}
		}()
		time.Sleep(500 * time.Millisecond) // let the follow-up park on the session
		var err error
		if verdict == "AuthApprove" {
			err = inst.AuthApprove(c, authID)
		} else {
			err = inst.AuthReject(c, authID)
		}
		if err != nil {
			cancel()
			t.Fatalf("%s on a registration Auth ID: %v", verdict, err)
		}
		var r fu
		select {
		case r = <-ch:
		case <-time.After(45 * time.Second):
			t.Fatal("follow-up did not return")
		}
		cancel()
		nodes := e.nodesOfMachine(t, inst, n)
		newID := authIDOfURL(r.resp.AuthURL)
		if len(nodes) != 0 || r.status != 200 || r.resp.AuthURL == "" || newID == authID || r.resp.MachineAuthorized {
			t.Fatalf("%s: nodes=%d follow-up http %d authURL-new=%v authorized=%v", verdict, len(nodes), r.status, newID != authID, r.resp.MachineAuthorized)
		}
		_, regErr := inst.AuthRegister(c, userAlice, authID)
		e.record(t, "V-26", verdict+" trên Auth ID của luồng đăng ký",
			fmt.Sprintf("%s ⇒ thành công (200); KHÔNG tạo node (0 node của machine key); follow-up của client nhận AuthURL MỚI (Auth ID khác), MachineAuthorized=false; AuthRegister bằng Auth ID cũ sau đó ⇒ %s",
				verdict, describe(regErr)),
			"claim web-auth chỉ dùng AuthRegister; AuthApprove/AuthReject chỉ cho phiên SSH-check")
		if kindOf(regErr) != "validation" {
			t.Fatalf("AuthRegister after %s: %s", verdict, describe(regErr))
		}
	}
}

func TestP1_V28_GetNodeVsListNodes(t *testing.T) {
	e := setup(t)
	inst := e.inst(t)
	c := ctx(t)
	alice := e.ensureUser(t, inst, userAlice)
	r := newFakeNode("ct-v28-router")
	r.Routes = []netip.Prefix{netip.MustParsePrefix("10.99.0.0/24"), netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
	e.registerWithKey(t, r, e.userKey(t, inst, alice.ID), time.Time{})
	_, stop := e.mapSession(t, r)
	defer stop()
	id := e.nodeOf(t, inst, r).ID
	set, err := inst.SetApprovedRoutes(c, id, []netip.Prefix{netip.MustParsePrefix("10.99.0.0/24"), netip.MustParsePrefix("0.0.0.0/0")})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)
	list := e.nodeOf(t, inst, r)
	get, err := inst.GetNode(c, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(get.SubnetRoutes) != 0 || len(list.SubnetRoutes) == 0 {
		t.Fatalf("GetNode/ListNodes subnet routes: get %v list %v", get.SubnetRoutes, list.SubnetRoutes)
	}
	e.record(t, "V-28", "GetNode so với ListNodes: subnet_routes",
		fmt.Sprintf("SetApprovedRoutes trả %s; ListNodes %s; GetNode %s", routes(set), routes(list), routes(get)),
		"cập nhật sổ thiết bị chỉ từ ListNodes; GetNode chỉ để read-back trường vừa ghi")

	// A user node converted with SetTags, and a node registered with a tag-only key.
	tg := newFakeNode("ct-v28-tagged")
	e.registerWithKey(t, tg, e.userKey(t, inst, alice.ID), time.Time{})
	tid := e.nodeOf(t, inst, tg).ID
	if _, err := inst.SetTags(c, tid, []string{"tag:ct-tagged"}); err != nil {
		t.Fatal(err)
	}
	tk := newFakeNode("ct-v28-tagkey")
	e.registerWithKey(t, tk, e.tagKey(t, inst, "tag:ct-tagged"), time.Time{})
	var obs []string
	for _, n := range []*fakeNode{tg, tk} {
		l := e.nodeOf(t, inst, n)
		g, err := inst.GetNode(c, l.ID)
		if err != nil {
			t.Fatal(err)
		}
		if owner(l) != headscale.TaggedDevicesUser || g.User != nil {
			t.Fatalf("%s: ListNodes user %s, GetNode user %s", n.Hostname, owner(l), owner(g))
		}
		obs = append(obs, fmt.Sprintf("%s (tags %v, register_method %s): ListNodes user=%q, GetNode user=null", n.Hostname, l.Tags, l.RegisterMethod, owner(l)))
	}
	e.record(t, "V-28", "GetNode so với ListNodes: user của tagged node", strings.Join(obs, "; "),
		"owner_membership_id chỉ suy từ ListNodes (tagged ⇒ không có owner); read-back bằng GetNode không được đọc user")
}

func TestP1_V28_SetTagsEmpty(t *testing.T) {
	e := setup(t)
	inst := e.inst(t)
	c := ctx(t)
	alice := e.ensureUser(t, inst, userAlice)
	un := newFakeNode("ct-v28-empty-user")
	e.registerWithKey(t, un, e.userKey(t, inst, alice.ID), time.Time{})
	tn := newFakeNode("ct-v28-empty-tagged")
	e.registerWithKey(t, tn, e.tagKey(t, inst, "tag:ct-tagged"), time.Time{})
	var obs []string
	for _, n := range []*fakeNode{un, tn} {
		node := e.nodeOf(t, inst, n)
		status, body := e.raw(t, rawReq{method: "POST", path: fmt.Sprintf("/api/v1/node/%d/tags", node.ID), body: `{"tags":[]}`})
		after, err := inst.GetNode(c, node.ID)
		if status != http.StatusBadRequest || err != nil || len(after.Tags) != len(node.Tags) {
			t.Errorf("%s: SetTags([]) ⇒ %s, tags %v → %v", n.Hostname, gatewayBody(status, body), node.Tags, after.Tags)
		}
		obs = append(obs, fmt.Sprintf("node %s (tags %v) ⇒ %s, tags không đổi", n.Hostname, node.Tags, gatewayBody(status, body)))
		_, aerr := inst.SetTags(c, node.ID, nil)
		if kindOf(aerr) != "validation" {
			t.Fatalf("adapter SetTags([]): %s", describe(aerr))
		}
	}
	e.record(t, "V-28", "SetTags với danh sách rỗng", strings.Join(obs, "; "),
		"adapter trả validation_failed cục bộ, không gọi Headscale; PUT /devices/{id}/tags [] ⇒ 422")
}

func TestP1_V28_AuthRegisterSameMachineKey(t *testing.T) {
	e := setup(t)
	inst := e.inst(t)
	c := ctx(t)
	e.ensureUser(t, inst, userAlice)
	e.ensureUser(t, inst, userBob)
	m := newFakeNode("ct-v28-machine")
	nc := e.noise(t, m)
	_, id1 := e.startInteractive(t, nc, m, time.Time{})
	n1, err := inst.AuthRegister(c, userAlice, id1)
	if err != nil {
		t.Fatal(err)
	}
	m.Node = key.NewNode() // re-login: same machine key, new node key
	_, id2 := e.startInteractive(t, nc, m, time.Time{})
	n2, err := inst.AuthRegister(c, userAlice, id2)
	if err != nil {
		t.Fatal(err)
	}
	m.Node = key.NewNode()
	_, id3 := e.startInteractive(t, nc, m, time.Time{})
	n3, err := inst.AuthRegister(c, userBob, id3)
	if err != nil {
		t.Fatal(err)
	}
	all := e.nodesOfMachine(t, inst, m)
	var desc []string
	for _, x := range all {
		desc = append(desc, fmt.Sprintf("id=%d user=%s nodekey=…%s", x.ID, owner(x), x.NodeKey[len(x.NodeKey)-6:]))
	}
	if n2.ID != n1.ID || n3.ID == n1.ID || len(all) != 2 {
		t.Fatalf("same machine key: n1=%d n2=%d n3=%d nodes=%v", n1.ID, n2.ID, n3.ID, desc)
	}
	e.record(t, "V-28", "AuthRegister lặp lại trên machine key đã có node",
		fmt.Sprintf("lần 1 (alice) ⇒ node %d; lần 2 cùng user, node key mới ⇒ node %d (re-auth node cũ, node key cập nhật=%v, không tạo node mới); lần 3 user khác (bob) ⇒ node MỚI %d; machine key giờ có %d node: %s",
			n1.ID, n2.ID, n2.NodeKey != n1.NodeKey, n3.ID, len(all), strings.Join(desc, ", ")),
		"§7.4 bước 8: node đã có của chính thành viên ⇒ coi là re-auth, không xóa; node mới cho user khác cùng machine key ⇒ ExpireNode + security_event")
}

// TestP1_PrepareNextPhases leaves what the runner and the later phases need.
func TestP1_PrepareNextPhases(t *testing.T) {
	e := setup(t)
	inst := e.inst(t)
	off := e.ensureUser(t, inst, userOfficial)
	k, err := inst.CreatePreAuthKey(ctx(t), headscale.PreAuthKeyOpts{User: off.ID, Expiration: time.Now().Add(30 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	e.writeSecretFile(t, "official_authkey", k.Key.Reveal())
	if _, err := inst.SetPolicy(ctx(t), portPolicy(1001)); err != nil {
		t.Fatal(err)
	}
	s := e.loadState(t)
	if got := filterSummary(e.firstMap(t, s.Nodes["observer"])); got != "ports=1001" {
		t.Fatalf("observer filter = %s", got)
	}
	p := newFakeNode("ct-pending")
	_, pendingID := e.startInteractive(t, e.noise(t, p), p, time.Time{})
	s.Values["pending_auth_id"] = pendingID
	e.saveState(t, s)
}
