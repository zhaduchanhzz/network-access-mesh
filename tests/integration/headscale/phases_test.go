package contract

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"tailscale.com/control/ts2021"

	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
)

// Phase 2 — the runner started the official Tailscale client with the key of TestP1_PrepareNextPhases.

func TestP2_V21_OfficialClientDefaultExpiry(t *testing.T) {
	e := setup(t)
	inst := e.inst(t)
	nodes, err := inst.ListNodes(ctx(t), userOfficial)
	if err != nil || len(nodes) != 1 {
		t.Fatalf("official client node: %v %d", err, len(nodes))
	}
	n := nodes[0]
	if n.Expiry == nil || !within(*n.Expiry, n.CreatedAt.Add(e.nodeExpiry), 2*time.Minute) {
		t.Fatalf("official client expiry %s, created %s", expiryString(n.Expiry), n.CreatedAt)
	}
	e.record(t, "V-21", "client chính thức (container tailscale v1.104.7) đăng ký bằng pre-auth key",
		fmt.Sprintf("hostname=%s register_method=%s; expiry = created_at + %s %+.3fs (%s)", n.Name, n.RegisterMethod, e.nodeExpiry,
			n.Expiry.Sub(n.CreatedAt.Add(e.nodeExpiry)).Seconds(), expiryString(n.Expiry)),
		"client chính thức không gửi RegisterRequest.Expiry ⇒ hạn mặc định của tenant")
}

func TestP2_V06_EmptyPolicyStored(t *testing.T) {
	e := setup(t)
	inst := e.inst(t)
	o := e.loadState(t).Nodes["observer"]
	if got := e.storedPolicy(t, inst); got != portPolicy(1001) {
		t.Fatalf("stored policy before = %s", e.policyName(got))
	}
	liveBefore := filterSummary(e.firstMap(t, o))
	status, body := e.raw(t, rawReq{method: "PUT", path: "/api/v1/policy", body: `{"policy":""}`})
	gs, gb := e.raw(t, rawReq{method: "GET", path: "/api/v1/policy"})
	_, aerr := inst.GetPolicy(ctx(t))
	liveAfter := filterSummary(e.firstMap(t, o))
	_, guard := inst.SetPolicy(ctx(t), "")
	if status != 200 || !errors.Is(aerr, headscale.ErrNoPolicy) || liveAfter != liveBefore || kindOf(guard) != "validation" {
		t.Fatalf("empty PUT: http %d, GetPolicy %s, live %s→%s, adapter %s", status, describe(aerr), liveBefore, liveAfter, describe(guard))
	}
	e.record(t, "V-06", "PUT policy rỗng (PL-06) — trước restart",
		fmt.Sprintf("SetPolicy(\"\") ⇒ %s; GetPolicy ⇒ %s; policy đang thực thi KHÔNG đổi (%s → %s)", gatewayBody(status, truncate(body, 120)),
			gatewayBody(gs, truncate(gb, 120)), liveBefore, liveAfter),
		fmt.Sprintf("SetPolicy(\"\") bị chặn cục bộ (%s); GetPolicy policy rỗng ⇒ %s", kindOf(guard), kindOf(aerr)))
}

// Phase 3 — after a restart.

func TestP3_V06_EmptyPolicyAfterRestart(t *testing.T) {
	e := setup(t)
	inst := e.inst(t)
	o := e.loadState(t).Nodes["observer"]
	live := filterSummary(e.firstMap(t, o))
	_, aerr := inst.GetPolicy(ctx(t))
	if live != "allow-all" || !errors.Is(aerr, headscale.ErrNoPolicy) {
		t.Fatalf("after restart: live %s, GetPolicy %s", live, describe(aerr))
	}
	if _, err := inst.SetPolicy(ctx(t), portPolicy(1001)); err != nil {
		t.Fatal(err)
	}
	restored := filterSummary(e.firstMap(t, o))
	e.record(t, "V-06", "PUT policy rỗng (PL-06) — sau restart",
		fmt.Sprintf("instance khởi động với \"no policy\" ⇒ filter thực thi = %s (ALLOW-ALL); GetPolicy ⇒ %s; SetPolicy P(tcp:1001) ⇒ filter %s",
			live, describe(aerr), restored),
		"nền tảng không bao giờ gửi policy rỗng; drift job coi no_policy là Critical")
}

func TestP3_PendingRegistrationLostOnRestart(t *testing.T) {
	e := setup(t)
	inst := e.inst(t)
	id := e.loadState(t).Values["pending_auth_id"]
	_, err := inst.AuthRegister(ctx(t), userAlice, id)
	if kindOf(err) != "validation" {
		t.Fatalf("pending registration after restart: %s", describe(err))
	}
	e.record(t, "ID-05", "Auth ID đăng ký đang chờ, sau restart Headscale",
		"AuthRegister ⇒ "+describe(err)+" (cache pending registration nằm trong bộ nhớ, mất khi restart)",
		"validation_failed; Portal yêu cầu người dùng chạy lại lệnh đăng ký")
}

// Phase 4 — the runner filled the instance's data volume: database writes fail.

func TestP4_V26_SetPolicyFailsAfterSwap(t *testing.T) {
	e := setup(t)
	inst := e.inst(t)
	c := ctx(t)
	o := e.loadState(t).Nodes["observer"]
	if got := e.storedPolicy(t, inst); got != portPolicy(1001) {
		t.Fatalf("stored before = %s", e.policyName(got))
	}
	if got := filterSummary(e.firstMap(t, o)); got != "ports=1001" {
		t.Fatalf("live before = %s", got)
	}

	_, err := inst.SetPolicy(c, portPolicy(1002))
	he, _ := headscale.AsError(err)
	if he == nil || he.Kind != headscale.KindPolicyRejected || he.Outcome != headscale.OutcomeUnknown {
		t.Fatalf("SetPolicy with a full disk: %s", describe(err))
	}
	stored := e.storedPolicy(t, inst)
	live := filterSummary(e.firstMap(t, o))
	if stored != portPolicy(1001) || live != "ports=1002" {
		t.Fatalf("after failed SetPolicy: stored %s live %s", e.policyName(stored), live)
	}
	e.record(t, "V-26", "SetPolicy trả lỗi SAU khi đã hoán đổi trong bộ nhớ (ghi DB thất bại — đĩa đầy)",
		fmt.Sprintf("SetPolicy P(tcp:1002) ⇒ %s; GetPolicy (bản DB) = %s; filter ĐANG THỰC THI = %s ⇒ policy lỗi vẫn được áp dụng, GetPolicy không thấy",
			describe(err), e.policyName(stored), live),
		"outcome=unknown cho mọi lỗi SetPolicy không phải \"setting policy: …\"; job policy.apply phải gửi lại bản applied gần nhất (không dựa vào đọc lại)")

	_, err2 := inst.SetPolicy(c, portPolicy(1001)) // re-assert the last applied policy
	live2 := filterSummary(e.firstMap(t, o))
	if err2 == nil || live2 != "ports=1001" {
		t.Fatalf("re-assert: %s live %s", describe(err2), live2)
	}
	e.record(t, "V-26", "gửi lại bản applied gần nhất khi đĩa vẫn đầy",
		fmt.Sprintf("SetPolicy P(tcp:1001) ⇒ %s nhưng filter thực thi trở về %s = bản DB ⇒ nhất quán lại", describe(err2), live2),
		"re-assert khôi phục policy thực thi ngay cả khi lần ghi báo lỗi")

	_, err3 := inst.SetPolicy(c, portPolicy(1003))
	live3 := filterSummary(e.firstMap(t, o))
	if err3 == nil || live3 != "ports=1003" {
		t.Fatalf("second divergence: %s live %s", describe(err3), live3)
	}
	s := e.loadState(t)
	s.Values["live_before_restart"] = live3
	e.saveState(t, s)
}

// Phase 5 — disk freed, instance restarted.

func TestP5_V26_AfterRestartStoredPolicyWins(t *testing.T) {
	e := setup(t)
	inst := e.inst(t)
	o := e.loadState(t).Nodes["observer"]
	stored := e.storedPolicy(t, inst)
	live := filterSummary(e.firstMap(t, o))
	if stored != portPolicy(1001) || live != "ports=1001" {
		t.Fatalf("after restart: stored %s live %s", e.policyName(stored), live)
	}
	e.record(t, "V-26", "sau restart (đĩa đã giải phóng)",
		fmt.Sprintf("trước restart thực thi %s (chưa lưu); sau restart thực thi %s = GetPolicy %s ⇒ policy chỉ-trong-bộ-nhớ bị mất",
			e.loadState(t).Values["live_before_restart"], live, e.policyName(stored)),
		"")
}

func (e *env) sshPair(t *testing.T, inst headscale.Instance, srcName string) (*fakeNode, uint64) {
	t.Helper()
	alice := e.ensureUser(t, inst, userAlice)
	src := newFakeNode(srcName)
	e.registerWithKey(t, src, e.userKey(t, inst, alice.ID), time.Time{})
	return src, e.nodeOf(t, inst, src).ID
}

func TestP5_V26_SSHCheckApproveControl(t *testing.T) {
	e := setup(t)
	inst := e.inst(t)
	c := ctx(t)
	if _, err := inst.SetPolicy(c, sshCheckPolicy); err != nil {
		t.Fatalf("SetPolicy ssh-check: %v", err)
	}
	dst := newFakeNode("ct-ssh-dst")
	e.registerWithKey(t, dst, e.tagKey(t, inst, "tag:ct-ssh"), time.Time{})
	dstID := e.nodeOf(t, inst, dst).ID
	nc := e.noise(t, dst)
	var obs []string
	for _, verdict := range []string{"AuthApprove", "AuthReject"} {
		_, srcID := e.sshPair(t, inst, "ct-ssh-src-"+strings.ToLower(verdict))
		hold, status, body := e.sshAction(t, c, nc, dst, srcID, dstID, "")
		if status != http.StatusOK || hold.HoldAndDelegate == "" || !strings.Contains(hold.Message, "/auth/") {
			t.Fatalf("SSH check hold: http %d %s %+v", status, body, hold)
		}
		id := authIDFromHold(t, hold.HoldAndDelegate)
		var err error
		if verdict == "AuthApprove" {
			err = inst.AuthApprove(c, id)
		} else {
			err = inst.AuthReject(c, id)
		}
		if err != nil {
			t.Fatalf("%s on an SSH-check Auth ID: %v", verdict, err)
		}
		final, fstatus, fbody := e.sshAction(t, c, nc, dst, srcID, dstID, id)
		if fstatus != http.StatusOK || final.Accept != (verdict == "AuthApprove") || final.Reject == (verdict == "AuthApprove") {
			t.Fatalf("follow-up after %s: http %d %s %+v", verdict, fstatus, fbody, final)
		}
		obs = append(obs, fmt.Sprintf("%s ⇒ follow-up của node đích nhận Accept=%v Reject=%v", verdict, final.Accept, final.Reject))
	}
	e.record(t, "V-26", "đối chứng: phiên SSH-check (rule action \"check\") với AuthApprove/AuthReject",
		"node đích gọi /machine/ssh/action ⇒ HoldAndDelegate + thông điệp chứa URL /auth/<Auth ID>; "+strings.Join(obs, "; "),
		"AuthApprove/AuthReject là API đúng cho SSH-check")
	s := e.loadState(t)
	s.Nodes["ssh_dst"] = dst
	s.Values["ssh_dst_id"] = strconv.FormatUint(dstID, 10)
	e.saveState(t, s)
}

// sshCheckHold registers a new source node for alice and makes the destination node ask for the SSH action of that
// pair: the answer is a HoldAndDelegate whose auth_id is the Auth ID of a pending SSH-check session.
func (e *env) sshCheckHold(t *testing.T, c context.Context, inst headscale.Instance, nc *ts2021.Client, srcName string) (string, uint64, uint64) {
	t.Helper()
	s := e.loadState(t)
	dst := s.Nodes["ssh_dst"]
	dstID, _ := strconv.ParseUint(s.Values["ssh_dst_id"], 10, 64)
	_, srcID := e.sshPair(t, inst, srcName)
	hold, status, body := e.sshAction(t, c, nc, dst, srcID, dstID, "")
	if status != http.StatusOK || hold.HoldAndDelegate == "" || !strings.Contains(hold.Message, "/auth/") {
		t.Fatalf("SSH check hold: http %d %s %+v", status, body, hold)
	}
	return authIDFromHold(t, hold.HoldAndDelegate), srcID, dstID
}

// aliveFor polls Health through the adapter for d and returns the answers; ok is false at the first failure.
func aliveFor(c context.Context, inst headscale.Instance, d time.Duration) (ok bool, answers []string) {
	for deadline := time.Now().Add(d); time.Now().Before(deadline); time.Sleep(time.Second) {
		h, err := inst.Health(c)
		if err != nil || !h.DatabaseConnectivity {
			return false, append(answers, "down: "+describe(err))
		}
		answers = append(answers, "ok")
	}
	return true, answers
}

// TestP5_V26_AuthRegisterWithSSHCheckIDRefused is V-26 on the PATCHED build (P2-T10a, patch 0001): AuthRegister with
// the Auth ID of a pending SSH-check session is a client error (HTTP 400, code 3), nothing is registered, the instance
// keeps running (the runner also compares the container's PID and start time around this phase), the SSH-check session
// itself still resolves with AuthApprove/AuthReject, and a registration Auth ID still registers afterwards. The
// official image panics and exits on the same call — negative control in phase 6.
func TestP5_V26_AuthRegisterWithSSHCheckIDRefused(t *testing.T) {
	e := setup(t)
	inst := e.inst(t)
	c := ctx(t)
	s := e.loadState(t)
	dst := s.Nodes["ssh_dst"]
	nc := e.noise(t, dst)
	var obs []string
	for _, verdict := range []string{"AuthApprove", "AuthReject"} {
		id, srcID, dstID := e.sshCheckHold(t, c, inst, nc, "ct-ssh-src-reg-"+strings.ToLower(verdict))
		before, err := inst.ListNodes(c, "")
		if err != nil {
			t.Fatal(err)
		}
		status, body := e.raw(t, rawReq{method: "POST", path: "/api/v1/auth/register",
			body: mustJSON(map[string]string{"user": userAlice, "authId": id})})
		_, regErr := inst.AuthRegister(c, userAlice, id)
		alive, answers := aliveFor(c, inst, 5*time.Second)
		after, err := inst.ListNodes(c, "")
		if err != nil {
			t.Fatal(err)
		}
		he, _ := headscale.AsError(regErr)
		g, _ := gatewayAnswer(body)
		if status != http.StatusBadRequest || g.Code != 3 || g.Message != "auth session is not for node registration" ||
			he == nil || he.Kind != headscale.KindValidation || he.ProblemCode() != "validation_failed" ||
			he.Outcome != headscale.OutcomeNotApplied || !alive || len(after) != len(before) {
			t.Fatalf("%s round: raw %s; adapter %s; alive=%v %v; nodes %d → %d", verdict, gatewayBody(status, body),
				describe(regErr), alive, answers, len(before), len(after))
		}
		// The session itself is untouched: the verdict still reaches the destination node.
		if verdict == "AuthApprove" {
			err = inst.AuthApprove(c, id)
		} else {
			err = inst.AuthReject(c, id)
		}
		if err != nil {
			t.Fatalf("%s on the SSH-check Auth ID after the refused AuthRegister: %v", verdict, err)
		}
		final, fstatus, fbody := e.sshAction(t, c, nc, dst, srcID, dstID, id)
		if fstatus != http.StatusOK || final.Accept != (verdict == "AuthApprove") || final.Reject == (verdict == "AuthApprove") {
			t.Fatalf("follow-up after %s: http %d %s %+v", verdict, fstatus, fbody, final)
		}
		obs = append(obs, fmt.Sprintf("vòng %s: AuthRegister ⇒ %s; adapter ⇒ %s; Health 5 s ⇒ %d/%d ok; node %d → %d; sau đó %s ⇒ follow-up Accept=%v Reject=%v",
			verdict, gatewayBody(status, body), describe(regErr), len(answers), len(answers), len(before), len(after), verdict, final.Accept, final.Reject))
	}
	// A registration Auth ID still registers on the same instance.
	w := newFakeNode("ct-v26-after")
	_, wid := e.startInteractive(t, e.noise(t, w), w, time.Time{})
	wn, err := inst.AuthRegister(c, userAlice, wid)
	if err != nil || owner(wn) != userAlice || wn.RegisterMethod != headscale.RegisterMethodCLI {
		t.Fatalf("AuthRegister with a registration Auth ID after the refusals: %s (owner %s)", describe(err), owner(wn))
	}
	e.record(t, "V-26", "AuthRegister với Auth ID của phiên SSH-check — BẢN VÁ (P2-T10a)",
		strings.Join(obs, "; ")+fmt.Sprintf("; rồi AuthRegister bằng Auth ID đăng ký ⇒ node %d của %s (register_method %s)", wn.ID, owner(wn), wn.RegisterMethod),
		"validation_failed (outcome not_applied, detail không chứa text upstream); vẫn giữ lint L10 (cấm rule SSH check) và giới hạn tần suất claim")
	e.saveNodeCount(t, inst, "nodes_after_p5")
}

// TestP5_V26_AuthIDRegressions: the other Auth ID answers of 0.29.7 are unchanged by the patch, and none of them takes
// the patched instance down.
func TestP5_V26_AuthIDRegressions(t *testing.T) {
	e := setup(t)
	inst := e.inst(t)
	c := ctx(t)
	alice := userAlice
	// consumed: a completed registration leaves the cache
	n := newFakeNode("ct-v26-consumed")
	_, consumed := e.startInteractive(t, e.noise(t, n), n, time.Time{})
	if _, err := inst.AuthRegister(c, alice, consumed); err != nil {
		t.Fatalf("AuthRegister: %v", err)
	}
	wrongPrefix := strings.Replace(unknownAuthID(), "authreq", "authrex", 1)
	cases := []struct {
		name, id string
		local    bool // refused by the adapter's format check, never sent
	}{
		{"Auth ID chưa từng cấp (đúng định dạng)", unknownAuthID(), false},
		{"Auth ID đã dùng (đăng ký đã hoàn tất)", consumed, false},
		{"Auth ID đăng ký đang chờ từ trước 2 lần restart (hết hạn — ID-05)", e.loadState(t).Values["pending_auth_id"], false},
		{"sai tiền tố", wrongPrefix, true},
		{"sai độ dài", unknownAuthID()[:30], true},
		{"rỗng", "", true},
	}
	var obs []string
	for _, tc := range cases {
		status, body := e.raw(t, rawReq{method: "POST", path: "/api/v1/auth/register",
			body: mustJSON(map[string]string{"user": alice, "authId": tc.id})})
		_, err := inst.AuthRegister(c, alice, tc.id)
		he, _ := headscale.AsError(err)
		g, _ := gatewayAnswer(body)
		wantMsg := "node not found in registration cache"
		if tc.local {
			wantMsg = "auth ID has invalid"
		}
		if he == nil || he.Kind != headscale.KindValidation || (he.Status == 0) != tc.local || status != http.StatusInternalServerError ||
			g.Code != 2 || !strings.Contains(g.Message, wantMsg) {
			t.Errorf("%s: raw %s; adapter %s", tc.name, gatewayBody(status, body), describe(err))
		}
		obs = append(obs, fmt.Sprintf("%s: Headscale ⇒ %s; adapter ⇒ %s", tc.name, gatewayBody(status, body), kindOf(err)+map[bool]string{true: " (chặn cục bộ)", false: ""}[tc.local]))
	}
	alive, answers := aliveFor(c, inst, 3*time.Second)
	if !alive {
		t.Fatalf("instance down after the regression cases: %v", answers)
	}
	e.record(t, "V-26", "hồi quy Auth ID chưa cấp / đã dùng / hết hạn / sai định dạng — bản vá", strings.Join(obs, "; ")+"; instance vẫn trả lời",
		"không đổi so với 0.29.7 chính thức: validation_failed; định dạng sai bị adapter chặn trước khi gọi")
	e.saveNodeCount(t, inst, "nodes_after_p5")
}

// saveNodeCount stores the number of nodes for a later phase (each test that registers a node calls it last).
func (e *env) saveNodeCount(t *testing.T, inst headscale.Instance, key string) {
	t.Helper()
	nodes, err := inst.ListNodes(ctx(t), "")
	if err != nil {
		t.Fatal(err)
	}
	s := e.loadState(t)
	s.Values[key] = strconv.Itoa(len(nodes))
	e.saveState(t, s)
}

// Phase 6 — NEGATIVE CONTROL. The runner stopped the patched instance and started the OFFICIAL image
// (versions.lock [images.headscale]) on the same data volume: rollback path (database last written by the patched
// build) and proof that the patch is what fixes V-26.

func TestP6_Rollback_OfficialImageOpensPatchedDB(t *testing.T) {
	e := setup(t)
	inst := e.inst(t)
	c := ctx(t)
	s := e.loadState(t)
	version, commit := e.versionInfo(t)
	h, err := inst.Health(c)
	nodes, lerr := inst.ListNodes(c, "")
	stored := e.storedPolicy(t, inst)
	want, _ := strconv.Atoi(s.Values["nodes_after_p5"])
	if err != nil || !h.DatabaseConnectivity || lerr != nil || len(nodes) != want || stored != sshCheckPolicy ||
		version != "v0.29.7" || commit != e.officialCommit {
		t.Fatalf("official image on the patched build's database: health %v, nodes %d (want %d) %v, policy %s, version %s commit %s",
			err, len(nodes), want, lerr, e.policyName(stored), version, commit)
	}
	e.record(t, "P2-T10a", "rollback: image CHÍNH THỨC mở DB do bản vá ghi",
		fmt.Sprintf("GET /version ⇒ %s commit %s; Health ok; %d node, policy %s, API key của lần chạy vẫn hợp lệ", version, commit, len(nodes), e.policyName(stored)), "")
}

func TestP6_V26_NegativeControlOfficialImageCrashes(t *testing.T) {
	e := setup(t)
	inst := e.inst(t)
	c := ctx(t)
	s := e.loadState(t)
	nc := e.noise(t, s.Nodes["ssh_dst"])
	id, _, _ := e.sshCheckHold(t, c, inst, nc, "ct-ssh-src-official")
	nodes, err := inst.ListNodes(c, "")
	if err != nil {
		t.Fatal(err)
	}
	s.Values["ssh_check_auth_id"] = id
	s.Values["nodes_before_crash"] = strconv.Itoa(len(nodes))
	e.saveState(t, s)

	_, regErr := inst.AuthRegister(c, userAlice, id)
	alive, answers := aliveFor(c, inst, 15*time.Second)
	e.record(t, "V-26", "ĐỐI CHỨNG ÂM — image CHÍNH THỨC: AuthRegister với Auth ID của phiên SSH-check",
		fmt.Sprintf("AuthRegister ⇒ %s; ngay sau đó Health ⇒ %v (instance ngừng trả lời=%v; trạng thái container do runner ghi)",
			describe(regErr), answers, !alive),
		"cùng lời gọi trên bản vá ⇒ 400 validation_failed, instance sống (pha 5) ⇒ bản vá là thứ sửa V-26")
	if regErr == nil || alive {
		t.Fatalf("negative control: the official image did not crash: %s; health %v", describe(regErr), answers)
	}
}

// Phase 7 — the runner started the PATCHED image again on the volume last written by the official image (forward path).

func TestP7_Forward_PatchedImageAfterOfficialCrash(t *testing.T) {
	e := setup(t)
	inst := e.inst(t)
	c := ctx(t)
	s := e.loadState(t)
	version, commit := e.versionInfo(t)
	h, err := inst.Health(c)
	if err != nil || !h.DatabaseConnectivity {
		t.Fatalf("Health after restart: %v", err)
	}
	nodes, err := inst.ListNodes(c, "")
	if err != nil {
		t.Fatal(err)
	}
	approveErr := inst.AuthApprove(c, s.Values["ssh_check_auth_id"])
	stored := e.storedPolicy(t, inst)
	before, _ := strconv.Atoi(s.Values["nodes_before_crash"])
	if len(nodes) != before || stored != sshCheckPolicy || kindOf(approveErr) != "validation" || version != "v0.29.7" ||
		commit != e.expectCommit {
		t.Fatalf("after the crash: nodes %d (before %d), policy %s, approve %s, version %s commit %s", len(nodes), before,
			e.policyName(stored), describe(approveErr), version, commit)
	}
	e.record(t, "V-26", "bản vá khởi động lại trên DB sau crash của image chính thức",
		fmt.Sprintf("GET /version ⇒ %s commit %s; Health ok; %d node như trước crash (không node nào được tạo từ Auth ID SSH-check); policy lưu = %s; phiên SSH-check cũ mất (AuthApprove ⇒ %s)",
			version, commit, len(nodes), e.policyName(stored), kindOf(approveErr)),
		"")
}

// secretPart returns the secret of a Headscale key: "hskey-<kind>-" + 12-character prefix + "-" + secret. The prefix
// and the secret are URL-safe base64 and may contain '-', so the cut is by length (as Headscale parses keys).
func secretPart(s string) string {
	for _, head := range []string{"hskey-api-", "hskey-auth-"} {
		if strings.HasPrefix(s, head) && len(s) > len(head)+13+16 {
			return s[len(head)+13:]
		}
	}
	return s
}

// TestP7_AdapterLogsHaveNoCredentials is the canary test of §25.1 rule 9 on a real run: the adapter's debug log and
// the observation file never contain the instance API key, the edge token or the issued pre-auth key.
func TestP7_AdapterLogsHaveNoCredentials(t *testing.T) {
	e := setup(t)
	logs, err := os.ReadFile(filepath.Join(e.stateDir, "adapter.log"))
	if err != nil {
		t.Fatal(err)
	}
	obs, err := os.ReadFile(e.obsFile)
	if err != nil {
		t.Fatal(err)
	}
	secrets := map[string]string{"api key": e.apiKey, "edge token": e.edgeToken}
	if b, err := os.ReadFile(filepath.Join(e.stateDir, "official_authkey")); err == nil {
		secrets["pre-auth key"] = strings.TrimSpace(string(b))
	}
	for name, s := range secrets {
		if len(s) < 40 {
			t.Fatalf("%s is unexpectedly short", name)
		}
		for file, content := range map[string][]byte{"adapter.log": logs, "observations": obs} {
			for _, needle := range []string{s, secretPart(s)} {
				if strings.Contains(string(content), needle) {
					t.Errorf("%s leaked into %s", name, file)
				}
			}
		}
	}
	calls := strings.Count(string(logs), `"msg":"headscale call`)
	if calls == 0 {
		t.Fatal("adapter log is empty — the canary proves nothing")
	}
	e.record(t, "§25.1-9", "canary trên lần chạy thật",
		fmt.Sprintf("%d dòng log adapter (debug) + file quan sát: không chứa API key, edge token, pre-auth key", calls), "")
}
