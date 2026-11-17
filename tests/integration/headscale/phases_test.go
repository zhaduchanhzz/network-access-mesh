package contract

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

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

func TestP5_V26_AuthRegisterWithSSHCheckID(t *testing.T) {
	e := setup(t)
	inst := e.inst(t)
	c := ctx(t)
	s := e.loadState(t)
	dst := s.Nodes["ssh_dst"]
	dstID, _ := strconv.ParseUint(s.Values["ssh_dst_id"], 10, 64)
	nc := e.noise(t, dst)
	_, srcID := e.sshPair(t, inst, "ct-ssh-src-register")
	hold, status, body := e.sshAction(t, c, nc, dst, srcID, dstID, "")
	if status != http.StatusOK || hold.HoldAndDelegate == "" {
		t.Fatalf("SSH check hold: http %d %s", status, body)
	}
	id := authIDFromHold(t, hold.HoldAndDelegate)
	nodes, err := inst.ListNodes(c, "")
	if err != nil {
		t.Fatal(err)
	}
	s.Values["ssh_check_auth_id"] = id
	s.Values["nodes_before"] = strconv.Itoa(len(nodes))
	e.saveState(t, s)

	_, regErr := inst.AuthRegister(c, userAlice, id)
	// Does the instance still answer?
	var alive []string
	deadline := time.Now().Add(15 * time.Second)
	down := false
	for time.Now().Before(deadline) {
		_, herr := inst.Health(c)
		alive = append(alive, kindOf(herr))
		if herr != nil {
			down = true
			break
		}
		time.Sleep(time.Second)
	}
	e.record(t, "V-26", "AuthRegister với Auth ID của phiên SSH-check",
		fmt.Sprintf("AuthRegister ⇒ %s; ngay sau đó Health ⇒ %v (instance ngừng trả lời=%v; trạng thái container do runner ghi)",
			describe(regErr), alive, down),
		"không phân biệt được hai loại Auth ID qua API ⇒ giữ lint L10 (cấm rule SSH check), giới hạn tần suất claim; báo upstream")
	if regErr == nil || !down {
		t.Fatalf("AuthRegister with an SSH-check Auth ID: %s; instance down=%v (%v)", describe(regErr), down, alive)
	}
}

// Phase 6 — the runner restarted the crashed instance.

func TestP6_RecoveredAfterCrash(t *testing.T) {
	e := setup(t)
	inst := e.inst(t)
	c := ctx(t)
	s := e.loadState(t)
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
	before, _ := strconv.Atoi(s.Values["nodes_before"])
	if len(nodes) != before || stored != sshCheckPolicy || kindOf(approveErr) != "validation" {
		t.Fatalf("after crash: nodes %d (before %d), policy %s, approve %s", len(nodes), before, e.policyName(stored), describe(approveErr))
	}
	e.record(t, "V-26", "sau khi Headscale khởi động lại từ crash",
		fmt.Sprintf("Health ok; %d node như trước crash (không node nào được tạo từ Auth ID SSH-check); policy lưu = %s; phiên SSH-check cũ mất (AuthApprove ⇒ %s)",
			len(nodes), e.policyName(stored), kindOf(approveErr)),
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

// TestP6_AdapterLogsHaveNoCredentials is the canary test of §25.1 rule 9 on a real run: the adapter's debug log and
// the observation file never contain the instance API key, the edge token or the issued pre-auth key.
func TestP6_AdapterLogsHaveNoCredentials(t *testing.T) {
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
