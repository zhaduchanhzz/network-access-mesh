package contract

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"slices"
	"strings"
	"testing"
	"time"

	"tailscale.com/control/ts2021"
	"tailscale.com/control/tsp"
	"tailscale.com/net/dnscache"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// fakeNode is a Tailscale node driven by the protocol library pinned in go.mod: real Noise (ts2021), real
// RegisterRequest/MapRequest, but with fields the official client never sets (RegisterRequest.Expiry) and calls
// only the destination node of an SSH session makes (SSH check action).
type fakeNode struct {
	Hostname string             `json:"hostname"`
	Machine  key.MachinePrivate `json:"machine"`
	Node     key.NodePrivate    `json:"node"`
	Routes   []netip.Prefix     `json:"routes,omitempty"`
}

func newFakeNode(hostname string) *fakeNode {
	return &fakeNode{Hostname: hostname, Machine: key.NewMachine(), Node: key.NewNode()}
}

// hostinfo is deterministic, so a repeated MapRequest is a no-op for Headscale (no database write — important
// while the data volume is full in phase 4).
func (n *fakeNode) hostinfo() *tailcfg.Hostinfo {
	return &tailcfg.Hostinfo{Hostname: n.Hostname, OS: "linux", IPNVersion: "hsct-1.104.7", RoutableIPs: slices.Clone(n.Routes)}
}

// noise opens a Noise (ts2021) client for the node's machine key.
func (e *env) noise(t *testing.T, n *fakeNode) *ts2021.Client {
	t.Helper()
	pub, err := tsp.DiscoverServerKey(ctx(t), e.controlURL)
	if err != nil {
		t.Fatalf("discover server key: %v", err)
	}
	nc, err := ts2021.NewClient(ts2021.ClientOpts{
		ServerURL: e.controlURL, PrivKey: n.Machine, ServerPubKey: pub,
		Dialer:   tsdial.NewFromFuncForDebug(logger.Discard, (&net.Dialer{}).DialContext),
		DNSCache: &dnscache.Resolver{Logf: logger.Discard}, Logf: logger.Discard,
	})
	if err != nil {
		t.Fatalf("noise client: %v", err)
	}
	t.Cleanup(func() { _ = nc.Close() })
	return nc
}

// noiseDo sends one request over the node's Noise channel.
func (e *env) noiseDo(c context.Context, nc *ts2021.Client, n *fakeNode, method, p string, body any) (int, []byte, error) {
	var rdr io.Reader = http.NoBody
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rdr = bytes.NewReader(b)
	}
	// Over Noise the inner HTTP/2 request must carry an https URL (as tsp does).
	u := strings.Replace(e.controlURL, "http:", "https:", 1) + p
	req, err := http.NewRequestWithContext(c, method, u, rdr)
	if err != nil {
		return 0, nil, err
	}
	ts2021.AddLBHeader(req, n.Node.Public())
	res, err := nc.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = res.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	return res.StatusCode, data, err
}

// register sends a RegisterRequest (NodeKey, Version and Hostinfo filled in when empty).
func (e *env) register(t *testing.T, nc *ts2021.Client, n *fakeNode, req tailcfg.RegisterRequest) (tailcfg.RegisterResponse, int, string) {
	t.Helper()
	return e.registerCtx(ctx(t), nc, n, req)
}

// registerCtx does not touch testing.T, so it may run in a goroutine (follow-up requests). Status 0 = transport
// error, -1 = undecodable 200 answer; the body or error text is returned either way.
func (e *env) registerCtx(c context.Context, nc *ts2021.Client, n *fakeNode, req tailcfg.RegisterRequest) (tailcfg.RegisterResponse, int, string) {
	req.Version = tailcfg.CurrentCapabilityVersion
	req.NodeKey = n.Node.Public()
	if req.Hostinfo == nil {
		req.Hostinfo = n.hostinfo()
	}
	status, body, err := e.noiseDo(c, nc, n, http.MethodPost, "/machine/register", req)
	if err != nil {
		return tailcfg.RegisterResponse{}, 0, err.Error()
	}
	var resp tailcfg.RegisterResponse
	if status == http.StatusOK {
		if err := json.Unmarshal(body, &resp); err != nil {
			return resp, -1, "decode RegisterResponse: " + err.Error()
		}
	}
	return resp, status, strings.TrimSpace(string(body))
}

// registerWithKey registers with a pre-auth key and an optional client-requested expiry (V-21).
func (e *env) registerWithKey(t *testing.T, n *fakeNode, authKey string, expiry time.Time) tailcfg.RegisterResponse {
	t.Helper()
	nc := e.noise(t, n)
	resp, status, body := e.register(t, nc, n, tailcfg.RegisterRequest{Auth: &tailcfg.RegisterResponseAuth{AuthKey: authKey}, Expiry: expiry})
	if status != http.StatusOK || resp.Error != "" || !resp.MachineAuthorized {
		t.Fatalf("register %s: http %d %s (error %q)", n.Hostname, status, body, resp.Error)
	}
	return resp
}

// startInteractive begins a web-auth registration and returns the Auth ID from the AuthURL.
func (e *env) startInteractive(t *testing.T, nc *ts2021.Client, n *fakeNode, expiry time.Time) (authURL, authID string) {
	t.Helper()
	resp, status, body := e.register(t, nc, n, tailcfg.RegisterRequest{Expiry: expiry})
	if status != http.StatusOK || resp.AuthURL == "" {
		t.Fatalf("interactive register %s: http %d %s", n.Hostname, status, body)
	}
	u, err := url.Parse(resp.AuthURL)
	if err != nil {
		t.Fatalf("auth url: %v", err)
	}
	return resp.AuthURL, path.Base(u.Path)
}

// followup sends the follow-up RegisterRequest a client keeps in flight while the user authenticates (no
// testing.T: it runs in a goroutine).
func (e *env) followup(c context.Context, nc *ts2021.Client, n *fakeNode, authURL string) (tailcfg.RegisterResponse, int, string) {
	return e.registerCtx(c, nc, n, tailcfg.RegisterRequest{Followup: authURL})
}

// firstMap opens a streaming map session, returns its first (full) MapResponse and closes the session.
func (e *env) firstMap(t *testing.T, n *fakeNode) *tailcfg.MapResponse {
	t.Helper()
	mr, stop := e.mapSession(t, n)
	stop()
	return mr
}

// mapSession opens a streaming map session (the node is "online" while it is open), returns the first MapResponse
// and a stop function; later frames are drained in the background.
func (e *env) mapSession(t *testing.T, n *fakeNode) (*tailcfg.MapResponse, func()) {
	t.Helper()
	c, err := tsp.NewClient(tsp.ClientOpts{ServerURL: e.controlURL, MachineKey: n.Machine, Logf: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	mctx, cancel := context.WithCancel(context.Background())
	sess, err := c.Map(mctx, tsp.MapOpts{NodeKey: n.Node, Hostinfo: n.hostinfo(), Stream: true})
	if err != nil {
		cancel()
		_ = c.Close()
		t.Fatalf("map %s: %v", n.Hostname, err)
	}
	type res struct {
		mr  *tailcfg.MapResponse
		err error
	}
	first := make(chan res, 1)
	go func() {
		mr, err := sess.Next()
		first <- res{mr, err}
		for err == nil {
			_, err = sess.Next()
		}
	}()
	var r res
	select {
	case r = <-first:
	case <-time.After(30 * time.Second):
		r.err = fmt.Errorf("no map response within 30s")
	}
	stop := func() {
		cancel()
		_ = sess.Close()
		_ = c.Close()
	}
	if r.err != nil {
		stop()
		t.Fatalf("map %s: %v", n.Hostname, r.err)
	}
	return r.mr, stop
}

// filterSummary describes the packet filter a node received: "allow-all", "deny-all" or the allowed ports.
func filterSummary(mr *tailcfg.MapResponse) string {
	rules := slices.Clone(mr.PacketFilter)
	keys := make([]string, 0, len(mr.PacketFilters))
	for k := range mr.PacketFilters {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		rules = append(rules, mr.PacketFilters[k]...)
	}
	if len(rules) == 0 {
		return "deny-all"
	}
	var ports []string
	for _, r := range rules {
		for _, dp := range r.DstPorts {
			if slices.Contains(r.SrcIPs, "*") && dp.IP == "*" && dp.Ports.First == 0 && dp.Ports.Last == 65535 {
				return "allow-all"
			}
			p := fmt.Sprintf("%d", dp.Ports.First)
			if dp.Ports.Last != dp.Ports.First {
				p = fmt.Sprintf("%d-%d", dp.Ports.First, dp.Ports.Last)
			}
			if !slices.Contains(ports, p) {
				ports = append(ports, p)
			}
		}
	}
	slices.Sort(ports)
	return "ports=" + strings.Join(ports, ",")
}

// sshAction is the call tailscaled makes as the DESTINATION of an SSH session whose rule has action "check".
func (e *env) sshAction(t *testing.T, c context.Context, nc *ts2021.Client, dst *fakeNode, srcID, dstID uint64, authID string) (tailcfg.SSHAction, int, string) {
	t.Helper()
	p := fmt.Sprintf("/machine/ssh/action/%d/to/%d?local_user=root", srcID, dstID)
	if authID != "" {
		p += "&auth_id=" + url.QueryEscape(authID)
	}
	status, body, err := e.noiseDo(c, nc, dst, http.MethodGet, p, nil)
	if err != nil {
		return tailcfg.SSHAction{}, 0, err.Error()
	}
	var a tailcfg.SSHAction
	if status == http.StatusOK {
		if err := json.Unmarshal(body, &a); err != nil {
			t.Fatalf("decode SSHAction: %v", err)
		}
	}
	return a, status, strings.TrimSpace(string(body))
}

// authIDFromHold extracts auth_id from a HoldAndDelegate URL.
func authIDFromHold(t *testing.T, hold string) string {
	t.Helper()
	u, err := url.Parse(strings.NewReplacer("$SRC_NODE_ID", "0", "$DST_NODE_ID", "0").Replace(hold))
	if err != nil {
		t.Fatalf("hold url: %v", err)
	}
	id := u.Query().Get("auth_id")
	if id == "" {
		t.Fatalf("no auth_id in HoldAndDelegate")
	}
	return id
}
