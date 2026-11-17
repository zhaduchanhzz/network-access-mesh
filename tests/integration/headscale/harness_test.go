package contract

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
)

// IDs of testdata/params.json (the rendered instance).
var (
	tenantID   = uuid.MustParse("11111111-1111-4111-8111-111111111111")
	instanceID = uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
)

// env is the contract environment prepared by run.sh.
type env struct {
	adminURL   string        // edge admin listener (the only path the adapter uses)
	slug       string        // X-MG-Instance
	controlURL string        // Headscale's own listener on the tenant network (Tailscale protocol, /key)
	apiKey     string        // instance API key, created per run inside the test instance
	edgeToken  string        // admin listener token, random per run
	nodeExpiry time.Duration // node.expiry of the rendered config
	stateDir   string
	obsFile    string
	reg        *headscale.CachingRegistry
}

var (
	envOnce sync.Once
	envVal  *env
	envErr  error
)

func setup(t *testing.T) *env {
	t.Helper()
	if os.Getenv("HSCT_ADMIN_URL") == "" {
		t.Skip("contract environment not set: run tests/integration/headscale/run.sh")
	}
	envOnce.Do(func() { envVal, envErr = loadEnv() })
	if envErr != nil {
		t.Fatalf("contract environment: %v", envErr)
	}
	return envVal
}

func loadEnv() (*env, error) {
	e := &env{adminURL: os.Getenv("HSCT_ADMIN_URL"), slug: os.Getenv("HSCT_SLUG"), controlURL: os.Getenv("HSCT_CONTROL_URL"),
		stateDir: os.Getenv("HSCT_STATE_DIR"), obsFile: os.Getenv("HSCT_OBS_FILE")}
	secrets := os.Getenv("HSCT_SECRETS_DIR")
	for name, dst := range map[string]*string{"api_key": &e.apiKey, "edge_token": &e.edgeToken} {
		b, err := os.ReadFile(filepath.Join(secrets, name)) //nolint:gosec // G304: directory set by run.sh (test harness)
		if err != nil {
			return nil, fmt.Errorf("read secret %s: %w", name, err)
		}
		*dst = strings.TrimSpace(string(b))
	}
	d, err := time.ParseDuration(os.Getenv("HSCT_NODE_EXPIRY"))
	if err != nil {
		return nil, fmt.Errorf("HSCT_NODE_EXPIRY: %w", err)
	}
	e.nodeExpiry = d
	if e.slug == "" || e.controlURL == "" || e.stateDir == "" || e.obsFile == "" {
		return nil, fmt.Errorf("HSCT_SLUG, HSCT_CONTROL_URL, HSCT_STATE_DIR and HSCT_OBS_FILE are required")
	}
	// Adapter logs go through logx at debug level into the state directory; TestP6_AdapterLogsHaveNoCredentials
	// checks the file (the canary test of §25.1 rule 9, on a real run).
	lf, err := os.OpenFile(filepath.Join(e.stateDir, "adapter.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // G703: directory set by run.sh
	if err != nil {
		return nil, err
	}
	e.reg = headscale.NewRegistry(headscale.StaticLocator{tenantID: e.target()}, headscale.Options{
		Logger: logx.New(lf, slog.LevelDebug, "hsct"), Timeout: 15 * time.Second,
	})
	return e, nil
}

func (e *env) target() headscale.Target {
	return headscale.Target{InstanceID: instanceID, Slug: e.slug, AdminURL: e.adminURL,
		APIKey: headscale.NewSecret(e.apiKey), EdgeToken: headscale.NewSecret(e.edgeToken)}
}

func (e *env) inst(t *testing.T) headscale.Instance {
	t.Helper()
	inst, err := e.reg.ForTenant(ctx(t), tenantID)
	if err != nil {
		t.Fatalf("ForTenant: %v", err)
	}
	return inst
}

// instWith builds an adapter instance with a modified target (wrong token, wrong slug, wrong key).
func (e *env) instWith(t *testing.T, mutate func(*headscale.Target)) (headscale.Instance, error) {
	t.Helper()
	tg := e.target()
	mutate(&tg)
	reg := headscale.NewRegistry(headscale.StaticLocator{tenantID: tg}, headscale.Options{
		Retry: headscale.RetryPolicy{Attempts: 1}, Timeout: 10 * time.Second})
	return reg.ForTenant(ctx(t), tenantID)
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	return c
}

// rawReq is a request sent through the edge admin listener without the adapter — for the quirks the adapter
// refuses to send (missing expiration, empty policy, decoder leniency, parameter placement).
type rawReq struct {
	method, path string
	query        url.Values
	body         string
	header       map[string]string // overrides; "" deletes
}

func (e *env) raw(t *testing.T, r rawReq) (int, string) {
	t.Helper()
	u := e.adminURL + r.path
	if len(r.query) > 0 {
		u += "?" + r.query.Encode()
	}
	var body io.Reader = http.NoBody
	if r.body != "" {
		body = strings.NewReader(r.body)
	}
	req, err := http.NewRequestWithContext(ctx(t), r.method, u, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(headscale.HeaderEdgeToken, e.edgeToken)
	req.Header.Set(headscale.HeaderInstance, e.slug)
	if strings.HasPrefix(r.path, "/api/v1/") {
		req.Header.Set("Authorization", "Bearer "+e.apiKey)
	}
	if r.body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range r.header {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	return do(t, req)
}

// control sends a plain HTTP request to Headscale's own listener (not through the edge).
func (e *env) control(t *testing.T, path string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx(t), http.MethodGet, e.controlURL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	return do(t, req)
}

func do(t *testing.T, req *http.Request) (int, string) {
	t.Helper()
	c := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	return res.StatusCode, strings.TrimSpace(string(b))
}

// observation is one recorded behaviour (JSON line in $HSCT_OBS_FILE; summarised in the evidence of P2-T10).
type observation struct {
	Quirk    string `json:"quirk"`
	Case     string `json:"case"`
	Test     string `json:"test"`
	Observed string `json:"observed"`
	Adapter  string `json:"adapter,omitempty"`
	At       string `json:"at"`
}

var obsMu sync.Mutex

// record appends an observation; credentials are scrubbed before anything is written.
func (e *env) record(t *testing.T, quirk, cas, observed, adapter string) {
	t.Helper()
	o := observation{Quirk: quirk, Case: cas, Test: t.Name(), Observed: e.scrub(observed), Adapter: e.scrub(adapter),
		At: time.Now().UTC().Format(time.RFC3339)}
	b, _ := json.Marshal(o)
	obsMu.Lock()
	defer obsMu.Unlock()
	f, err := os.OpenFile(e.obsFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("observation file: %v", err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(append(b, '\n')); err != nil {
		t.Fatal(err)
	}
	t.Logf("OBSERVED [%s] %s: %s", quirk, cas, o.Observed)
}

func (e *env) scrub(s string) string {
	for _, secret := range []string{e.apiKey, e.edgeToken} {
		if secret != "" {
			s = strings.ReplaceAll(s, secret, logx.Redacted)
		}
	}
	return logx.RedactString(s)
}

// state carries fake nodes and values between phases (a file on the run's tmpfs state volume).
type state struct {
	Nodes  map[string]*fakeNode `json:"nodes"`
	Values map[string]string    `json:"values"`
}

func (e *env) loadState(t *testing.T) *state {
	t.Helper()
	s := &state{Nodes: map[string]*fakeNode{}, Values: map[string]string{}}
	b, err := os.ReadFile(filepath.Join(e.stateDir, "state.json"))
	if err == nil {
		if err := json.Unmarshal(b, s); err != nil {
			t.Fatalf("state: %v", err)
		}
	}
	return s
}

func (e *env) saveState(t *testing.T, s *state) {
	t.Helper()
	b, err := json.MarshalIndent(s, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.stateDir, "state.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeSecretFile hands a credential to the runner (e.g. the official client's pre-auth key) without printing it.
func (e *env) writeSecretFile(t *testing.T, name, value string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(e.stateDir, name), []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
}

// kindOf returns the adapter error kind ("" for nil, "?" for a foreign error).
func kindOf(err error) string {
	if err == nil {
		return ""
	}
	if he, ok := headscale.AsError(err); ok {
		return string(he.Kind)
	}
	return "?"
}

// describe summarises an adapter error for the evidence (kind, problem code, outcome, status/code, message).
func describe(err error) string {
	if err == nil {
		return "ok"
	}
	he, ok := headscale.AsError(err)
	if !ok {
		return "foreign error: " + err.Error()
	}
	return fmt.Sprintf("kind=%s problem=%s outcome=%s http=%d code=%d msg=%q", he.Kind, he.ProblemCode(), he.Outcome,
		he.Status, he.Code, he.Upstream)
}

// gatewayBody returns "http <status> code <c>: <message>" for a gateway error body, or the raw text.
func gatewayBody(status int, body string) string {
	var g struct {
		Code    *int   `json:"code"`
		Message string `json:"message"`
	}
	if json.Unmarshal([]byte(body), &g) == nil && g.Code != nil {
		return fmt.Sprintf("http %d code %d: %q", status, *g.Code, g.Message)
	}
	if body == "" {
		return fmt.Sprintf("http %d (empty body)", status)
	}
	return fmt.Sprintf("http %d: %q", status, truncate(body, 300))
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func mustJSON(v any) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return strings.TrimSpace(b.String())
}
