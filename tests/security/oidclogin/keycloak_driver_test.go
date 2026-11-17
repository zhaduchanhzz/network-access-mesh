//go:build mgtestfixture

package oidclogin_test

// Keycloak driver of the test: the stack of tests/idp/run_dev.sh (P2-T05) reached through its TLS test proxy, its
// Admin API as the bootstrap admin (only to read the client secret of mg-portal and to create/delete the test user)
// and its HTML forms as a browser would fill them (password, mandatory TOTP enrolment, OTP). Same approach as the
// Keycloak tests of internal/identity (keycloak_test.go — a test file, not importable, and re-run unchanged by this
// task). No secret, cookie, token or TOTP seed is ever printed.

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // TOTP (RFC 6238) is HMAC-SHA1 by definition
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

type kcEnv struct {
	base   *url.URL
	client *http.Client // TLS to the test proxy, no redirect following, no cookies
	admin  string       // bearer token of the bootstrap admin (master realm)
}

// kcSetup reads the MG_TEST_KEYCLOAK_* variables (skips without MG_TEST_KEYCLOAK_URL, like the Keycloak tests of
// internal/identity: CI has no Keycloak) and logs in to the Admin API.
func kcSetup(t *testing.T) *kcEnv {
	t.Helper()
	raw := os.Getenv("MG_TEST_KEYCLOAK_URL")
	if raw == "" {
		t.Skip("MG_TEST_KEYCLOAK_URL not set — Keycloak integration skipped (tests/idp/run_dev.sh)")
	}
	base, err := url.Parse(raw)
	if err != nil || base.Scheme != "https" || !strings.HasPrefix(base.Hostname(), "auth.") {
		t.Fatalf("MG_TEST_KEYCLOAK_URL %q: want https://auth.<domain>", raw)
	}
	pem, err := os.ReadFile(os.Getenv("MG_TEST_KEYCLOAK_CAFILE")) //nolint:gosec // path given by the test operator
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("no CA certificate in MG_TEST_KEYCLOAK_CAFILE")
	}
	connect := os.Getenv("MG_TEST_KEYCLOAK_CONNECT")
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr == base.Hostname()+":443" && connect != "" {
				addr = connect
			}
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, addr)
		},
	}
	e := &kcEnv{base: base, client: &http.Client{Transport: tr, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	conf := readKeycloakConf(t, os.Getenv("MG_TEST_KEYCLOAK_ADMIN_CONF"))
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	e.form(t, "/realms/master/protocol/openid-connect/token", url.Values{"grant_type": {"password"},
		"client_id": {"admin-cli"}, "username": {conf["bootstrap-admin-username"]}, "password": {conf["bootstrap-admin-password"]}}, &tok)
	if tok.AccessToken == "" {
		t.Fatal("no admin token")
	}
	e.admin = tok.AccessToken
	return e
}

func readKeycloakConf(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path) //nolint:gosec // test configuration
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), "="); ok && !strings.HasPrefix(strings.TrimSpace(k), "#") {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out
}

// do sends one request to Keycloak with the cookies of jar (nil = none) and stores the cookies Keycloak sets.
func (e *kcEnv) do(t *testing.T, jar http.CookieJar, method, target string, body io.Reader, hdr http.Header) *http.Response {
	t.Helper()
	u, err := e.base.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	// Not t.Context(): the user is deleted in a cleanup, after the test context is cancelled.
	req, err := http.NewRequestWithContext(context.Background(), method, u.String(), body)
	if err != nil {
		t.Fatal(err)
	}
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if jar != nil {
		for _, c := range jar.Cookies(u) {
			req.AddCookie(c) //nolint:gosec // request cookie (attributes only exist in Set-Cookie)
		}
	}
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, u.Path, err)
	}
	if jar != nil {
		jar.SetCookies(u, resp.Cookies())
	}
	return resp
}

func (e *kcEnv) form(t *testing.T, target string, v url.Values, out any) {
	t.Helper()
	resp := e.do(t, nil, http.MethodPost, target, strings.NewReader(v.Encode()),
		http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST %s: HTTP %d", target, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatal(err)
	}
}

// api calls the Admin REST API as the bootstrap admin and returns the response headers.
func (e *kcEnv) api(t *testing.T, method, path string, in, out any) http.Header {
	t.Helper()
	var body io.Reader
	hdr := http.Header{"Authorization": {"Bearer " + e.admin}, "Accept": {"application/json"}}
	if in != nil {
		b, _ := json.Marshal(in)
		body = strings.NewReader(string(b))
		hdr.Set("Content-Type", "application/json")
	}
	resp := e.do(t, nil, method, path, body, hdr)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		t.Fatalf("%s %s: HTTP %d", method, path, resp.StatusCode)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatal(err)
		}
	}
	return resp.Header
}

// kcUser is the throwaway user of one test run.
type kcUser struct {
	id, username, password string
}

// kcRealm reads the client secret of mg-portal (generated by Keycloak at import; production reads it from the
// SecretStore) and creates a test user with a random password (CONFIGURE_TOTP is a default required action of the
// realm template), deleted when the test ends.
func (e *kcEnv) kcRealm(t *testing.T, realm string) (secret string, user kcUser) {
	t.Helper()
	var clients []struct {
		ID string `json:"id"`
	}
	e.api(t, http.MethodGet, "/admin/realms/"+realm+"/clients?clientId=mg-portal", nil, &clients)
	if len(clients) != 1 {
		t.Fatal("mg-portal not found")
	}
	var sec struct {
		Value string `json:"value"`
	}
	e.api(t, http.MethodGet, "/admin/realms/"+realm+"/clients/"+clients[0].ID+"/client-secret", nil, &sec)
	if sec.Value == "" {
		t.Fatal("no client secret")
	}
	user = kcUser{username: "p2t15a-" + randomHex(4), password: randomHex(16)}
	hdr := e.api(t, http.MethodPost, "/admin/realms/"+realm+"/users", map[string]any{
		"username": user.username, "email": user.username + "@example.invalid", "emailVerified": true, "enabled": true,
		"firstName": "P2T15a", "lastName": "Login",
		"credentials": []map[string]any{{"type": "password", "value": user.password, "temporary": false}},
	}, nil)
	loc := hdr.Get("Location")
	user.id = loc[strings.LastIndex(loc, "/")+1:]
	t.Cleanup(func() {
		r := e.do(t, nil, http.MethodDelete, "/admin/realms/"+realm+"/users/"+user.id, nil,
			http.Header{"Authorization": {"Bearer " + e.admin}})
		_ = r.Body.Close()
	})
	return sec.Value, user
}

// totp generates RFC 6238 codes (SHA-1, 6 digits, 30 s) strictly increasing in counter: Keycloak refuses a code
// twice (otpPolicyCodeReusable=false) and accepts the current or the next period.
type totp struct {
	key  []byte
	last int64
}

func (o *totp) code() string {
	for {
		now := time.Now().Unix() / 30
		for _, c := range []int64{now, now + 1} {
			if c > o.last {
				o.last = c
				m := hmac.New(sha1.New, o.key)
				_ = binary.Write(m, binary.BigEndian, c)
				sum := m.Sum(nil)
				off := sum[len(sum)-1] & 0x0f
				v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
				return fmt.Sprintf("%06d", v%1000000)
			}
		}
		time.Sleep(time.Until(time.Unix((now+1)*30, 0)) + 500*time.Millisecond)
	}
}

var (
	formRE  = regexp.MustCompile(`(?is)<form\b([^>]*)>|</form>|<input\b([^>]*)>`)
	attrRE  = regexp.MustCompile(`(?is)([a-z_:][-a-z0-9_:.]*)\s*=\s*"([^"]*)"`)
	checkRE = regexp.MustCompile(`(?i)\bchecked\b`)
)

type htmlForm struct {
	action string
	inputs map[string]string
}

// parseForms extracts the forms of a Keycloak page (action and named inputs).
func parseForms(page string) []htmlForm {
	var forms []htmlForm
	var cur *htmlForm
	for _, m := range formRE.FindAllStringSubmatch(page, -1) {
		switch {
		case strings.HasPrefix(strings.ToLower(m[0]), "<form"):
			a := attrs(m[1])
			forms = append(forms, htmlForm{action: a["action"], inputs: map[string]string{}})
			cur = &forms[len(forms)-1]
		case strings.HasPrefix(m[0], "</"):
			cur = nil
		case cur != nil:
			a := attrs(m[2])
			typ := strings.ToLower(a["type"])
			if a["name"] == "" || typ == "submit" || typ == "button" || typ == "image" || typ == "reset" ||
				((typ == "checkbox" || typ == "radio") && !checkRE.MatchString(m[2])) {
				continue
			}
			cur.inputs[a["name"]] = a["value"]
		}
	}
	return forms
}

func attrs(s string) map[string]string {
	out := map[string]string{}
	for _, m := range attrRE.FindAllStringSubmatch(s, -1) {
		out[strings.ToLower(m[1])] = html.UnescapeString(m[2])
	}
	return out
}

func formWith(forms []htmlForm, names ...string) *htmlForm {
	for i := range forms {
		ok := true
		for _, n := range names {
			if _, has := forms[i].inputs[n]; !has {
				ok = false
			}
		}
		if ok {
			return &forms[i]
		}
	}
	return nil
}

// browserLogin drives Keycloak from the authorization URL to its redirect back to the Portal host; it returns that
// redirect (the callback URL of our API) and the steps taken.
func (e *kcEnv) browserLogin(t *testing.T, authURL string, user kcUser, otp *totp, portal string) (*url.URL, []string) {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	var steps []string
	resp := e.do(t, jar, http.MethodGet, authURL, nil, nil)
	for range 12 {
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther {
			loc, err := url.Parse(resp.Header.Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			if loc.Host == portal {
				return loc, steps
			}
			resp = e.do(t, jar, http.MethodGet, loc.String(), nil, nil)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Keycloak HTTP %d at step %v", resp.StatusCode, steps)
		}
		forms := parseForms(string(body))
		post := func(f *htmlForm, step string, set map[string]string) {
			v := url.Values{}
			for k, val := range f.inputs {
				v.Set(k, val)
			}
			for k, val := range set {
				v.Set(k, val)
			}
			steps = append(steps, step)
			resp = e.do(t, jar, http.MethodPost, f.action, strings.NewReader(v.Encode()), //nolint:bodyclose // closed at the top of the next iteration
				http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
		}
		if f := formWith(forms, "password"); f != nil && formWith(forms, "totp") == nil {
			set := map[string]string{"password": user.password}
			if _, ok := f.inputs["username"]; ok {
				set["username"] = user.username
			}
			post(f, "password", set)
			continue
		}
		if f := formWith(forms, "totp", "totpSecret"); f != nil {
			otp.key = []byte(f.inputs["totpSecret"])
			post(f, "configure_totp", map[string]string{"totp": otp.code(), "userLabel": "p2t15a-test"})
			continue
		}
		if f := formWith(forms, "otp"); f != nil {
			post(f, "otp", map[string]string{"otp": otp.code()})
			continue
		}
		t.Fatalf("unexpected Keycloak page after %v (%d forms)", steps, len(forms))
	}
	t.Fatalf("too many Keycloak steps: %v", steps)
	return nil, nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
