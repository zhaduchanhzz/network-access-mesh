package identity

// FakeIdP is an OpenID Provider for tests (httptest): discovery, JWKS, an authorization endpoint that "logs the
// user in" at once and redirects to the registered redirect URI, and a token endpoint that checks client
// authentication, the redirect URI and the PKCE verifier before minting an RS256 ID token. Knobs let a test break
// one property of the answer at a time (issuer, key, audience, nonce, expiry, auth_time, claims, iss parameter).

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// FakeUser is the end user the fake IdP authenticates.
type FakeUser struct {
	Sub           string
	Email         string
	EmailVerified bool
	Name          string
	Extra         map[string]any // additional ID-token claims (hd, org, groups…)
}

type fakeClient struct {
	secret       string
	redirectURIs map[string]bool
}

type fakeCode struct {
	clientID, redirectURI, challenge, nonce string
	user                                    FakeUser
	authTime                                time.Time
	used                                    bool
}

// FakeIdP is a test OpenID Provider.
type FakeIdP struct {
	Server *httptest.Server
	Issuer string
	Key    *rsa.PrivateKey
	KID    string

	// AdvertiseIss sets authorization_response_iss_parameter_supported and adds iss to every authorization response.
	AdvertiseIss bool
	// Now is the IdP clock (share the service clock).
	Now func() time.Time

	mu       sync.Mutex
	clients  map[string]fakeClient
	codes    map[string]*fakeCode
	user     FakeUser
	ssoTime  time.Time                          // auth_time when the user is "already logged in" (zero = now)
	ignorePL bool                               // ignore prompt=login (keep ssoTime)
	mutate   func(claims map[string]any)        // edits the ID-token claims before signing
	override func(claims map[string]any) string // replaces the whole ID token
	lastAuth url.Values
	lastVer  string

	TokenCalls     atomic.Int32
	AuthorizeCalls atomic.Int32
}

var (
	fakeKeyMu   sync.Mutex
	fakeKeyPool []*rsa.PrivateKey
)

// fakeKey hands out a distinct RSA key per fake IdP (never reused: tests rely on two IdPs having different keys).
// Keys are generated in parallel batches because 2048-bit generation is slow under -race.
func fakeKey() *rsa.PrivateKey {
	fakeKeyMu.Lock()
	defer fakeKeyMu.Unlock()
	if len(fakeKeyPool) == 0 {
		const batch = 12
		keys := make([]*rsa.PrivateKey, batch)
		var wg sync.WaitGroup
		for i := range keys {
			wg.Add(1)
			go func() {
				defer wg.Done()
				k, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					panic(err)
				}
				keys[i] = k
			}()
		}
		wg.Wait()
		fakeKeyPool = keys
	}
	k := fakeKeyPool[len(fakeKeyPool)-1]
	fakeKeyPool = fakeKeyPool[:len(fakeKeyPool)-1]
	return k
}

// NewFakeIdP starts a fake OpenID Provider; it is closed at the end of the test.
func NewFakeIdP(t testing.TB, now func() time.Time) *FakeIdP {
	t.Helper()
	f := &FakeIdP{
		Key: fakeKey(), KID: "kid-" + randomHex(4), Now: now,
		clients: map[string]fakeClient{}, codes: map[string]*fakeCode{},
		user: FakeUser{Sub: "user-" + randomHex(4), Email: "user@example.test", EmailVerified: true, Name: "Test User"},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", f.discovery)
	mux.HandleFunc("GET /jwks", f.jwks)
	mux.HandleFunc("GET /authorize", f.authorize)
	mux.HandleFunc("POST /token", f.token)
	f.Server = httptest.NewServer(mux)
	f.Issuer = f.Server.URL
	t.Cleanup(f.Server.Close)
	return f
}

// AddClient registers a client and its redirect URIs.
func (f *FakeIdP) AddClient(id, secret string, redirectURIs ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := fakeClient{secret: secret, redirectURIs: map[string]bool{}}
	for _, u := range redirectURIs {
		c.redirectURIs[u] = true
	}
	f.clients[id] = c
}

// SetUser sets the user of the next authorizations.
func (f *FakeIdP) SetUser(u FakeUser) { f.mu.Lock(); f.user = u; f.mu.Unlock() }

// SetSSOTime sets the auth_time of an existing IdP session (zero = authenticate now). With ignorePromptLogin the
// IdP keeps it even when asked for prompt=login (a non-conforming IdP).
func (f *FakeIdP) SetSSOTime(t time.Time, ignorePromptLogin bool) {
	f.mu.Lock()
	f.ssoTime, f.ignorePL = t, ignorePromptLogin
	f.mu.Unlock()
}

// Mutate edits the claims of the next ID tokens (nil = none).
func (f *FakeIdP) Mutate(fn func(claims map[string]any)) { f.mu.Lock(); f.mutate = fn; f.mu.Unlock() }

// Override replaces the next ID tokens entirely (nil = none).
func (f *FakeIdP) Override(fn func(claims map[string]any) string) {
	f.mu.Lock()
	f.override = fn
	f.mu.Unlock()
}

// LastAuthorize returns the query of the last authorization request.
func (f *FakeIdP) LastAuthorize() url.Values { f.mu.Lock(); defer f.mu.Unlock(); return f.lastAuth }

// LastVerifier returns the PKCE verifier received by the last token request.
func (f *FakeIdP) LastVerifier() string { f.mu.Lock(); defer f.mu.Unlock(); return f.lastVer }

func (f *FakeIdP) discovery(w http.ResponseWriter, _ *http.Request) {
	doc := map[string]any{
		"issuer":                                f.Issuer,
		"authorization_endpoint":                f.Issuer + "/authorize",
		"token_endpoint":                        f.Issuer + "/token",
		"jwks_uri":                              f.Issuer + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "email", "email_verified", "name"},
	}
	if f.AdvertiseIss {
		doc["authorization_response_iss_parameter_supported"] = true
	}
	writeJSON(w, http.StatusOK, doc)
}

func (f *FakeIdP) jwks(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]string{JWK(&f.Key.PublicKey, f.KID)}})
}

// JWK returns the public JWK of an RSA key.
func JWK(k *rsa.PublicKey, kid string) map[string]string {
	return map[string]string{
		"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
	}
}

func (f *FakeIdP) authorize(w http.ResponseWriter, r *http.Request) {
	f.AuthorizeCalls.Add(1)
	q := r.URL.Query()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastAuth = q
	c, ok := f.clients[q.Get("client_id")]
	if !ok || !c.redirectURIs[q.Get("redirect_uri")] {
		http.Error(w, "invalid client or redirect_uri", http.StatusBadRequest)
		return
	}
	if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" ||
		!strings.Contains(" "+q.Get("scope")+" ", " openid ") {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	authTime := f.ssoTime
	if authTime.IsZero() || (q.Get("prompt") == "login" && !f.ignorePL) || q.Get("max_age") == "0" && !f.ignorePL {
		authTime = f.Now()
	}
	code := randomHex(16)
	f.codes[code] = &fakeCode{
		clientID: q.Get("client_id"), redirectURI: q.Get("redirect_uri"), challenge: q.Get("code_challenge"),
		nonce: q.Get("nonce"), user: f.user, authTime: authTime,
	}
	resp := url.Values{"code": {code}, "state": {q.Get("state")}}
	if f.AdvertiseIss {
		resp.Set("iss", f.Issuer)
	}
	// redirect_uri was checked against the client's registered URIs above (test IdP).
	http.Redirect(w, r, q.Get("redirect_uri")+"?"+resp.Encode(), http.StatusFound) //nolint:gosec // registered URI only
}

func (f *FakeIdP) token(w http.ResponseWriter, r *http.Request) {
	f.TokenCalls.Add(1)
	if err := r.ParseForm(); err != nil {
		oauthError(w, "invalid_request")
		return
	}
	id, secret, ok := r.BasicAuth()
	if ok {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	} else {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	c, known := f.clients[id]
	if !known || !hmac.Equal([]byte(c.secret), []byte(secret)) {
		oauthError(w, "invalid_client")
		return
	}
	code, ok := f.codes[r.PostForm.Get("code")]
	if r.PostForm.Get("grant_type") != "authorization_code" || !ok || code.used || code.clientID != id ||
		code.redirectURI != r.PostForm.Get("redirect_uri") {
		oauthError(w, "invalid_grant")
		return
	}
	code.used = true
	ver := r.PostForm.Get("code_verifier")
	sum := sha256.Sum256([]byte(ver))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != code.challenge {
		oauthError(w, "invalid_grant")
		return
	}
	f.lastVer = ver
	now := f.Now()
	claims := map[string]any{
		"iss": f.Issuer, "sub": code.user.Sub, "aud": id, "azp": id, "exp": now.Add(5 * time.Minute).Unix(),
		"iat": now.Unix(), "auth_time": code.authTime.Unix(), "nonce": code.nonce, "name": code.user.Name,
		"acr": "1",
	}
	if code.user.Email != "" {
		claims["email"], claims["email_verified"] = code.user.Email, code.user.EmailVerified
	}
	for k, v := range code.user.Extra {
		claims[k] = v
	}
	if f.mutate != nil {
		f.mutate(claims)
	}
	var idToken string
	if f.override != nil {
		idToken = f.override(claims)
	} else {
		idToken = SignRS256(f.Key, f.KID, claims)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": "at-" + randomHex(8), "token_type": "Bearer", "expires_in": 300, "id_token": idToken,
	})
}

// SignRS256 signs claims as a compact JWS (RS256).
func SignRS256(k *rsa.PrivateKey, kid string, claims map[string]any) string {
	h, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": kid, "typ": "JWT"})
	p, _ := json.Marshal(claims)
	in := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)
	d := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, d[:])
	if err != nil {
		panic(err)
	}
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// SignHS256 signs claims with an HMAC key (an alg the RP must refuse).
func SignHS256(key []byte, claims map[string]any) string {
	h, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	p, _ := json.Marshal(claims)
	in := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)
	m := hmac.New(sha256.New, key)
	_, _ = m.Write([]byte(in))
	return in + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// UnsignedJWT returns an alg=none token (the RP must refuse it).
func UnsignedJWT(claims map[string]any) string {
	h, _ := json.Marshal(map[string]string{"alg": "none", "typ": "JWT"})
	p, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p) + "."
}

func oauthError(w http.ResponseWriter, code string) {
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": code})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
