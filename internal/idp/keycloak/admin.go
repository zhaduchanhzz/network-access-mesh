package keycloak

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
)

// tokenSource names how to obtain a bearer token: client credentials of clientID in realm (secret from the
// SecretStore), or — Bootstrap only — the password grant of a master-realm user through admin-cli.
type tokenSource struct {
	realm    string
	clientID string
	username string // password grant when set
	secret   secrets.Ref
}

func (t tokenSource) key() string {
	return t.realm + "|" + t.clientID + "|" + t.username + "|" + t.secret.String()
}

type cachedToken struct {
	value string
	exp   time.Time
}

// admin is the Admin REST client shared by the driver and Bootstrap.
type admin struct {
	http    *http.Client
	base    string
	secrets secrets.SecretStore
	log     *slog.Logger
	now     func() time.Time

	mu     sync.Mutex
	tokens map[string]cachedToken
}

func newAdmin(route *idp.PlatformRoute, st secrets.SecretStore, log *slog.Logger, now func() time.Time) *admin {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if now == nil {
		now = time.Now
	}
	return &admin{http: route.Client(), base: route.BaseURL(), secrets: st, log: log.With("module", "idp", "driver", "keycloak"),
		now: now, tokens: map[string]cachedToken{}}
}

// token returns a cached bearer token or fetches a new one. The secret is read from the SecretStore at each fetch and
// wiped after use; tokens and secrets are never logged.
func (a *admin) token(ctx context.Context, op string, ts tokenSource) (string, error) {
	k := ts.key()
	a.mu.Lock()
	t, ok := a.tokens[k]
	a.mu.Unlock()
	if ok && a.now().Before(t.exp) {
		return t.value, nil
	}
	value, ttl, err := a.fetchToken(ctx, op, ts)
	if err != nil {
		return "", err
	}
	skew := 30 * time.Second
	if ttl <= 2*skew {
		skew = ttl / 2
	}
	a.mu.Lock()
	a.tokens[k] = cachedToken{value: value, exp: a.now().Add(ttl - skew)}
	a.mu.Unlock()
	return value, nil
}

func (a *admin) invalidate(ts tokenSource) {
	a.mu.Lock()
	delete(a.tokens, ts.key())
	a.mu.Unlock()
}

// invalidateRealm drops every cached token of realm (after it was disabled or deleted).
func (a *admin) invalidateRealm(realm string) {
	a.mu.Lock()
	for k := range a.tokens {
		if strings.HasPrefix(k, realm+"|") {
			delete(a.tokens, k)
		}
	}
	a.mu.Unlock()
}

// fetchToken runs the token request of ts at the realm's token endpoint.
func (a *admin) fetchToken(ctx context.Context, op string, ts tokenSource) (string, time.Duration, error) {
	secret, err := idp.ReadSecret(ctx, a.secrets, op, ts.secret)
	if err != nil {
		return "", 0, err
	}
	defer secret.Wipe()
	form := url.Values{"client_id": {ts.clientID}}
	if ts.username != "" {
		form.Set("grant_type", "password")
		form.Set("username", ts.username)
		form.Set("password", string(secret.Bytes()))
	} else {
		form.Set("grant_type", "client_credentials")
		form.Set("client_secret", string(secret.Bytes()))
	}
	return a.postToken(ctx, op, ts.realm, form)
}

func (a *admin) postToken(ctx context.Context, op, realm string, form url.Values) (string, time.Duration, error) {
	endpoint := a.base + "/realms/" + url.PathEscape(realm) + "/protocol/openid-connect/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, idp.NewError(idp.CodeInternal, op, "token_request", nil)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := a.http.Do(req)
	if err != nil {
		return "", 0, idp.Classify(op, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, idp.Classify(op, err)
	}
	if resp.StatusCode != http.StatusOK {
		e := idp.StatusError(op, resp.StatusCode)
		e.Reason = "token_" + e.Reason
		return "", 0, e
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if json.Unmarshal(body, &tok) != nil || tok.AccessToken == "" {
		return "", 0, idp.NewError(idp.CodeUpstream, op, "token_malformed", nil)
	}
	ttl := time.Duration(tok.ExpiresIn) * time.Second
	if ttl <= 0 || ttl > time.Hour {
		ttl = time.Minute
	}
	return tok.AccessToken, ttl, nil
}

// call performs one Admin REST call with the token of ts: in (if not nil) is sent as JSON, a 2xx JSON body is
// decoded into out (numbers as json.Number). A status listed in accept is returned without error; any other non-2xx
// status is an *idp.Error built from the status alone — the response body is never read into an error or a log. A
// 401 drops the cached token and the call is retried once with a fresh one.
func (a *admin) call(ctx context.Context, op string, ts tokenSource, method, p string, in, out any,
	accept ...int,
) (int, http.Header, error) {
	var payload []byte
	if in != nil {
		var err error
		if payload, err = json.Marshal(in); err != nil {
			return 0, nil, idp.NewError(idp.CodeInternal, op, "encode", err)
		}
	}
	for attempt := 0; ; attempt++ {
		tok, err := a.token(ctx, op, ts)
		if err != nil {
			return 0, nil, err
		}
		var body io.Reader
		if payload != nil {
			body = bytes.NewReader(payload)
		}
		req, err := http.NewRequestWithContext(ctx, method, a.base+p, body)
		if err != nil {
			return 0, nil, idp.NewError(idp.CodeInternal, op, "request", nil)
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Accept", "application/json")
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := a.http.Do(req)
		if err != nil {
			return 0, nil, idp.Classify(op, err)
		}
		data, rerr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if rerr != nil {
			return resp.StatusCode, nil, idp.Classify(op, rerr)
		}
		switch st := resp.StatusCode; {
		case st == http.StatusUnauthorized && attempt == 0:
			a.invalidate(ts)
			continue
		case st >= 200 && st < 300:
			if out != nil && len(bytes.TrimSpace(data)) > 0 {
				dec := json.NewDecoder(bytes.NewReader(data))
				dec.UseNumber()
				if err := dec.Decode(out); err != nil {
					return st, resp.Header, idp.NewError(idp.CodeUpstream, op, "malformed_json", nil)
				}
			}
			return st, resp.Header, nil
		case slices.Contains(accept, st):
			return st, resp.Header, nil
		default:
			a.log.Debug("keycloak: admin call refused", "op", op, "method", method, "status", st)
			return st, resp.Header, idp.StatusError(op, st)
		}
	}
}

// createdID returns the id at the end of the Location header of a 201 (a UUID for users and clients).
func createdID(op string, h http.Header) (string, error) {
	loc, err := url.Parse(h.Get("Location"))
	if err != nil || loc.Path == "" {
		return "", idp.NewError(idp.CodeUpstream, op, "location_missing", nil)
	}
	id := path.Base(loc.Path)
	if _, err := uuid.Parse(id); err != nil {
		return "", idp.NewError(idp.CodeUpstream, op, "location_invalid", nil)
	}
	return id, nil
}

// Path helpers (every variable segment escaped; realm names are validated before use).
func realmPath(realm string) string { return "/admin/realms/" + url.PathEscape(realm) }

func realmSub(realm string, parts ...string) string {
	p := realmPath(realm)
	for _, s := range parts {
		p += "/" + url.PathEscape(s)
	}
	return p
}
