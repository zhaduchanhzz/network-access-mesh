//go:build linux && dockerintegration

package provisioning

// The two collaborators of the worker that are not real in this harness: the IdP driver (no Keycloak) and the prober
// (apps/probe is not deployed — the test prober probes the instance through the public listener of the test edge).

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/orchestrator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
)

// keycloakDriver is an in-memory "keycloak" driver: realm = slug; EnsureClient stores a random client secret in the
// REAL SecretStore (idp.<id>.client) like the real driver, so the orphan detector judges a real secret row.
type keycloakDriver struct {
	sec    orchestrator.SecretStore
	mu     sync.Mutex
	realms map[string]string // realm → enabled/disabled (lost when the worker process restarts — the driver is idempotent)
}

var _ idp.IdPDriver = (*keycloakDriver)(nil)

func (d *keycloakDriver) Name() string { return idp.DriverKeycloak }

func (d *keycloakDriver) EnsureIssuer(_ context.Context, spec idp.IssuerSpec) (idp.IssuerResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	realm := spec.Realm
	if spec.DriverRef != "" {
		realm = spec.DriverRef
	}
	_, existed := d.realms[realm]
	d.realms[realm] = "enabled"
	return idp.IssuerResult{Issuer: "https://auth.pit.test/realms/" + realm, DriverRef: realm, Created: !existed}, nil
}

func (d *keycloakDriver) EnsureClient(ctx context.Context, spec idp.ClientSpec) (idp.ClientResult, error) {
	if spec.ClientSecretRef != "" {
		return idp.ClientResult{ClientID: spec.ClientID, ClientSecretRef: spec.ClientSecretRef}, nil
	}
	name := idp.ClientSecretName(spec.IdPID)
	if ref, err := d.sec.Latest(ctx, spec.TenantID, name); err == nil {
		return idp.ClientResult{ClientID: spec.ClientID, ClientSecretRef: ref.String()}, nil
	} else if !errors.Is(err, secrets.ErrNotFound) {
		return idp.ClientResult{}, idp.NewError(idp.CodeCredentials, "EnsureClient", "secret_store", err)
	}
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	value := []byte(hex.EncodeToString(b))
	defer clear(value)
	ref := secrets.TenantRef(spec.TenantID, name, 1)
	if err := d.sec.Put(ctx, ref, value); err != nil && !errors.Is(err, secrets.ErrExists) {
		return idp.ClientResult{}, idp.NewError(idp.CodeCredentials, "EnsureClient", "secret_store", err)
	}
	return idp.ClientResult{ClientID: spec.ClientID, ClientSecretRef: ref.String(), Created: true, SecretRotated: true}, nil
}

func (d *keycloakDriver) InviteUser(context.Context, idp.Registration, idp.Invite) (idp.InviteResult, error) {
	return idp.InviteResult{}, idp.NewError(idp.CodeUnsupported, "InviteUser", "harness", nil)
}

func (d *keycloakDriver) DisableUser(context.Context, idp.Registration, string) (idp.DisableResult, error) {
	return idp.DisableResult{}, idp.NewError(idp.CodeUnsupported, "DisableUser", "harness", nil)
}

func (d *keycloakDriver) RemoveIssuer(_ context.Context, reg idp.Registration, mode idp.RemoveMode) (idp.RemoveResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, ok := d.realms[reg.DriverRef]
	d.realms[reg.DriverRef] = string(mode)
	return idp.RemoveResult{Mode: mode, AlreadyAbsent: !ok, Changed: true}, nil
}

func (d *keycloakDriver) CheckDiscovery(context.Context, idp.Registration) (idp.Discovery, error) {
	return idp.Discovery{}, nil
}

type drivers map[string]idp.IdPDriver

func (m drivers) Driver(name string) (idp.IdPDriver, error) {
	if d, ok := m[name]; ok {
		return d, nil
	}
	return nil, idp.NewError(idp.CodeUnknownDriver, "Driver", name, nil)
}

// edgeProber probes through the public listener of the test edge (§11.3 steps 17–18, without TLS): /key?v= must answer
// the instance's Noise public key, every forbidden path must be 404, /derp/probe must answer 200. The shared STUN
// responder is not part of the harness (check "stun" reported skipped).
type edgeProber struct {
	client *http.Client
}

func newEdgeProber() *edgeProber {
	return &edgeProber{client: &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// forbiddenPaths of §11.3 step 18 (and §14.6): the public listener must hide them.
var forbiddenPaths = []string{"/api/v1/apikey", "/swagger", "/verify", "/version", "/health", "/metrics", "/debug/pprof/"}

func (p *edgeProber) get(ctx context.Context, address, host, path string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+path, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Host = host
	resp, err := p.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, b, err
}

func (p *edgeProber) Relay(ctx context.Context, r orchestrator.RelayProbe) (orchestrator.ProbeResult, error) {
	status, _, err := p.get(ctx, r.Address, r.Host, "/derp/probe")
	if err != nil {
		return orchestrator.ProbeResult{}, fmt.Errorf("relay probe: %w", err)
	}
	derp := orchestrator.ProbeCheck{Name: "/derp/probe", OK: status == http.StatusOK, Status: status}
	stun := orchestrator.ProbeCheck{Name: "stun", OK: true, Code: "skipped_in_harness"}
	return orchestrator.ProbeResult{OK: derp.OK, Checks: []orchestrator.ProbeCheck{derp, stun}}, nil
}

func (p *edgeProber) Edge(ctx context.Context, r orchestrator.EdgeProbe) (orchestrator.ProbeResult, error) {
	status, body, err := p.get(ctx, r.Address, r.Host, "/key?v=113")
	if err != nil {
		return orchestrator.ProbeResult{}, fmt.Errorf("edge probe: %w", err)
	}
	var k struct {
		PublicKey string `json:"publicKey"`
	}
	_ = json.Unmarshal(body, &k)
	res := orchestrator.ProbeResult{Checks: []orchestrator.ProbeCheck{{Name: "/key", OK: status == 200 && k.PublicKey == r.PublicKey, Status: status}}}
	res.KeyMismatch = status == 200 && k.PublicKey != "" && k.PublicKey != r.PublicKey
	ok := res.Checks[0].OK
	for _, f := range forbiddenPaths {
		st, _, err := p.get(ctx, r.Address, r.Host, f)
		c := orchestrator.ProbeCheck{Name: f, Status: st, OK: err == nil && (st == 404 || st == 421)}
		if err != nil {
			c.Code = "unreachable"
		} else if !c.OK {
			res.Exposed = append(res.Exposed, f)
		}
		ok = ok && c.OK
		res.Checks = append(res.Checks, c)
	}
	res.OK = ok
	return res, nil
}
