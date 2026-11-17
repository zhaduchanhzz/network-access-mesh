package idp_test

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp/idptest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
)

type stubDriver struct{ name string }

func (s stubDriver) Name() string { return s.name }
func (stubDriver) EnsureIssuer(context.Context, idp.IssuerSpec) (idp.IssuerResult, error) {
	return idp.IssuerResult{}, nil
}
func (stubDriver) EnsureClient(context.Context, idp.ClientSpec) (idp.ClientResult, error) {
	return idp.ClientResult{}, nil
}
func (stubDriver) InviteUser(context.Context, idp.Registration, idp.Invite) (idp.InviteResult, error) {
	return idp.InviteResult{}, nil
}
func (stubDriver) DisableUser(context.Context, idp.Registration, string) (idp.DisableResult, error) {
	return idp.DisableResult{}, nil
}
func (stubDriver) RemoveIssuer(context.Context, idp.Registration, idp.RemoveMode) (idp.RemoveResult, error) {
	return idp.RemoveResult{}, nil
}
func (stubDriver) CheckDiscovery(context.Context, idp.Registration) (idp.Discovery, error) {
	return idp.Discovery{}, nil
}

func TestRegistry(t *testing.T) {
	r, err := idp.NewRegistry(stubDriver{idp.DriverKeycloak}, stubDriver{idp.DriverExternal})
	if err != nil {
		t.Fatal(err)
	}
	if d, err := r.For(idp.Registration{Driver: "external"}); err != nil || d.Name() != "external" {
		t.Fatalf("For(external) = %v, %v", d, err)
	}
	if _, err := r.Driver("ldap"); idp.CodeOf(err) != idp.CodeUnknownDriver {
		t.Fatalf("unknown driver: %v", err)
	}
	if strings.Join(r.Names(), ",") != "external,keycloak" {
		t.Fatalf("Names = %v", r.Names())
	}
	for _, bad := range [][]idp.IdPDriver{{stubDriver{"keycloak"}, stubDriver{"keycloak"}}, {stubDriver{"zitadel"}}, {nil}} {
		if _, err := idp.NewRegistry(bad...); err == nil {
			t.Errorf("NewRegistry(%v) accepted", bad)
		}
	}
}

func TestRegistrationValidate(t *testing.T) {
	id, tenant := uuid.New(), uuid.New()
	for name, c := range map[string]struct {
		reg idp.Registration
		ok  bool
	}{
		"tenant":            {idp.Registration{IdPID: id, Scope: idp.ScopeTenant, TenantID: tenant}, true},
		"platform":          {idp.Registration{IdPID: id, Scope: idp.ScopePlatform}, true},
		"platform + tenant": {idp.Registration{IdPID: id, Scope: idp.ScopePlatform, TenantID: tenant}, false},
		"tenant w/o tenant": {idp.Registration{IdPID: id, Scope: idp.ScopeTenant}, false},
		"no id":             {idp.Registration{Scope: idp.ScopePlatform}, false},
		"bad scope":         {idp.Registration{IdPID: id, Scope: "org"}, false},
	} {
		if err := c.reg.Validate("t"); (err == nil) != c.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
	reg := idp.Registration{IdPID: id, Scope: idp.ScopeTenant, TenantID: tenant}
	if got := reg.ClientSecretOwner(2).String(); got != "mgsec://"+tenant.String()+"/idp."+id.String()+".client#2" {
		t.Fatalf("tenant client secret ref %s", got)
	}
	reg = idp.Registration{IdPID: id, Scope: idp.ScopePlatform}
	if got := reg.ClientSecretOwner(1).String(); got != "mgsec://platform/idp."+id.String()+".client#1" {
		t.Fatalf("platform client secret ref %s", got)
	}
}

func TestErrors(t *testing.T) {
	cause := errors.New("cause")
	e := idp.NewError(idp.CodeForbidden, "keycloak.X", "realm_not_managed", cause)
	if e.Error() != "idp: keycloak.X: idp_forbidden (realm_not_managed)" || !errors.Is(e, cause) {
		t.Fatalf("Error() = %q", e.Error())
	}
	wrapped := fmt.Errorf("job: %w", e)
	if idp.CodeOf(wrapped) != idp.CodeForbidden || !errors.Is(wrapped, &idp.Error{Code: idp.CodeForbidden}) ||
		errors.Is(wrapped, &idp.Error{Code: idp.CodeConflict}) {
		t.Fatal("CodeOf/Is through wrapping")
	}
	if idp.CodeOf(nil) != "" || idp.CodeOf(errors.New("x")) != idp.CodeInternal {
		t.Fatal("CodeOf of nil / foreign error")
	}
	for status, code := range map[int]idp.Code{400: idp.CodeUpstream, 401: idp.CodeUnauthenticated, 403: idp.CodeForbidden,
		404: idp.CodeNotFound, 409: idp.CodeConflict, 500: idp.CodeUnavailable, 501: idp.CodeUnsupported,
		503: idp.CodeUnavailable, 302: idp.CodeRedirectRefused, 418: idp.CodeUpstream} {
		if e := idp.StatusError("op", status); e.Code != code || e.Status != status {
			t.Errorf("status %d → %s", status, e.Code)
		}
	}
	if c := idp.Classify("op", &url.Error{Op: "Get", URL: "u", Err: context.DeadlineExceeded}); c.Code != idp.CodeTimeout {
		t.Errorf("deadline → %s", c.Code)
	}
	if c := idp.Classify("op", &net.DNSError{Err: "nx", Name: "x"}); c.Code != idp.CodeUnavailable || c.Reason != "dns" {
		t.Errorf("dns → %s/%s", c.Code, c.Reason)
	}
	if c := idp.Classify("op", e); c != e {
		t.Error("an *Error must pass through Classify")
	}
}

// TestStoreNewVersion: version 1 first, then one more than the latest, whatever version the caller believed latest;
// older versions destroyed on request.
func TestStoreNewVersion(t *testing.T) {
	st := idptest.NewSecrets()
	base := secrets.PlatformRef("idp.test.driver", 1)
	ctx := t.Context()
	r1, err := idp.StoreNewVersion(ctx, st, base, []byte("one"), secrets.WithPlatformOps())
	if err != nil || r1.Version != 1 || st.Value(r1) != "one" || !st.WrittenWithOptions(r1) {
		t.Fatalf("first: %v %v", r1, err)
	}
	r2, _ := idp.StoreNewVersion(ctx, st, base, []byte("two"))
	r3, err := idp.StoreNewVersion(ctx, st, r1, []byte("three"))
	if err != nil || r2.Version != 2 || r3.Version != 3 || st.Value(r3) != "three" {
		t.Fatalf("later: %v %v %v", r2, r3, err)
	}
	if err := idp.DestroyOlder(ctx, st, r3); err != nil || !st.Destroyed(r1) || !st.Destroyed(r2) || st.Destroyed(r3) {
		t.Fatalf("DestroyOlder: %v", err)
	}
	if err := idp.DestroyOlder(ctx, st, r3); err != nil {
		t.Fatalf("DestroyOlder twice: %v", err)
	}
	if _, err := idp.ReadSecret(ctx, st, "op", r1); idp.CodeOf(err) != idp.CodeCredentials {
		t.Fatalf("destroyed version: %v", err)
	}
	if _, err := idp.ReadSecret(ctx, nil, "op", r3); idp.CodeOf(err) != idp.CodeCredentials {
		t.Fatalf("no store: %v", err)
	}
	v, err := idp.NewSecretValue()
	if err != nil || len(v) != 43 || strings.ContainsAny(string(v), "+/=") {
		t.Fatalf("NewSecretValue: %d %v", len(v), err)
	}
	if fmt.Sprint(v) != "[REDACTED]" {
		t.Fatal("a secret value must print redacted")
	}
}

// TestNoBusinessImports double-checks the §13.6 rule of the module from its own side (archtest covers the tree).
func TestNoBusinessImports(t *testing.T) {
	for _, dir := range []string{".", "external", "keycloak", "idptest"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			b, _ := fs.ReadFile(os.DirFS(dir), e.Name())
			for _, mod := range []string{"identity", "tenants", "members", "headscale", "provisioning", "devices", "httpapi", "authz"} {
				if strings.Contains(string(b), `network-access-mesh/internal/`+mod+`"`) {
					t.Errorf("%s/%s imports %s", dir, e.Name(), mod)
				}
			}
		}
	}
}
