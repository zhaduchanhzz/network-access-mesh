package main

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp/keycloak"
)

type fakeRealmSMTP struct {
	calls   []string
	changed map[string]bool
	err     map[string]error
}

func (f *fakeRealmSMTP) EnsureSMTP(_ context.Context, reg idp.Registration) (bool, error) {
	f.calls = append(f.calls, "smtp:"+reg.Issuer)
	return f.changed[reg.Issuer], f.err[reg.Issuer]
}

func (f *fakeRealmSMTP) EnsureI18n(_ context.Context, reg idp.Registration) (bool, error) {
	f.calls = append(f.calls, "i18n:"+reg.Issuer)
	return f.changed[reg.Issuer], f.err[reg.Issuer]
}

// realmTargets: a realm to repair, one already repaired, a rendered tenant realm, the rendered platform realm, a deleted IdP,
// a pending IdP.
func realmTargets() []realmSMTPTarget {
	tenant := uuid.New()
	ref := func(realm string) string {
		return keycloak.DriverRef{Realm: realm, DriverSecret: "mgsec://platform/idp.x.driver#1"}.Encode()
	}
	return []realmSMTPTarget{
		{Reg: idp.Registration{IdPID: uuid.New(), Scope: idp.ScopeTenant, TenantID: tenant, Issuer: "iss/new", DriverRef: ref("new")}, Status: "active"},
		{Reg: idp.Registration{IdPID: uuid.New(), Scope: idp.ScopeTenant, TenantID: tenant, Issuer: "iss/ok", DriverRef: ref("ok")}, Status: "active"},
		{Reg: idp.Registration{IdPID: uuid.New(), Scope: idp.ScopeTenant, TenantID: tenant, Issuer: "iss/tenant-a", DriverRef: "tenant-a"}, Status: "active"},
		{Reg: idp.Registration{IdPID: uuid.New(), Scope: idp.ScopePlatform, Issuer: "iss/platform", DriverRef: "platform"}, Status: "active"},
		{Reg: idp.Registration{IdPID: uuid.New(), Scope: idp.ScopeTenant, TenantID: tenant, Issuer: "iss/gone", DriverRef: ref("gone")}, Status: "disabled"},
		{Reg: idp.Registration{IdPID: uuid.New(), Scope: idp.ScopeTenant, TenantID: tenant, Issuer: "iss/bad", DriverRef: ref("bad")}, Status: "pending"},
	}
}

type repairCmd func(ctx context.Context, args []string, stdout, stderr io.Writer, env realmSMTPEnv) int

// runRepair runs a repair command with env and the fake driver; opened reports whether the registry was read and with
// which relay.
func runRepair(t *testing.T, cmd repairCmd, args []string, env map[string]string, f *fakeRealmSMTP) (code int, out, stderr string, opened bool, relay *keycloak.SMTPServer) {
	t.Helper()
	var o, e bytes.Buffer
	var list []string
	for k, v := range env {
		list = append(list, k+"="+v)
	}
	code = cmd(t.Context(), args, &o, &e, realmSMTPEnv{getenv: func(k string) string { return env[k] },
		environ: list, open: func(_ context.Context, _ config.Config, s *keycloak.SMTPServer, _ io.Writer) ([]realmSMTPTarget,
			realmSMTPEnsurer, func(), error,
		) {
			opened, relay = true, s
			return realmTargets(), f, func() {}, nil
		}})
	return code, o.String(), e.String(), opened, relay
}

// TestIdpRealmSMTP (G4b-E1): the command repairs only the realms the driver created (JSON driver_ref, not disabled),
// with the relay of MG_SMTP_*; rendered realms and deleted IdPs are skipped; --dry-run writes nothing; a failure is
// reported and exits 1; no relay (or an authenticated one) is a configuration error before anything is read.
func TestIdpRealmSMTP(t *testing.T) {
	env := wiredWorkerEnv(t)
	env["MG_SMTP_ADDR"], env["MG_SMTP_TLS"], env["MG_SMTP_FROM"] = "mailrelay:587", "starttls", "MeshGuard <no-reply@example.com>"

	f := &fakeRealmSMTP{changed: map[string]bool{"iss/new": true}, err: map[string]error{}}
	code, out, stderr, _, smtp := runRepair(t, idpRealmSMTP, nil, env, f)
	if code != 0 || smtp == nil || smtp.Host != "mailrelay" || smtp.Port != 587 || !smtp.StartTLS || smtp.From != "no-reply@example.com" {
		t.Fatalf("exit %d smtp %+v\n%s%s", code, smtp, out, stderr)
	}
	for _, want := range []string{"iss/new: updated", "iss/ok: unchanged", "iss/tenant-a: skipped:rendered_realm",
		"iss/platform: skipped:rendered_realm", "iss/gone: skipped:disabled", "iss/bad: unchanged",
		"updated 1, unchanged 2, skipped 3, failed 0", "OK"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Join(f.calls, ",") != "smtp:iss/new,smtp:iss/ok,smtp:iss/bad" {
		t.Fatalf("EnsureSMTP calls %v", f.calls)
	}

	f = &fakeRealmSMTP{err: map[string]error{"iss/bad": idp.NewError(idp.CodeUnavailable, "op", "x", nil)}}
	if code, out, _, _, _ := runRepair(t, idpRealmSMTP, nil, env, f); code != 1 || !strings.Contains(out, "iss/bad: failed:unavailable") {
		t.Fatalf("failure: exit %d\n%s", code, out)
	}
	f = &fakeRealmSMTP{}
	if code, out, _, _, _ := runRepair(t, idpRealmSMTP, []string{"--dry-run"}, env, f); code != 0 || len(f.calls) != 0 || !strings.Contains(out, "would-update") {
		t.Fatalf("dry run: exit %d calls %v\n%s", code, f.calls, out)
	}
	if code, _, stderr, _, _ := runRepair(t, idpRealmSMTP, []string{"--tenant", "x"}, env, f); code != 2 || !strings.Contains(stderr, "usage:") {
		t.Fatalf("bad flag: exit %d %q", code, stderr)
	}
	e := wiredWorkerEnv(t)
	for k, v := range env {
		e[k] = v
	}
	delete(e, "MG_SMTP_ADDR")
	delete(e, "MG_SMTP_TLS")
	delete(e, "MG_SMTP_FROM")
	if code, _, stderr, opened, _ := runRepair(t, idpRealmSMTP, nil, e, &fakeRealmSMTP{}); code != 2 || opened || !strings.Contains(stderr, "no realm relay") {
		t.Fatalf("no relay: exit %d opened=%v %q", code, opened, stderr)
	}
}

// TestIdpRealmI18n (G4b-E14): same targets and rules as idp-realm-smtp, through EnsureI18n, and no relay needed (the
// driver is opened without one).
func TestIdpRealmI18n(t *testing.T) {
	env := wiredWorkerEnv(t)
	f := &fakeRealmSMTP{changed: map[string]bool{"iss/new": true}, err: map[string]error{}}
	code, out, stderr, opened, relay := runRepair(t, idpRealmI18n, nil, env, f)
	if code != 0 || !opened || relay != nil {
		t.Fatalf("exit %d opened %v relay %+v\n%s%s", code, opened, relay, out, stderr)
	}
	for _, want := range []string{"iss/new: updated", "iss/ok: unchanged", "iss/tenant-a: skipped:rendered_realm",
		"iss/platform: skipped:rendered_realm", "iss/gone: skipped:disabled",
		"idp-realm-i18n: updated 1, unchanged 2, skipped 3, failed 0", "OK"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Join(f.calls, ",") != "i18n:iss/new,i18n:iss/ok,i18n:iss/bad" {
		t.Fatalf("EnsureI18n calls %v", f.calls)
	}
	f = &fakeRealmSMTP{}
	if code, out, _, _, _ := runRepair(t, idpRealmI18n, []string{"--dry-run"}, env, f); code != 0 || len(f.calls) != 0 || !strings.Contains(out, "would-update") {
		t.Fatalf("dry run: exit %d calls %v\n%s", code, f.calls, out)
	}
	if code, _, stderr, _, _ := runRepair(t, idpRealmI18n, []string{"x"}, env, f); code != 2 || !strings.Contains(stderr, "idp-realm-i18n [--dry-run]") {
		t.Fatalf("bad argument: exit %d %q", code, stderr)
	}
}
