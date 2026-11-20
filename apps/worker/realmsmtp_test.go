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
	f.calls = append(f.calls, reg.Issuer)
	return f.changed[reg.Issuer], f.err[reg.Issuer]
}

// TestIdpRealmSMTP (G4b-E1): the command repairs only the realms the driver created (JSON driver_ref, not disabled),
// with the relay of MG_SMTP_*; rendered realms and deleted IdPs are skipped; --dry-run writes nothing; a failure is
// reported and exits 1; no relay (or an authenticated one) is a configuration error before anything is read.
func TestIdpRealmSMTP(t *testing.T) {
	tenant := uuid.New()
	ref := func(realm string) string {
		return keycloak.DriverRef{Realm: realm, DriverSecret: "mgsec://platform/idp.x.driver#1"}.Encode()
	}
	targets := []realmSMTPTarget{
		{Reg: idp.Registration{IdPID: uuid.New(), Scope: idp.ScopeTenant, TenantID: tenant, Issuer: "iss/new", DriverRef: ref("new")}, Status: "active"},
		{Reg: idp.Registration{IdPID: uuid.New(), Scope: idp.ScopeTenant, TenantID: tenant, Issuer: "iss/ok", DriverRef: ref("ok")}, Status: "active"},
		{Reg: idp.Registration{IdPID: uuid.New(), Scope: idp.ScopeTenant, TenantID: tenant, Issuer: "iss/tenant-a", DriverRef: "tenant-a"}, Status: "active"},
		{Reg: idp.Registration{IdPID: uuid.New(), Scope: idp.ScopeTenant, TenantID: tenant, Issuer: "iss/gone", DriverRef: ref("gone")}, Status: "disabled"},
		{Reg: idp.Registration{IdPID: uuid.New(), Scope: idp.ScopeTenant, TenantID: tenant, Issuer: "iss/bad", DriverRef: ref("bad")}, Status: "pending"},
	}
	run := func(args []string, env map[string]string, f *fakeRealmSMTP) (int, string, string, *keycloak.SMTPServer) {
		var got *keycloak.SMTPServer
		var out, errb bytes.Buffer
		var list []string
		for k, v := range env {
			list = append(list, k+"="+v)
		}
		code := idpRealmSMTP(t.Context(), args, &out, &errb, realmSMTPEnv{getenv: func(k string) string { return env[k] },
			environ: list, open: func(_ context.Context, _ config.Config, s keycloak.SMTPServer, _ io.Writer) ([]realmSMTPTarget,
				realmSMTPEnsurer, func(), error,
			) {
				got = &s
				return targets, f, func() {}, nil
			}})
		return code, out.String(), errb.String(), got
	}
	env := wiredWorkerEnv(t)
	env["MG_SMTP_ADDR"], env["MG_SMTP_TLS"], env["MG_SMTP_FROM"] = "mailrelay:587", "starttls", "MeshGuard <no-reply@example.com>"

	f := &fakeRealmSMTP{changed: map[string]bool{"iss/new": true}, err: map[string]error{}}
	code, out, stderr, smtp := run(nil, env, f)
	if code != 0 || smtp == nil || smtp.Host != "mailrelay" || smtp.Port != 587 || !smtp.StartTLS || smtp.From != "no-reply@example.com" {
		t.Fatalf("exit %d smtp %+v\n%s%s", code, smtp, out, stderr)
	}
	for _, want := range []string{"iss/new: updated", "iss/ok: unchanged", "iss/tenant-a: skipped:rendered_realm",
		"iss/gone: skipped:disabled", "iss/bad: unchanged", "updated 1, unchanged 2, skipped 2, failed 0", "OK"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Join(f.calls, ",") != "iss/new,iss/ok,iss/bad" {
		t.Fatalf("EnsureSMTP calls %v", f.calls)
	}

	f = &fakeRealmSMTP{err: map[string]error{"iss/bad": idp.NewError(idp.CodeUnavailable, "op", "x", nil)}}
	if code, out, _, _ := run(nil, env, f); code != 1 || !strings.Contains(out, "iss/bad: failed:unavailable") {
		t.Fatalf("failure: exit %d\n%s", code, out)
	}
	f = &fakeRealmSMTP{}
	if code, out, _, _ := run([]string{"--dry-run"}, env, f); code != 0 || len(f.calls) != 0 || !strings.Contains(out, "would-update") {
		t.Fatalf("dry run: exit %d calls %v\n%s", code, f.calls, out)
	}
	if code, _, stderr, _ := run([]string{"--tenant", "x"}, env, f); code != 2 || !strings.Contains(stderr, "usage:") {
		t.Fatalf("bad flag: exit %d %q", code, stderr)
	}
	for _, mut := range []func(m map[string]string){
		func(m map[string]string) {
			delete(m, "MG_SMTP_ADDR")
			delete(m, "MG_SMTP_TLS")
			delete(m, "MG_SMTP_FROM")
		},
	} {
		e := wiredWorkerEnv(t)
		for k, v := range env {
			e[k] = v
		}
		mut(e)
		code, _, stderr, got := run(nil, e, &fakeRealmSMTP{})
		if code != 2 || got != nil || !strings.Contains(stderr, "no realm relay") {
			t.Fatalf("no relay: exit %d opened=%v %q", code, got != nil, stderr)
		}
	}
}
