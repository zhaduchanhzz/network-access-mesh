package notifications

import (
	"context"
	"errors"
	"io"
	"mime"
	"mime/quotedprintable"
	"net/mail"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/notifications/smtptest"
)

var (
	tA   = uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	idX  = uuid.MustParse("11111111-2222-4333-8444-555555555555")
	when = time.Date(2026, 11, 20, 8, 30, 0, 0, time.UTC)
)

// samples are one event of every kind, built with its constructor.
func samples() []Event {
	owner := uuid.MustParse("99999999-8888-4777-8666-555555555555")
	return []Event{
		TenantActivated(tA, "owner@example.com"),
		Invitation(tA, idX, "new@example.com", "tenant_owner", when, LocaleEN),
		TenantSuspended(tA, idX), TenantResumed(tA, idX),
		DeviceNew(tA, idX, &owner, "laptop-1", when), DeviceExpiring(tA, idX, nil, "router-1", when),
		APIKeyExpiring(idX, "tenant-a", when),
		PolicyApplied(tA, idX, idX, 3, "baseline", "manual", strings.Repeat("ab", 32)),
		SupportGrantRequested(tA, idX, "Support Staff", "ticket 42", when),
		BreakGlass(tA, idX, "Support Staff", "Super Admin", "outage", when),
		SupportGrantUsed(tA, idX, "Support Staff", when),
		ApprovalRequested(tA, idX, "tenant.settings.four_eyes_off", "", "Alice", when),
		IdPAdminChange(tA, idX.String(), "idp.user.credential_reset", "platform IdP administrator", "Alice", when),
		IdPConsoleLogin(idX.String(), "mg-bootstrap-admin", "security-admin-console", "203.0.113.7", when),
		IdPConsoleLoginSummary(ConsoleLoginSummary{Ref: "idp-console-window:0123456789abcdef:1", LastEventID: idX.String(),
			Username: "mg-bootstrap-admin", Client: "admin-cli", Count: 49, Sources: "admin-cli 203.0.113.7",
			First: when, Last: when.Add(9 * time.Minute), WindowMinutes: 10}),
		InstanceRestored(tA, idX, when, true),
		InstanceOperationFailed(idX, idX, "acme", "upgrade", "preflight_failed", "rolled_back"),
		TenantDeleted(tA, idX, when, true),
		InstanceQuarantined(idX, "acme", idX, OutcomeIsolated),
		InstanceReleased(idX, "acme", idX, OutcomeReleased),
		IdPConfigChanged(tA, idX, IdPStageRequested, IdPChangeByPlatform, "required_claims", "Super Admin", &idX, 3),
		SecuritySettingsChanged(tA, `"abc"`, "policy.four_eyes", "Alice", nil),
		TenantDeletionRequested(tA, "Alice", when),
		PlatformTenantDeletionRequested(tA, "tenant-a", "Alice", when),
		EnrollmentApproved(tA, idX, owner, "web_auth", "laptop-1", "Alice", when),
		EnrollmentRejected(tA, idX, owner, "preauth_key", "", ""),
	}
}

// TestConstructorsAreValid: every constructor builds an event its kind accepts; every kind has a constructor here.
func TestConstructorsAreValid(t *testing.T) {
	seen := map[Kind]bool{}
	for _, ev := range samples() {
		if _, err := ev.validate(); err != nil {
			t.Errorf("%s: %v", ev.Kind, err)
		}
		seen[ev.Kind] = true
	}
	for _, k := range Kinds() {
		if !seen[k] {
			t.Errorf("kind %s has no sample", k)
		}
	}
}

// TestRecipientRules: the audience each constructor sets (§6.3).
func TestRecipientRules(t *testing.T) {
	owner := uuid.New()
	cases := []struct {
		ev   Event
		want Audience
	}{
		{TenantActivated(tA, "o@example.com"), Audience{Roles: []string{RoleTenantOwner}, Emails: []string{"o@example.com"}}},
		{BreakGlass(tA, idX, "s", "", "", time.Time{}), Audience{Roles: []string{RoleTenantOwner}}},
		{SupportGrantUsed(tA, idX, "s", when), Audience{Roles: []string{RoleTenantOwner}}},
		{DeviceNew(tA, idX, &owner, "d", time.Time{}), Audience{Roles: []string{RoleTenantOwner}, Members: []uuid.UUID{owner}}},
		{DeviceExpiring(tA, idX, &owner, "d", when), Audience{Members: []uuid.UUID{owner}}},
		{DeviceExpiring(tA, idX, nil, "d", when), Audience{Roles: []string{RoleTenantOwner, RoleTenantAdmin}}},
		{SupportGrantRequested(tA, idX, "s", "", time.Time{}), Audience{Permission: "tenant.support_grant:decide"}},
		{ApprovalRequested(tA, idX, "a.b", "", "", time.Time{}), Audience{Permission: "tenant.approval:decide"}},
		{PolicyApplied(tA, idX, idX, 1, "baseline", "manual", "x"), Audience{Roles: []string{RoleTenantOwner, RoleTenantAdmin}}},
		{TenantSuspended(tA, idX), Audience{Roles: []string{RoleTenantOwner, RoleTenantAdmin}}},
		{TenantDeleted(tA, idX, when, false), Audience{Roles: []string{RoleTenantOwner, RoleTenantAdmin}}},
		{APIKeyExpiring(idX, "s", when), Audience{PlatformRoles: []string{RoleSuperAdmin, RolePlatformOperator}}},
		{Invitation(tA, idX, "n@example.com", "end_user", when, ""), Audience{Emails: []string{"n@example.com"}}},
		{IdPAdminChange(tA, "e1", "idp.user.update", "a", "", when), Audience{Roles: []string{RoleTenantOwner}}},
		{IdPConsoleLogin("e1", "", "admin-cli", "", when), Audience{PlatformRoles: []string{RoleSuperAdmin, RolePlatformOperator}}},
		{IdPConsoleLoginSummary(ConsoleLoginSummary{Ref: "r1", LastEventID: "e1", Client: "admin-cli", Count: 2, First: when,
			Last: when, WindowMinutes: 10}), Audience{PlatformRoles: []string{RoleSuperAdmin, RolePlatformOperator}}},
		{InstanceOperationFailed(idX, idX, "s", "restart", "no_policy", "rolled_back"),
			Audience{PlatformRoles: []string{RoleSuperAdmin, RolePlatformOperator}}},
		{InstanceQuarantined(idX, "acme", idX, OutcomeIncomplete), Audience{PlatformRoles: []string{RoleSuperAdmin, RolePlatformOperator}}},
		{InstanceReleased(idX, "acme", idX, OutcomeRefused), Audience{PlatformRoles: []string{RoleSuperAdmin, RolePlatformOperator}}},
		{EnrollmentApproved(tA, idX, owner, "web_auth", "", "", when), Audience{Members: []uuid.UUID{owner}}},
		{EnrollmentRejected(tA, idX, owner, "web_auth", "", ""), Audience{Members: []uuid.UUID{owner}}},
	}
	for _, c := range cases {
		a := c.ev.To
		if !slices.Equal(a.Roles, c.want.Roles) || a.Permission != c.want.Permission || !slices.Equal(a.Members, c.want.Members) ||
			!slices.Equal(a.Emails, c.want.Emails) || !slices.Equal(a.PlatformRoles, c.want.PlatformRoles) {
			t.Errorf("%s: audience %+v, want %+v", c.ev.Kind, a, c.want)
		}
	}
}

// TestEnrollmentPayloads: the follow-up kinds of P4-T06 — one ref per decision, and a display name or a device label
// that the no-secret rule refuses is dropped instead of failing the event.
func TestEnrollmentPayloads(t *testing.T) {
	req := uuid.New()
	member := uuid.New()
	if a, r := EnrollmentApproved(tA, req, member, "web_auth", "", "", when), EnrollmentRejected(tA, req, member, "web_auth", "", ""); a.Ref == r.Ref ||
		a.Ref != "enrollment:"+req.String()+":approved" {
		t.Fatalf("enrollment refs %q %q", a.Ref, r.Ref)
	}
	ev := EnrollmentApproved(tA, req, member, "web_auth", "lap\ntop", "https://evil.example/x", when)
	p, err := ev.validate()
	if err != nil || p["decided_by"] != nil || p["device_label"] != nil || p["expires_at"] != when.Format(time.RFC3339) {
		t.Fatalf("enrollment payload %v %v", p, err)
	}
}

// TestValidateRefusesSecretsAndStrangers: the payload of a kind takes its fields only, never a credential-shaped value,
// a URL, a multi-line value; scope and audience must match the kind.
func TestValidateRefusesSecretsAndStrangers(t *testing.T) {
	base := func() Event { return SupportGrantUsed(tA, idX, "Staff", when) }
	mut := []struct {
		name string
		f    func(*Event)
	}{
		{"unknown field", func(e *Event) { e.Payload["token"] = "x" }},
		{"headscale key", func(e *Event) { e.Payload["staff"] = "hskey-auth-abc-def" }},
		{"jwt", func(e *Event) { e.Payload["staff"] = "eyJhbGciOiJIUzI1NiJ9.e30.x" }},
		{"bearer", func(e *Event) { e.Payload["staff"] = "Bearer abc" }},
		{"pem", func(e *Event) { e.Payload["staff"] = "-----BEGIN PRIVATE KEY-----" }},
		{"url", func(e *Event) { e.Payload["staff"] = "https://evil.example/?t=1" }},
		{"newline", func(e *Event) { e.Payload["staff"] = "a\r\nBcc: x@example.com" }},
		{"long", func(e *Event) { e.Payload["staff"] = strings.Repeat("a", 300) }},
		{"wrong type", func(e *Event) { e.Payload["grant_id"] = 42 }},
		{"missing required", func(e *Event) { delete(e.Payload, "staff") }},
		{"no tenant", func(e *Event) { e.TenantID = nil }},
		{"platform audience", func(e *Event) { e.To.PlatformRoles = []string{"super_admin"} }},
		{"no audience", func(e *Event) { e.To = Audience{} }},
		{"bad ref", func(e *Event) { e.Ref = "a b" }},
		{"bad locale", func(e *Event) { e.Locale = "fr" }},
		{"bad email", func(e *Event) { e.To.Emails = []string{"Name <x@example.com>"} }},
		{"unknown kind", func(e *Event) { e.Kind = "tenant.unknown" }},
	}
	for _, m := range mut {
		ev := base()
		m.f(&ev)
		if _, err := ev.validate(); !errors.Is(err, ErrInvalidEvent) {
			t.Errorf("%s: err %v", m.name, err)
		}
	}
	p := APIKeyExpiring(idX, "a", when)
	p.TenantID = &tA
	if _, err := p.validate(); !errors.Is(err, ErrInvalidEvent) {
		t.Error("platform kind with a tenant accepted")
	}
	p = APIKeyExpiring(idX, "a", when)
	p.To.Roles = []string{"tenant_owner"}
	if _, err := p.validate(); !errors.Is(err, ErrInvalidEvent) {
		t.Error("platform kind with tenant roles accepted")
	}
}

// TestCatalogCoversEveryKind: every kind renders in vi and en from its sample payload, the subject is one line, the
// links come from the configuration, and nothing outside the payload and the links appears.
func TestCatalogCoversEveryKind(t *testing.T) {
	tm, err := parseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range samples() {
		payload, err := ev.validate()
		if err != nil {
			t.Fatal(err)
		}
		payload["tenant_name"], payload["tenant_slug"] = "Acme", "acme"
		for _, loc := range []string{LocaleVI, LocaleEN} {
			if _, ok := catalog[ev.Kind][loc]; !ok {
				t.Errorf("%s: no %s template", ev.Kind, loc)
				continue
			}
			data := map[string]any{"portal_url": "https://app.example.test", "console_url": "https://admin.example.test"}
			for k, v := range payload {
				data[k] = v
			}
			subject, body, err := tm.render(ev.Kind, loc, data)
			if err != nil {
				t.Errorf("%s/%s: %v", ev.Kind, loc, err)
				continue
			}
			if subject == "" || strings.ContainsAny(subject, "\r\n") || !strings.HasPrefix(subject, "[MeshGuard]") {
				t.Errorf("%s/%s: subject %q", ev.Kind, loc, subject)
			}
			if !strings.Contains(body, "https://app.example.test") || strings.Contains(body, "<no value>") {
				t.Errorf("%s/%s: body %q", ev.Kind, loc, body)
			}
		}
	}
	// A missing required field is an error (missingkey=error), not an empty value.
	if _, _, err := tm.render(KindPolicyApplied, LocaleVI, map[string]any{"portal_url": "x", "console_url": "y"}); err == nil {
		t.Error("render without the kind's fields succeeded")
	}
	// Unknown locale ⇒ the default (vi).
	s, _, err := tm.render(KindTenantActivated, "de", map[string]any{"tenant_name": "Acme", "tenant_slug": "acme",
		"portal_url": "x", "console_url": "y"})
	if err != nil || !strings.Contains(s, "đã sẵn sàng") {
		t.Errorf("default locale: %q %v", s, err)
	}
}

// TestComposeMessage: the RFC 5322 message — UTF-8 subject encoded, quoted-printable body, Message-ID, no header
// injection through the subject.
func TestComposeMessage(t *testing.T) {
	m, err := NewSMTPMailer(SMTPConfig{Addr: "localhost:25", TLS: TLSNone, From: "MeshGuard <no-reply@example.test>"})
	if err != nil {
		t.Fatal(err)
	}
	to, _ := mail.ParseAddress("owner@example.test")
	raw, err := m.compose(to, Message{To: "owner@example.test", Subject: "Tenant Đà Nẵng\r\nBcc: x@evil.test",
		Body: "Xin chào\nDòng hai — ✓", MessageID: "<id@example.test>"})
	if err != nil {
		t.Fatal(err)
	}
	msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	subj, _ := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
	if subj != "Tenant Đà Nẵng Bcc: x@evil.test" || msg.Header.Get("Bcc") != "" {
		t.Fatalf("subject %q, bcc %q", subj, msg.Header.Get("Bcc"))
	}
	body, _ := io.ReadAll(quotedprintable.NewReader(msg.Body))
	if !strings.Contains(string(body), "Dòng hai — ✓") || msg.Header.Get("Message-ID") != "<id@example.test>" ||
		msg.Header.Get("Content-Transfer-Encoding") != "quoted-printable" {
		t.Fatalf("body %q headers %v", body, msg.Header)
	}
	if _, err := m.compose(to, Message{To: "a@example.test", MessageID: "<x>\r\nBcc: y"}); err == nil {
		t.Fatal("a line break in Message-ID accepted")
	}
}

// TestSMTPMailerTLSAndAuth: STARTTLS with AUTH PLAIN against the fake relay (certificate verified), implicit TLS, a relay
// without STARTTLS refused (no downgrade), wrong credentials and 5xx permanent, 4xx temporary; the password file is
// read at every send.
func TestSMTPMailerTLSAndAuth(t *testing.T) {
	ctx := context.Background()
	pw := t.TempDir() + "/smtp_password"
	writeFile(t, pw, "s3cret-pw\n")
	srv := smtptest.New(t, smtptest.Options{StartTLS: true, Users: map[string]string{"mailer": "s3cret-pw"}})
	m, err := NewSMTPMailer(SMTPConfig{Addr: srv.Addr(), Username: "mailer", PasswordFile: pw, RootCAs: srv.Roots,
		From: "MeshGuard <no-reply@example.test>", Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Send(ctx, Message{To: "owner@example.test", Subject: "s", Body: "b", MessageID: "<1@example.test>"}); err != nil {
		t.Fatal(err)
	}
	got := srv.Messages()
	if len(got) != 1 || !got[0].TLS || got[0].AuthUser != "mailer" || got[0].From != "no-reply@example.test" ||
		len(got[0].To) != 1 || got[0].To[0] != "owner@example.test" {
		t.Fatalf("relay saw %+v", got)
	}
	// rotated password picked up without a new mailer; a wrong one is permanent.
	writeFile(t, pw, "wrong\n")
	if err := m.Send(ctx, Message{To: "owner@example.test", Subject: "s", Body: "b"}); err == nil || !IsPermanent(err) {
		t.Fatalf("wrong password: %v", err)
	}
	writeFile(t, pw, "s3cret-pw\n")
	srv.FailNext(451, 550)
	if err := m.Send(ctx, Message{To: "owner@example.test", Subject: "s", Body: "b"}); err == nil || IsPermanent(err) {
		t.Fatalf("451: %v", err)
	}
	if err := m.Send(ctx, Message{To: "owner@example.test", Subject: "s", Body: "b"}); err == nil || !IsPermanent(err) {
		t.Fatalf("550: %v", err)
	}
	// untrusted certificate ⇒ refused
	bad, _ := NewSMTPMailer(SMTPConfig{Addr: srv.Addr(), From: "a@example.test"})
	if err := bad.Send(ctx, Message{To: "owner@example.test", Subject: "s", Body: "b"}); err == nil {
		t.Fatal("an untrusted certificate was accepted")
	}
	// relay without STARTTLS ⇒ permanent, nothing sent in clear
	plain := smtptest.New(t, smtptest.Options{})
	pm, _ := NewSMTPMailer(SMTPConfig{Addr: plain.Addr(), From: "a@example.test"})
	if err := pm.Send(ctx, Message{To: "owner@example.test", Subject: "s", Body: "b"}); err == nil || !IsPermanent(err) {
		t.Fatalf("no STARTTLS: %v", err)
	}
	if len(plain.Messages()) != 0 {
		t.Fatal("a message went out without TLS")
	}
	// implicit TLS
	imp := smtptest.New(t, smtptest.Options{Implicit: true})
	im, _ := NewSMTPMailer(SMTPConfig{Addr: imp.Addr(), TLS: TLSImplicit, RootCAs: imp.Roots, From: "a@example.test"})
	if err := im.Send(ctx, Message{To: "owner@example.test", Subject: "s", Body: "b"}); err != nil || len(imp.Messages()) != 1 || !imp.Messages()[0].TLS {
		t.Fatalf("implicit TLS: %v", err)
	}
	// configuration refusals
	for _, c := range []SMTPConfig{{Addr: "nohost", From: "a@example.test"}, {Addr: "h:25", TLS: "ssl", From: "a@example.test"},
		{Addr: "h:25", Username: "u", From: "a@example.test"}, {Addr: "h:25", TLS: TLSNone, Username: "u", PasswordFile: pw, From: "a@example.test"},
		{Addr: "h:25", From: "not an address"}} {
		if _, err := NewSMTPMailer(c); err == nil {
			t.Errorf("accepted %+v", c)
		}
	}
}

func writeFile(t *testing.T, p, s string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}
