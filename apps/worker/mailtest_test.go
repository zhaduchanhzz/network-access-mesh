package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/notifications"
)

type fakeMailer struct {
	sent []notifications.Message
	err  error
}

func (f *fakeMailer) Send(_ context.Context, m notifications.Message) error {
	f.sent = append(f.sent, m)
	return f.err
}

// TestMailTest: `admin mail-test` sends exactly one message through the relay of MG_SMTP_*, prints the address masked,
// and maps the client's answer to its exit status; usage and configuration errors exit 2 before anything is sent.
func TestMailTest(t *testing.T) {
	envOf := func(m map[string]string, f *fakeMailer) mailTestEnv {
		var list []string
		for k, v := range m {
			list = append(list, k+"="+v)
		}
		return mailTestEnv{getenv: func(k string) string { return m[k] }, environ: list,
			open: func(c config.SMTP) (mailSender, error) {
				if c.Addr != "mailrelay:587" || c.TLS != "none" {
					return nil, errors.New("unexpected relay configuration")
				}
				return f, nil
			}}
	}
	relay := map[string]string{"MG_SMTP_ADDR": "mailrelay:587", "MG_SMTP_TLS": "none", "MG_SMTP_FROM": "MeshGuard <no-reply@example.com>"}
	run := func(args []string, m map[string]string, f *fakeMailer) (int, string, string) {
		var out, errb bytes.Buffer
		code := mailTest(t.Context(), args, &out, &errb, envOf(m, f))
		return code, out.String(), errb.String()
	}

	f := &fakeMailer{}
	for _, args := range [][]string{nil, {"--to"}, {"--to", "a@localhost"}, {"--to", "Name <a@example.org>"}, {"--to", "a@example.org", "x"}} {
		if code, _, stderr := run(args, relay, f); code != 2 || !strings.Contains(stderr, "usage:") {
			t.Errorf("%q: exit %d %q", args, code, stderr)
		}
	}
	if code, _, stderr := run([]string{"--to", "owner@example.org"}, map[string]string{}, f); code != 2 ||
		!strings.Contains(stderr, "no relay configured") {
		t.Errorf("no relay: exit %d %q", code, stderr)
	}
	if len(f.sent) != 0 {
		t.Fatal("something was sent before the checks passed")
	}

	code, stdout, _ := run([]string{"--to", "Owner@Example.org"}, relay, f)
	var got mailTestOutput
	if err := json.Unmarshal([]byte(stdout), &got); err != nil || code != 0 || got.Result != "sent" || got.To != "o***@example.org" ||
		!strings.HasPrefix(got.MessageID, "<mail-test-") || !strings.HasSuffix(got.MessageID, "@example.com>") {
		t.Fatalf("sent: exit %d %q", code, stdout)
	}
	if len(f.sent) != 1 || f.sent[0].To != "Owner@Example.org" || f.sent[0].MessageID != got.MessageID ||
		!strings.HasPrefix(f.sent[0].Subject, "[MeshGuard]") || strings.Contains(stdout, "Owner@") {
		t.Fatalf("message: %+v / %s", f.sent, stdout)
	}

	f.err = errors.New("smtp data: 451 4.3.0 temporary relay failure (auth_signature), try again later")
	code, stdout, _ = run([]string{"--to", "owner@example.org"}, relay, f)
	if err := json.Unmarshal([]byte(stdout), &got); err != nil || code != 1 || got.Result != "temporary" ||
		!strings.Contains(got.Error, "auth_signature") {
		t.Fatalf("temporary: exit %d %q", code, stdout)
	}
}
