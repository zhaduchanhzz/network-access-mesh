//go:build mgtestfixture

package authzmatrix_test

// IT-10 (§5.2, P2-T15 part): no answer of the API — whatever the operation, the client and the outcome — and no line
// of its log (nor of the device service, the Locator and the Headscale adapter behind the handlers) carries a secret:
// the canaries planted in the SecretStore (API keys of the instances — handed to the adapter by the real Locator —,
// IdP client secrets), the edge admin token, session ids and CSRF tokens of every session (a client only ever sees its
// own CSRF token, in GET /auth/session), the passwords of the database roles, or anything shaped like a credential.

import (
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
	"github.com/zhaduchanhzz/network-access-mesh/tests/security/sessionfixture"
)

// credentialShapes are values that must never leave the server in any form.
var credentialShapes = map[string]*regexp.Regexp{
	"Headscale credential (hskey-)": regexp.MustCompile(`(?i)hskey-`),
	"JWT":                           regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.`),
	"PEM block":                     regexp.MustCompile(`-----BEGIN [A-Z ]+-----`),
	"Authorization value":           regexp.MustCompile(`(?i)\b(bearer|basic) [A-Za-z0-9._~+/=-]{16,}`),
}

// dbRoles are the roles whose derived test passwords the harness sets (storetest).
var dbRoles = []string{"mg_api_tenant", "mg_worker_tenant", "mg_api_platform", "mg_worker_platform", "mg_readonly",
	"mg_audit_writer", "mg_partition_maint", "mg_migrator", "mg_backup"}

func (m *matrix) scan(t *testing.T) {
	t.Helper()
	type secret struct{ what, value string }
	var secretValues []secret
	for _, c := range m.obj.canaries {
		secretValues = append(secretValues, secret{"SecretStore canary", c})
	}
	sessions := append([]*sessionfixture.Session{}, m.throwaway...)
	for _, a := range m.actors {
		if a.session != nil && a.session.CookieValue() != "" && a.kind != kindCrossOrigin && a.kind != kindCrossSite {
			sessions = append(sessions, a.session)
		}
	}
	for _, s := range sessions {
		secretValues = append(secretValues, secret{"session id of " + s.String(), s.CookieValue()})
		secretValues = append(secretValues, secret{"CSRF token of " + s.String(), s.CSRFToken()})
	}
	env := storetest.Require(t)
	for _, r := range dbRoles {
		secretValues = append(secretValues, secret{"password of " + r, env.Password(r)})
	}
	if u, err := url.Parse(os.Getenv("MG_TEST_PG_ADMIN_URL")); err == nil {
		if pw, ok := u.User.Password(); ok && pw != "" {
			secretValues = append(secretValues, secret{"superuser password", pw})
		}
	}

	leaks := 0
	report := func(where, what string) {
		leaks++
		if leaks <= 10 {
			t.Errorf("IT-10: %s carries %s", where, what)
		}
	}
	for _, c := range m.calls {
		var sb strings.Builder
		for k, vs := range c.rec.Header() {
			sb.WriteString(k + ": " + strings.Join(vs, ", ") + "\n")
		}
		sb.WriteString(c.rec.Body.String())
		text := sb.String()
		for _, s := range secretValues {
			if !strings.Contains(text, s.value) {
				continue
			}
			own := c.op.ID == "getAuthSession" && c.rec.Code == 200 && c.session != nil && s.value == c.session.CSRFToken()
			if !own {
				report("the answer to "+c.String(), s.what)
			}
		}
		for what, re := range credentialShapes {
			if re.MatchString(text) {
				report("the answer to "+c.String(), "a "+what)
			}
		}
	}
	logs := m.Logs() + m.svcLog.String() // the API's log and the log of the services behind the handlers
	for _, s := range secretValues {
		if strings.Contains(logs, s.value) {
			report("the API log", s.what)
		}
	}
	for what, re := range credentialShapes {
		if re.MatchString(logs) {
			report("the API log", "a "+what)
		}
	}
	t.Logf("IT-10 scan: %d answers and %d log bytes against %d secret values and %d credential shapes — %d leaks",
		len(m.calls), len(logs), len(secretValues), len(credentialShapes), leaks)
}
