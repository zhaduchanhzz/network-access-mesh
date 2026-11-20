package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/mail"
	"sort"
	"strconv"
	"strings"

	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
)

// SMTPServer is the smtpServer of the realms the driver creates (G4b-E1): the relay Keycloak e-mails required-actions
// links through (execute-actions-email of InviteUser). It never carries a credential — a realm's smtpServer is stored
// in Keycloak's database and returned by its Admin API — so only an unauthenticated relay can be configured (on
// staging/production the internal relay mailrelay:587, STARTTLS, its internal CA trusted by Keycloak through
// KC_TRUSTSTORE_PATHS — tools/render_idp.py, P3-T05b-mail). The three rendered realms (platform, tenant-a, tenant-b)
// get the same values from tools/render_idp.py; realms created before the driver had it are repaired by EnsureSMTP
// (`meshguard-worker admin idp-realm-smtp`).
type SMTPServer struct {
	Host            string
	Port            int
	From            string // bare address
	FromDisplayName string // "" = none
	StartTLS        bool   // STARTTLS required (port 587)
	SSL             bool   // implicit TLS (port 465)
}

// SMTPFromConfig derives the realm relay from the worker's notification relay (config.SMTP — MG_SMTP_*): the same
// host:port, TLS mode and sender as the worker's own e-mails (render_app gives the worker MG_SMTP_ADDR=mailrelay:587,
// MG_SMTP_TLS=starttls and MG_SMTP_FROM — exactly the realm smtpServer render_idp gives the rendered realms). ok=false
// (no realm SMTP) when the worker has no relay or authenticates to it: a password never goes into a realm.
func SMTPFromConfig(addr, tlsMode, from, username, baseDomain string) (SMTPServer, bool, error) {
	addr, username = strings.TrimSpace(addr), strings.TrimSpace(username)
	if addr == "" || username != "" {
		return SMTPServer{}, false, nil
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return SMTPServer{}, false, errors.New("keycloak: realm SMTP: MG_SMTP_ADDR is not host:port")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 || host == "" {
		return SMTPServer{}, false, errors.New("keycloak: realm SMTP: MG_SMTP_ADDR has no valid host and port")
	}
	s := SMTPServer{Host: host, Port: p}
	switch strings.ToLower(strings.TrimSpace(tlsMode)) {
	case "", "starttls":
		s.StartTLS = true
	case "implicit":
		s.SSL = true
	case "none":
	default:
		return SMTPServer{}, false, errors.New("keycloak: realm SMTP: MG_SMTP_TLS must be starttls, implicit or none")
	}
	from = strings.TrimSpace(from)
	if from == "" {
		from = "MeshGuard <no-reply@" + strings.TrimSpace(baseDomain) + ">"
	}
	a, err := mail.ParseAddress(from)
	if err != nil {
		return SMTPServer{}, false, errors.New("keycloak: realm SMTP: MG_SMTP_FROM is not an address")
	}
	s.From, s.FromDisplayName = a.Address, a.Name
	return s, true, s.validate()
}

func (s SMTPServer) validate() error {
	if s.Host == "" || strings.ContainsAny(s.Host, " /\\@") || s.Port < 1 || s.Port > 65535 {
		return errors.New("keycloak: realm SMTP: invalid host or port")
	}
	if a, err := mail.ParseAddress(s.From); err != nil || a.Address != s.From {
		return errors.New("keycloak: realm SMTP: invalid sender address")
	}
	if strings.ContainsAny(s.FromDisplayName, "\r\n<>\"") || len(s.FromDisplayName) > 64 {
		return errors.New("keycloak: realm SMTP: invalid sender display name")
	}
	if s.StartTLS && s.SSL {
		return errors.New("keycloak: realm SMTP: STARTTLS and implicit TLS are exclusive")
	}
	return nil
}

// rep is the smtpServer representation (Keycloak stores string values only).
func (s SMTPServer) rep() map[string]any {
	m := map[string]any{"host": s.Host, "port": strconv.Itoa(s.Port), "from": s.From, "auth": "false",
		"ssl": strconv.FormatBool(s.SSL), "starttls": strconv.FormatBool(s.StartTLS)}
	if s.FromDisplayName != "" {
		m["fromDisplayName"] = s.FromDisplayName
	}
	return m
}

// smtpNorm makes a smtpServer comparable between the wanted representation and Keycloak's answer: string values, no
// empty value, no password (Keycloak masks it) — as smtp_norm of infrastructure/idp/realm-update.sh.
func smtpNorm(v any) string {
	m := asMap(v)
	keys := make([]string, 0, len(m))
	for k, x := range m {
		if k == "password" || x == nil || x == "" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make(map[string]string, len(keys))
	for _, k := range keys {
		switch x := m[k].(type) {
		case string:
			out[k] = x
		case json.Number:
			out[k] = x.String()
		case bool:
			out[k] = strconv.FormatBool(x)
		default:
			b, _ := json.Marshal(x) //nolint:errchkjson // decoded JSON re-encodes
			out[k] = string(b)
		}
	}
	b, _ := json.Marshal(out) //nolint:errchkjson // map of strings
	return string(b)
}

// smtpDiffers reports whether the realm's smtpServer must be set to want (nil want: the driver has no realm SMTP and
// leaves whatever the realm holds).
func smtpDiffers(want, live any) bool {
	return want != nil && smtpNorm(want) != smtpNorm(live)
}

// EnsureSMTP sets the smtpServer of the realm of a driver-created tenant or platform IdP to the driver's relay when it
// differs (G4b-E1: realms created before the template carried it e-mail nothing — KC-SERVICES0088 "Invalid sender
// address 'null'"). Idempotent: changed=false when the realm already has it. Only realms created by the driver (JSON
// driver_ref) whose attributes name this IdP are touched; an adopted rendered realm (bare driver_ref) keeps the
// smtpServer infrastructure/idp/realm-update.sh gives it (CodeUnsupported). Without a configured relay the driver
// refuses (CodeInvalidArgument, reason realm_smtp_not_configured) rather than clear a realm's SMTP.
func (d *Driver) EnsureSMTP(ctx context.Context, reg idp.Registration) (changed bool, err error) {
	const op = "keycloak.EnsureSMTP"
	if err := reg.Validate(op); err != nil {
		return false, err
	}
	if d.smtp == nil {
		return false, idp.NewError(idp.CodeInvalidArgument, op, "realm_smtp_not_configured", nil)
	}
	if reg.Scope == idp.ScopeTenant && validRealm(reg.DriverRef) {
		return false, idp.NewError(idp.CodeUnsupported, op, "rendered_realm", nil)
	}
	ref, _, err := ParseDriverRef(reg.DriverRef)
	if err != nil {
		return false, err
	}
	ts := d.provisioner()
	var live map[string]any
	if _, _, err := d.call(ctx, op, ts, http.MethodGet, realmPath(ref.Realm), nil, &live); err != nil {
		return false, err
	}
	la := asMap(live["attributes"])
	if str(la["meshguard.idp_id"]) != reg.IdPID.String() || str(la["meshguard.scope"]) != string(reg.Scope) {
		return false, idp.NewError(idp.CodeConflict, op, "realm_of_another_idp", nil)
	}
	want := d.smtp.rep()
	if !smtpDiffers(want, live["smtpServer"]) {
		return false, nil
	}
	if _, _, err := d.call(ctx, op, ts, http.MethodPut, realmPath(ref.Realm), map[string]any{"smtpServer": want}, nil); err != nil {
		return false, err
	}
	d.log.Info("keycloak: realm smtpServer set", "realm", ref.Realm)
	return true, nil
}
