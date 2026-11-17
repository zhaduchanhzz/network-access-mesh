package keycloak

import (
	"context"
	"net/http"
	"net/mail"
	"net/url"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
)

// DefaultInviteActions are the required actions of an invited user: prove the e-mail address, set a password, enrol
// TOTP (MFA is mandatory — P2-T05).
var DefaultInviteActions = []string{"VERIFY_EMAIL", "UPDATE_PASSWORD", "CONFIGURE_TOTP"}

var allowedActions = map[string]bool{"VERIFY_EMAIL": true, "UPDATE_PASSWORD": true, "CONFIGURE_TOTP": true,
	"UPDATE_PROFILE": true, "webauthn-register": true, "CONFIGURE_RECOVERY_AUTHN_CODES": true}

// normalizeEmail returns the lower-case bare address, or "" when invalid.
func normalizeEmail(s string) string {
	s = strings.TrimSpace(s)
	a, err := mail.ParseAddress(s)
	if err != nil || a.Address != s || a.Name != "" || len(s) > 254 || strings.ContainsAny(s, " \t\r\n") {
		return ""
	}
	return strings.ToLower(s)
}

// realmOf parses the registration's driver_ref and returns the token source of its mg-idp-driver service account.
func (d *Driver) realmOf(op string, reg idp.Registration) (string, tokenSource, error) {
	if err := reg.Validate(op); err != nil {
		return "", tokenSource{}, err
	}
	ref, sref, err := ParseDriverRef(reg.DriverRef)
	if err != nil {
		return "", tokenSource{}, err
	}
	return ref.Realm, realmToken(ref.Realm, sref), nil
}

// InviteUser creates the user (username = e-mail) with its required actions using the realm's own service account
// (manage-users only — never the provisioning identity), or finds it when it exists: no duplicate. A disabled user is
// not re-enabled (CodeConflict: reactivation is an explicit decision). SendEmail asks Keycloak to e-mail the
// required-actions link; without SMTP at the IdP that fails with CodeEmailFailed (the user still exists).
func (d *Driver) InviteUser(ctx context.Context, reg idp.Registration, inv idp.Invite) (idp.InviteResult, error) {
	const op = "keycloak.InviteUser"
	realm, ts, err := d.realmOf(op, reg)
	if err != nil {
		return idp.InviteResult{}, err
	}
	email := normalizeEmail(inv.Email)
	if email == "" {
		return idp.InviteResult{}, idp.NewError(idp.CodeInvalidArgument, op, "email", nil)
	}
	actions := inv.Actions
	if actions == nil {
		actions = DefaultInviteActions
	}
	for _, a := range actions {
		if !allowedActions[a] {
			return idp.InviteResult{}, idp.NewError(idp.CodeInvalidArgument, op, "required_action", nil)
		}
	}
	for _, n := range []string{inv.FirstName, inv.LastName} {
		if len(n) > 255 || strings.ContainsAny(n, "\r\n\t<>") {
			return idp.InviteResult{}, idp.NewError(idp.CodeInvalidArgument, op, "name", nil)
		}
	}
	res := idp.InviteResult{}
	user, err := d.findUser(ctx, op, ts, realm, email)
	if err != nil {
		return res, err
	}
	if user == nil {
		rep := map[string]any{"username": email, "email": email, "emailVerified": false, "enabled": true,
			"requiredActions": actions}
		if inv.FirstName != "" {
			rep["firstName"] = inv.FirstName
		}
		if inv.LastName != "" {
			rep["lastName"] = inv.LastName
		}
		st, h, err := d.call(ctx, op, ts, http.MethodPost, realmSub(realm, "users"), rep, nil, http.StatusConflict)
		if err != nil {
			return res, err
		}
		if st == http.StatusConflict { // created concurrently
			if user, err = d.findUser(ctx, op, ts, realm, email); err != nil || user == nil {
				return res, idp.NewError(idp.CodeConflict, op, "user_conflict", err)
			}
		} else {
			id, err := createdID(op, h)
			if err != nil {
				return res, err
			}
			res.Subject, res.Created = id, true
		}
	}
	if user != nil {
		if user["enabled"] != true {
			return idp.InviteResult{Subject: str(user["id"])}, idp.NewError(idp.CodeConflict, op, "user_disabled", nil)
		}
		res.Subject = str(user["id"])
	}
	if inv.SendEmail {
		q := url.Values{}
		if inv.LinkLifespan > 0 {
			q.Set("lifespan", strconv.FormatInt(int64(inv.LinkLifespan.Seconds()), 10))
		}
		p := realmSub(realm, "users", res.Subject, "execute-actions-email")
		if len(q) > 0 {
			p += "?" + q.Encode()
		}
		if _, _, err := d.call(ctx, op, ts, http.MethodPut, p, actions, nil); err != nil {
			if c := idp.CodeOf(err); c == idp.CodeUnavailable || c == idp.CodeUpstream {
				return res, idp.NewError(idp.CodeEmailFailed, op, "execute_actions_email", err)
			}
			return res, err
		}
		res.EmailSent = true
	}
	d.log.Info("keycloak: user invited", "realm", realm, "subject", res.Subject, "created", res.Created,
		"email_sent", res.EmailSent)
	return res, nil
}

// findUser looks the user up by exact username, then by exact e-mail.
func (d *Driver) findUser(ctx context.Context, op string, ts tokenSource, realm, email string) (map[string]any, error) {
	for _, field := range []string{"username", "email"} {
		var list []map[string]any
		q := url.Values{field: {email}, "exact": {"true"}}
		if _, _, err := d.call(ctx, op, ts, http.MethodGet, realmSub(realm, "users")+"?"+q.Encode(), nil, &list); err != nil {
			return nil, err
		}
		for _, u := range list {
			if strings.EqualFold(str(u[field]), email) {
				return u, nil
			}
		}
	}
	return nil, nil
}

// DisableUser disables the user (subject = Keycloak user id = sub claim) and logs out every IdP session of it,
// through the realm's own service account. A user that does not exist is a success with Found=false.
func (d *Driver) DisableUser(ctx context.Context, reg idp.Registration, subject string) (idp.DisableResult, error) {
	const op = "keycloak.DisableUser"
	realm, ts, err := d.realmOf(op, reg)
	if err != nil {
		return idp.DisableResult{}, err
	}
	if id, err := uuid.Parse(subject); err != nil || id.String() != subject {
		return idp.DisableResult{}, idp.NewError(idp.CodeInvalidArgument, op, "subject", nil)
	}
	res := idp.DisableResult{Subject: subject}
	var user map[string]any
	st, _, err := d.call(ctx, op, ts, http.MethodGet, realmSub(realm, "users", subject), nil, &user, http.StatusNotFound)
	if err != nil {
		return res, err
	}
	if st == http.StatusNotFound {
		return res, nil
	}
	res.Found = true
	if user["enabled"] == true {
		user["enabled"] = false
		if _, _, err := d.call(ctx, op, ts, http.MethodPut, realmSub(realm, "users", subject), user, nil); err != nil {
			return res, err
		}
	} else {
		res.AlreadyDisabled = true
	}
	if _, _, err := d.call(ctx, op, ts, http.MethodPost, realmSub(realm, "users", subject, "logout"), nil, nil); err != nil {
		return res, err
	}
	res.SessionsRevoked = true
	d.log.Info("keycloak: user disabled", "realm", realm, "subject", subject, "already_disabled", res.AlreadyDisabled)
	return res, nil
}
