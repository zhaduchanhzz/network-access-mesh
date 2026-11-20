package keycloak

import (
	"context"
	"net/http"

	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
)

// i18nKeys are the realm settings of the language of the login pages and e-mails (G4b-E14): internationalization on,
// the Portal's languages (vi, en — Keycloak 26.8.2 ships the vi messages of the login, e-mail and account themes) and
// the default language. The Portal passes its language as ui_locales (identity.LoginRequest.UILocales).
var i18nKeys = []string{"internationalizationEnabled", "supportedLocales", "defaultLocale"}

// templateI18n returns the i18n settings of the realm template.
func templateI18n() (map[string]any, error) {
	var tmpl map[string]any
	if err := decodeJSON(realmTemplateJSON, &tmpl); err != nil {
		return nil, err
	}
	out := make(map[string]any, len(i18nKeys))
	for _, k := range i18nKeys {
		out[k] = tmpl[k]
	}
	return out, nil
}

// EnsureI18n gives the realm of a driver-created tenant or platform IdP the i18n settings of the template when they
// differ (G4b-E14: realms created before the template carried them show every page in English whatever ui_locales
// says). Idempotent: changed=false when the realm already has them (supportedLocales compared as a set). Same
// precondition as EnsureSMTP: only realms created by the driver whose attributes name this IdP; a rendered realm is
// infrastructure/idp/realm-update.sh's (CodeUnsupported). Realms created or reconciled by EnsureIssuer get them from
// the template already.
func (d *Driver) EnsureI18n(ctx context.Context, reg idp.Registration) (changed bool, err error) {
	const op = "keycloak.EnsureI18n"
	if err := reg.Validate(op); err != nil {
		return false, err
	}
	want, err := templateI18n()
	if err != nil {
		return false, idp.NewError(idp.CodeInternal, op, "template", err)
	}
	realm, live, err := d.driverRealm(ctx, op, reg)
	if err != nil {
		return false, err
	}
	if len(diffKeys(want, live, nil)) == 0 {
		return false, nil
	}
	if _, _, err := d.call(ctx, op, d.provisioner(), http.MethodPut, realmPath(realm), want, nil); err != nil {
		return false, err
	}
	d.log.Info("keycloak: realm i18n set", "realm", realm)
	return true, nil
}
