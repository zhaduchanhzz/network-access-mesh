package keycloak

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
)

// Reading the events of a realm (P3-T15, job idp.audit_sync — §8.2 "admin event của Keycloak … được chuyển vào
// audit_events của tenant"). Every read uses the provisioning identity: Keycloak gives a realm's creator every role of
// that realm's management client but impersonation (view-events included), Bootstrap gives it the same for the realms
// it adopts and exactly view-events of master-realm and of the realms it only audits (the platform realm). The
// representation of an admin event can hold a secret (a client's secret on a client update): callers parse it into an
// allow-list of fields and never store, log or forward it (internal/idp/auditsync).

// MasterRealm is the name of Keycloak's administration realm (console logins, the provisioning identity).
const MasterRealm = masterRealm

// EventPageMax is the largest page the event reads ask for.
const EventPageMax = 100

// AuthDetails is the authDetails of an admin event: who acted. ClientID is the internal id (UUID) of the client in
// the actor's realm, RealmID the internal id of that realm — Keycloak does not give their names.
type AuthDetails struct {
	RealmID   string `json:"realmId"`
	ClientID  string `json:"clientId"`
	UserID    string `json:"userId"`
	IPAddress string `json:"ipAddress"`
}

// AdminEvent is one admin event (GET /admin/realms/{realm}/admin-events). Representation is the raw JSON text of the
// representation Keycloak recorded — possibly holding a secret: never log, store or forward it.
type AdminEvent struct {
	ID             string            `json:"id"`
	Time           int64             `json:"time"` // milliseconds since the epoch
	RealmID        string            `json:"realmId"`
	AuthDetails    AuthDetails       `json:"authDetails"`
	OperationType  string            `json:"operationType"` // CREATE, UPDATE, DELETE, ACTION
	ResourceType   string            `json:"resourceType"`  // USER, CLIENT, REALM_ROLE_MAPPING…
	ResourcePath   string            `json:"resourcePath"`  // relative: users/<id>/reset-password
	Representation string            `json:"representation"`
	Error          string            `json:"error"`
	Details        map[string]string `json:"details"`
}

// UserEvent is one login/user event (GET /admin/realms/{realm}/events). ClientID is the clientId (a name).
type UserEvent struct {
	ID        string            `json:"id"`
	Time      int64             `json:"time"`
	Type      string            `json:"type"`
	RealmID   string            `json:"realmId"`
	ClientID  string            `json:"clientId"`
	UserID    string            `json:"userId"`
	SessionID string            `json:"sessionId"`
	IPAddress string            `json:"ipAddress"`
	Error     string            `json:"error"`
	Details   map[string]string `json:"details"`
}

// EventsConfig is the events configuration of a realm (GET /admin/realms/{realm}/events/config).
type EventsConfig struct {
	EventsEnabled             bool     `json:"eventsEnabled"`
	AdminEventsEnabled        bool     `json:"adminEventsEnabled"`
	AdminEventsDetailsEnabled bool     `json:"adminEventsDetailsEnabled"`
	EnabledEventTypes         []string `json:"enabledEventTypes"`
}

// EventQuery selects one page of events of a realm, oldest first: events at or after FromMillis (Keycloak's dateFrom
// in epoch milliseconds, inclusive), starting at offset First, at most Max (≤ EventPageMax). Types filters user
// events by type (ignored for admin events).
type EventQuery struct {
	FromMillis int64
	First      int
	Max        int
	Types      []string
}

var eventTypeRE = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,63}$`)

// eventRealm accepts the realms whose events are read: a managed realm name or master.
func eventRealm(r string) bool { return r == masterRealm || validRealm(r) }

func (q EventQuery) values(user bool) (url.Values, error) {
	if q.FromMillis < 0 || q.First < 0 || q.Max <= 0 || q.Max > EventPageMax || len(q.Types) > 16 {
		return nil, idp.NewError(idp.CodeInvalidArgument, "keycloak.events", "query", nil)
	}
	v := url.Values{"direction": {"asc"}, "first": {strconv.Itoa(q.First)}, "max": {strconv.Itoa(q.Max)}}
	if q.FromMillis > 0 {
		v.Set("dateFrom", strconv.FormatInt(q.FromMillis, 10))
	}
	if user {
		for _, t := range q.Types {
			if !eventTypeRE.MatchString(t) {
				return nil, idp.NewError(idp.CodeInvalidArgument, "keycloak.events", "event_type", nil)
			}
			v.Add("type", t)
		}
	}
	return v, nil
}

// AdminEvents returns one page of the admin events of realm, oldest first.
func (d *Driver) AdminEvents(ctx context.Context, realm string, q EventQuery) ([]AdminEvent, error) {
	const op = "keycloak.AdminEvents"
	if !eventRealm(realm) {
		return nil, idp.NewError(idp.CodeInvalidArgument, op, "realm", nil)
	}
	v, err := q.values(false)
	if err != nil {
		return nil, err
	}
	var out []AdminEvent
	if _, _, err := d.call(ctx, op, d.provisioner(), http.MethodGet, realmSub(realm, "admin-events")+"?"+v.Encode(), nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// UserEvents returns one page of the login/user events of realm of the given types, oldest first.
func (d *Driver) UserEvents(ctx context.Context, realm string, q EventQuery) ([]UserEvent, error) {
	const op = "keycloak.UserEvents"
	if !eventRealm(realm) {
		return nil, idp.NewError(idp.CodeInvalidArgument, op, "realm", nil)
	}
	v, err := q.values(true)
	if err != nil {
		return nil, err
	}
	var out []UserEvent
	if _, _, err := d.call(ctx, op, d.provisioner(), http.MethodGet, realmSub(realm, "events")+"?"+v.Encode(), nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// EventsConfig returns the events configuration of realm (view-events is enough to read it).
func (d *Driver) EventsConfig(ctx context.Context, realm string) (EventsConfig, error) {
	const op = "keycloak.EventsConfig"
	if !eventRealm(realm) {
		return EventsConfig{}, idp.NewError(idp.CodeInvalidArgument, op, "realm", nil)
	}
	var out EventsConfig
	_, _, err := d.call(ctx, op, d.provisioner(), http.MethodGet, realmSub(realm, "events", "config"), nil, &out)
	return out, err
}

// ClientUUID returns the internal id of the client clientID of realm ("" when it does not exist); it needs
// view-clients of that realm (the realms the provisioning identity created or adopted), so it fails with
// CodeForbidden on a realm it only audits.
func (d *Driver) ClientUUID(ctx context.Context, realm, clientID string) (string, error) {
	const op = "keycloak.ClientUUID"
	if !validRealm(realm) {
		return "", idp.NewError(idp.CodeInvalidArgument, op, "realm", nil)
	}
	c, err := d.findClient(ctx, op, d.provisioner(), realm, clientID)
	if err != nil || c == nil {
		return "", err
	}
	id := str(c["id"])
	if _, err := uuid.Parse(id); err != nil {
		return "", idp.NewError(idp.CodeUpstream, op, "client_id", nil)
	}
	return id, nil
}

// ProvisionerUserID returns the id of the provisioning identity's service-account user (the sub of its token): the
// userId its own admin events and logins carry. The token comes from the token endpoint over the platform route (TLS
// verified for auth.<domain>); only this claim is read, nothing is trusted beyond identifying our own actor.
func (d *Driver) ProvisionerUserID(ctx context.Context) (string, error) {
	const op = "keycloak.ProvisionerUserID"
	tok, err := d.token(ctx, op, d.provisioner())
	if err != nil {
		return "", err
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return "", idp.NewError(idp.CodeUpstream, op, "token_format", nil)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", idp.NewError(idp.CodeUpstream, op, "token_payload", nil)
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if json.Unmarshal(raw, &claims) != nil || claims.Sub == "" {
		return "", idp.NewError(idp.CodeUpstream, op, "token_sub", nil)
	}
	if _, err := uuid.Parse(claims.Sub); err != nil {
		return "", idp.NewError(idp.CodeUpstream, op, "token_sub", nil)
	}
	return claims.Sub, nil
}

// ProvisionerClientID is the client id of the provisioning identity (its CLIENT_LOGIN events are the driver's own).
func (d *Driver) ProvisionerClientID() string { return d.prov.ClientID }

// RealmOfIssuer returns the realm of an issuer of this IdP (https://<platform IdP host>/realms/<realm>), or false.
func (d *Driver) RealmOfIssuer(issuer string) (string, bool) {
	r, ok := strings.CutPrefix(issuer, d.base+"/realms/")
	if !ok || !validRealm(r) {
		return "", false
	}
	return r, true
}
