package keycloak

import (
	"bytes"
	_ "embed" // realm template
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
)

// realmTemplateJSON is a byte copy of infrastructure/idp/realms/tenant-a.json.tmpl (TestTemplateIsInfrastructureTemplate).
//
//go:embed realm.json.tmpl
var realmTemplateJSON []byte

// scopeValues are the per-scope values that differ from the tenant template — exactly platform.json.tmpl minus
// tenant-a.json.tmpl (TestTemplateMatchesInfrastructure): SSO session limits of §8.3 step 6 (= Portal session limits)
// and the name of the Portal client.
var scopeValues = map[idp.Scope]struct {
	idle, max      int
	portalName     string
	defaultDisplay string
}{
	idp.ScopeTenant:   {idle: 1800, max: 43200, portalName: "MeshGuard Tenant Portal"},
	idp.ScopePlatform: {idle: 900, max: 28800, portalName: "MeshGuard Platform Console", defaultDisplay: "Platform"},
}

// realmParams are the per-realm values of a realm representation.
type realmParams struct {
	Realm       string
	DisplayName string // "" = realm name (tenant) or "Platform"
	Scope       idp.Scope
	IdPID       uuid.UUID
	RedirectURI string
}

// decodeJSON decodes JSON keeping numbers exact (json.Number).
func decodeJSON(b []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	return dec.Decode(out)
}

// realmRep returns the representation of a realm: the template with the per-realm values set. It refuses a result
// that still holds a ${…} placeholder (Keycloak would expand it from its own environment at import) or a string
// longer than 255 characters (varchar(255) columns of Keycloak — P2-T05 F4).
func realmRep(p realmParams) (map[string]any, error) {
	sv, ok := scopeValues[p.Scope]
	if !ok {
		return nil, fmt.Errorf("keycloak: unknown scope %q", p.Scope)
	}
	var rep map[string]any
	if err := decodeJSON(realmTemplateJSON, &rep); err != nil {
		return nil, fmt.Errorf("keycloak: realm template: %w", err)
	}
	display := p.DisplayName
	if display == "" {
		display = sv.defaultDisplay
	}
	if display == "" {
		display = p.Realm
	}
	rep["realm"] = p.Realm
	rep["displayName"] = "MeshGuard — " + display
	attrs, _ := rep["attributes"].(map[string]any)
	if attrs == nil {
		return nil, errors.New("keycloak: realm template without attributes")
	}
	attrs["meshguard.scope"] = string(p.Scope)
	attrs["meshguard.idp_id"] = p.IdPID.String()
	rep["ssoSessionIdleTimeout"] = json.Number(strconv.Itoa(sv.idle))
	rep["ssoSessionMaxLifespan"] = json.Number(strconv.Itoa(sv.max))
	portal := clientsOf(rep)[PortalClientID]
	if portal == nil {
		return nil, errors.New("keycloak: realm template without the Portal client")
	}
	portal["name"] = sv.portalName
	portal["redirectUris"] = []any{p.RedirectURI}
	// RP-Initiated Logout (G2 round 2, A-1): the only page Keycloak may send the browser back to after a logout is the
	// root of the Portal origin of the callback (https://<app|admin host>/).
	plr, err := postLogoutRedirectURI(p.RedirectURI)
	if err != nil {
		return nil, err
	}
	attrs, _ = portal["attributes"].(map[string]any)
	if attrs == nil {
		return nil, errors.New("keycloak: realm template without Portal client attributes")
	}
	attrs["post.logout.redirect.uris"] = plr
	b, err := json.Marshal(rep)
	if err != nil {
		return nil, err
	}
	if bytes.Contains(b, []byte("${")) {
		return nil, errors.New("keycloak: realm representation still holds a ${…} placeholder")
	}
	if long := longStrings(rep, ""); len(long) > 0 {
		return nil, fmt.Errorf("keycloak: strings longer than 255 characters: %v", long)
	}
	return rep, nil
}

// postLogoutRedirectURI is the origin root of a Portal callback URI.
func postLogoutRedirectURI(redirectURI string) (string, error) {
	u, err := url.Parse(redirectURI)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", fmt.Errorf("keycloak: redirect URI %q is not an https URL", redirectURI)
	}
	return "https://" + u.Host + "/", nil
}

func longStrings(v any, at string) []string {
	var out []string
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			out = append(out, longStrings(e, at+"."+k)...)
		}
	case []any:
		for i, e := range x {
			out = append(out, longStrings(e, at+"["+strconv.Itoa(i)+"]")...)
		}
	case string:
		if utf8.RuneCountInString(x) > 255 {
			out = append(out, at)
		}
	}
	return out
}

// clientsOf indexes the clients of a representation by clientId.
func clientsOf(rep map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	list, _ := rep["clients"].([]any)
	for _, c := range list {
		if m, ok := c.(map[string]any); ok {
			if id, _ := m["clientId"].(string); id != "" {
				out[id] = m
			}
		}
	}
	return out
}

// clientIDs returns the clientIds of the template, sorted.
func clientIDs(rep map[string]any) []string {
	var out []string
	for id := range clientsOf(rep) {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// execWant is one execution of a flow, flattened depth-first as Keycloak lists them (level 0 = the top-level flow).
type execWant struct {
	Level       int
	Key         string // authenticator provider id, or the alias of a sub-flow
	Requirement string
}

// flowExecutions flattens flow alias of the representation depth-first, executions ordered by priority.
func flowExecutions(rep map[string]any, alias string) ([]execWant, error) {
	flows := map[string]map[string]any{}
	list, _ := rep["authenticationFlows"].([]any)
	for _, f := range list {
		if m, ok := f.(map[string]any); ok {
			if a, _ := m["alias"].(string); a != "" {
				flows[a] = m
			}
		}
	}
	var out []execWant
	var walk func(alias string, level int) error
	walk = func(alias string, level int) error {
		f := flows[alias]
		if f == nil || level > 4 {
			return fmt.Errorf("keycloak: template flow %q missing", alias)
		}
		execs, _ := f["authenticationExecutions"].([]any)
		sorted := slices.Clone(execs)
		sort.SliceStable(sorted, func(i, j int) bool { return priority(sorted[i]) < priority(sorted[j]) })
		for _, e := range sorted {
			m, _ := e.(map[string]any)
			req, _ := m["requirement"].(string)
			if sub, _ := m["flowAlias"].(string); sub != "" && m["authenticatorFlow"] == true {
				out = append(out, execWant{Level: level, Key: sub, Requirement: req})
				if err := walk(sub, level+1); err != nil {
					return err
				}
				continue
			}
			a, _ := m["authenticator"].(string)
			out = append(out, execWant{Level: level, Key: a, Requirement: req})
		}
		return nil
	}
	return out, walk(alias, 0)
}

func priority(e any) int64 {
	m, _ := e.(map[string]any)
	n, _ := m["priority"].(json.Number)
	v, _ := n.Int64()
	return v
}

// serviceAccountRoles returns, for the service account of clientID in the template, its realm roles and its client
// roles per role-container client.
func serviceAccountRoles(rep map[string]any, clientID string) ([]string, map[string][]string) {
	users, _ := rep["users"].([]any)
	for _, u := range users {
		m, _ := u.(map[string]any)
		if m["serviceAccountClientId"] != clientID {
			continue
		}
		realm := stringList(m["realmRoles"])
		clients := map[string][]string{}
		if cr, ok := m["clientRoles"].(map[string]any); ok {
			for c, roles := range cr {
				clients[c] = stringList(roles)
			}
		}
		return realm, clients
	}
	return nil, nil
}

// scopeMappingsOf returns the scope mappings the template gives clientID: realm roles and roles per role-container
// client (clientScopeMappings).
func scopeMappingsOf(rep map[string]any, clientID string) ([]string, map[string][]string) {
	var realm []string
	if sm, ok := rep["scopeMappings"].([]any); ok {
		for _, e := range sm {
			m, _ := e.(map[string]any)
			if m["client"] == clientID {
				realm = append(realm, stringList(m["roles"])...)
			}
		}
	}
	clients := map[string][]string{}
	if csm, ok := rep["clientScopeMappings"].(map[string]any); ok {
		for container, entries := range csm {
			list, _ := entries.([]any)
			for _, e := range list {
				m, _ := e.(map[string]any)
				if m["client"] == clientID {
					clients[container] = append(clients[container], stringList(m["roles"])...)
				}
			}
		}
	}
	return realm, clients
}

func stringList(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, e := range list {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// sameJSON compares two decoded JSON values; lists made only of strings compare as sets (redirect URIs, event
// listeners, scopes), numbers by value.
func sameJSON(a, b any) bool {
	switch x := a.(type) {
	case []any:
		y, ok := b.([]any)
		if !ok {
			return false
		}
		if xs, ys := stringList(x), stringList(y); len(xs) == len(x) && len(ys) == len(y) {
			return sameSet(xs, ys)
		}
		if len(x) != len(y) {
			return false
		}
		for i := range x {
			if !sameJSON(x[i], y[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, v := range x {
			w, ok := y[k]
			if !ok || !sameJSON(v, w) {
				return false
			}
		}
		return true
	case json.Number:
		y, ok := b.(json.Number)
		if !ok {
			return false
		}
		if x == y {
			return true
		}
		fx, ex := x.Float64()
		fy, ey := y.Float64()
		return ex == nil && ey == nil && fx == fy
	default:
		return reflect.DeepEqual(a, b)
	}
}

func sameSet(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(slices.Compact(x), slices.Compact(y))
}

// diffKeys returns, sorted, the keys of want (minus skip) whose value differs in have.
func diffKeys(want, have map[string]any, skip map[string]bool) []string {
	var out []string
	for k, w := range want {
		if skip[k] {
			continue
		}
		if h, ok := have[k]; !ok || !sameJSON(w, h) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// mergeAttributes returns have's attributes with want's set; changed lists the keys whose value differed.
func mergeAttributes(want, have map[string]any) (merged map[string]any, changed []string) {
	merged = map[string]any{}
	for k, v := range have {
		merged[k] = v
	}
	for k, v := range want {
		if h, ok := have[k]; !ok || !sameJSON(v, h) {
			changed = append(changed, k)
			merged[k] = v
		}
	}
	sort.Strings(changed)
	return merged, changed
}

// deepCopy copies a decoded JSON value.
func deepCopy(v map[string]any) map[string]any {
	b, _ := json.Marshal(v) //nolint:errchkjson // decoded JSON re-encodes
	var out map[string]any
	_ = decodeJSON(b, &out)
	return out
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// joinChange formats a change entry: "<kind>.<object>.<field>".
func joinChange(parts ...string) string { return strings.Join(parts, ".") }
