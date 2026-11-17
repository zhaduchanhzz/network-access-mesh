//go:build mgtestfixture

package authzmatrix_test

// The permission matrices of §8.5 (platform) and §8.6 (tenant), written out by hand from the master document — NOT
// read from database/seeds/rbac.sql, which is what the API decides with. TestHandTablesMatchTheMaster parses the two
// tables of docs/planning/implementation-master-plan.md and requires this encoding to be identical cell by cell, so a
// change of the master fails here until the expectations are reviewed; a wrong seed (or a wrong seed generator) fails
// the matrix itself.

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
)

// Cells of §8.5/§8.6 (the master's own symbols).
const (
	Y  = "✔"         // allowed
	N  = "—"         // refused
	O  = "○"         // allowed on the caller's own resources only (x-own-resource)
	P2 = "2P"        // allowed with a second approver (x-dual-control)
	G  = "G"         // staff column: support_operator and support_admin (through a Support Access Grant)
	GA = "G (Admin)" // staff column: support_admin only
	// Conditional cells — the seed turns them into grants with a condition the operation must enforce (P2-T07).
	condSelfEnroll  = "✔ (nếu tenant cho phép self-enroll)"
	condNoSA        = "✔ (không gồm role SA)"
	condTenantIdP2P = "✔ (IdP của tenant: 2P)"
	condRestoreOnly = "chỉ cho restore"
)

// conditions maps a conditional cell to the condition of its grant (authz.Cond*).
var conditions = map[string]string{
	condSelfEnroll:  authz.CondSelfEnroll,
	condNoSA:        authz.CondExcludesSuperAdmin,
	condTenantIdP2P: authz.CondTenantIdPDualControl,
	condRestoreOnly: authz.CondRestoreOnly,
}

// Columns of the two tables and the role keys of §8.4 they stand for.
var (
	platformColumns = []string{"SA", "PO", "PS", "PV"}
	tenantColumns   = []string{"TO", "TA", "TP", "TV", "EU", "Staff"}
	columnRole      = map[string]string{
		"SA": authz.RoleSuperAdmin, "PO": authz.RolePlatformOperator, "PS": authz.RolePlatformSupport,
		"PV": authz.RolePlatformViewer, "TO": authz.RoleTenantOwner, "TA": authz.RoleTenantAdmin,
		"TP": authz.RoleTenantOperator, "TV": authz.RoleTenantViewer, "EU": authz.RoleEndUser,
	}
)

// platformMatrix is §8.5: SA, PO, PS, PV.
var platformMatrix = map[string][]string{
	"platform.tenant:read":              {Y, Y, Y, Y},
	"platform.tenant:create":            {Y, Y, N, N},
	"platform.tenant:update":            {Y, Y, N, N},
	"platform.tenant:suspend":           {Y, Y, N, N},
	"platform.tenant:delete":            {P2, N, N, N},
	"platform.approval:read":            {Y, Y, N, Y},
	"platform.approval:decide":          {Y, condRestoreOnly, N, N},
	"platform.instance:read":            {Y, Y, Y, Y},
	"platform.instance:operate":         {Y, Y, N, N},
	"platform.instance:upgrade":         {Y, Y, N, N},
	"platform.instance:restore":         {P2, P2, N, N},
	"platform.instance:quarantine":      {Y, Y, N, N},
	"platform.instance:release":         {P2, P2, N, N},
	"platform.host:read":                {Y, Y, Y, Y},
	"platform.host:manage":              {Y, Y, N, N},
	"platform.relay:read":               {Y, Y, Y, Y},
	"platform.relay:manage":             {Y, Y, N, N},
	"platform.health:read":              {Y, Y, Y, Y},
	"platform.job:read":                 {Y, Y, Y, Y},
	"platform.job:control":              {Y, Y, N, N},
	"platform.settings:read":            {Y, Y, N, Y},
	"platform.settings:update":          {Y, N, N, N},
	"platform.idp:read":                 {Y, Y, N, Y},
	"platform.idp:manage":               {condTenantIdP2P, N, N, N},
	"platform.user:read":                {Y, Y, N, Y},
	"platform.user:assign":              {condNoSA, N, N, N},
	"platform.user:assign_super_admin":  {P2, N, N, N},
	"platform.plan:read":                {Y, Y, Y, Y},
	"platform.plan:manage":              {Y, N, N, N},
	"platform.usage:read":               {Y, Y, N, Y},
	"platform.audit:read":               {Y, Y, N, Y},
	"platform.security_event:read":      {Y, Y, Y, Y},
	"platform.support_grant:request":    {Y, Y, Y, N},
	"platform.support_grant:read":       {Y, Y, Y, Y},
	"platform.support_grant:revoke":     {Y, N, N, N},
	"platform.support_grant:breakglass": {P2, N, N, N},
	"platform.backup:read":              {Y, Y, N, Y},
}

// tenantMatrix is §8.6: TO, TA, TP, TV, EU, Staff.
var tenantMatrix = map[string][]string{
	"tenant.tenant:read":                 {Y, Y, Y, Y, Y, G},
	"tenant.dashboard:read":              {Y, Y, Y, Y, N, G},
	"tenant.device:read":                 {Y, Y, Y, Y, O, G},
	"tenant.device:rename":               {Y, Y, Y, N, O, G},
	"tenant.device:tag":                  {Y, Y, N, N, N, GA},
	"tenant.device:expire":               {Y, Y, Y, N, O, G},
	"tenant.device:delete":               {Y, Y, N, N, O, GA},
	"tenant.device:sync":                 {Y, Y, Y, N, N, G},
	"tenant.tag:read":                    {Y, Y, Y, Y, N, G},
	"tenant.tag:manage":                  {Y, Y, N, N, N, N},
	"tenant.user:read":                   {Y, Y, Y, Y, N, G},
	"tenant.user:manage":                 {Y, Y, N, N, N, N},
	"tenant.invitation:manage":           {Y, Y, N, N, N, N},
	"tenant.membership:assign":           {Y, Y, N, N, N, N},
	"tenant.membership:assign_admin":     {Y, N, N, N, N, N},
	"tenant.group:read":                  {Y, Y, Y, Y, N, G},
	"tenant.group:manage":                {Y, Y, N, N, N, N},
	"tenant.enrollment:request":          {Y, Y, Y, N, condSelfEnroll, N},
	"tenant.enrollment:approve":          {Y, Y, Y, N, N, G},
	"tenant.enrollment:issue_privileged": {Y, Y, N, N, N, N},
	"tenant.enrollment:read":             {Y, Y, Y, Y, O, G},
	"tenant.enrollment:revoke":           {Y, Y, Y, N, O, G},
	"tenant.policy:read":                 {Y, Y, Y, Y, N, G},
	"tenant.policy:edit":                 {Y, Y, N, N, N, N},
	"tenant.policy:approve":              {Y, Y, N, N, N, N},
	"tenant.policy:apply":                {Y, Y, N, N, N, GA},
	"tenant.dns:read":                    {Y, Y, Y, Y, N, G},
	"tenant.dns:update":                  {Y, Y, N, N, N, N},
	"tenant.route:read":                  {Y, Y, Y, Y, N, G},
	"tenant.route:approve":               {Y, Y, N, N, N, N},
	"tenant.resource:read":               {Y, Y, Y, Y, N, G},
	"tenant.resource:manage":             {Y, Y, N, N, N, N},
	"tenant.diagnostics:read":            {Y, Y, Y, N, N, G},
	"tenant.diagnostics:run":             {Y, Y, Y, N, O, G},
	"tenant.relay:read":                  {Y, Y, Y, Y, N, G},
	"tenant.usage:read":                  {Y, Y, N, Y, N, G},
	"tenant.billing:read":                {Y, N, N, N, N, N},
	"tenant.audit:read":                  {Y, Y, N, Y, N, G},
	"tenant.notification:read":           {O, O, O, O, O, N},
	"tenant.settings:read":               {Y, Y, Y, Y, N, G},
	"tenant.settings:update":             {Y, Y, N, N, N, N},
	"tenant.settings:update_security":    {Y, N, N, N, N, N},
	"tenant.idp:read":                    {Y, Y, N, N, N, N},
	"tenant.idp:update":                  {Y, N, N, N, N, N},
	"tenant.support_grant:read":          {Y, Y, N, Y, N, N},
	"tenant.support_grant:decide":        {Y, Y, N, N, N, N},
	"tenant.approval:read":               {Y, Y, N, Y, N, N},
	"tenant.approval:decide":             {Y, Y, N, N, N, N},
	"tenant.job:read":                    {Y, Y, Y, Y, N, G},
	"tenant.lifecycle:request_delete":    {Y, N, N, N, N, N},
}

// cellOf returns the §8.5/§8.6 cell of role for perm ("" when the role is not a column of the permission's table).
func cellOf(perm authz.Permission, role string) string {
	table, cols := platformMatrix, platformColumns
	if perm.Scope() == authz.ScopeTenant {
		table, cols = tenantMatrix, tenantColumns
	}
	row, ok := table[string(perm)]
	if !ok {
		return ""
	}
	for i, c := range cols {
		if columnRole[c] == role {
			return row[i]
		}
	}
	return ""
}

// rowHas reports whether some role column of perm holds cell.
func rowHas(perm authz.Permission, cell string) bool {
	table := platformMatrix
	if perm.Scope() == authz.ScopeTenant {
		table = tenantMatrix
	}
	return slices.Contains(table[string(perm)], cell)
}

// masterPath is the master document, from this package's directory.
var masterPath = filepath.Join("..", "..", "..", "docs", "planning", "implementation-master-plan.md")

// parseMasterMatrix reads the table under heading: its role columns and, per permission key, the cell of each column
// (a row "`k:read` / `:manage`" with cells "✔ / —" gives two keys; a cell without " / " applies to both).
func parseMasterMatrix(t *testing.T, lines []string, heading string) ([]string, map[string][]string) {
	t.Helper()
	start := slices.IndexFunc(lines, func(l string) bool { return strings.HasPrefix(l, heading) })
	if start < 0 {
		t.Fatalf("master: heading %q not found", heading)
	}
	var cols []string
	rows := map[string][]string{}
	for _, l := range lines[start+1:] {
		if strings.HasPrefix(l, "### ") || strings.HasPrefix(l, "## ") {
			break
		}
		cells := splitRow(l)
		if len(cells) < 3 {
			continue
		}
		if cells[0] == "Permission" {
			cols = cells[2:]
			continue
		}
		if !strings.HasPrefix(cells[0], "`") {
			continue
		}
		keys := permissionKeys(cells[0])
		perKey := make([][]string, len(keys))
		for _, c := range cells[2:] {
			parts := strings.Split(c, " / ")
			switch {
			case len(parts) == len(keys):
			case len(parts) == 1:
				parts = slices.Repeat(parts, len(keys))
			default:
				t.Fatalf("master: row %q, cell %q does not split into %d parts", cells[0], c, len(keys))
			}
			for i, p := range parts {
				perKey[i] = append(perKey[i], strings.TrimSpace(p))
			}
		}
		for i, k := range keys {
			if prev, dup := rows[k]; dup && !slices.Equal(prev, perKey[i]) {
				t.Fatalf("master: duplicate row %s with different cells %v / %v", k, prev, perKey[i])
			}
			rows[k] = perKey[i]
		}
	}
	return cols, rows
}

func splitRow(l string) []string {
	l = strings.TrimSpace(l)
	if !strings.HasPrefix(l, "|") || !strings.HasSuffix(l, "|") {
		return nil
	}
	parts := strings.Split(l[1:len(l)-1], "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// permissionKeys extracts "`platform.approval:read` / `:decide`" ⇒ platform.approval:read, platform.approval:decide.
func permissionKeys(cell string) []string {
	var keys []string
	for i, tok := range strings.Split(cell, "`") {
		if i%2 == 0 || tok == "" {
			continue
		}
		if strings.HasPrefix(tok, ":") && len(keys) > 0 {
			base := keys[0][:strings.Index(keys[0], ":")]
			tok = base + tok
		}
		keys = append(keys, tok)
	}
	return keys
}

// TestHandTablesMatchTheMaster — the hand encoding above is §8.5/§8.6 of the master, cell by cell, and every cell is
// a symbol the matrix knows how to turn into an expectation.
func TestHandTablesMatchTheMaster(t *testing.T) {
	raw, err := os.ReadFile(masterPath) //nolint:gosec // G304: a fixed path of the repository
	if err != nil {
		t.Fatalf("read the master document: %v", err)
	}
	lines := strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")
	known := map[string]bool{Y: true, N: true, O: true, P2: true, G: true, GA: true}
	for c := range conditions {
		known[c] = true
	}
	for _, tc := range []struct {
		heading string
		cols    []string
		hand    map[string][]string
	}{
		{"### 8.5 Permission Matrix", platformColumns, platformMatrix},
		{"### 8.6 Permission Matrix", tenantColumns, tenantMatrix},
	} {
		cols, rows := parseMasterMatrix(t, lines, tc.heading)
		if !slices.Equal(cols, tc.cols) {
			t.Errorf("%s: columns %v, the hand table has %v", tc.heading, cols, tc.cols)
		}
		if len(rows) == 0 {
			t.Fatalf("%s: no row parsed", tc.heading)
		}
		for k, cells := range rows {
			hand, ok := tc.hand[k]
			switch {
			case !ok:
				t.Errorf("%s: row %s is missing from the hand table", tc.heading, k)
			case !slices.Equal(cells, hand):
				t.Errorf("%s: row %s = %q in the master, %q in the hand table", tc.heading, k, cells, hand)
			}
			for _, c := range cells {
				if !known[c] {
					t.Errorf("%s: row %s has cell %q the matrix cannot interpret — extend master_test.go", tc.heading, k, c)
				}
			}
		}
		for k := range tc.hand {
			if _, ok := rows[k]; !ok {
				t.Errorf("%s: the hand table has row %s that the master does not", tc.heading, k)
			}
		}
		t.Logf("%s: %d rows match the hand encoding", tc.heading, len(rows))
	}
}

// TestEveryOperationHasAnExpectation — the matrix covers the spec, nothing else: every operation of the generated
// authorization table is a method of the generated strict server and back, its x-permission has a row (or is a special
// value), its 2P flag agrees with the row, and it has a request recipe; no recipe names an operation the spec lacks.
func TestEveryOperationHasAnExpectation(t *testing.T) {
	ops := authz.Operations()
	server := reflect.TypeFor[gen.StrictServerInterface]()
	methods := map[string]bool{}
	for i := range server.NumMethod() {
		methods[server.Method(i).Name] = true
	}
	seen := map[string]bool{}
	for _, op := range ops {
		seen[op.ID] = true
		name := goName(op.ID)
		if !methods[name] {
			t.Errorf("%s: no method %s on gen.StrictServerInterface", op.ID, name)
		}
		delete(methods, name)
		switch op.Permission {
		case authz.Public, authz.Authenticated, authz.Internal:
		default:
			if cellOf(op.Permission, columnRole[columnsOf(op.Permission)[0]]) == "" {
				t.Errorf("%s: x-permission %s has no row in the hand-encoded §8.5/§8.6 table — add the expectation", op.ID, op.Permission)
				continue
			}
			if op.DualControl != rowHas(op.Permission, P2) {
				t.Errorf("%s: x-dual-control %v but the row of %s has 2P cells: %v", op.ID, op.DualControl, op.Permission,
					rowHas(op.Permission, P2))
			}
		}
		if _, ok := recipes[op.ID]; !ok {
			t.Errorf("%s: no request recipe in recipes_test.go — the matrix cannot send it", op.ID)
		}
		for _, p := range pathParams(op.Path) {
			if _, ok := paramObjects[p]; !ok && (p != "tenantId" || !op.TenantScoped()) {
				t.Errorf("%s: path parameter {%s} has no object kind in paramObjects", op.ID, p)
			}
		}
	}
	for m := range methods {
		t.Errorf("gen.StrictServerInterface.%s is not in the authorization table", m)
	}
	var stale []string
	for id := range recipes {
		if !seen[id] {
			stale = append(stale, id)
		}
	}
	sort.Strings(stale)
	for _, id := range stale {
		t.Errorf("recipe %s names no operation of the spec", id)
	}
	t.Logf("%d operations, %d recipes", len(ops), len(recipes))
}

func columnsOf(perm authz.Permission) []string {
	if perm.Scope() == authz.ScopeTenant {
		return tenantColumns
	}
	return platformColumns
}

// goName is the Go name oapi-codegen gives an operation ("listDevices" → "ListDevices").
func goName(id string) string { return strings.ToUpper(id[:1]) + id[1:] }

// pathParams lists the {params} of a path template.
func pathParams(path string) []string {
	var out []string
	for _, seg := range strings.Split(path, "/") {
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			out = append(out, seg[1:len(seg)-1])
		}
	}
	return out
}
