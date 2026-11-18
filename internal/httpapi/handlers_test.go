package httpapi

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
)

// specTasks reads operationId → x-task from api/openapi.yaml (the strict YAML subset enforced by tools/openapi_lint.py:
// within an operation, `operationId:` comes before `x-task:`). The Go method name is the operationId with its first
// letter upper-cased, as oapi-codegen names it.
func specTasks(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	op := ""
	for _, ln := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		ln = strings.TrimSpace(ln)
		if v, ok := strings.CutPrefix(ln, "operationId: "); ok {
			op = strings.ToUpper(v[:1]) + v[1:]
		}
		if v, ok := strings.CutPrefix(ln, "x-task: "); ok && op != "" {
			out[op] = v
			op = ""
		}
	}
	if len(out) == 0 {
		t.Fatal("no operation found in api/openapi.yaml")
	}
	return out
}

// TestHandlerGroupsFollowSpec: each handler interface holds exactly the operations whose x-task is its task, so a
// task plugs one interface and nothing else.
func TestHandlerGroupsFollowSpec(t *testing.T) {
	groups := map[string]reflect.Type{
		"P2-T06":  reflect.TypeFor[AuthHandlers](),
		"P2-T11":  reflect.TypeFor[TenantHandlers](),
		"P2-T13":  reflect.TypeFor[DeviceHandlers](),
		"P2-T08":  reflect.TypeFor[AuditHandlers](),
		"P2-T12":  reflect.TypeFor[JobHandlers](),
		"P2-T13a": reflect.TypeFor[MonitoringHandlers](),
		"P3-T04":  reflect.TypeFor[HostHandlers](),
		"P3-T05b": reflect.TypeFor[NotificationHandlers](),
		"P3-T04a": reflect.TypeFor[ApprovalHandlers](),
		"P3-T05a": reflect.TypeFor[InvitationHandlers](),
		"P3-T15":  reflect.TypeFor[IdPConsoleHandlers](),
		"P3-T05":  reflect.TypeFor[ProvisioningHandlers](),
		"P3-T08":  reflect.TypeFor[LifecycleHandlers](),
	}
	tasks := specTasks(t)
	for task, iface := range groups {
		var want, got []string
		for op, tk := range tasks {
			if tk == task {
				want = append(want, op)
			}
		}
		for i := range iface.NumMethod() {
			got = append(got, iface.Method(i).Name)
		}
		slices.Sort(want)
		slices.Sort(got)
		if !slices.Equal(want, got) {
			t.Errorf("%s (%s): spec operations %v, interface methods %v", iface.Name(), task, want, got)
		}
	}
	for op, task := range tasks {
		if _, ok := groups[task]; !ok {
			t.Errorf("operation %s has x-task %s, which has no handler interface yet", op, task)
		}
	}
}

// TestNotImplementedAnswersEveryOperation calls every method of NotImplemented through the generated interface.
func TestNotImplementedAnswersEveryOperation(t *testing.T) {
	v := reflect.ValueOf(gen.StrictServerInterface(NotImplemented{}))
	iface := reflect.TypeFor[gen.StrictServerInterface]()
	for i := range iface.NumMethod() {
		m := iface.Method(i)
		res := v.MethodByName(m.Name).Call([]reflect.Value{
			reflect.ValueOf(context.Background()), reflect.Zero(m.Type.In(1)),
		})
		var p *problem.Error
		err, _ := res[1].Interface().(error)
		if !res[0].IsNil() || !errors.As(err, &p) || p.Code != gen.ProblemCodeNotImplemented || !strings.Contains(p.Detail, m.Name) {
			t.Errorf("%s: got (%v, %v)", m.Name, res[0], err)
		}
	}
}

// partialTenants implements only ListMyTenants; the rest of its interface comes from NotImplemented.
type partialTenants struct{ NotImplemented }

func (partialTenants) ListMyTenants(context.Context, gen.ListMyTenantsRequestObject) (gen.ListMyTenantsResponseObject, error) {
	return gen.ListMyTenants200JSONResponse{Items: []gen.Tenant{}}, nil
}

func TestPartialHandlerSet(t *testing.T) {
	e := newEnv(t, Options{Handlers: Handlers{Tenants: partialTenants{}}, Hooks: Hooks{Authz: passAuthz}})
	if w := e.do(http.MethodGet, "/api/v1/tenants", ""); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"items":[]`) {
		t.Errorf("implemented operation: %d %s", w.Code, w.Body.String())
	}
	for _, target := range []string{"/api/v1/tenants/" + tenantID, "/api/v1/platform/instances", "/api/v1/auth/session"} {
		if w := e.do(http.MethodGet, target, ""); w.Code != http.StatusNotImplemented {
			t.Errorf("%s: %d", target, w.Code)
		}
	}
}
