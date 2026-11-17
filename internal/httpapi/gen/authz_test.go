package gen_test

import (
	"reflect"
	"testing"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
)

// TestEveryOperationHasAuthorization is deny-by-default (§8.4 invariant 4) between the two code generators: every
// operation of the strict server, under the name its middlewares receive, has an entry in the authorization table
// generated from the same spec (internal/authz/operations_gen.go), and the table has nothing else.
func TestEveryOperationHasAuthorization(t *testing.T) {
	typ := reflect.TypeFor[gen.StrictServerInterface]()
	for i := 0; i < typ.NumMethod(); i++ {
		name := typ.Method(i).Name
		op, ok := authz.OperationByID(name)
		if !ok {
			t.Errorf("%s: no authorization entry — regenerate internal/authz (make authz-gen)", name)
			continue
		}
		if op.Permission == "" {
			t.Errorf("%s: empty x-permission", name)
		}
	}
	if n := len(authz.Operations()); n != typ.NumMethod() {
		t.Errorf("authz table has %d operations, the strict server %d", n, typ.NumMethod())
	}
}
