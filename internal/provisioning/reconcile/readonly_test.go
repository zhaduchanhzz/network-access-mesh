package reconcile

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
)

// readMethods are the only methods of the agent and of a Headscale instance that reconcile may call.
var readMethods = map[string]bool{"GetInstanceStatus": true, "ListInstances": true, "ListAPIKeys": true, "ForTenant": true}

// TestPackageCallsNoWriteMethod is the static half of "report only": no source file of the package calls a method of
// the agent API (agentv1.AgentServiceClient) or of a Headscale instance (headscale.Instance) other than the reads
// above, nor imports the compose driver, a Docker client or the SecretStore. The Agent interface of the package lists
// the two reads only, so a write would not compile either; this test keeps a later edit from widening it silently.
func TestPackageCallsNoWriteMethod(t *testing.T) {
	forbidden := map[string]bool{}
	for _, typ := range []reflect.Type{reflect.TypeFor[agentv1.AgentServiceClient](), reflect.TypeFor[headscale.Instance]()} {
		for i := range typ.NumMethod() {
			if name := typ.Method(i).Name; !readMethods[name] {
				forbidden[name] = true
			}
		}
	}
	if len(forbidden) < 30 || !forbidden["RemoveInstance"] || !forbidden["ExpireAPIKey"] || !forbidden["StartInstance"] {
		t.Fatalf("forbidden set looks wrong: %v", forbidden)
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	files := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		files++
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, e.Name(), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if strings.Contains(p, "/driver/compose") || strings.Contains(p, "moby") || strings.Contains(p, "docker") ||
				strings.HasSuffix(p, "/internal/secrets") {
				t.Errorf("%s imports %s", e.Name(), p)
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && forbidden[sel.Sel.Name] {
				t.Errorf("%s refers to %s — reconcile only reads", fset.Position(sel.Pos()), sel.Sel.Name)
			}
			return true
		})
	}
	if files < 5 {
		t.Fatalf("scanned %d files", files)
	}
}
