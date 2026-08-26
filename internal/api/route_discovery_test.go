package api

// Shared route discovery for the contract guards, built on go/ast rather
// than a regex: a regex sees only the literal-with-method form, so a route
// registered through a concatenated or variable pattern would ship invisible
// to the guards (proven with a live patched route in review). The AST walk
// finds EVERY Handle/HandleFunc call in the package - and the guard fails
// outright on any whose pattern is not a plain "METHOD /path" string
// literal, so the discovery itself cannot be dodged.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

func registeredRoutes(t *testing.T) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	routes := map[string]bool{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, e.Name(), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "Handle" && sel.Sel.Name != "HandleFunc") {
				return true
			}
			pos := fset.Position(call.Pos())
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				t.Errorf("%s: %s registration whose pattern is NOT a plain string literal - the contract guards cannot see such a route; register with a literal \"METHOD /path\"", pos, sel.Sel.Name)
				return true
			}
			pattern := strings.Trim(lit.Value, "`\"")
			// EXACTLY two mounts exist (sub-muxes grafted under a prefix:
			// "/v1/" behind the auth middleware, "/portal/" for the portal UI
			// and API); their real endpoints are their own registrations,
			// which this walk also visits. The list is explicit, NOT a shape
			// heuristic: ServeMux treats any trailing-slash pattern as a
			// subtree match on EVERY method, i.e. a real endpoint - a shape
			// carve-out was demonstrated to hide one from both guards.
			if pattern == "/v1/" || pattern == "/portal/" {
				return true
			}
			method, path, found := strings.Cut(pattern, " ")
			if !found || method != strings.ToUpper(method) || !strings.HasPrefix(path, "/") {
				t.Errorf("%s: pattern %q is not \"METHOD /path\" - method-less registrations match every method and dodge the per-method contract; name the method", pos, pattern)
				return true
			}
			routes[method+" "+path] = true
			return true
		})
	}
	if len(routes) < 30 {
		t.Fatalf("route discovery looks broken: found only %d registrations", len(routes))
	}
	return routes
}
