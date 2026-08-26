package api

// The contract guard: NO route may exist undocumented. Every mux
// registration in this package must appear in api/openapi.yaml with its
// method - a new endpoint that ships without a spec entry fails this test.
// Same structural pattern as the erasure sweep: the invariant is enforced
// by discovery, not by remembering.

import (
	"strings"
	"testing"

	apispec "github.com/fvisic/sunder/api"
)

// routesExemptFromSpec are non-API surfaces, each with its reason. Adding
// here is an explicit decision, reviewed like code.
var routesExemptFromSpec = map[string]string{
	"GET /openapi.yaml": "the spec serving itself",
	"GET /portal/":      "static portal UI assets (the portal API itself IS specified)",
}

func TestEveryRouteIsDocumented(t *testing.T) {
	// 1. Every Handle/HandleFunc registration, via go/ast (fails on any
	// non-literal pattern - see route_discovery_test.go).
	registered := registeredRoutes(t)

	// 2. Every path+method pair the spec documents. The spec is our own
	// file with a stable layout ("  /path:" then "    method:"), so a tiny
	// scanner suffices - no YAML dependency.
	documented := map[string]bool{}
	var current string
	for _, line := range strings.Split(string(apispec.OpenAPI), "\n") {
		// A trailing comment must not hide a path or attribute its methods
		// to the previous one (a "  /v1/x: # note" line used to fail the
		// suffix test and silently mis-parent its operations).
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimRight(line, " ")
		if strings.HasPrefix(line, "  /") && strings.HasSuffix(line, ":") {
			current = strings.TrimSuffix(strings.TrimSpace(line), ":")
			continue
		}
		if current == "" || !strings.HasPrefix(line, "    ") || strings.HasPrefix(line, "     ") {
			continue
		}
		m := strings.TrimSuffix(strings.TrimSpace(line), ":")
		switch m {
		case "get", "post", "put", "patch", "delete", "head", "options":
			documented[strings.ToUpper(m)+" "+current] = true
		}
	}
	if len(documented) < 30 {
		t.Fatalf("spec parsing looks broken: found only %d documented operations", len(documented))
	}

	// 3. Every registration is documented or explicitly exempt...
	for route := range registered {
		if routesExemptFromSpec[route] != "" {
			continue
		}
		if !documented[route] {
			t.Errorf("route %q is registered but NOT in api/openapi.yaml - no method may exist undocumented; add the spec entry (or an explicit exemption with a reason)", route)
		}
	}
	// ...and the spec documents nothing that does not exist.
	for op := range documented {
		if !registered[op] {
			t.Errorf("spec documents %q but no such route is registered - remove it or wire it", op)
		}
	}
	// Exemptions must not rot either.
	for route := range routesExemptFromSpec {
		if !registered[route] {
			t.Errorf("exemption %q matches no registered route - remove it", route)
		}
	}
}
