package api

// DOCS-5: the route-level contract guard verifies that every ENDPOINT is
// documented. It says nothing about FIELDS, so three shipped features -
// F2 phone-suffix search, P4.2 operator attribution and F7 cascade erasure -
// were absent from the machine-readable contract the project designates as
// authoritative, and `LookupRequest`'s anyOf made a supported request
// provably invalid against the published schema.
//
// This is the field-level analogue: every JSON tag on a request or response
// struct listed below must appear in the spec. Reflection over the actual
// Go types, so a field added tomorrow either lands in the spec or fails CI.

import (
	"reflect"
	"strings"
	"testing"

	apispec "github.com/fvisic/sunder/api"
	"github.com/fvisic/sunder/internal/service"
)

// specFields is every field name the spec mentions anywhere, as a set. A
// coarse check on purpose: it catches "this field is documented nowhere",
// which is the whole failure class, without coupling the test to the spec's
// nesting.
func specFields(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, line := range strings.Split(string(apispec.OpenAPI), "\n") {
		trimmed := strings.TrimSpace(line)
		name, _, found := strings.Cut(trimmed, ":")
		if !found || name == "" || strings.HasPrefix(name, "#") || strings.HasPrefix(name, "-") {
			continue
		}
		out[strings.Trim(name, "'\"")] = true
	}
	return out
}

func TestEveryRequestAndResponseFieldIsDocumented(t *testing.T) {
	documented := specFields(t)
	if len(documented) < 50 {
		t.Fatalf("spec scan looks broken: found %d names", len(documented))
	}

	for _, tc := range []struct {
		what string
		v    any
	}{
		{"LookupInput (POST /v1/lookup body)", service.LookupInput{}},
		{"RegisterInput (POST /v1/contacts body)", service.RegisterInput{}},
		{"ScopeData (DSR access/export)", service.ScopeData{}},
		{"LinkedErasure (POST /v1/dsr/erase response)", service.LinkedErasure{}},
		{"AuditTrailEntry (DSR access trail)", service.AuditTrailEntry{}},
		{"ValueTokenRef (DSR holdings)", service.ValueTokenRef{}},
		{"ShareRef (DSR holdings)", service.ShareRef{}},
		{"FileRef (DSR holdings)", service.FileRef{}},
		{"LinkRef (DSR holdings)", service.LinkRef{}},
		{"TokenizeInput (POST /v1/tokens body)", service.TokenizeInput{}},
		{"ShareInput (POST /v1/shares body)", service.ShareInput{}},
		{"Predicate (OTI selective disclosure)", service.Predicate{}},
	} {
		rt := reflect.TypeOf(tc.v)
		for i := 0; i < rt.NumField(); i++ {
			tag := rt.Field(i).Tag.Get("json")
			name, _, _ := strings.Cut(tag, ",")
			if name == "" || name == "-" {
				continue
			}
			if !documented[name] {
				t.Errorf("%s: field %q appears nowhere in api/openapi.yaml.\n"+
					"The spec is designated the source of truth for every request/response schema, "+
					"so a generated client or a validating gateway cannot use this field - and, if the "+
					"schema constrains the request, may reject a supported call outright (DOCS-5).",
					tc.what, name)
			}
		}
	}
}
