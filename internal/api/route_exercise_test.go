package api

// The house testing rule, enforced mechanically: every endpoint carries at
// least THREE tests - one happy path and two edge cases (malformed input,
// oversized input, unknown targets, exhausted limits...). A route referenced
// by fewer than three distinct test functions in this package fails here,
// so a new endpoint cannot ship under-tested any more than it can ship
// undocumented (TestEveryRouteIsDocumented).
//
// The match is heuristic but conservative: a test function counts for a
// route when its body contains every literal segment of the route's path
// (placeholders stripped) AND the quoted HTTP method. Over-matching would
// hide gaps, so tighten the heuristic before loosening the threshold.

import (
	"context"
	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/config"
	"github.com/fvisic/sunder/internal/testutil"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
)

const minTestsPerRoute = 3

// routeExerciseExemptions lists routes where fewer than three tests is an
// argued decision, each with its reason. Additions are reviewed like code.
var routeExerciseExemptions = map[string]string{}

func TestEveryRouteIsExercised(t *testing.T) {
	// 1. Registered routes via the shared AST discovery.
	registered := registeredRoutes(t)
	// 2. Test function bodies from the test sources.
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	reFunc := regexp.MustCompile(`(?m)^func (Test\w+)\(`)
	// A path named only in a // comment must not count as exercising the
	// route - strip comment lines before matching.
	reComment := regexp.MustCompile(`(?m)//[^\n]*`)
	bodies := map[string]string{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		src, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatal(err)
		}
		idx := reFunc.FindAllStringSubmatchIndex(string(src), -1)
		for i, m := range idx {
			end := len(src)
			if i+1 < len(idx) {
				end = idx[i+1][0]
			}
			bodies[string(src[m[2]:m[3]])] = reComment.ReplaceAllString(string(src[m[1]:end]), "")
		}
	}
	if len(bodies) < 50 {
		t.Fatalf("discovery looks broken: %d test funcs", len(bodies))
	}

	stripParams := regexp.MustCompile(`\{[^}]+\}`)
	for key := range registered {
		if routeExerciseExemptions[key] != "" {
			continue
		}
		method, path, _ := strings.Cut(key, " ")
		var lits []string
		for _, seg := range stripParams.Split(path, -1) {
			if seg != "" && seg != "/" {
				lits = append(lits, seg)
			}
		}
		var hits []string
		for name, body := range bodies {
			if !strings.Contains(body, `"`+method+`"`) && !strings.Contains(body, `"`+method+` `) {
				continue
			}
			ok := true
			for _, l := range lits {
				if !strings.Contains(body, l) {
					ok = false
					break
				}
			}
			if ok {
				hits = append(hits, name)
			}
		}
		if len(hits) < minTestsPerRoute {
			t.Errorf("route %q is exercised by only %d test function(s) %v - the house rule is at least %d (one happy path, two edge cases); add tests or an explicit exemption with a reason",
				key, len(hits), hits, minTestsPerRoute)
		}
	}
	for key := range routeExerciseExemptions {
		if !registered[key] {
			t.Errorf("exemption %q matches no registered route - remove it", key)
		}
	}
}

// The credential-less share fetch is the only unauthenticated route on the
// API listener, and its per-IP limit is the ONLY control on it - so the
// limited branch must actually refuse, and it must key off the API
// listener's own client-IP setting, not the portal's (AUTHZ-5).
func TestPublicShareFetchIsPerIPLimited(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewDB(t)
	cred, err := auth.Create(ctx, st.Pool, auth.Client{
		ID: "crm", Name: "CRM", Scope: "crm",
		AllowedActions:  []string{auth.ActContactsRegister, auth.ActSharesCreate, auth.ActAttributesRead},
		AllowedPurposes: []string{"support"}, RateLimit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(config.Config{Keystore: "file", KeyRetireGrace: -1, KeystorePath: t.TempDir(),
		SharesPublic: true}, st)
	if err != nil {
		t.Fatal(err)
	}
	e := &e2eEnv{srv: srv, credCRM: cred}
	_, out := e.do(t, cred, "POST", "/v1/contacts", map[string]any{
		"email": "public-share@example.com", "attributes": map[string]string{"tier": "gold"}})
	cid := out["cid"]
	_, out = e.do(t, cred, "POST", "/v1/shares", map[string]any{
		"cid": cid, "fields": []string{"tier"}, "partner_label": "p",
		"purpose": "support", "ttl_seconds": 3600})
	uuid := out["uuid"]
	if uuid == "" {
		t.Fatalf("share not created: %v", out)
	}

	fetch := func(ip string) int {
		req := httptest.NewRequest("GET", "/v1/shares/"+uuid, nil)
		req.RemoteAddr = ip + ":1000"
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec.Code
	}
	// Credential-less, and it works.
	if code := fetch("203.0.113.7"); code != 200 {
		t.Fatalf("a public share fetch must need no credential: %d", code)
	}
	// The budget is per IP, so a different source is unaffected...
	if code := fetch("203.0.113.8"); code != 200 {
		t.Fatalf("the limit must be per source IP: %d", code)
	}
	// ...and the same source is eventually refused.
	limited := false
	for i := 0; i < publicShareRateLimit+5; i++ {
		if fetch("203.0.113.7") == 429 {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatalf("the only control on the credential-less route must actually refuse after %d requests", publicShareRateLimit)
	}
}
