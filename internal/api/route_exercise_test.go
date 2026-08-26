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
