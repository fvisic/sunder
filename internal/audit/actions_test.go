package audit

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// repoRoot walks up from this package to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("go.mod not found above the test's working directory")
	return ""
}

// TestEveryRegisteredActionHasAMeaning stops the map degenerating into a
// list of strings, which is what it would become the first time someone
// added an entry just to make the guard pass.
func TestEveryRegisteredActionHasAMeaning(t *testing.T) {
	for action, meaning := range Actions {
		if len(strings.TrimSpace(meaning)) < 15 {
			t.Errorf("action %q has no useful meaning (%q) - the entry exists to tell a "+
				"reader what its presence in the trail signifies", action, meaning)
		}
	}
	for _, f := range Families {
		if !strings.HasSuffix(f.Prefix, ".") {
			t.Errorf("family prefix %q does not end in a dot, so it can collide with a "+
				"literal action", f.Prefix)
		}
		if len(f.Suffixes) == 0 {
			t.Errorf("family %q lists no suffixes, so IsKnownAction accepts nothing under it", f.Prefix)
		}
	}
}

// TestLookupActionsAreAClosedPrefix pins the property consumers rely on:
// every lookup form is under the `lookup` prefix, so a filter written as a
// prefix match cannot miss one, and nothing ELSE shares that prefix.
func TestLookupActionsAreAClosedPrefix(t *testing.T) {
	for _, a := range LookupActions {
		if _, ok := Actions[a]; !ok {
			t.Errorf("%q is in LookupActions but not registered", a)
		}
		if a != "lookup" && !strings.HasPrefix(a, "lookup.") {
			t.Errorf("%q is not under the lookup prefix - a consumer filtering on "+
				"`action LIKE 'lookup%%'` would miss it", a)
		}
	}
	for a := range Actions {
		if a != "lookup" && !strings.HasPrefix(a, "lookup.") {
			continue
		}
		if !contains(LookupActions, a) {
			t.Errorf("%q is under the lookup prefix but absent from LookupActions - a "+
				"consumer enumerating the set would miss it", a)
		}
	}
}

// TestPortalMailFamilyListsEveryStatusTheCodePasses closes the gap the family
// mechanism opens. Families are accepted by prefix, so an unlisted suffix
// would sail through IsKnownAction's caller-side check and land in the trail
// as an action nobody registered. The suffixes are decided at the settleMail
// call sites, so that is where the truth is read from.
func TestPortalMailFamilyListsEveryStatusTheCodePasses(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(repoRoot(t), "internal", "service", "portal.go"))
	if err != nil {
		t.Fatal(err)
	}
	call := regexp.MustCompile(`settleMail\([^)]*"([A-Z_]+)"\s*\)`)
	var family *ActionFamily
	for i := range Families {
		if Families[i].Prefix == "portal.mail." {
			family = &Families[i]
		}
	}
	if family == nil {
		t.Fatal("the portal.mail. family is gone from the registry")
	}
	passed := map[string]bool{}
	for _, m := range call.FindAllStringSubmatch(string(src), -1) {
		passed[strings.ToLower(m[1])] = true
	}
	if len(passed) == 0 {
		t.Fatal("no settleMail call sites found - this guard has stopped guarding; " +
			"fix the pattern rather than deleting the test")
	}
	for status := range passed {
		if !contains(family.Suffixes, status) {
			t.Errorf("settleMail passes %q, so the trail carries portal.mail.%s, which is "+
				"not in the family's Suffixes", strings.ToUpper(status), status)
		}
	}
	for _, s := range family.Suffixes {
		if !passed[s] {
			t.Errorf("the family lists suffix %q but no settleMail call site passes it", s)
		}
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
