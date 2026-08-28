package audit

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
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

var actionLiteral = regexp.MustCompile(`Action:\s*"([a-z0-9._-]+)"`)

// productionActions scans the non-test source for every literal audit action
// and returns action -> the files that write it.
func productionActions(t *testing.T) map[string][]string {
	t.Helper()
	root := repoRoot(t)
	found := map[string][]string{}
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.Walk(filepath.Join(root, dir), func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			// testutil exists to build fixtures; its actions are not part
			// of the product's vocabulary. actions.go is the registry
			// itself - its prose describes actions, it does not write them.
			if strings.Contains(path, string(filepath.Separator)+"testutil"+string(filepath.Separator)) ||
				strings.HasSuffix(path, string(filepath.Separator)+"audit"+string(filepath.Separator)+"actions.go") {
				return nil
			}
			src, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, path)
			for _, m := range actionLiteral.FindAllStringSubmatch(string(src), -1) {
				found[m[1]] = append(found[m[1]], rel)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return found
}

// TestEveryAuditActionIsRegistered is the closed-enum guard. It reads the
// tree rather than the map, so the map cannot drift away from what the code
// actually writes.
//
// This is the test that makes `action` answerable. Without it, "what values
// can this column hold?" is answered by grepping, and the answer is stale the
// next time someone adds a call site.
func TestEveryAuditActionIsRegistered(t *testing.T) {
	var unregistered []string
	for action, files := range productionActions(t) {
		if isFamilyGenerator(action) {
			// `Action: "portal.mail." + status` - the literal the scanner
			// sees is the prefix, and the family carries the suffixes.
			continue
		}
		if !IsKnownAction(action) {
			unregistered = append(unregistered,
				action+" (written by "+strings.Join(dedupe(files), ", ")+")")
		}
	}
	if len(unregistered) > 0 {
		sort.Strings(unregistered)
		t.Fatalf("audit actions written by the code but absent from audit.Actions:\n  %s\n\n"+
			"Add each to internal/audit/actions.go with a one-line meaning, or - if it is\n"+
			"generated from runtime state - to Families. An unregistered action is one a\n"+
			"SIEM rule, a retention policy and a human reader all have to guess about.",
			strings.Join(unregistered, "\n  "))
	}
}

// TestNoRegisteredActionIsStale is the other half: an entry describing an
// action nothing writes any more is a lie about the system, and lies about
// the audit trail are the expensive kind.
func TestNoRegisteredActionIsStale(t *testing.T) {
	written := productionActions(t)
	// Actions produced through a variable rather than a literal - the
	// scanner cannot see them, so they are named here with the call site
	// that produces them. Anything added to this list needs a reason.
	viaVariable := map[string]string{
		// gdpr.go's terminal() picks between these two at runtime.
		"dsr.erase.failed":      "internal/service/gdpr.go terminal()",
		"dsr.cascade_completed": "internal/service/gdpr.go, cascade worker",
		// All three lookup forms come out of lookupAction(), which picks
		// the variant from the shape of the query and from
		// SUNDER_AUDIT_LOOKUP_ACTIONS. `lookup` is in this list rather
		// than the literal scan because the call site names the constant.
		ActionLookup:       "internal/service/lookup.go lookupAction()",
		ActionLookupFuzzy:  "internal/service/lookup.go lookupAction()",
		ActionLookupSuffix: "internal/service/lookup.go lookupAction()",
	}
	var stale []string
	for action := range Actions {
		if _, ok := written[action]; ok {
			continue
		}
		if where, ok := viaVariable[action]; ok {
			// The escape hatch is itself checked. An unverified exemption
			// list is a hole: delete the last call site and the guard
			// stays green while the registry describes a dead action.
			assertCallSiteMentions(t, action, where)
			continue
		}
		stale = append(stale, action)
	}
	if len(stale) > 0 {
		sort.Strings(stale)
		t.Fatalf("registered audit actions that no production call site writes:\n  %s\n\n"+
			"Either the code stopped writing them (remove the entry) or they are produced\n"+
			"through a variable (add them to viaVariable here, with the call site).",
			strings.Join(stale, "\n  "))
	}
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

// isFamilyGenerator reports whether a literal is exactly a family prefix -
// the shape produced by `Action: "portal.mail." + status`.
func isFamilyGenerator(literal string) bool {
	for _, f := range Families {
		if literal == f.Prefix {
			return true
		}
	}
	return false
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

func dedupe(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

// goIdent turns an action string into the Go constant name a call site is
// likely to use: "lookup.fuzzy" -> "ActionLookupFuzzy".
func goIdent(action string) string {
	out := "Action"
	for _, part := range strings.FieldsFunc(action, func(r rune) bool { return r == '.' || r == '_' || r == '-' }) {
		out += strings.ToUpper(part[:1]) + part[1:]
	}
	return out
}

// assertCallSiteMentions checks that the file named in viaVariable really
// does produce this action - either by naming the string or by naming the
// exported constant for it.
func assertCallSiteMentions(t *testing.T, action, where string) {
	t.Helper()
	file := strings.Fields(where)[0]
	src, err := os.ReadFile(filepath.Join(repoRoot(t), filepath.FromSlash(file)))
	if err != nil {
		t.Errorf("%q is exempted as produced by %s, but that file cannot be read: %v",
			action, where, err)
		return
	}
	body := string(src)
	if strings.Contains(body, `"`+action+`"`) || strings.Contains(body, goIdent(action)) {
		return
	}
	t.Errorf("%q is exempted from the stale check as produced by %s, but that file "+
		"mentions neither the string nor %s. Either the call site moved (update the "+
		"exemption) or it is gone (remove the registry entry).",
		action, where, goIdent(action))
}

// TestIsKnownActionAcceptsFamiliesButNotOpenPrefixes. The family mechanism
// exists so `portal.mail.delivered` need not be spelled out at every call
// site, and its risk is obvious: accept a prefix too loosely and the closed
// set stops being closed. An attacker cannot write audit rows through this
// path, but a future call site can, and the guard's whole value is that a
// new action has to be a deliberate edit here.
func TestIsKnownActionAcceptsFamiliesButNotOpenPrefixes(t *testing.T) {
	for _, ok := range []string{
		"lookup", "lookup.suffix", "dsr.erase",
		"portal.mail.delivered", "portal.mail.failed", "portal.mail.no_mailer",
	} {
		if !IsKnownAction(ok) {
			t.Errorf("%q is part of the vocabulary but IsKnownAction refuses it", ok)
		}
	}
	for _, bad := range []string{
		"",                        // the empty action
		"portal.mail.",            // the bare prefix is a generator, never a value
		"portal.mail.bounced",     // a plausible suffix nobody registered
		"portal.mail.delivered.x", // suffix match must be exact, not prefix-of
		"portal.mailbox",          // shares a prefix by accident of spelling
		"lookup.exhaustive",       // an unregistered member of a real prefix
		"LOOKUP",                  // case matters; the column is lowercase
	} {
		if IsKnownAction(bad) {
			t.Errorf("IsKnownAction accepts %q, so the action set is not closed", bad)
		}
	}
}
