package playground

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The phase definition of done is "the playground covers every scenario"
// (PLAN 17.5). These two tests are how that stops being a claim in a
// document: one maps the shipped demo scripts onto walkthroughs, the other
// keeps every walkthrough pointing at a guide page that exists.

// pendingDemos are demo scripts with no walkthrough yet (PLAN Phase 8).
// Remove an entry when its scenario lands; a script that is neither covered
// nor listed fails the test, so a new demo cannot quietly arrive without a
// walkthrough. Phase 8's exit criterion is this map reaching empty, with
// deliberateOmissions as the only escape hatch.
var pendingDemos = map[string]string{}

// deliberateOmissions are features that will NOT get a browser walkthrough,
// each with the reason and where the reader should look instead. An entry
// here is a decision someone wrote down - which is the whole point: silence
// is what Phase 8 exists to make impossible.
var deliberateOmissions = map[string]string{
	"f9-shamir-recovery.sh": "custodian shares are an operator ceremony at a terminal, not a browser flow: " +
		"the shares are printed once and must never transit a web page. See docs-site/docs/admin/shamir-recovery.md",
}

// featureOmissions records surfaces with NO demo script either, so the
// allow-list is complete rather than only covering what someone happened to
// write a script for. Each entry says why a walkthrough is the wrong shape
// and where the reader should go instead. TestOmissionsPointSomewhereReal
// keeps the pointers honest.
var featureOmissions = map[string]string{
	"privacy portal": "a CITIZEN surface with its own listener, its own session cookie and a magic " +
		"link delivered by mail - the playground drives API credentials, not browser sessions, and " +
		"faking the mail step would demonstrate the wrong thing. Enable SUNDER_PORTAL_ENABLED and " +
		"open the portal itself. See docs-site/docs/gdpr/privacy-portal.md",
	"retention sweep": "an operator cron (`sunder retention run`), not a request: what it destroys is " +
		"visible only by running it and looking before and after, which is a terminal exercise. " +
		"See docs-site/docs/gdpr/rights-and-consent.md",
	"external claims": "an issuer-signed PASETO envelope is bound to ONE pseudonym and consumed once, " +
		"so a repeatable walkthrough would need the playground to hold issuer signing material and " +
		"mint a fresh envelope per visitor. Holding a key that forges attestations is exactly what " +
		"the product tells operators not to do, so this stays a documented flow. " +
		"See docs-site/docs/concepts/external-issuers.md",
	"unattended bootstrap": "`sunder bootstrap` prints the first admin credential once, before any " +
		"credential exists to drive a walkthrough with. See docs-site/docs/install/bootstrap.md",
	"multi-jurisdiction": "two independent instances with separate databases and keystores; the " +
		"playground is one stack, and a second one would demonstrate deployment topology rather " +
		"than product behaviour. See docs-site/docs/install/multi-jurisdiction.md",
	"key rotation": "an operator CLI sweep (`sunder keys rotate` + `rekey`) whose effect is that " +
		"nothing changes for callers - the interesting evidence is in the key ring and the audit " +
		"chain, not in a response. See docs-site/docs/admin/rotation-and-rekey.md",
}

// TestOmissionsPointSomewhereReal keeps the allow-list from rotting into a
// list of excuses: every entry must name a docs page that exists.
func TestOmissionsPointSomewhereReal(t *testing.T) {
	root := filepath.Join("..", "..", "docs-site", "docs")
	if _, err := os.Stat(root); err != nil {
		t.Skipf("docs site not readable from here: %v", err)
	}
	all := map[string]string{}
	for k, v := range deliberateOmissions {
		all[k] = v
	}
	for k, v := range featureOmissions {
		all[k] = v
	}
	for name, reason := range all {
		idx := strings.Index(reason, "docs-site/docs/")
		if idx < 0 {
			t.Errorf("omission %q gives a reason but no docs pointer: say where the reader should look instead", name)
			continue
		}
		page := strings.TrimRight(strings.Fields(reason[idx+len("docs-site/docs/"):])[0], ".,")
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(page))); err != nil {
			t.Errorf("omission %q points at docs page %q, which does not exist", name, page)
		}
	}
}

// demoToScenario maps a demo script to the walkthrough that tells the same
// story through the UI.
var demoToScenario = map[string]string{
	"quickstart.sh":        "lookup-handoff",
	"f4-value-tokens.sh":   "value-tokens",
	"f5-file-vault.sh":     "file-vault",
	"f6-versioning.sh":     "attribute-history",
	"f7-sub-accounts.sh":   "sub-accounts",
	"f8-shared-records.sh": "shared-records",
	"escalation.sh":        "delayed-notification",
}

func TestEveryDemoScriptHasAWalkthroughOrIsListedPending(t *testing.T) {
	dir := filepath.Join("..", "..", "demo")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Skipf("demo directory not readable from here: %v", err)
	}
	have := map[string]bool{}
	for _, sc := range embedded(t) {
		have[sc.ID] = true
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".sh") || name == "lib.sh" {
			continue
		}
		id, mapped := demoToScenario[name]
		if mapped {
			if !have[id] {
				t.Errorf("demo/%s maps to scenario %q, which is not shipped", name, id)
			}
			continue
		}
		if _, omitted := deliberateOmissions[name]; omitted {
			continue
		}
		if _, pending := pendingDemos[name]; !pending {
			t.Errorf("demo/%s has no walkthrough and is not listed in pendingDemos: "+
				"add a scenario or record the gap explicitly", name)
		}
	}
	// The reverse direction: a pending entry for a script that no longer
	// exists is stale bookkeeping.
	for name := range deliberateOmissions {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("deliberateOmissions lists demo/%s, which does not exist", name)
		}
	}
	for name := range pendingDemos {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("pendingDemos lists demo/%s, which does not exist", name)
		}
	}
}

func TestScenarioDocLinksExist(t *testing.T) {
	root := filepath.Join("..", "..", "docs-site", "docs")
	if _, err := os.Stat(root); err != nil {
		t.Skipf("docs site not readable from here: %v", err)
	}
	for _, sc := range embedded(t) {
		if sc.Doc == "" {
			t.Errorf("scenario %q has no doc page: every walkthrough should send the reader somewhere", sc.ID)
			continue
		}
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(sc.Doc))); err != nil {
			t.Errorf("scenario %q points at docs page %q, which does not exist", sc.ID, sc.Doc)
		}
	}
}
