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

// pendingDemos are demo scripts with no walkthrough yet - the remaining
// F1-F11 panels (PLAN P3.7). Remove an entry when its scenario lands; a
// script that is neither covered nor listed fails the test, so a new demo
// cannot quietly arrive without a panel.
var pendingDemos = map[string]string{
	"f4-value-tokens.sh":    "F4 value tokenization panel",
	"f5-file-vault.sh":      "F5 file vault panel",
	"f6-versioning.sh":      "F6 attribute versioning panel",
	"f7-sub-accounts.sh":    "F7 sub-accounts panel",
	"f8-shared-records.sh":  "F8 shared records panel",
	"f9-shamir-recovery.sh": "F9 Shamir recovery walkthrough (CLI-only feature)",
	"escalation.sh":         "delayed-notification walkthrough",
}

// demoToScenario maps a demo script to the walkthrough that tells the same
// story through the UI.
var demoToScenario = map[string]string{
	"quickstart.sh": "lookup-handoff",
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
		if _, pending := pendingDemos[name]; !pending {
			t.Errorf("demo/%s has no walkthrough and is not listed in pendingDemos: "+
				"add a scenario or record the gap explicitly", name)
		}
	}
	// The reverse direction: a pending entry for a script that no longer
	// exists is stale bookkeeping.
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
