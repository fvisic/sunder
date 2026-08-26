package playground

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// The scenarios and the UI ship inside the binary: the playground must run
// from a single container image with no volume to mount, exactly like the
// service it demonstrates.
//
//go:embed scenarios/*.json
var scenarioFS embed.FS

//go:embed ui
var uiFS embed.FS

// LoadEmbedded returns the scenarios compiled into the binary.
func LoadEmbedded() ([]*Scenario, error) {
	return loadFS(scenarioFS, "scenarios")
}

// LoadDir returns the scenarios in a directory on disk, for authoring a new
// walkthrough without rebuilding the image.
func LoadDir(dir string) ([]*Scenario, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	out := make([]*Scenario, 0, len(names))
	for _, n := range names {
		raw, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			return nil, err
		}
		sc, err := decodeScenario(n, raw)
		if err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return dedupe(out)
}

func loadFS(fsys fs.FS, dir string) ([]*Scenario, error) {
	names, err := fs.Glob(fsys, dir+"/*.json")
	if err != nil {
		return nil, err
	}
	// Glob order is lexical already, but sorting states the intent: the
	// file name prefix (01-, 02-) IS the order the walkthroughs are meant
	// to be read in.
	sort.Strings(names)
	out := make([]*Scenario, 0, len(names))
	for _, n := range names {
		raw, err := fs.ReadFile(fsys, n)
		if err != nil {
			return nil, err
		}
		sc, err := decodeScenario(n, raw)
		if err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return dedupe(out)
}

func decodeScenario(name string, raw []byte) (*Scenario, error) {
	var sc Scenario
	dec := json.NewDecoder(bytes.NewReader(raw))
	// Unknown fields are a typo ("step" for "steps"), and a typo that
	// silently drops half a walkthrough is worse than a load failure.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&sc); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if err := sc.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return &sc, nil
}

func dedupe(in []*Scenario) ([]*Scenario, error) {
	seen := map[string]bool{}
	for _, sc := range in {
		if seen[sc.ID] {
			return nil, fmt.Errorf("duplicate scenario id %q", sc.ID)
		}
		seen[sc.ID] = true
	}
	return in, nil
}
