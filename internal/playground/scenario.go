// Package playground serves the interactive demo: every guide scenario as a
// clickable walkthrough over a real Sunder instance, with the underlying
// HTTP request and response shown for each step, so the demo teaches the
// API and not just the story (PLAN 17.4).
//
// Two rules shape the design:
//
//  1. The browser never sees a credential. Steps execute server-side and the
//     Authorization header is redacted in what the UI renders - a demo that
//     leaks a working credential into a devtools tab teaches the wrong
//     lesson, and the same instance may be exposed publicly.
//  2. Only steps declared in a loaded scenario can execute. The playground
//     holds real credentials, so a generic "proxy any request" surface would
//     be an open relay with our own actions; the scenario files are the
//     allowlist.
package playground

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Scenario is one clickable walkthrough - the JSON shape under
// internal/playground/scenarios (overridable from disk with -scenarios).
type Scenario struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Summary string `json:"summary"`
	// Panel names the specialized visualization the UI puts above the wire
	// view: "handoff" (two systems side by side), "consent", "webhook",
	// "audit", or "" for the plain step list.
	Panel string `json:"panel"`
	// Doc links the guide page this scenario mirrors, so the playground and
	// the docs site stay one story.
	Doc   string `json:"doc,omitempty"`
	Roles []Role `json:"roles"`
	Steps []Step `json:"steps"`
}

// Role is one API client the scenario speaks as. The playground resolves
// the credential by name (PLAYGROUND_CRED_<NAME>); Scope/Actions/Purposes
// are documentation the UI shows and the seed script consumes - they are
// what `sunder client create` must have been given.
type Role struct {
	Name     string   `json:"name"`
	Label    string   `json:"label"`
	Scope    string   `json:"scope"`
	Actions  []string `json:"actions"`
	Purposes []string `json:"purposes"`
}

// Step is one HTTP call plus the teaching note that goes with it.
type Step struct {
	Label string `json:"label"`
	// Note is the "why" the UI prints next to the wire view. Plain text;
	// the UI never renders it as HTML.
	Note   string `json:"note"`
	Actor  string `json:"actor"`
	Method string `json:"method"`
	Path   string `json:"path"`
	// Body is sent verbatim after {{var}} substitution. Kept as raw JSON so
	// the UI can show exactly what went on the wire, formatting included.
	Body json.RawMessage `json:"body,omitempty"`
	// Expect is the status code this step MUST return. Several steps expect
	// a non-2xx on purpose (a 400 for a name-only lookup, a 409 for an OTI
	// replay): the refusal IS the lesson, so it is asserted like a success.
	Expect int `json:"expect"`
	// Capture pulls values out of the response into session variables:
	// {"crm_cid": "cid"} stores the response's "cid" field as {{crm_cid}}.
	Capture map[string]string `json:"capture,omitempty"`
	// Assert states an invariant between two variables once both exist -
	// this is where "the two systems hold different pseudonyms" stops being
	// a claim in prose and becomes a checked property.
	Assert []Assertion `json:"assert,omitempty"`
}

// Assertion compares two session variables. Kind is "equals" or "differs".
type Assertion struct {
	Kind    string `json:"kind"`
	Left    string `json:"left"`
	Right   string `json:"right"`
	Message string `json:"message"`
}

const (
	AssertEquals  = "equals"
	AssertDiffers = "differs"
)

// varPattern matches the {{name}} placeholders substituted into paths and
// bodies. Names are deliberately narrow: a template is not an expression
// language, and anything richer invites the runner to become one.
var varPattern = regexp.MustCompile(`\{\{([a-z0-9_]+)\}\}`)

var methodAllowed = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true,
}

// Validate rejects a scenario the runner could not execute honestly: an
// unknown actor, a missing expectation, a capture with no source field. A
// broken scenario file must fail at load, in CI, not halfway through a
// walkthrough in front of an audience.
func (s *Scenario) Validate() error {
	if s.ID == "" || s.Title == "" {
		return fmt.Errorf("scenario needs an id and a title")
	}
	if len(s.Steps) == 0 {
		return fmt.Errorf("scenario %q has no steps", s.ID)
	}
	roles := map[string]bool{}
	for _, r := range s.Roles {
		if r.Name == "" {
			return fmt.Errorf("scenario %q: a role needs a name", s.ID)
		}
		if roles[r.Name] {
			return fmt.Errorf("scenario %q: duplicate role %q", s.ID, r.Name)
		}
		roles[r.Name] = true
	}
	// Variables a step may reference: the builtins plus everything an
	// EARLIER step captured. Forward references are the classic authoring
	// bug (a body using {{erp_cid}} before the OTI is verified) and produce
	// a confusing runtime error, so they are a load-time failure.
	known := map[string]bool{}
	for _, v := range builtinVarNames() {
		known[v] = true
	}
	for i := range s.Steps {
		st := &s.Steps[i]
		if st.Label == "" {
			return fmt.Errorf("scenario %q step %d: label required", s.ID, i+1)
		}
		if !roles[st.Actor] {
			return fmt.Errorf("scenario %q step %q: unknown actor %q", s.ID, st.Label, st.Actor)
		}
		if !methodAllowed[st.Method] {
			return fmt.Errorf("scenario %q step %q: method %q not allowed", s.ID, st.Label, st.Method)
		}
		if !strings.HasPrefix(st.Path, "/") {
			return fmt.Errorf("scenario %q step %q: path must start with '/'", s.ID, st.Label)
		}
		if st.Expect < 100 || st.Expect > 599 {
			return fmt.Errorf("scenario %q step %q: expect must be an HTTP status", s.ID, st.Label)
		}
		if len(st.Body) > 0 && !json.Valid(stripVars(st.Body)) {
			// Checked with placeholders replaced by a literal: {{cid}} is
			// not valid JSON on its own, but the shape around it must be.
			return fmt.Errorf("scenario %q step %q: body is not valid JSON", s.ID, st.Label)
		}
		for _, ref := range refs(st.Path, string(st.Body)) {
			if !known[ref] {
				return fmt.Errorf("scenario %q step %q: references {{%s}} before any step captures it", s.ID, st.Label, ref)
			}
		}
		for name, field := range st.Capture {
			if name == "" || field == "" {
				return fmt.Errorf("scenario %q step %q: capture needs both a name and a response field", s.ID, st.Label)
			}
			known[name] = true
		}
		for _, a := range st.Assert {
			if a.Kind != AssertEquals && a.Kind != AssertDiffers {
				return fmt.Errorf("scenario %q step %q: assert kind %q is not equals|differs", s.ID, st.Label, a.Kind)
			}
			if !known[a.Left] || !known[a.Right] {
				return fmt.Errorf("scenario %q step %q: assert compares unknown variables", s.ID, st.Label)
			}
		}
	}
	return nil
}

// refs lists the distinct variables referenced in the given strings, sorted
// so error messages are stable.
func refs(parts ...string) []string {
	seen := map[string]bool{}
	for _, p := range parts {
		for _, m := range varPattern.FindAllStringSubmatch(p, -1) {
			seen[m[1]] = true
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// stripVars replaces every placeholder with a harmless literal so the
// surrounding structure can be validated. Placeholders live INSIDE JSON
// strings by convention ("cid": "{{crm_cid}}"), which is what keeps the
// substituted value escapable; a bare {{x}} as a whole value would fail
// this check, and that is the intended verdict.
func stripVars(body []byte) []byte {
	return varPattern.ReplaceAll(body, []byte(`x`))
}

// RoleNames lists every role the scenario speaks as, sorted.
func (s *Scenario) RoleNames() []string {
	out := make([]string, 0, len(s.Roles))
	for _, r := range s.Roles {
		out = append(out, r.Name)
	}
	sort.Strings(out)
	return out
}
