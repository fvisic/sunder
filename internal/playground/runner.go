package playground

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Wire is one side of the HTTP exchange, exactly as it went out or came
// back - the panel that makes the demo teach the API instead of a story.
type Wire struct {
	Method  string            `json:"method,omitempty"`
	URL     string            `json:"url,omitempty"`
	Status  int               `json:"status,omitempty"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

// StepResult is what the UI renders for one executed step.
type StepResult struct {
	Scenario   string            `json:"scenario"`
	Step       int               `json:"step"`
	Label      string            `json:"label"`
	Note       string            `json:"note"`
	Actor      string            `json:"actor"`
	OK         bool              `json:"ok"`
	Expect     int               `json:"expect"`
	Status     int               `json:"status"`
	DurationMS int64             `json:"duration_ms"`
	Request    Wire              `json:"request"`
	Response   Wire              `json:"response"`
	Captured   map[string]string `json:"captured,omitempty"`
	Assertions []AssertResult    `json:"assertions,omitempty"`
	// Error carries a transport or authoring failure (the instance is down,
	// a variable is missing). A step that merely returned the "wrong"
	// status is not an error: it is a failed expectation, reported through
	// OK/Status so the UI can show the actual response.
	Error string `json:"error,omitempty"`
}

// AssertResult is one checked invariant, e.g. "the two pseudonyms differ".
type AssertResult struct {
	Kind    string `json:"kind"`
	Left    string `json:"left"`
	Right   string `json:"right"`
	Message string `json:"message"`
	OK      bool   `json:"ok"`
}

// Runner executes scenario steps against a live Sunder instance.
type Runner struct {
	BaseURL string
	// Creds maps a role name to its bearer credential. Never serialized:
	// the JSON the browser receives carries a redacted Authorization
	// header, so a screen-shared demo cannot leak a working credential.
	Creds  map[string]string
	Client *http.Client
}

// ErrNoCredential means the operator did not provide the credential a
// scenario role needs; the UI turns it into setup instructions rather than
// a dead step.
type ErrNoCredential struct{ Role string }

func (e *ErrNoCredential) Error() string {
	return fmt.Sprintf("no credential for role %q (set PLAYGROUND_CRED_%s)", e.Role, strings.ToUpper(e.Role))
}

const maxResponseBytes = 256 << 10 // demo responses are small; a huge body is a bug or an attack

// RunStep executes one step and folds its captures into vars. vars is
// mutated only on success, so a failed step cannot leave half-written
// state behind.
func (r *Runner) RunStep(ctx context.Context, sc *Scenario, idx int, vars map[string]string) *StepResult {
	step := sc.Steps[idx]
	res := &StepResult{
		Scenario: sc.ID, Step: idx, Label: step.Label, Note: step.Note,
		Actor: step.Actor, Expect: step.Expect,
	}
	cred, ok := r.Creds[step.Actor]
	if !ok || cred == "" {
		res.Error = (&ErrNoCredential{Role: step.Actor}).Error()
		return res
	}
	path, err := expandPath(step.Path, vars)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	var body []byte
	if len(step.Body) > 0 {
		expanded, err := expand(string(step.Body), vars, jsonEscape)
		if err != nil {
			res.Error = err.Error()
			return res
		}
		body = []byte(expanded)
	}
	req, err := http.NewRequestWithContext(ctx, step.Method, r.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		res.Error = err.Error()
		return res
	}
	req.Header.Set("Authorization", "Bearer "+cred)
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	res.Request = Wire{
		Method: step.Method, URL: path,
		Headers: redactedHeaders(req.Header, cred),
		Body:    prettyJSON(body),
	}

	started := time.Now()
	client := r.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	res.DurationMS = time.Since(started).Milliseconds()
	if err != nil {
		res.Error = "the Sunder instance did not answer: " + err.Error()
		return res
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		res.Error = "reading the response failed: " + err.Error()
		return res
	}
	res.Status = resp.StatusCode
	res.Response = Wire{
		Status:  resp.StatusCode,
		Headers: map[string]string{"Content-Type": resp.Header.Get("Content-Type")},
		Body:    prettyJSON(raw),
	}
	res.OK = resp.StatusCode == step.Expect

	if res.OK && len(step.Capture) > 0 {
		captured, err := capture(raw, step.Capture)
		if err != nil {
			res.OK = false
			res.Error = err.Error()
			return res
		}
		res.Captured = captured
		for k, v := range captured {
			vars[k] = v
		}
	}
	for _, a := range step.Assert {
		left, lok := vars[a.Left]
		right, rok := vars[a.Right]
		ok := lok && rok && ((a.Kind == AssertEquals && left == right) || (a.Kind == AssertDiffers && left != right))
		res.Assertions = append(res.Assertions, AssertResult{
			Kind: a.Kind, Left: a.Left, Right: a.Right, Message: a.Message, OK: ok,
		})
		if !ok {
			// A broken invariant is a failed step even with the expected
			// status: "both systems got the same pseudonym" must never
			// render green.
			res.OK = false
		}
	}
	return res
}

// expandPath substitutes into a request target, escaping each value for the
// part it lands in. The two halves need different escaping: PathEscape
// leaves '&', '=' and '+' alone, so a value carrying one of those into the
// query string would silently add a parameter or turn into a space. Today's
// captured values are base32 pseudonyms and tokens, but the escaping has to
// be right for the value, not for the values we happen to have.
func expandPath(tmpl string, vars map[string]string) (string, error) {
	path, query, hasQuery := strings.Cut(tmpl, "?")
	out, err := expand(path, vars, url.PathEscape)
	if err != nil {
		return "", err
	}
	if !hasQuery {
		return out, nil
	}
	q, err := expand(query, vars, url.QueryEscape)
	if err != nil {
		return "", err
	}
	return out + "?" + q, nil
}

// expand substitutes {{vars}} using esc to make each value safe for its
// context. A missing variable is an error: sending the literal "{{crm_cid}}"
// would produce a baffling 404 instead of naming the authoring mistake.
func expand(in string, vars map[string]string, esc func(string) string) (string, error) {
	var missing []string
	out := varPattern.ReplaceAllStringFunc(in, func(m string) string {
		name := m[2 : len(m)-2]
		v, ok := vars[name]
		if !ok {
			missing = append(missing, name)
			return m
		}
		return esc(v)
	})
	if len(missing) > 0 {
		return "", fmt.Errorf("run the earlier steps first: %s is not set yet", strings.Join(missing, ", "))
	}
	return out, nil
}

// jsonEscape renders a value for the inside of a JSON string literal.
func jsonEscape(v string) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b[1 : len(b)-1])
}

// capture reads top-level response fields by name. Only top-level, and only
// strings or numbers: a scenario variable ends up in a URL or a request
// body, and a nested-path mini-language here would be a second template
// engine to get wrong.
func capture(raw []byte, want map[string]string) (map[string]string, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("the response is not a JSON object, so %v cannot be captured", keysOf(want))
	}
	out := map[string]string{}
	for name, field := range want {
		v, ok := obj[field]
		if !ok {
			return nil, fmt.Errorf("the response has no %q field to capture as %s", field, name)
		}
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			// Numbers (erasure_id) are captured as their literal form.
			s = strings.Trim(string(v), `"`)
		}
		out[name] = s
	}
	return out, nil
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// redactedHeaders is what the UI is allowed to see. The credential is
// reduced to its client id plus a mask - enough to show WHICH client spoke,
// never enough to replay the call.
func redactedHeaders(h http.Header, cred string) map[string]string {
	out := map[string]string{}
	for k := range h {
		out[k] = h.Get(k)
	}
	id := cred
	if i := strings.IndexByte(cred, '.'); i > 0 {
		id = cred[:i]
	}
	out["Authorization"] = "Bearer " + id + ".********"
	return out
}

// prettyJSON indents a JSON body for display and leaves anything else
// untouched.
func prettyJSON(raw []byte) string {
	if len(bytes.TrimSpace(raw)) == 0 {
		return ""
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		return string(raw)
	}
	return buf.String()
}
