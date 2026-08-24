package sunder

// Mock-server suite, matching the other five SDKs: every method's path,
// method, body and success shape, the full error taxonomy, and the retry
// policy - especially the rule that VerifyOTI is NEVER blind-retried.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// recorded is one request the mock server saw.
type recorded struct {
	Method string
	Path   string
	Body   map[string]any
	Auth   string
}

// reply is one canned response.
type reply struct {
	status int
	body   string
}

// mock serves the queued replies in order and records every request. The
// last reply repeats if more requests arrive, so a retry test can assert
// the request COUNT rather than guessing how many replies to queue.
type mock struct {
	t       *testing.T
	srv     *httptest.Server
	mu      sync.Mutex
	replies []reply
	reqs    []recorded
}

func newMock(t *testing.T, replies ...reply) (*Client, *mock) {
	t.Helper()
	m := &mock{t: t, replies: replies}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		rec := recorded{Method: r.Method, Path: r.URL.RequestURI(), Auth: r.Header.Get("Authorization")}
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &rec.Body)
		}
		m.mu.Lock()
		m.reqs = append(m.reqs, rec)
		var rep reply
		switch {
		case len(m.replies) == 0:
			rep = reply{500, `{"error":"internal"}`}
		case len(m.reqs) <= len(m.replies):
			rep = m.replies[len(m.reqs)-1]
		default:
			rep = m.replies[len(m.replies)-1]
		}
		m.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(rep.status)
		_, _ = w.Write([]byte(rep.body))
	}))
	t.Cleanup(m.srv.Close)
	c, err := New(m.srv.URL, "client_id.secret")
	if err != nil {
		t.Fatal(err)
	}
	return c, m
}

func (m *mock) requests() []recorded {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]recorded, len(m.reqs))
	copy(out, m.reqs)
	return out
}

func (m *mock) only() recorded {
	m.t.Helper()
	r := m.requests()
	if len(r) != 1 {
		m.t.Fatalf("expected exactly 1 request, got %d", len(r))
	}
	return r[0]
}

// -- construction -----------------------------------------------------------

func TestNewRequiresURLAndCredential(t *testing.T) {
	t.Setenv("SUNDER_URL", "")
	t.Setenv("SUNDER_CREDENTIAL", "")
	if _, err := New("", ""); err == nil {
		t.Fatal("a client with no URL must be refused, not built")
	}
	if _, err := New("https://sunder.internal", ""); err == nil {
		t.Fatal("a client with no credential must be refused")
	}
	// The environment is the documented fallback.
	t.Setenv("SUNDER_URL", "https://sunder.internal/")
	t.Setenv("SUNDER_CREDENTIAL", "crm.secret")
	c, err := New("", "")
	if err != nil {
		t.Fatal(err)
	}
	if c.baseURL != "https://sunder.internal" {
		t.Fatalf("trailing slash must be trimmed, got %q", c.baseURL)
	}
	// Explicit arguments win over the environment.
	c, err = New("https://other.internal", "erp.secret")
	if err != nil {
		t.Fatal(err)
	}
	if c.baseURL != "https://other.internal" || c.credential != "erp.secret" {
		t.Fatal("explicit arguments must take precedence over the environment")
	}
	_ = os.Getenv("SUNDER_URL")
}

func TestOptions(t *testing.T) {
	c, err := New("https://x", "a.b", WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if c.http.Timeout != 3*time.Second {
		t.Fatalf("timeout option ignored: %s", c.http.Timeout)
	}
	custom := &http.Client{Timeout: 42 * time.Second}
	c, err = New("https://x", "a.b", WithHTTPClient(custom))
	if err != nil {
		t.Fatal(err)
	}
	if c.http != custom {
		t.Fatal("a supplied http.Client must be used as-is")
	}
}

// -- contacts ---------------------------------------------------------------

func TestRegisterContact(t *testing.T) {
	c, m := newMock(t, reply{201, `{"cid":"CID-ABC"}`})
	cid, err := c.RegisterContact(context.Background(), RegisterInput{
		Email: "filip@example.com", Phone: "+385911234567", Name: "Filip",
		Attributes: map[string]string{"tier": "gold"},
	})
	if err != nil || cid != "CID-ABC" {
		t.Fatalf("register: %q %v", cid, err)
	}
	req := m.only()
	if req.Method != http.MethodPost || req.Path != "/v1/contacts" {
		t.Fatalf("wrong route: %s %s", req.Method, req.Path)
	}
	if req.Auth != "Bearer client_id.secret" {
		t.Fatalf("credential not sent: %q", req.Auth)
	}
	if req.Body["email"] != "filip@example.com" {
		t.Fatalf("body: %v", req.Body)
	}
	// Empty optional fields must be omitted, not sent as "".
	if _, present := req.Body["emails"]; present {
		t.Fatal("empty plural fields must be omitted from the body")
	}
}

func TestRegisterContactMultipleIdentifiers(t *testing.T) {
	c, m := newMock(t, reply{201, `{"cid":"CID-MULTI"}`})
	if _, err := c.RegisterContact(context.Background(), RegisterInput{
		Emails: []string{"a@example.com", "b@example.com"},
		Phones: []string{"+385911234567"},
	}); err != nil {
		t.Fatal(err)
	}
	body := m.only().Body
	emails, ok := body["emails"].([]any)
	if !ok || len(emails) != 2 {
		t.Fatalf("plural emails not sent: %v", body)
	}
}

func TestIssueScopedCID(t *testing.T) {
	c, m := newMock(t, reply{201, `{"cid":"CID-BILLING"}`})
	cid, err := c.IssueScopedCID(context.Background(), "CID-CRM", "billing")
	if err != nil || cid != "CID-BILLING" {
		t.Fatalf("scoped cid: %q %v", cid, err)
	}
	req := m.only()
	if req.Path != "/v1/contacts/CID-CRM/scopes" {
		t.Fatalf("path: %s", req.Path)
	}
	if req.Body["scope"] != "billing" {
		t.Fatalf("body: %v", req.Body)
	}
}

// -- lookup -----------------------------------------------------------------

func TestLookups(t *testing.T) {
	for _, tc := range []struct {
		name string
		call func(*Client) (string, error)
		key  string
	}{
		{"email", func(c *Client) (string, error) {
			return c.LookupByEmail(context.Background(), "filip@example.com")
		}, "email"},
		{"phone", func(c *Client) (string, error) {
			return c.LookupByPhone(context.Background(), "+385911234567")
		}, "phone"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, m := newMock(t, reply{200, `{"cid":"CID-FOUND"}`})
			cid, err := tc.call(c)
			if err != nil || cid != "CID-FOUND" {
				t.Fatalf("%s: %q %v", tc.name, cid, err)
			}
			req := m.only()
			if req.Path != "/v1/lookup" || req.Method != http.MethodPost {
				t.Fatalf("route: %s %s", req.Method, req.Path)
			}
			if _, ok := req.Body[tc.key]; !ok {
				t.Fatalf("%s not in body: %v", tc.key, req.Body)
			}
		})
	}
}

func TestLookupByNameRequiresSecondFactor(t *testing.T) {
	c, m := newMock(t, reply{200, `{"cid":"CID-X"}`})
	// A name alone must fail CLIENT-side: no request may leave.
	_, err := c.LookupByName(context.Background(), "Filip Visic", "", "")
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("a name alone must be a validation error, got %v", err)
	}
	if n := len(m.requests()); n != 0 {
		t.Fatalf("no request may be sent for an invalid lookup, sent %d", n)
	}
	// With a second factor it goes through.
	if _, err := c.LookupByName(context.Background(), "Filip Visic", "filip@example.com", ""); err != nil {
		t.Fatal(err)
	}
	body := m.only().Body
	if body["name"] != "Filip Visic" || body["email"] != "filip@example.com" {
		t.Fatalf("body: %v", body)
	}
}

func TestLookupMissIsNotFound(t *testing.T) {
	c, _ := newMock(t, reply{404, `{"error":"not_found"}`})
	_, err := c.LookupByEmail(context.Background(), "ghost@example.com")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("a miss must be ErrNotFound, got %v", err)
	}
}

// -- attributes -------------------------------------------------------------

func TestGetAttribute(t *testing.T) {
	c, m := newMock(t, reply{200, `{"value":"gold"}`})
	v, err := c.GetAttribute(context.Background(), "CID-1", "loyalty_tier", "support")
	if err != nil || v != "gold" {
		t.Fatalf("attribute: %q %v", v, err)
	}
	req := m.only()
	if req.Method != http.MethodGet {
		t.Fatalf("method: %s", req.Method)
	}
	if req.Path != "/v1/contacts/CID-1/attributes/loyalty_tier?purpose=support" {
		t.Fatalf("path: %s", req.Path)
	}
	if req.Body != nil {
		t.Fatal("a GET must carry no body")
	}
}

func TestGetAttributeEscapesPathSegments(t *testing.T) {
	// An external-claim attribute carries provenance in its name. '@' is a
	// legal path character (RFC 3986) so it travels as-is, which is what
	// the server routes on.
	c, m := newMock(t, reply{200, `{"value":"true"}`})
	if _, err := c.GetAttribute(context.Background(), "CID-1", "age_gte_18@gov.wallet", "kyc"); err != nil {
		t.Fatal(err)
	}
	if p := m.only().Path; p != "/v1/contacts/CID-1/attributes/age_gte_18@gov.wallet?purpose=kyc" {
		t.Fatalf("provenance name must survive intact: %s", p)
	}

	// Characters that WOULD change the request's shape must be escaped, so
	// a caller-supplied name can never inject a path segment or a query.
	c2, m2 := newMock(t, reply{200, `{"value":"x"}`})
	if _, err := c2.GetAttribute(context.Background(), "CID-1", "a/../../admin", "support"); err != nil {
		t.Fatal(err)
	}
	got := m2.only().Path
	if strings.Contains(got, "a/../../admin") {
		t.Fatalf("a slash in the attribute name must be escaped: %s", got)
	}
	if !strings.Contains(got, "a%2F..%2F..%2Fadmin") {
		t.Fatalf("unexpected escaping: %s", got)
	}

	// The same for the purpose, which rides the query string.
	c3, m3 := newMock(t, reply{200, `{"value":"x"}`})
	if _, err := c3.GetAttribute(context.Background(), "CID-1", "tier", "a&admin=1"); err != nil {
		t.Fatal(err)
	}
	if p := m3.only().Path; strings.Contains(p, "a&admin=1") {
		t.Fatalf("the purpose must be query-escaped: %s", p)
	}

	// And a CID that tries to escape its own segment.
	c4, m4 := newMock(t, reply{201, `{"cid":"CID-X"}`})
	if _, err := c4.IssueScopedCID(context.Background(), "CID-1/../../evil", "billing"); err != nil {
		t.Fatal(err)
	}
	if p := m4.only().Path; strings.Contains(p, "/../") {
		t.Fatalf("a cid must not be able to inject path segments: %s", p)
	}
}

func TestGetAttributeConsentDenied(t *testing.T) {
	c, _ := newMock(t, reply{403, `{"error":"consent_denied"}`})
	_, err := c.GetAttribute(context.Background(), "CID-1", "email", "marketing")
	if !errors.Is(err, ErrConsentDenied) {
		t.Fatalf("withdrawn consent must be distinguishable from a missing grant, got %v", err)
	}
	if errors.Is(err, ErrPurposeNotAllowed) {
		t.Fatal("consent_denied must NOT collapse into purpose_not_allowed")
	}
}

// -- one-time identifiers ---------------------------------------------------

func TestIssueAndVerifyOTI(t *testing.T) {
	c, m := newMock(t,
		reply{201, `{"token":"v4.public.abc","expires_at":"2026-08-24T12:00:00Z"}`},
		reply{200, `{"cid":"CID-ERP"}`},
	)
	oti, err := c.IssueOTI(context.Background(), "CID-CRM", "create_order", "erp", nil)
	if err != nil {
		t.Fatal(err)
	}
	if oti.Token != "v4.public.abc" || oti.ExpiresAt != "2026-08-24T12:00:00Z" {
		t.Fatalf("oti: %+v", oti)
	}
	cid, err := c.VerifyOTI(context.Background(), oti.Token, "create_order", "erp")
	if err != nil || cid != "CID-ERP" {
		t.Fatalf("verify: %q %v", cid, err)
	}
	reqs := m.requests()
	if reqs[0].Path != "/v1/oti" || reqs[1].Path != "/v1/oti/verify" {
		t.Fatalf("routes: %s %s", reqs[0].Path, reqs[1].Path)
	}
	if reqs[1].Body["token"] != "v4.public.abc" {
		t.Fatalf("verify body: %v", reqs[1].Body)
	}
}

func TestIssueOTIWithSharingDirectives(t *testing.T) {
	c, m := newMock(t, reply{201, `{"token":"v4.public.p","expires_at":"x"}`})
	if _, err := c.IssueOTI(context.Background(), "CID-1", "age_check", "webshop", &IssueOptions{
		ShareAttributes: []string{"tier"},
		SharePredicates: []Predicate{AgeAtLeast("birthdate", 18), Exists("iban")},
	}); err != nil {
		t.Fatal(err)
	}
	body := m.only().Body
	attrs, _ := body["share_attributes"].([]any)
	if len(attrs) != 1 || attrs[0] != "tier" {
		t.Fatalf("share_attributes: %v", body)
	}
	preds, _ := body["share_predicates"].([]any)
	if len(preds) != 2 {
		t.Fatalf("share_predicates: %v", body)
	}
	first, _ := preds[0].(map[string]any)
	if first["op"] != "age_gte" || first["value"] != float64(18) {
		t.Fatalf("age_gte predicate: %v", first)
	}
	// exists must carry NO value: an omitted threshold is a loud failure
	// server-side, and a zero would be silently always-true.
	second, _ := preds[1].(map[string]any)
	if _, present := second["value"]; present {
		t.Fatalf("exists must not carry a value: %v", second)
	}
}

func TestVerifyOTIFullSurfacesPredicates(t *testing.T) {
	c, _ := newMock(t, reply{200, `{"cid":"CID-WEB","shared":["tier"],
		"predicates":[{"attr":"birthdate","op":"age_gte","value":18,"result":true,"known":true},
		              {"attr":"iban","op":"exists","result":false,"known":true}]}`})
	out, err := c.VerifyOTIFull(context.Background(), "v4.public.p", "age_check", "webshop")
	if err != nil {
		t.Fatal(err)
	}
	if out.CID != "CID-WEB" || len(out.Shared) != 1 || out.Shared[0] != "tier" {
		t.Fatalf("result: %+v", out)
	}
	if len(out.Predicates) != 2 {
		t.Fatalf("predicates: %+v", out.Predicates)
	}
	if !out.Predicates[0].Result || !out.Predicates[0].Known {
		t.Fatalf("age_gte: %+v", out.Predicates[0])
	}
	if out.Predicates[0].Value == nil || *out.Predicates[0].Value != 18 {
		t.Fatalf("threshold not decoded: %+v", out.Predicates[0])
	}
	// exists reports known=true even for an absent attribute: absence IS
	// the answer that predicate asks for.
	if out.Predicates[1].Result || !out.Predicates[1].Known {
		t.Fatalf("exists: %+v", out.Predicates[1])
	}
}

func TestPredicateUnknownIsNotAFailedCheck(t *testing.T) {
	c, _ := newMock(t, reply{200, `{"cid":"CID-WEB",
		"predicates":[{"attr":"birthdate","op":"age_gte","value":18,"result":false,"known":false}]}`})
	out, err := c.VerifyOTIFull(context.Background(), "t", "age_check", "webshop")
	if err != nil {
		t.Fatal(err)
	}
	p := out.Predicates[0]
	if p.Result || p.Known {
		t.Fatalf("an absent birthdate must be result=false known=false: %+v", p)
	}
}

// -- retry policy -----------------------------------------------------------

func TestLookupRetriesOnceOn5xx(t *testing.T) {
	c, m := newMock(t,
		reply{503, `{"error":"internal"}`},
		reply{200, `{"cid":"CID-OK"}`},
	)
	cid, err := c.LookupByEmail(context.Background(), "filip@example.com")
	if err != nil || cid != "CID-OK" {
		t.Fatalf("lookup must succeed on the retry: %q %v", cid, err)
	}
	if n := len(m.requests()); n != 2 {
		t.Fatalf("expected exactly 2 attempts, got %d", n)
	}
}

func TestIssueOTIRetriesOnceOn5xx(t *testing.T) {
	c, m := newMock(t,
		reply{500, `{"error":"internal"}`},
		reply{201, `{"token":"v4.public.x","expires_at":"x"}`},
	)
	if _, err := c.IssueOTI(context.Background(), "CID-1", "p", "a", nil); err != nil {
		t.Fatal(err)
	}
	if n := len(m.requests()); n != 2 {
		t.Fatalf("expected 2 attempts, got %d", n)
	}
}

func TestRetryStopsAtTwoAttempts(t *testing.T) {
	c, m := newMock(t, reply{503, `{"error":"internal"}`})
	_, err := c.LookupByEmail(context.Background(), "x@example.com")
	if !errors.Is(err, ErrServiceUnavailable) {
		t.Fatalf("persistent 5xx must surface as ErrServiceUnavailable, got %v", err)
	}
	if n := len(m.requests()); n != 2 {
		t.Fatalf("retry must be a SINGLE extra attempt, made %d", n)
	}
}

func TestVerifyOTINeverRetries(t *testing.T) {
	c, m := newMock(t, reply{503, `{"error":"internal"}`})
	_, err := c.VerifyOTI(context.Background(), "v4.public.x", "p", "a")
	if err == nil {
		t.Fatal("a 503 must surface")
	}
	// The whole point: a single-use token must not be replayed by the SDK.
	if n := len(m.requests()); n != 1 {
		t.Fatalf("verify is single-use and must NEVER be retried, made %d attempts", n)
	}
}

func TestNoRetryOnDefiniteVerdict(t *testing.T) {
	c, m := newMock(t, reply{404, `{"error":"not_found"}`})
	if _, err := c.LookupByEmail(context.Background(), "ghost@example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v", err)
	}
	if n := len(m.requests()); n != 1 {
		t.Fatalf("a 4xx verdict must not be retried, made %d attempts", n)
	}
}

// -- error taxonomy ---------------------------------------------------------

func TestErrorTaxonomy(t *testing.T) {
	cases := []struct {
		status  int
		code    string
		want    error
		retried bool
	}{
		{401, "unauthorized", ErrUnauthorized, false},
		{401, "credential_expired", ErrCredentialExpired, false},
		{403, "forbidden", ErrForbidden, false},
		{403, "consent_denied", ErrConsentDenied, false},
		{403, "purpose_not_allowed", ErrPurposeNotAllowed, false},
		{403, "audience_mismatch", ErrAudienceMismatch, false},
		{404, "not_found", ErrNotFound, false},
		{400, "validation", ErrValidation, false},
		{400, "bad_json", ErrValidation, false},
		{400, "token_invalid", ErrTokenInvalid, false},
		{409, "token_used", ErrTokenUsed, false},
		{410, "token_expired", ErrTokenExpired, false},
		{429, "rate_limited", ErrRateLimited, false},
		{503, "service_unavailable", ErrServiceUnavailable, true},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			c, _ := newMock(t, reply{tc.status, `{"error":"` + tc.code + `"}`})
			_, err := c.VerifyOTI(context.Background(), "t", "p", "a")
			if !errors.Is(err, tc.want) {
				t.Fatalf("%d %s -> %v, want %v", tc.status, tc.code, err, tc.want)
			}
			var e *Error
			if !errors.As(err, &e) {
				t.Fatalf("every failure must be a *Error, got %T", err)
			}
			if e.Status != tc.status {
				t.Fatalf("status not preserved: %d", e.Status)
			}
		})
	}
}

func TestErrorCarriesDetailOnValidation(t *testing.T) {
	c, _ := newMock(t, reply{400, `{"error":"validation","detail":"at least one email or phone required"}`})
	_, err := c.RegisterContact(context.Background(), RegisterInput{})
	var e *Error
	if !errors.As(err, &e) || e.Detail == "" {
		t.Fatalf("validation detail must survive: %v", err)
	}
	if !strings.Contains(err.Error(), "email or phone") {
		t.Fatalf("Error() must include the detail: %s", err)
	}
}

func TestUnknownStatusFallsBackByStatus(t *testing.T) {
	// A proxy error page: no JSON, no code - the status must still classify.
	c, _ := newMock(t, reply{502, `<html>Bad Gateway</html>`})
	_, err := c.VerifyOTI(context.Background(), "t", "p", "a")
	if !errors.Is(err, ErrServiceUnavailable) {
		t.Fatalf("a non-JSON 502 must map by status, got %v", err)
	}
}

func TestNonJSONSuccessBodyIsBadResponse(t *testing.T) {
	c, _ := newMock(t, reply{200, `not json at all`})
	_, err := c.LookupByEmail(context.Background(), "x@example.com")
	if !errors.Is(err, ErrBadResponse) {
		t.Fatalf("a non-JSON 2xx must be ErrBadResponse, never a raw decode error: %v", err)
	}
}

func TestMissingFieldInSuccessBodyIsBadResponse(t *testing.T) {
	c, _ := newMock(t, reply{200, `{"unexpected":"shape"}`})
	if _, err := c.LookupByEmail(context.Background(), "x@example.com"); !errors.Is(err, ErrBadResponse) {
		t.Fatalf("a 2xx without a cid must be ErrBadResponse, got %v", err)
	}
	c2, _ := newMock(t, reply{201, `{"expires_at":"x"}`})
	if _, err := c2.IssueOTI(context.Background(), "CID-1", "p", "a", nil); !errors.Is(err, ErrBadResponse) {
		t.Fatalf("an issue response without a token must be ErrBadResponse, got %v", err)
	}
}

// -- network failures -------------------------------------------------------

func TestNetworkFailureIsServiceUnavailable(t *testing.T) {
	// A listener that is closed immediately: connecting always fails.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()
	c, err := New(url, "a.b", WithTimeout(500*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.LookupByEmail(context.Background(), "x@example.com")
	if !errors.Is(err, ErrServiceUnavailable) {
		t.Fatalf("a network failure must surface as ErrServiceUnavailable, got %v", err)
	}
	var e *Error
	if !errors.As(err, &e) || e.Status != 0 {
		t.Fatalf("a network failure carries status 0, got %+v", e)
	}
	if _, err := c.Health(context.Background()); !errors.Is(err, ErrServiceUnavailable) {
		t.Fatalf("Health must map network failures too, got %v", err)
	}
}

func TestContextCancellationIsNotRetried(t *testing.T) {
	var hits int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		time.Sleep(300 * time.Millisecond)
		w.WriteHeader(200)
	}))
	defer srv.Close()
	c, err := New(srv.URL, "a.b")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.LookupByEmail(ctx, "x@example.com"); err == nil {
		t.Fatal("a cancelled context must surface an error")
	}
	mu.Lock()
	defer mu.Unlock()
	if hits != 1 {
		t.Fatalf("a cancelled context must not be retried, made %d attempts", hits)
	}
}

// -- ops --------------------------------------------------------------------

func TestHealth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			t.Errorf("path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "" {
			t.Error("the liveness probe must not require a credential")
		}
		_, _ = w.Write([]byte("ok\n"))
	}))
	defer srv.Close()
	c, err := New(srv.URL, "a.b")
	if err != nil {
		t.Fatal(err)
	}
	status, err := c.Health(context.Background())
	if err != nil || status != "ok" {
		t.Fatalf("health: %q %v", status, err)
	}
}

func TestHealthEmptyBodyDefaultsToOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	c, _ := New(srv.URL, "a.b")
	if status, err := c.Health(context.Background()); err != nil || status != "ok" {
		t.Fatalf("an empty 200 body means ok: %q %v", status, err)
	}
}

// -- concurrency ------------------------------------------------------------

func TestClientIsSafeForConcurrentUse(t *testing.T) {
	c, m := newMock(t, reply{200, `{"cid":"CID-OK"}`})
	var wg sync.WaitGroup
	errs := make([]error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = c.LookupByEmail(context.Background(), "x@example.com")
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}
	if n := len(m.requests()); n != 32 {
		t.Fatalf("expected 32 requests, got %d", n)
	}
}
