// Package sunder is a thin client for the Sunder pseudonymous identity API.
//
// It implements the canonical client interface every Sunder SDK shares
// (docs/DESIGN.md): transport, auth, timeouts, retries and error mapping
// only. Zero cryptography, zero dependencies beyond the standard library -
// the same "stdlib first" policy the server follows.
//
// Retry policy, baked in rather than configurable:
//   - lookups and IssueOTI retry once on 5xx or network failures (safe:
//     they are idempotent);
//   - VerifyOTI is NEVER blind-retried. The token is single-use, so a retry
//     after an ambiguous network failure would legitimately come back as
//     ErrTokenUsed, and the caller could not tell whether the first attempt
//     succeeded. That reconciliation is the caller's decision to make.
//
// Remember the doctrine the API enforces: LOOKUP != AUTHENTICATION. A
// lookup hit returns a pseudonym; it never proves you are talking to that
// person.
package sunder

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Version tracks the SDK release, not the server's.
const Version = "0.5.0"

// Client talks to one Sunder instance with one client credential.
// Safe for concurrent use.
type Client struct {
	baseURL    string
	credential string
	userID     string
	http       *http.Client
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient supplies your own *http.Client - for a custom transport,
// mTLS client certificates, or a proxy. The default carries a 10 second
// timeout and nothing else.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.http = h }
}

// WithTimeout replaces the default 10 second per-request timeout. Ignored
// when WithHTTPClient supplies a client with its own timeout.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) { c.http = &http.Client{Timeout: d} }
}

// WithUserID attributes every read this client makes to an operator inside
// the calling system, sent as X-Sunder-User-Id and recorded in the audit
// chain. It upgrades an Article 15 answer from "which system accessed this"
// to "which operator that system says accessed it".
//
// It is CLIENT-ASSERTED and unverifiable by design: Sunder records the
// claim and proves it was not altered afterwards, not that it was true.
// Accepts [A-Za-z0-9._@:-], 1-64 characters; anything else is a 400 rather
// than a silent drop.
func WithUserID(id string) Option {
	return func(c *Client) { c.userID = id }
}

// New builds a client. An empty baseURL or credential falls back to
// SUNDER_URL and SUNDER_CREDENTIAL, and it is an error if neither is set -
// a client with no credential would fail on every call with 401 instead of
// telling you what is actually wrong.
//
// The credential is the "<client_id>.<secret>" string `sunder client
// create` printed once. Treat it as a secret: it is a bearer credential.
func New(baseURL, credential string, opts ...Option) (*Client, error) {
	if baseURL == "" {
		baseURL = os.Getenv("SUNDER_URL")
	}
	if credential == "" {
		credential = os.Getenv("SUNDER_CREDENTIAL")
	}
	if baseURL == "" {
		return nil, fmt.Errorf("sunder: base URL required (argument or SUNDER_URL)")
	}
	if credential == "" {
		return nil, fmt.Errorf("sunder: credential required (argument or SUNDER_CREDENTIAL)")
	}
	c := &Client{
		baseURL:    strings.TrimSuffix(baseURL, "/"),
		credential: credential,
		http:       &http.Client{Timeout: 10 * time.Second},
	}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// -- contacts ---------------------------------------------------------------

// RegisterInput is the register-contact request body. At least one email or
// phone is required: a name alone is not an identifier.
//
// Emails and Phones carry additional searchable identifiers for a contact
// that has several. Attributes holds custom fields; names containing '@'
// are rejected by the server, which reserves that separator for
// external-issuer provenance.
type RegisterInput struct {
	Email      string            `json:"email,omitempty"`
	Emails     []string          `json:"emails,omitempty"`
	Phone      string            `json:"phone,omitempty"`
	Phones     []string          `json:"phones,omitempty"`
	Name       string            `json:"name,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// RegisterContact registers a contact, or dedup-merges it onto the person
// who already owns one of those identifiers, and returns the CID for the
// CALLER's scope. Another scope registering the same person gets a
// different CID: that unlinkability is the point.
func (c *Client) RegisterContact(ctx context.Context, in RegisterInput) (string, error) {
	var out struct {
		CID string `json:"cid"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/contacts", in, &out, false); err != nil {
		return "", err
	}
	return requireCID(out.CID)
}

// IssueScopedCID returns the same person's pseudonym in another scope. This
// is a LINKAGE-CAPABLE operation - it deliberately joins two scopes - so it
// needs its own grant and is audited. For a handoff between systems, use an
// OTI instead: the verifier learns its own CID and the issuer learns nothing.
func (c *Client) IssueScopedCID(ctx context.Context, cid, scope string) (string, error) {
	var out struct {
		CID string `json:"cid"`
	}
	path := "/v1/contacts/" + url.PathEscape(cid) + "/scopes"
	if err := c.do(ctx, http.MethodPost, path, map[string]string{"scope": scope}, &out, false); err != nil {
		return "", err
	}
	return requireCID(out.CID)
}

// -- lookup (LOOKUP != AUTHENTICATION) --------------------------------------

// LookupByEmail resolves an email to the caller-scope CID. A miss returns
// ErrNotFound; the server audits both hits and misses and rate-limits the
// endpoint, because a lookup API is an enumeration surface by nature.
func (c *Client) LookupByEmail(ctx context.Context, email string) (string, error) {
	return c.lookup(ctx, map[string]string{"email": email})
}

// LookupByPhone resolves a phone number (any format; the server normalizes
// to E.164) to the caller-scope CID.
func (c *Client) LookupByPhone(ctx context.Context, phone string) (string, error) {
	return c.lookup(ctx, map[string]string{"phone": phone})
}

// LookupByName resolves a name PLUS a second factor. A name alone is never
// an identifier, so email or phone is required - enforced here as well as
// server-side, to fail before the request rather than after it.
func (c *Client) LookupByName(ctx context.Context, name, email, phone string) (string, error) {
	if email == "" && phone == "" {
		return "", &Error{
			Code:   ErrValidation.code,
			Detail: "LookupByName requires email or phone as a second factor",
		}
	}
	body := map[string]string{"name": name}
	if email != "" {
		body["email"] = email
	}
	if phone != "" {
		body["phone"] = phone
	}
	return c.lookup(ctx, body)
}

func (c *Client) lookup(ctx context.Context, body map[string]string) (string, error) {
	var out struct {
		CID string `json:"cid"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/lookup", body, &out, true); err != nil {
		return "", err
	}
	return requireCID(out.CID)
}

// -- attributes -------------------------------------------------------------

// GetAttribute fetches exactly one attribute value. The purpose is
// mandatory, checked against the client's grants AND against the person's
// consent, and the read is audited before the value is released - so an
// audit failure withholds the value rather than disclosing it unlogged.
func (c *Client) GetAttribute(ctx context.Context, cid, name, purpose string) (string, error) {
	var out struct {
		Value string `json:"value"`
	}
	path := "/v1/contacts/" + url.PathEscape(cid) + "/attributes/" + url.PathEscape(name) +
		"?purpose=" + url.QueryEscape(purpose)
	if err := c.do(ctx, http.MethodGet, path, nil, &out, false); err != nil {
		return "", err
	}
	return out.Value, nil
}

// -- one-time identifiers ---------------------------------------------------

// Predicate is an issuer-authorized claim evaluated at verification against
// the ISSUER's data. Op is "age_gte" (Attr read as an ISO date) or "exists".
//
// Value is required for age_gte and must be absent for exists; it is a
// pointer so an omitted threshold is a loud validation failure rather than
// a silently-always-true zero.
type Predicate struct {
	Attr  string `json:"attr"`
	Op    string `json:"op"`
	Value *int   `json:"value,omitempty"`
}

// AgeAtLeast builds the common predicate: prove the person is at least
// years old without disclosing the date.
func AgeAtLeast(attr string, years int) Predicate {
	return Predicate{Attr: attr, Op: "age_gte", Value: &years}
}

// Exists builds a presence predicate: prove an attribute is on file
// without disclosing its value.
func Exists(attr string) Predicate {
	return Predicate{Attr: attr, Op: "exists"}
}

// IssueOptions carries the optional sharing directives for a handoff.
type IssueOptions struct {
	// ShareAttributes lists attributes copied from the issuer's scope into
	// the verifier's scope at verification. This is what makes delayed
	// flows work (an escalation e-mail sent hours later): the verifier
	// stores no PII itself and fetches just-in-time.
	ShareAttributes []string
	// SharePredicates lists claims evaluated against the issuer's data. The
	// verifier receives booleans only; the underlying value never crosses
	// the scope boundary and nothing is copied into the verifier's blob.
	SharePredicates []Predicate
}

// OTI is a freshly issued one-time identifier.
type OTI struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}

// IssueOTI mints a handoff token for one purpose and one audience (the
// scope allowed to verify it). Single-use, five minutes by default. Safe to
// retry: it retries once on 5xx or network failure.
func (c *Client) IssueOTI(ctx context.Context, cid, purpose, audience string, opts *IssueOptions) (OTI, error) {
	body := map[string]any{"cid": cid, "purpose": purpose, "audience": audience}
	if opts != nil {
		if len(opts.ShareAttributes) > 0 {
			body["share_attributes"] = opts.ShareAttributes
		}
		if len(opts.SharePredicates) > 0 {
			body["share_predicates"] = opts.SharePredicates
		}
	}
	var out OTI
	if err := c.do(ctx, http.MethodPost, "/v1/oti", body, &out, true); err != nil {
		return OTI{}, err
	}
	if out.Token == "" {
		return OTI{}, &Error{Code: ErrBadResponse.code, Status: http.StatusCreated,
			Detail: "issue response carried no token"}
	}
	return out, nil
}

// PredicateResult is one evaluated claim: booleans only.
//
// Known is op-specific, on purpose. For age_gte it is false when the
// attribute is absent or unparseable, so "we do not know the birthdate"
// never reads as "under 18". For exists it is always true, because absence
// is the answer that predicate asks for.
type PredicateResult struct {
	Attr   string `json:"attr"`
	Op     string `json:"op"`
	Value  *int   `json:"value,omitempty"`
	Result bool   `json:"result"`
	Known  bool   `json:"known"`
}

// VerifyResult is the verifier's full view of a consumed handoff.
type VerifyResult struct {
	// CID is the VERIFIER's own pseudonym for the person. The issuer's
	// pseudonym never crosses the scope boundary.
	CID string `json:"cid"`
	// Shared lists attribute names copied into the verifier's scope.
	Shared []string `json:"shared,omitempty"`
	// Predicates carries the evaluated claims, when the token had any.
	Predicates []PredicateResult `json:"predicates,omitempty"`
}

// VerifyOTI verifies and consumes a token, returning the verifier's own CID.
//
// NEVER retried: see the package documentation. On an ambiguous network
// failure the caller decides how to reconcile, because a blind retry can
// legitimately return ErrTokenUsed for a handoff that already succeeded.
func (c *Client) VerifyOTI(ctx context.Context, token, purpose, audience string) (string, error) {
	out, err := c.VerifyOTIFull(ctx, token, purpose, audience)
	if err != nil {
		return "", err
	}
	return out.CID, nil
}

// VerifyOTIFull is VerifyOTI with the shared attributes and predicate
// results the token carried.
func (c *Client) VerifyOTIFull(ctx context.Context, token, purpose, audience string) (VerifyResult, error) {
	body := map[string]string{"token": token, "purpose": purpose, "audience": audience}
	var out VerifyResult
	if err := c.do(ctx, http.MethodPost, "/v1/oti/verify", body, &out, false); err != nil {
		return VerifyResult{}, err
	}
	if out.CID == "" {
		return VerifyResult{}, &Error{Code: ErrBadResponse.code, Status: http.StatusOK,
			Detail: "verify response carried no cid"}
	}
	return out, nil
}

// -- ops --------------------------------------------------------------------

// Health is the unauthenticated liveness probe. Network failures surface as
// ErrServiceUnavailable like everywhere else, never as a raw transport error.
func (c *Client) Health(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/healthz", nil)
	if err != nil {
		return "", &Error{Code: ErrValidation.code, Detail: err.Error()}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", &Error{Code: ErrServiceUnavailable.code,
			Detail: "network failure calling GET /healthz: " + err.Error()}
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		code, detail := parseErrorBody(raw)
		return "", mapError(resp.StatusCode, code, detail)
	}
	status := strings.TrimSpace(string(raw))
	if status == "" {
		status = "ok"
	}
	return status, nil
}

// -- transport --------------------------------------------------------------

// do performs one request, decoding a JSON success body into out. When
// retry is set, a 5xx or network failure is attempted exactly once more.
func (c *Client) do(ctx context.Context, method, path string, body, out any, retry bool) error {
	attempts := 1
	if retry {
		attempts = 2
	}
	var lastErr error
	for i := 0; i < attempts; i++ {
		err := c.attempt(ctx, method, path, body, out)
		if err == nil {
			return nil
		}
		lastErr = err
		// A definite verdict from the server is never retried, and neither
		// is a cancelled context - retrying that would ignore the caller.
		if !retryable(err) || ctx.Err() != nil {
			return err
		}
	}
	return lastErr
}

// setHeaders applies the auth, accept and attribution headers every request
// carries, plus any call-specific extras.
func (c *Client) setHeaders(req *http.Request, extra map[string]string) {
	req.Header.Set("Authorization", "Bearer "+c.credential)
	req.Header.Set("Accept", "application/json")
	if c.userID != "" {
		req.Header.Set("X-Sunder-User-Id", c.userID)
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
}

// doWithHeaders is do() for a call that carries extra headers - the bulk
// vault routes and their single-use unlock token. Never retried: the token
// is spent by the first attempt, so a retry would fail as already-used and
// leave the caller unable to tell whether the first call landed.
func (c *Client) doWithHeaders(ctx context.Context, method, path string, body, out any, headers map[string]string) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return &Error{Code: ErrValidation.code, Detail: "request body is not JSON-encodable: " + err.Error()}
	}
	h := map[string]string{"Content-Type": "application/json"}
	for k, v := range headers {
		h[k] = v
	}
	return c.raw(ctx, method, path, encoded, h, out, nil)
}

// raw performs one request with a caller-supplied body and header set. It
// is the path for anything that is not a plain JSON POST - multipart
// uploads and the unlock-gated routes - and is never retried.
func (c *Client) raw(ctx context.Context, method, path string, body []byte, headers map[string]string, out any, _ any) error {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return &Error{Code: ErrValidation.code, Detail: err.Error()}
	}
	c.setHeaders(req, headers)
	resp, err := c.http.Do(req)
	if err != nil {
		return &Error{Code: ErrServiceUnavailable.code,
			Detail: fmt.Sprintf("network failure calling %s %s: %v", method, path, err)}
	}
	defer func() { _ = resp.Body.Close() }()
	rawBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if readErr != nil {
		return &Error{Code: ErrServiceUnavailable.code,
			Detail: "truncated response body: " + readErr.Error()}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		code, detail := parseErrorBody(rawBody)
		return mapError(resp.StatusCode, code, detail)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(rawBody, out); err != nil {
		return &Error{Code: ErrBadResponse.code, Status: resp.StatusCode,
			Detail: "success body was not the expected JSON: " + err.Error()}
	}
	return nil
}

func (c *Client) attempt(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return &Error{Code: ErrValidation.code, Detail: "request body is not JSON-encodable: " + err.Error()}
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return &Error{Code: ErrValidation.code, Detail: err.Error()}
	}
	c.setHeaders(req, nil)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		// Status 0 marks a network-level failure, which retryable() treats
		// as worth one more attempt.
		return &Error{Code: ErrServiceUnavailable.code,
			Detail: fmt.Sprintf("network failure calling %s %s: %v", method, path, err)}
	}
	defer func() { _ = resp.Body.Close() }()
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if readErr != nil {
		return &Error{Code: ErrServiceUnavailable.code,
			Detail: "truncated response body: " + readErr.Error()}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		code, detail := parseErrorBody(raw)
		return mapError(resp.StatusCode, code, detail)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		// A non-JSON success body is an SDK-level error, never a raw
		// json.SyntaxError escaping to the caller.
		return &Error{Code: ErrBadResponse.code, Status: resp.StatusCode,
			Detail: "success body was not the expected JSON: " + err.Error()}
	}
	return nil
}

// parseErrorBody extracts the API's error code and detail, tolerating a
// body that is not JSON at all (a proxy error page, for instance).
func parseErrorBody(raw []byte) (code, detail string) {
	var payload struct {
		Error  string `json:"error"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", ""
	}
	return payload.Error, payload.Detail
}

func requireCID(cid string) (string, error) {
	if cid == "" {
		return "", &Error{Code: ErrBadResponse.code, Detail: "response carried no cid"}
	}
	return cid, nil
}
