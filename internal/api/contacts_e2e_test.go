package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/config"
	"github.com/fvisic/sunder/internal/testutil"
)

// e2eEnv boots a full server against real PostgreSQL with a temp keystore.
type e2eEnv struct {
	srv     *Server
	credCRM string // scope crm: register, scopes.issue, attributes.read, purpose newsletter
	credDWH string // scope dwh: attributes.read only, no purposes
}

func newE2E(t *testing.T) *e2eEnv {
	t.Helper()
	ctx := context.Background()
	st := testutil.NewDB(t)
	credCRM, err := auth.Create(ctx, st.Pool, auth.Client{
		ID: "crm", Name: "CRM", Scope: "crm",
		AllowedActions:  []string{auth.ActContactsRegister, auth.ActScopesIssue, auth.ActAttributesRead},
		AllowedPurposes: []string{"newsletter"}, RateLimit: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	credDWH, err := auth.Create(ctx, st.Pool, auth.Client{
		ID: "dwh", Name: "DWH", Scope: "dwh",
		AllowedActions: []string{auth.ActAttributesRead}, AllowedPurposes: []string{"analytics"}, RateLimit: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Keystore: "file", KeystorePath: t.TempDir()}
	return &e2eEnv{srv: New(cfg, st), credCRM: credCRM, credDWH: credDWH}
}

func (e *e2eEnv) do(t *testing.T, cred, method, path string, body any) (*httptest.ResponseRecorder, map[string]string) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	if cred != "" {
		req.Header.Set("Authorization", "Bearer "+cred)
	}
	rec := httptest.NewRecorder()
	e.srv.Handler().ServeHTTP(rec, req)
	out := map[string]string{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func TestE2ERegisterAndAttributeFlow(t *testing.T) {
	e := newE2E(t)

	// Unauthenticated request is rejected.
	rec, _ := e.do(t, "", "POST", "/v1/contacts", map[string]string{"email": "f@example.com"})
	if rec.Code != 401 {
		t.Fatalf("unauthenticated: got %d", rec.Code)
	}

	// Register a contact from the CRM.
	rec, out := e.do(t, e.credCRM, "POST", "/v1/contacts", map[string]any{
		"email": "Filip@Example.com", "phone": "+385 91 123 4567", "name": "Filip Visic",
		"attributes": map[string]string{"loyalty_tier": "gold"},
	})
	if rec.Code != 201 || out["cid"] == "" {
		t.Fatalf("register: got %d %s", rec.Code, rec.Body.String())
	}
	cid := out["cid"]

	// Re-registering the same email yields the same scoped CID (dedup).
	rec, out2 := e.do(t, e.credCRM, "POST", "/v1/contacts", map[string]any{"email": "filip@example.com"})
	if rec.Code != 201 || out2["cid"] != cid {
		t.Fatalf("dedup: got %d cid=%s want %s", rec.Code, out2["cid"], cid)
	}

	// Attribute fetch with an allowed purpose returns the normalized email.
	rec, out = e.do(t, e.credCRM, "GET", fmt.Sprintf("/v1/contacts/%s/attributes/email?purpose=newsletter", cid), nil)
	if rec.Code != 200 || out["value"] != "filip@example.com" {
		t.Fatalf("attribute: got %d %s", rec.Code, rec.Body.String())
	}

	// Custom attribute round-trips too.
	rec, out = e.do(t, e.credCRM, "GET", fmt.Sprintf("/v1/contacts/%s/attributes/loyalty_tier?purpose=newsletter", cid), nil)
	if rec.Code != 200 || out["value"] != "gold" {
		t.Fatalf("custom attribute: got %d %s", rec.Code, rec.Body.String())
	}

	// Disallowed purpose is refused.
	rec, out = e.do(t, e.credCRM, "GET", fmt.Sprintf("/v1/contacts/%s/attributes/email?purpose=marketing-spam", cid), nil)
	if rec.Code != 403 || out["error"] != "purpose_not_allowed" {
		t.Fatalf("purpose check: got %d %s", rec.Code, rec.Body.String())
	}

	// Missing purpose is a validation error.
	rec, _ = e.do(t, e.credCRM, "GET", fmt.Sprintf("/v1/contacts/%s/attributes/email", cid), nil)
	if rec.Code != 400 {
		t.Fatalf("missing purpose: got %d", rec.Code)
	}

	// A foreign scope's CID is indistinguishable from absence (DWH uses its
	// own allowed purpose, so the scope check is what fires).
	rec, _ = e.do(t, e.credDWH, "GET", fmt.Sprintf("/v1/contacts/%s/attributes/email?purpose=analytics", cid), nil)
	if rec.Code != 404 {
		t.Fatalf("foreign scope must 404: got %d", rec.Code)
	}

	// Issue a billing-scope CID for the same person: different pseudonym.
	rec, out = e.do(t, e.credCRM, "POST", "/v1/contacts/"+cid+"/scopes", map[string]string{"scope": "billing"})
	if rec.Code != 200 || out["cid"] == "" || out["cid"] == cid {
		t.Fatalf("scoped cid: got %d %s", rec.Code, rec.Body.String())
	}

	// DWH lacks contacts.register: forbidden.
	rec, _ = e.do(t, e.credDWH, "POST", "/v1/contacts", map[string]string{"email": "x@example.com"})
	if rec.Code != 403 {
		t.Fatalf("action check: got %d", rec.Code)
	}

	// Bad credential shapes are rejected.
	for _, bad := range []string{"crm.wrongsecret", "nosuch.abc", "garbage"} {
		rec, _ = e.do(t, bad, "POST", "/v1/contacts", map[string]string{"email": "x@example.com"})
		if rec.Code != 401 {
			t.Fatalf("cred %q: got %d", bad, rec.Code)
		}
	}
}

func TestReadyzWithDatabase(t *testing.T) {
	e := newE2E(t)
	rec, _ := e.do(t, "", "GET", "/readyz", nil)
	if rec.Code != 200 {
		t.Fatalf("readyz with live db: got %d", rec.Code)
	}
	// After closing the pool, readiness must fail.
	e.srv.Store.Close()
	rec, _ = e.do(t, "", "GET", "/readyz", nil)
	if rec.Code != 503 {
		t.Fatalf("readyz with closed pool: got %d", rec.Code)
	}
}

func TestE2EAuditTrailWritten(t *testing.T) {
	e := newE2E(t)
	_, out := e.do(t, e.credCRM, "POST", "/v1/contacts", map[string]string{"email": "a@example.com"})
	e.do(t, e.credCRM, "GET", "/v1/contacts/"+out["cid"]+"/attributes/email?purpose=newsletter", nil)

	var n int
	err := e.srv.Store.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit WHERE action IN ('contacts.register','attributes.read')`).Scan(&n)
	if err != nil {
		t.Fatal(err)
	}
	if n < 2 {
		t.Fatalf("expected register+read audit records, got %d", n)
	}
}
