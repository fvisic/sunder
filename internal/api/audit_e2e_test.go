package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fvisic/sunder/internal/audit"
	"github.com/fvisic/sunder/internal/auth"
)

// auditEnv adds an auditor client: audit.verify only, no PII privileges at
// all - the whole point of the separate action.
func auditEnv(t *testing.T) (*e2eEnv, string) {
	t.Helper()
	e := newE2E(t)
	cred, err := auth.Create(context.Background(), e.srv.Store.Pool, auth.Client{
		ID: "auditor", Name: "Auditor", Scope: "crm",
		AllowedActions: []string{auth.ActAuditVerify}, AllowedPurposes: []string{}, RateLimit: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	return e, cred
}

// doRaw is do() for responses whose fields are not all strings.
func (e *e2eEnv) doRaw(t *testing.T, cred, method, path string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if cred != "" {
		req.Header.Set("Authorization", "Bearer "+cred)
	}
	rec := httptest.NewRecorder()
	e.srv.Handler().ServeHTTP(rec, req)
	out := map[string]any{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func TestAuditVerifyAndChainOverHTTP(t *testing.T) {
	e, credAuditor := auditEnv(t)
	ctx := context.Background()
	// Produce a few audited events, then seal so there is a chain to walk.
	registerFilip(t, e)
	if _, err := audit.SealOnce(ctx, e.srv.Store.Pool, 100, 0); err != nil {
		t.Fatal(err)
	}

	rec, out := e.doRaw(t, credAuditor, "GET", "/v1/admin/audit/verify")
	if rec.Code != http.StatusOK || out["ok"] != true {
		t.Fatalf("verify: %d %s", rec.Code, rec.Body.String())
	}
	if _, reported := out["broken_chain_seq"]; reported {
		t.Fatalf("an intact chain must not report a break: %s", rec.Body.String())
	}

	rec, out = e.doRaw(t, credAuditor, "GET", "/v1/admin/audit/chain?limit=5")
	if rec.Code != http.StatusOK {
		t.Fatalf("chain: %d %s", rec.Code, rec.Body.String())
	}
	rows, _ := out["rows"].([]any)
	if len(rows) == 0 {
		t.Fatalf("expected sealed rows: %s", rec.Body.String())
	}
	first, _ := rows[0].(map[string]any)
	if first["hash"] == "" || first["action"] == "" {
		t.Fatalf("chain rows must carry the hash links and the action: %v", first)
	}
	// The view must not leak the subject or the detail blob: proving the
	// chain is intact is a different privilege from reading what happened.
	for _, forbidden := range []string{"cid", "detail"} {
		if _, present := first[forbidden]; present {
			t.Fatalf("the chain view exposed %q: %v", forbidden, first)
		}
	}

	// A tampered record is reported as a break, with its position.
	if _, err := e.srv.Store.Pool.Exec(ctx, `ALTER TABLE audit DISABLE TRIGGER audit_no_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.srv.Store.Pool.Exec(ctx,
		`UPDATE audit SET action = 'rewritten' WHERE chain_seq = 1`); err != nil {
		t.Fatal(err)
	}
	rec, out = e.doRaw(t, credAuditor, "GET", "/v1/admin/audit/verify")
	if rec.Code != http.StatusOK || out["ok"] != false {
		t.Fatalf("a rewritten record must be reported: %d %s", rec.Code, rec.Body.String())
	}
	if out["broken_chain_seq"] != float64(1) || out["reason"] == "" {
		t.Fatalf("expected the break position and a reason: %s", rec.Body.String())
	}
}

func TestAuditSurfaceIsGatedAndValidated(t *testing.T) {
	e, credAuditor := auditEnv(t)

	// The CRM client has every day-to-day privilege but not audit.verify.
	for _, path := range []string{"/v1/admin/audit/verify", "/v1/admin/audit/chain"} {
		rec, out := e.doRaw(t, e.credCRM, "GET", path)
		if rec.Code != http.StatusForbidden || out["error"] != "forbidden" {
			t.Fatalf("%s without the action: %d %s", path, rec.Code, rec.Body.String())
		}
		rec, _ = e.doRaw(t, "", "GET", path)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s unauthenticated: %d", path, rec.Code)
		}
	}
	for _, bad := range []string{"0", "-1", "abc", "99999"} {
		rec, out := e.doRaw(t, credAuditor, "GET", "/v1/admin/audit/chain?limit="+bad)
		if rec.Code != http.StatusBadRequest || out["error"] != "validation" {
			t.Fatalf("limit=%q: %d %s", bad, rec.Code, rec.Body.String())
		}
	}
	// A huge but well-formed limit is clamped, not refused.
	rec, _ := e.doRaw(t, credAuditor, "GET", "/v1/admin/audit/chain?limit=9999")
	if rec.Code != http.StatusOK {
		t.Fatalf("limit=9999 should clamp: %d %s", rec.Code, rec.Body.String())
	}
}

// TestAuditSurfaceRateLimitAndQueryErrors covers the rate-limit branches and
// the 500 query-error branches of the audit endpoints.
func TestAuditSurfaceRateLimitAndQueryErrors(t *testing.T) {
	ctx := context.Background()
	e := newE2E(t)
	// A tiny-budget auditor to trip the per-client rate limit.
	slow, err := auth.Create(ctx, e.srv.Store.Pool, auth.Client{
		ID: "auditor-slow", Name: "Slow", Scope: "crm",
		AllowedActions: []string{auth.ActAuditVerify}, AllowedPurposes: []string{}, RateLimit: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	got429 := false
	for i := 0; i < 10; i++ {
		rec, _ := e.doRaw(t, slow, "GET", "/v1/admin/audit/verify")
		if rec.Code == 429 {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Fatal("audit verify must be rate limited")
	}

	// Query errors: break the audit table so verify and chain return 500.
	auditor, err := auth.Create(ctx, e.srv.Store.Pool, auth.Client{
		ID: "auditor2", Name: "Auditor2", Scope: "crm",
		AllowedActions: []string{auth.ActAuditVerify}, AllowedPurposes: []string{}, RateLimit: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.srv.Store.Pool.Exec(ctx, `ALTER TABLE audit RENAME TO audit_hidden_x`); err != nil {
		t.Fatal(err)
	}
	defer e.srv.Store.Pool.Exec(ctx, `ALTER TABLE audit_hidden_x RENAME TO audit`)
	if rec, _ := e.doRaw(t, auditor, "GET", "/v1/admin/audit/verify"); rec.Code != 500 {
		t.Fatalf("verify on a broken table must 500, got %d", rec.Code)
	}
	if rec, _ := e.doRaw(t, auditor, "GET", "/v1/admin/audit/chain"); rec.Code != 500 {
		t.Fatalf("chain on a broken table must 500, got %d", rec.Code)
	}
}
