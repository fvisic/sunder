package api

import (
	"context"
	"testing"

	"github.com/fvisic/sunder/internal/auth"
)

func registerFilip(t *testing.T, e *e2eEnv) string {
	t.Helper()
	rec, out := e.do(t, e.credCRM, "POST", "/v1/contacts", map[string]any{
		"email": "filip@example.com", "phone": "+385911234567", "name": "Filip Visic",
	})
	if rec.Code != 201 {
		t.Fatalf("register: %d %s", rec.Code, rec.Body.String())
	}
	return out["cid"]
}

func TestLookupByEmailPhoneAndName(t *testing.T) {
	e := newE2E(t)
	// Grant CRM the lookup action for this test.
	_, err := e.srv.Store.Pool.Exec(context.Background(),
		`UPDATE clients SET allowed_actions = allowed_actions || '{lookup}' WHERE client_id='crm'`)
	if err != nil {
		t.Fatal(err)
	}
	cid := registerFilip(t, e)

	// Email hit — formatting differences must not matter (normalization).
	rec, out := e.do(t, e.credCRM, "POST", "/v1/lookup", map[string]string{"email": " FILIP@Example.com "})
	if rec.Code != 200 || out["cid"] != cid {
		t.Fatalf("email lookup: %d %s", rec.Code, rec.Body.String())
	}
	// Phone hit with formatting noise.
	rec, out = e.do(t, e.credCRM, "POST", "/v1/lookup", map[string]string{"phone": "+385 91 123-4567"})
	if rec.Code != 200 || out["cid"] != cid {
		t.Fatalf("phone lookup: %d %s", rec.Code, rec.Body.String())
	}
	// Name alone is refused.
	rec, _ = e.do(t, e.credCRM, "POST", "/v1/lookup", map[string]string{"name": "Filip Visic"})
	if rec.Code != 400 {
		t.Fatalf("name-only lookup must be 400, got %d", rec.Code)
	}
	// Name + phone narrows to a hit.
	rec, out = e.do(t, e.credCRM, "POST", "/v1/lookup", map[string]string{
		"name": "filip VISIC", "phone": "+385911234567"})
	if rec.Code != 200 || out["cid"] != cid {
		t.Fatalf("name+phone lookup: %d %s", rec.Code, rec.Body.String())
	}
	// Wrong name with right phone is a miss (narrowing works).
	rec, _ = e.do(t, e.credCRM, "POST", "/v1/lookup", map[string]string{
		"name": "Ivan Horvat", "phone": "+385911234567"})
	if rec.Code != 404 {
		t.Fatalf("wrong-name lookup must miss, got %d", rec.Code)
	}
	// Plain miss.
	rec, _ = e.do(t, e.credCRM, "POST", "/v1/lookup", map[string]string{"email": "nobody@example.com"})
	if rec.Code != 404 {
		t.Fatalf("miss must 404, got %d", rec.Code)
	}
}

func TestLookupScopeIsolation(t *testing.T) {
	e := newE2E(t)
	ctx := context.Background()
	for _, id := range []string{"crm", "dwh"} {
		if _, err := e.srv.Store.Pool.Exec(ctx,
			`UPDATE clients SET allowed_actions = allowed_actions || '{lookup}' WHERE client_id=$1`, id); err != nil {
			t.Fatal(err)
		}
	}
	registerFilip(t, e)
	// The person exists, but DWH's scope has no CID for them: must read as a
	// miss, or one scope could enumerate another scope's customer base.
	rec, _ := e.do(t, e.credDWH, "POST", "/v1/lookup", map[string]string{"email": "filip@example.com"})
	if rec.Code != 404 {
		t.Fatalf("foreign-scope lookup must miss, got %d", rec.Code)
	}
}

func TestLookupRateLimitAndAction(t *testing.T) {
	e := newE2E(t)
	ctx := context.Background()
	// Client with lookup action but a rate limit of 3/min.
	cred, err := auth.Create(ctx, e.srv.Store.Pool, auth.Client{
		ID: "kiosk", Name: "Kiosk", Scope: "crm",
		AllowedActions: []string{auth.ActLookup}, AllowedPurposes: []string{}, RateLimit: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		rec, _ := e.do(t, cred, "POST", "/v1/lookup", map[string]string{"email": "nobody@example.com"})
		if rec.Code != 404 {
			t.Fatalf("expected 404 miss, got %d", rec.Code)
		}
	}
	rec, out := e.do(t, cred, "POST", "/v1/lookup", map[string]string{"email": "nobody@example.com"})
	if rec.Code != 429 || out["error"] != "rate_limited" {
		t.Fatalf("expected 429 rate_limited, got %d %s", rec.Code, rec.Body.String())
	}
	// CRM has no lookup action by default in these tests: forbidden.
	rec, _ = e.do(t, e.credCRM, "POST", "/v1/lookup", map[string]string{"email": "x@example.com"})
	if rec.Code != 403 {
		t.Fatalf("client without lookup action must 403, got %d", rec.Code)
	}
}

func TestLookupAudited(t *testing.T) {
	e := newE2E(t)
	ctx := context.Background()
	if _, err := e.srv.Store.Pool.Exec(ctx,
		`UPDATE clients SET allowed_actions = allowed_actions || '{lookup}' WHERE client_id='crm'`); err != nil {
		t.Fatal(err)
	}
	registerFilip(t, e)
	e.do(t, e.credCRM, "POST", "/v1/lookup", map[string]string{"email": "filip@example.com"})
	e.do(t, e.credCRM, "POST", "/v1/lookup", map[string]string{"email": "nobody@example.com"})

	var hits, misses int
	if err := e.srv.Store.Pool.QueryRow(ctx,
		`SELECT count(*) FILTER (WHERE detail LIKE '%"matched":true%'),
		        count(*) FILTER (WHERE detail LIKE '%"matched":false%')
		 FROM audit WHERE action='lookup'`).Scan(&hits, &misses); err != nil {
		t.Fatal(err)
	}
	if hits != 1 || misses != 1 {
		t.Fatalf("expected 1 hit + 1 miss audited, got %d/%d", hits, misses)
	}
}
