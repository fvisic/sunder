package api

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fvisic/sunder/internal/audit"
	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/config"
	"github.com/fvisic/sunder/internal/service"
	"github.com/fvisic/sunder/internal/testutil"
)

// setReadsAPI pins the read-audit mode for one test in this package.
func setReadsAPI(t *testing.T, m string) {
	t.Helper()
	old := audit.ReadsMode()
	audit.SetReadsMode(m)
	t.Cleanup(func() { audit.SetReadsMode(old) })
}

// TestUserIDAttributionEndToEnd covers the P4.2 decision as decided: the
// operator id travels as the "user_id" body field on lookup and as the
// X-Sunder-User-Id header on GET routes, lands as a real queryable column
// or bucket key, and comes back out in the Article 15 trail.
func TestUserIDAttributionEndToEnd(t *testing.T) {
	setReadsAPI(t, audit.ReadsBucketed)
	ctx := context.Background()
	st := testutil.NewDB(t)
	cred, err := auth.Create(ctx, st.Pool, auth.Client{
		ID: "crm", Name: "CRM", Scope: "crm",
		AllowedActions:  []string{auth.ActContactsRegister, auth.ActLookup, auth.ActAttributesRead},
		AllowedPurposes: []string{"support"}, RateLimit: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(config.Config{Keystore: "file", KeystorePath: t.TempDir()}, st)
	if err != nil {
		t.Fatal(err)
	}
	e := &e2eEnv{srv: srv, credCRM: cred}

	rec, out := e.do(t, cred, "POST", "/v1/contacts", map[string]any{
		"email": "ana@example.com", "attributes": map[string]string{"tier": "gold"}})
	if rec.Code != 201 && rec.Code != 200 {
		t.Fatalf("register: %d %s", rec.Code, rec.Body.String())
	}
	cid := out["cid"]

	// user_id in the lookup BODY (the decided shape for POST routes).
	rec, _ = e.do(t, cred, "POST", "/v1/lookup",
		map[string]string{"email": "ana@example.com", "user_id": "agent-7"})
	if rec.Code != 200 {
		t.Fatalf("lookup with user_id: %d %s", rec.Code, rec.Body.String())
	}
	// Malformed user_id is a 400, never a silent drop.
	rec, _ = e.do(t, cred, "POST", "/v1/lookup",
		map[string]string{"email": "ana@example.com", "user_id": "agent 7 with spaces"})
	if rec.Code != 400 {
		t.Fatalf("malformed body user_id must 400, got %d", rec.Code)
	}

	// The header path on a GET route (attribute read has no body).
	req := httptest.NewRequest("GET", "/v1/contacts/"+cid+"/attributes/tier?purpose=support", nil)
	req.Header.Set("Authorization", "Bearer "+cred)
	req.Header.Set("X-Sunder-User-Id", "agent-9")
	hrec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(hrec, req)
	if hrec.Code != 200 {
		t.Fatalf("attribute read with header: %d %s", hrec.Code, hrec.Body.String())
	}
	// Malformed header is a 400 too.
	req = httptest.NewRequest("GET", "/v1/contacts/"+cid+"/attributes/tier?purpose=support", nil)
	req.Header.Set("Authorization", "Bearer "+cred)
	req.Header.Set("X-Sunder-User-Id", strings.Repeat("x", 65))
	hrec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(hrec, req)
	if hrec.Code != 400 {
		t.Fatalf("malformed header must 400, got %d", hrec.Code)
	}

	// Both operators are distinct bucket keys.
	var agents int64
	if err := st.Pool.QueryRow(ctx, `
		SELECT count(DISTINCT user_id) FROM audit_read_buckets WHERE user_id <> ''`).Scan(&agents); err != nil {
		t.Fatal(err)
	}
	if agents != 2 {
		t.Fatalf("want buckets for 2 distinct operators, got %d", agents)
	}

	// The Article 15 trail carries the read buckets with user_id and count:
	// without this, the default mode would silently drop every read from
	// "who accessed my data".
	officer := &auth.Client{ID: "dpo", Scope: "crm",
		AllowedActions: []string{auth.ActDSRAccess}}
	out2, err := srv.GDPR.Access(ctx, officer, cid)
	if err != nil {
		t.Fatal(err)
	}
	trail, _ := out2["audit_trail"].([]service.AuditTrailEntry)
	var sawAgent7 bool
	for _, e := range trail {
		if e.UserID == "agent-7" && e.Count >= 1 {
			sawAgent7 = true
		}
	}
	if !sawAgent7 {
		t.Fatalf("Article 15 trail must include the bucketed lookup by agent-7, got %+v", trail)
	}
}

// TestPhoneSuffixLookupOverHTTP: the F2 path end to end through the API,
// with the config flags threaded from Config into the service.
func TestPhoneSuffixLookupOverHTTP(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewDB(t)
	cred, err := auth.Create(ctx, st.Pool, auth.Client{
		ID: "crm", Name: "CRM", Scope: "crm",
		AllowedActions:  []string{auth.ActContactsRegister, auth.ActLookup},
		AllowedPurposes: []string{"support"}, RateLimit: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(config.Config{Keystore: "file", KeystorePath: t.TempDir(),
		SearchFuzzyName: true, SearchPhoneSuffix: true}, st)
	if err != nil {
		t.Fatal(err)
	}
	e := &e2eEnv{srv: srv, credCRM: cred}

	rec, out := e.do(t, cred, "POST", "/v1/contacts", map[string]any{
		"phone": "+385 91 123 4567", "name": "Ana Anić"})
	if rec.Code != 201 && rec.Code != 200 {
		t.Fatalf("register: %d %s", rec.Code, rec.Body.String())
	}
	cid := out["cid"]

	// Caller-ID shape: national number in the body, fuzzy name beside it.
	rec, out = e.do(t, cred, "POST", "/v1/lookup",
		map[string]string{"phone_suffix": "0911234567", "name": "anic"})
	if rec.Code != 200 || out["cid"] != cid {
		t.Fatalf("suffix lookup over HTTP: %d %s", rec.Code, rec.Body.String())
	}
	// Validation surfaces as 400, not 404.
	rec, _ = e.do(t, cred, "POST", "/v1/lookup", map[string]string{"phone_suffix": "123"})
	if rec.Code != 400 {
		t.Fatalf("short suffix must 400, got %d", rec.Code)
	}
}

// TestSearchUnlockStrictPosture: with SUNDER_SEARCH_UNLOCK=true a fuzzy or
// partial lookup requires a fresh unlock token; exact lookups never do.
func TestSearchUnlockStrictPosture(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewDB(t)
	cred, err := auth.Create(ctx, st.Pool, auth.Client{
		ID: "crm", Name: "CRM", Scope: "crm",
		AllowedActions:  []string{auth.ActContactsRegister, auth.ActLookup, auth.ActAdminUnlock},
		AllowedPurposes: []string{"support"}, RateLimit: 100})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(config.Config{Keystore: "file", KeystorePath: t.TempDir(),
		SearchFuzzyName: true, SearchPhoneSuffix: true, SearchUnlock: true}, st)
	if err != nil {
		t.Fatal(err)
	}
	e := &e2eEnv{srv: srv, credCRM: cred}

	rec, _ := e.do(t, cred, "POST", "/v1/contacts", map[string]any{
		"phone": "+385911234567", "name": "Ana Anić", "email": "ana@example.com"})
	if rec.Code != 201 && rec.Code != 200 {
		t.Fatalf("register: %d", rec.Code)
	}

	// Exact lookup: NO unlock needed even in strict posture.
	rec, _ = e.do(t, cred, "POST", "/v1/lookup", map[string]string{"email": "ana@example.com"})
	if rec.Code != 200 {
		t.Fatalf("exact lookup must not need unlock: %d %s", rec.Code, rec.Body.String())
	}
	// Suffix lookup without a token: 403 with the pointer.
	rec, out := e.do(t, cred, "POST", "/v1/lookup", map[string]string{"phone_suffix": "0911234567"})
	if rec.Code != 403 || out["error"] != "unlock_required" {
		t.Fatalf("suffix without unlock must 403 unlock_required: %d %s", rec.Code, rec.Body.String())
	}
	// Mint a token, spend it on the lookup: 200.
	rec, out = e.do(t, cred, "POST", "/v1/admin/unlock", map[string]string{"purpose": "search"})
	if rec.Code != 201 || out["unlock_token"] == "" {
		t.Fatalf("unlock mint: %d %s", rec.Code, rec.Body.String())
	}
	token := out["unlock_token"]
	req := httptest.NewRequest("POST", "/v1/lookup", strings.NewReader(`{"phone_suffix":"0911234567"}`))
	req.Header.Set("Authorization", "Bearer "+cred)
	req.Header.Set("X-Sunder-Unlock", token)
	req.Header.Set("Content-Type", "application/json")
	hrec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(hrec, req)
	if hrec.Code != 200 {
		t.Fatalf("suffix with unlock must 200: %d %s", hrec.Code, hrec.Body.String())
	}
	// The token is spent: replaying it fails.
	req = httptest.NewRequest("POST", "/v1/lookup", strings.NewReader(`{"phone_suffix":"0911234567"}`))
	req.Header.Set("Authorization", "Bearer "+cred)
	req.Header.Set("X-Sunder-Unlock", token)
	req.Header.Set("Content-Type", "application/json")
	hrec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(hrec, req)
	if hrec.Code != 403 {
		t.Fatalf("replayed unlock must 403: %d", hrec.Code)
	}
	// Fuzzy name narrowing is gated too in strict posture.
	rec, _ = e.do(t, cred, "POST", "/v1/lookup", map[string]string{"email": "ana@example.com", "name": "anic"})
	if rec.Code != 403 {
		t.Fatalf("fuzzy narrowing without unlock must 403 in strict posture: %d", rec.Code)
	}
}
