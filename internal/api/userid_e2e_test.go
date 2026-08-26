package api

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
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

// TestValueTokenBulkRequiresUnlock: bulk tokenization spends an unlock
// token ALWAYS - independent of SUNDER_SEARCH_UNLOCK.
func TestValueTokenBulkRequiresUnlock(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewDB(t)
	cred, err := auth.Create(ctx, st.Pool, auth.Client{
		ID: "crm", Name: "CRM", Scope: "crm",
		AllowedActions:  []string{auth.ActTokensCreate, auth.ActTokensRead, auth.ActAdminUnlock},
		AllowedPurposes: []string{}, RateLimit: 100})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(config.Config{Keystore: "file", KeystorePath: t.TempDir()}, st)
	if err != nil {
		t.Fatal(err)
	}
	e := &e2eEnv{srv: srv, credCRM: cred}

	// Single-item tokenize needs no unlock.
	rec, out := e.do(t, cred, "POST", "/v1/tokens", map[string]any{"value": "HR12"})
	if rec.Code != 201 || out["token"] == "" {
		t.Fatalf("single tokenize: %d %s", rec.Code, rec.Body.String())
	}
	single := out["token"]
	rec, out = e.do(t, cred, "GET", "/v1/tokens/"+single, nil)
	if rec.Code != 200 || out["value"] != "HR12" {
		t.Fatalf("detokenize: %d %s", rec.Code, rec.Body.String())
	}

	// Bulk without unlock: 403, regardless of configuration.
	rec, out = e.do(t, cred, "POST", "/v1/tokens/bulk",
		map[string]any{"items": []map[string]any{{"value": "a"}, {"value": "b"}}})
	if rec.Code != 403 || out["error"] != "unlock_required" {
		t.Fatalf("bulk without unlock must 403: %d %s", rec.Code, rec.Body.String())
	}
	// Mint the unlock with the RIGHT purpose and retry.
	rec, out = e.do(t, cred, "POST", "/v1/admin/unlock", map[string]string{"purpose": "bulk-tokens"})
	if rec.Code != 201 {
		t.Fatalf("unlock mint: %d", rec.Code)
	}
	req := httptest.NewRequest("POST", "/v1/tokens/bulk",
		strings.NewReader(`{"items":[{"value":"a"},{"value":"b"}]}`))
	req.Header.Set("Authorization", "Bearer "+cred)
	req.Header.Set("X-Sunder-Unlock", out["unlock_token"])
	req.Header.Set("Content-Type", "application/json")
	hrec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(hrec, req)
	if hrec.Code != 201 {
		t.Fatalf("bulk with unlock: %d %s", hrec.Code, hrec.Body.String())
	}
	// A search-purpose token must NOT open the bulk door.
	rec, out = e.do(t, cred, "POST", "/v1/admin/unlock", map[string]string{"purpose": "search"})
	if rec.Code != 201 {
		t.Fatalf("unlock mint 2: %d", rec.Code)
	}
	req = httptest.NewRequest("POST", "/v1/tokens/bulk/read", strings.NewReader(`{"tokens":["x"]}`))
	req.Header.Set("Authorization", "Bearer "+cred)
	req.Header.Set("X-Sunder-Unlock", out["unlock_token"])
	req.Header.Set("Content-Type", "application/json")
	hrec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(hrec, req)
	if hrec.Code != 403 {
		t.Fatalf("wrong-purpose unlock must 403: %d", hrec.Code)
	}
}

// TestReviewF4_UnlockNotBurnedOnNonSearch: the strict-posture gate must not
// spend a token for a request that never searches (malformed suffix,
// disabled feature, missing action).
func TestReviewF4_UnlockNotBurnedOnNonSearch(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewDB(t)
	cred, err := auth.Create(ctx, st.Pool, auth.Client{
		ID: "crm", Name: "CRM", Scope: "crm",
		AllowedActions:  []string{auth.ActContactsRegister, auth.ActLookup, auth.ActAdminUnlock},
		AllowedPurposes: []string{}, RateLimit: 100})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(config.Config{Keystore: "file", KeystorePath: t.TempDir(),
		SearchFuzzyName: true, SearchPhoneSuffix: true, SearchUnlock: true}, st)
	if err != nil {
		t.Fatal(err)
	}
	e := &e2eEnv{srv: srv, credCRM: cred}
	e.do(t, cred, "POST", "/v1/contacts", map[string]any{"phone": "+385911234567", "name": "Ana"})

	mint := func() string {
		rec, out := e.do(t, cred, "POST", "/v1/admin/unlock", map[string]string{"purpose": "search"})
		if rec.Code != 201 {
			t.Fatalf("mint: %d", rec.Code)
		}
		return out["unlock_token"]
	}
	suffixWith := func(token, body string) int {
		req := httptest.NewRequest("POST", "/v1/lookup", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+cred)
		req.Header.Set("X-Sunder-Unlock", token)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec.Code
	}

	// A malformed suffix (too short) must 400 WITHOUT burning the token:
	// the same token then works on a valid request.
	tok := mint()
	if code := suffixWith(tok, `{"phone_suffix":"123"}`); code != 400 {
		t.Fatalf("short suffix must 400, got %d", code)
	}
	if code := suffixWith(tok, `{"phone_suffix":"0911234567"}`); code != 200 {
		t.Fatalf("token must survive the earlier validation failure: %d", code)
	}
}

// TestFileVaultOverHTTP drives the F5 endpoints end to end: multipart
// upload, list, streaming download with a purpose, delete.
func TestFileVaultOverHTTP(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewDB(t)
	cred, err := auth.Create(ctx, st.Pool, auth.Client{
		ID: "crm", Name: "CRM", Scope: "crm",
		AllowedActions:  []string{auth.ActContactsRegister, auth.ActFilesWrite, auth.ActFilesRead},
		AllowedPurposes: []string{"support"}, RateLimit: 100})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(config.Config{Keystore: "file", KeystorePath: t.TempDir(),
		FilesStorage: "local", FilesDir: t.TempDir(), FilesMaxMB: 1}, st)
	if err != nil {
		t.Fatal(err)
	}
	e := &e2eEnv{srv: srv, credCRM: cred}
	_, out := e.do(t, cred, "POST", "/v1/contacts", map[string]any{"email": "ana@example.com"})
	cid := out["cid"]

	// Multipart upload.
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, _ := mw.CreateFormFile("file", "dopis.txt")
	part.Write([]byte("podsjetnik za sastanak"))
	mw.Close()
	req := httptest.NewRequest("POST", "/v1/contacts/"+cid+"/files", &body)
	req.Header.Set("Authorization", "Bearer "+cred)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != 201 {
		t.Fatalf("upload: %d %s", rec.Code, rec.Body.String())
	}
	var meta map[string]any
	json.Unmarshal(rec.Body.Bytes(), &meta)
	fileID, _ := meta["id"].(string)
	if fileID == "" {
		t.Fatalf("no file id: %s", rec.Body.String())
	}

	// List (metadata only).
	rec2 := httptest.NewRecorder()
	lreq := httptest.NewRequest("GET", "/v1/contacts/"+cid+"/files", nil)
	lreq.Header.Set("Authorization", "Bearer "+cred)
	srv.Handler().ServeHTTP(rec2, lreq)
	if rec2.Code != 200 || !strings.Contains(rec2.Body.String(), "dopis.txt") {
		t.Fatalf("list: %d %s", rec2.Code, rec2.Body.String())
	}

	// Download with a purpose streams the plaintext back.
	dreq := httptest.NewRequest("GET", "/v1/files/"+fileID+"?purpose=support", nil)
	dreq.Header.Set("Authorization", "Bearer "+cred)
	drec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(drec, dreq)
	if drec.Code != 200 || drec.Body.String() != "podsjetnik za sastanak" {
		t.Fatalf("download: %d %q", drec.Code, drec.Body.String())
	}
	if cd := drec.Header().Get("Content-Disposition"); !strings.Contains(cd, "dopis.txt") {
		t.Fatalf("content-disposition: %q", cd)
	}

	// Download without a purpose: 400.
	dreq2 := httptest.NewRequest("GET", "/v1/files/"+fileID, nil)
	dreq2.Header.Set("Authorization", "Bearer "+cred)
	drec2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(drec2, dreq2)
	if drec2.Code != 400 {
		t.Fatalf("no purpose must 400: %d", drec2.Code)
	}

	// Delete.
	delreq := httptest.NewRequest("DELETE", "/v1/files/"+fileID, nil)
	delreq.Header.Set("Authorization", "Bearer "+cred)
	delrec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(delrec, delreq)
	if delrec.Code != 200 {
		t.Fatalf("delete: %d", delrec.Code)
	}
}

// TestValueTokenHTTPSingleItem covers the non-bulk token handlers.
func TestValueTokenHTTPSingleItem(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewDB(t)
	cred, err := auth.Create(ctx, st.Pool, auth.Client{
		ID: "crm", Name: "CRM", Scope: "crm",
		AllowedActions:  []string{auth.ActTokensCreate, auth.ActTokensRead},
		AllowedPurposes: []string{}, RateLimit: 100})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(config.Config{Keystore: "file", KeystorePath: t.TempDir()}, st)
	if err != nil {
		t.Fatal(err)
	}
	e := &e2eEnv{srv: srv, credCRM: cred}
	rec, out := e.do(t, cred, "POST", "/v1/tokens", map[string]any{"value": "HR12", "type": "card"})
	if rec.Code != 400 { // "HR12" is not Luhn-valid
		t.Fatalf("non-card value as card must 400: %d", rec.Code)
	}
	rec, out = e.do(t, cred, "POST", "/v1/tokens", map[string]any{"value": "HR12 secret"})
	if rec.Code != 201 {
		t.Fatalf("tokenize: %d %s", rec.Code, rec.Body.String())
	}
	token := out["token"]
	rec, out = e.do(t, cred, "GET", "/v1/tokens/"+token, nil)
	if rec.Code != 200 || out["value"] != "HR12 secret" {
		t.Fatalf("detokenize: %d %s", rec.Code, rec.Body.String())
	}
	rec, _ = e.do(t, cred, "DELETE", "/v1/tokens/"+token, nil)
	if rec.Code != 200 {
		t.Fatalf("delete: %d", rec.Code)
	}
	rec, _ = e.do(t, cred, "GET", "/v1/tokens/"+token, nil)
	if rec.Code != 404 {
		t.Fatalf("deleted token must 404: %d", rec.Code)
	}
}

// TestFileAndTokenHTTPErrorPaths covers the handler error branches:
// malformed multipart, missing file part, bulk read, bad token id.
func TestFileAndTokenHTTPErrorPaths(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewDB(t)
	cred, err := auth.Create(ctx, st.Pool, auth.Client{
		ID: "crm", Name: "CRM", Scope: "crm",
		AllowedActions: []string{auth.ActContactsRegister, auth.ActFilesWrite, auth.ActFilesRead,
			auth.ActTokensCreate, auth.ActTokensRead, auth.ActAdminUnlock},
		AllowedPurposes: []string{"support"}, RateLimit: 100})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(config.Config{Keystore: "file", KeystorePath: t.TempDir(),
		FilesStorage: "local", FilesDir: t.TempDir(), FilesMaxMB: 1}, st)
	if err != nil {
		t.Fatal(err)
	}
	e := &e2eEnv{srv: srv, credCRM: cred}
	_, out := e.do(t, cred, "POST", "/v1/contacts", map[string]any{"email": "a@example.com"})
	cid := out["cid"]

	do := func(method, path, ctype, body string, hdr map[string]string) int {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+cred)
		if ctype != "" {
			req.Header.Set("Content-Type", ctype)
		}
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec.Code
	}

	// Upload with a non-multipart body: 400.
	if code := do("POST", "/v1/contacts/"+cid+"/files", "application/json", `{}`, nil); code != 400 {
		t.Fatalf("non-multipart upload must 400, got %d", code)
	}
	// Multipart without a "file" part: 400.
	var b bytes.Buffer
	mw := multipart.NewWriter(&b)
	mw.WriteField("notfile", "x")
	mw.Close()
	if code := do("POST", "/v1/contacts/"+cid+"/files", mw.FormDataContentType(), b.String(), nil); code != 400 {
		t.Fatalf("multipart without file part must 400, got %d", code)
	}
	// Download a nonexistent (but well-formed) file id: 404.
	if code := do("GET", "/v1/files/00000000-0000-4000-8000-000000000000?purpose=support", "", "", nil); code != 404 {
		t.Fatalf("missing file must 404, got %d", code)
	}

	// Bulk token read behind unlock: mint, then read.
	_, o := e.do(t, cred, "POST", "/v1/admin/unlock", map[string]string{"purpose": "bulk-tokens"})
	if code := do("POST", "/v1/tokens/bulk/read", "application/json",
		`{"tokens":["VT-NOPE"]}`, map[string]string{"X-Sunder-Unlock": o["unlock_token"]}); code != 200 {
		t.Fatalf("bulk read with unlock must 200 (misses are empty slots), got %d", code)
	}
	// Detokenize a nonexistent token: 404 audited miss.
	if code := do("GET", "/v1/tokens/VT-NOPE", "", "", nil); code != 404 {
		t.Fatalf("missing token must 404, got %d", code)
	}
}

// TestNewEndpointsForbiddenPaths exercises the writeErr/logErr branches of
// the F3/F4/F5 handlers for a client lacking the actions.
func TestNewEndpointsForbiddenPaths(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewDB(t)
	// A client with NO token/file/unlock actions.
	cred, err := auth.Create(ctx, st.Pool, auth.Client{
		ID: "weak", Name: "Weak", Scope: "crm",
		AllowedActions: []string{auth.ActLookup}, AllowedPurposes: []string{}, RateLimit: 100})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(config.Config{Keystore: "file", KeystorePath: t.TempDir(),
		FilesStorage: "local", FilesDir: t.TempDir(), FilesMaxMB: 1}, st)
	if err != nil {
		t.Fatal(err)
	}
	e := &e2eEnv{srv: srv, credCRM: cred}

	// Unlock without the action: 403 forbidden (not unlock_required).
	rec, _ := e.do(t, cred, "POST", "/v1/admin/unlock", map[string]string{"purpose": "search"})
	if rec.Code != 403 {
		t.Fatalf("unlock without action: %d", rec.Code)
	}
	// Tokenize without the action: 403.
	rec, _ = e.do(t, cred, "POST", "/v1/tokens", map[string]any{"value": "x"})
	if rec.Code != 403 {
		t.Fatalf("tokenize without action: %d", rec.Code)
	}
	// Token read of a bad id without action: 403 (permission before lookup).
	rec, _ = e.do(t, cred, "GET", "/v1/tokens/VT-X", nil)
	if rec.Code != 403 {
		t.Fatalf("token read without action: %d", rec.Code)
	}
	// File list without action: 403.
	_, out := e.do(t, cred, "POST", "/v1/lookup", map[string]string{"email": "x@example.com"})
	_ = out
	rec, _ = e.do(t, cred, "GET", "/v1/contacts/CID-X/files", nil)
	if rec.Code != 403 {
		t.Fatalf("file list without action: %d", rec.Code)
	}
	// File delete without action: 403.
	rec, _ = e.do(t, cred, "DELETE", "/v1/files/00000000-0000-4000-8000-000000000000", nil)
	if rec.Code != 403 {
		t.Fatalf("file delete without action: %d", rec.Code)
	}
}

// TestTokenAndFileHandlerErrorBranches drives each handler's error arm
// (writeErr paths) that the happy-path tests miss.
func TestTokenAndFileHandlerErrorBranches(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewDB(t)
	cred, err := auth.Create(ctx, st.Pool, auth.Client{
		ID: "crm", Name: "CRM", Scope: "crm",
		AllowedActions: []string{auth.ActContactsRegister, auth.ActTokensCreate, auth.ActTokensRead,
			auth.ActFilesWrite, auth.ActFilesRead, auth.ActAdminUnlock},
		AllowedPurposes: []string{"support"}, RateLimit: 100})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(config.Config{Keystore: "file", KeystorePath: t.TempDir(),
		FilesStorage: "local", FilesDir: t.TempDir(), FilesMaxMB: 1}, st)
	if err != nil {
		t.Fatal(err)
	}
	e := &e2eEnv{srv: srv, credCRM: cred}

	// Delete a nonexistent token: 404 through handleTokenDelete's writeErr.
	rec, _ := e.do(t, cred, "DELETE", "/v1/tokens/VT-NOPE", nil)
	if rec.Code != 404 {
		t.Fatalf("delete missing token: %d", rec.Code)
	}
	// Tokenize a bad body (non-object): decode fail path.
	req := httptest.NewRequest("POST", "/v1/tokens", strings.NewReader(`not json`))
	req.Header.Set("Authorization", "Bearer "+cred)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 400 {
		t.Fatalf("bad tokenize body: %d", rr.Code)
	}
	// Card value that fails Luhn: service ErrValidation via writeErr.
	rec, _ = e.do(t, cred, "POST", "/v1/tokens", map[string]any{"type": "card", "value": "1234"})
	if rec.Code != 400 {
		t.Fatalf("bad card: %d", rec.Code)
	}

	// Bulk create with a bad item after unlock: service error via writeErr.
	_, o := e.do(t, cred, "POST", "/v1/admin/unlock", map[string]string{"purpose": "bulk-tokens"})
	req = httptest.NewRequest("POST", "/v1/tokens/bulk", strings.NewReader(`{"items":[{"value":""}]}`))
	req.Header.Set("Authorization", "Bearer "+cred)
	req.Header.Set("X-Sunder-Unlock", o["unlock_token"])
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 400 {
		t.Fatalf("bulk create bad item: %d %s", rr.Code, rr.Body.String())
	}
	// Bulk read with a malformed body after unlock.
	_, o = e.do(t, cred, "POST", "/v1/admin/unlock", map[string]string{"purpose": "bulk-tokens"})
	req = httptest.NewRequest("POST", "/v1/tokens/bulk/read", strings.NewReader(`{"tokens":`))
	req.Header.Set("Authorization", "Bearer "+cred)
	req.Header.Set("X-Sunder-Unlock", o["unlock_token"])
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 400 {
		t.Fatalf("bulk read bad body: %d", rr.Code)
	}
	// Upload to an unknown CID: service ErrNotFound via writeErr.
	var mb bytes.Buffer
	mw := multipart.NewWriter(&mb)
	pw, _ := mw.CreateFormFile("file", "x.txt")
	pw.Write([]byte("x"))
	mw.Close()
	req = httptest.NewRequest("POST", "/v1/contacts/CID-NONEXISTENT0000000000000/files", &mb)
	req.Header.Set("Authorization", "Bearer "+cred)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 404 {
		t.Fatalf("upload to unknown cid: %d", rr.Code)
	}
}

// TestHandlerHardErrorPaths breaks a table mid-request so the service
// returns a non-validation error, exercising the handlers' logErr/writeErr
// branches (500 paths) that clean 4xx tests never reach.
func TestHandlerHardErrorPaths(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewDB(t)
	cred, err := auth.Create(ctx, st.Pool, auth.Client{
		ID: "crm", Name: "CRM", Scope: "crm",
		AllowedActions: []string{auth.ActContactsRegister, auth.ActLookup, auth.ActAdminUnlock,
			auth.ActTokensCreate, auth.ActTokensRead},
		AllowedPurposes: []string{}, RateLimit: 100})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(config.Config{Keystore: "file", KeystorePath: t.TempDir(),
		SearchPhoneSuffix: true, SearchUnlock: true}, st)
	if err != nil {
		t.Fatal(err)
	}
	e := &e2eEnv{srv: srv, credCRM: cred}
	e.do(t, cred, "POST", "/v1/contacts", map[string]any{"phone": "+385911234567"})

	// Mint an unlock token, then break unlock_tokens so Consume returns a
	// hard DB error (not ErrUnlockRequired): the handler must 500, not 403.
	_, o := e.do(t, cred, "POST", "/v1/admin/unlock", map[string]string{"purpose": "search"})
	if _, err := st.Pool.Exec(ctx, `ALTER TABLE unlock_tokens RENAME TO unlock_hidden`); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/v1/lookup", strings.NewReader(`{"phone_suffix":"0911234567"}`))
	req.Header.Set("Authorization", "Bearer "+cred)
	req.Header.Set("X-Sunder-Unlock", o["unlock_token"])
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code < 500 {
		t.Fatalf("a hard DB error during unlock consume must 5xx, got %d", rr.Code)
	}
	if _, err := st.Pool.Exec(ctx, `ALTER TABLE unlock_hidden RENAME TO unlock_tokens`); err != nil {
		t.Fatal(err)
	}

	// Break value_tokens so tokenize returns a hard error.
	if _, err := st.Pool.Exec(ctx, `ALTER TABLE value_tokens RENAME TO vt_hidden`); err != nil {
		t.Fatal(err)
	}
	rec, _ := e.do(t, cred, "POST", "/v1/tokens", map[string]any{"value": "x"})
	if rec.Code < 500 {
		t.Fatalf("a hard DB error during tokenize must 5xx, got %d", rec.Code)
	}
	if _, err := st.Pool.Exec(ctx, `ALTER TABLE vt_hidden RENAME TO value_tokens`); err != nil {
		t.Fatal(err)
	}

	// A hard DB error during the bulk unlock consume must 5xx via
	// requireUnlock's writeErr branch, not 403.
	if _, err := st.Pool.Exec(ctx, `ALTER TABLE unlock_tokens RENAME TO ut_hidden2`); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest("POST", "/v1/tokens/bulk", strings.NewReader(`{"items":[{"value":"a"}]}`))
	req.Header.Set("Authorization", "Bearer "+cred)
	req.Header.Set("X-Sunder-Unlock", "sometoken")
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code < 500 {
		t.Fatalf("a hard DB error during bulk unlock consume must 5xx, got %d", rr.Code)
	}
}
