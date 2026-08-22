package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/service"
)

// gdprEnv: CRM with the consent action, plus a privacy-officer client
// holding the org-wide DSR privileges in the crm scope.
func gdprEnv(t *testing.T) (e *e2eEnv, credDPO string) {
	t.Helper()
	e = newE2E(t)
	ctx := context.Background()
	if _, err := e.srv.Store.Pool.Exec(ctx,
		`UPDATE clients SET allowed_actions = allowed_actions || '{consent.manage,lookup,oti.issue,dsr.export}',
		                    allowed_purposes = allowed_purposes || '{create_order}'
		 WHERE client_id='crm'`); err != nil {
		t.Fatal(err)
	}
	credDPO, err := auth.Create(ctx, e.srv.Store.Pool, auth.Client{
		ID: "dpo", Name: "Privacy Officer", Scope: "crm",
		AllowedActions:  []string{auth.ActDSRAccess, auth.ActDSRErase},
		AllowedPurposes: []string{}, RateLimit: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	return e, credDPO
}

func TestConsentBlocksAttributeAndOTI(t *testing.T) {
	e, _ := gdprEnv(t)
	cid := registerFilip(t, e)

	// Withdraw consent for newsletter.
	rec, _ := e.do(t, e.credCRM, "POST", "/v1/consent", map[string]any{
		"cid": cid, "purpose": "newsletter", "granted": false})
	if rec.Code != 200 {
		t.Fatalf("consent set: %d %s", rec.Code, rec.Body.String())
	}
	rec, out := e.do(t, e.credCRM, "GET", "/v1/contacts/"+cid+"/attributes/email?purpose=newsletter", nil)
	if rec.Code != 403 || out["error"] != "consent_denied" {
		t.Fatalf("attribute read must be consent_denied: %d %s", rec.Code, rec.Body.String())
	}
	// Other purposes are unaffected (absence of a row = not consent-governed).
	rec, _ = e.do(t, e.credCRM, "POST", "/v1/oti", map[string]string{
		"cid": cid, "purpose": "create_order", "audience": "erp"})
	if rec.Code != 201 {
		t.Fatalf("unrelated purpose blocked: %d", rec.Code)
	}
	// Withdrawn consent blocks OTI issuance for that purpose too.
	rec, _ = e.do(t, e.credCRM, "POST", "/v1/consent", map[string]any{
		"cid": cid, "purpose": "create_order", "granted": false})
	if rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	rec, out = e.do(t, e.credCRM, "POST", "/v1/oti", map[string]string{
		"cid": cid, "purpose": "create_order", "audience": "erp"})
	if rec.Code != 403 || out["error"] != "consent_denied" {
		t.Fatalf("oti issue must be consent_denied: %d %s", rec.Code, rec.Body.String())
	}
	// Re-granting restores access; the decision list reflects history.
	rec, _ = e.do(t, e.credCRM, "POST", "/v1/consent", map[string]any{
		"cid": cid, "purpose": "newsletter", "granted": true})
	if rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	rec, _ = e.do(t, e.credCRM, "GET", "/v1/contacts/"+cid+"/attributes/email?purpose=newsletter", nil)
	if rec.Code != 200 {
		t.Fatalf("re-granted purpose still blocked: %d", rec.Code)
	}
	rec, _ = e.do(t, e.credCRM, "GET", "/v1/consent/"+cid, nil)
	if rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	var listed struct {
		Consents []service.Consent `json:"consents"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil || len(listed.Consents) != 2 {
		t.Fatalf("expected 2 consent decisions, got %v (%v)", listed.Consents, err)
	}
}

func TestDSRAccessAndExport(t *testing.T) {
	e, credDPO := gdprEnv(t)
	cid := registerFilip(t, e)
	// Give the person a second scope so access proves org-wide reach.
	rec, _ := e.do(t, e.credCRM, "POST", "/v1/contacts/"+cid+"/scopes", map[string]string{"scope": "billing"})
	if rec.Code != 200 {
		t.Fatal(rec.Code)
	}

	rec, _ = e.do(t, credDPO, "GET", "/v1/dsr/access?cid="+cid, nil)
	if rec.Code != 200 {
		t.Fatalf("dsr access: %d %s", rec.Code, rec.Body.String())
	}
	var access struct {
		Scopes []service.ScopeData       `json:"scopes"`
		Trail  []service.AuditTrailEntry `json:"audit_trail"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &access); err != nil {
		t.Fatal(err)
	}
	if len(access.Scopes) != 2 {
		t.Fatalf("expected 2 scopes in access response, got %d", len(access.Scopes))
	}
	if access.Scopes[0].Scope == access.Scopes[1].Scope {
		t.Fatal("duplicate scopes")
	}
	found := false
	for _, s := range access.Scopes {
		if s.Scope == "crm" && s.Attributes["email"] == "filip@example.com" {
			found = true
		}
	}
	if !found {
		t.Fatal("crm attributes missing from access response")
	}
	if len(access.Trail) == 0 {
		t.Fatal("audit trail missing from access response")
	}
	// The ordinary CRM client must NOT be able to call dsr/access.
	rec, _ = e.do(t, e.credCRM, "GET", "/v1/dsr/access?cid="+cid, nil)
	if rec.Code != 403 {
		t.Fatalf("dsr.access must require its action: %d", rec.Code)
	}

	// Portability export: caller-scope data only.
	rec, _ = e.do(t, e.credCRM, "GET", "/v1/dsr/export?cid="+cid, nil)
	if rec.Code != 200 {
		t.Fatalf("dsr export: %d %s", rec.Code, rec.Body.String())
	}
	var exp service.ScopeData
	if err := json.Unmarshal(rec.Body.Bytes(), &exp); err != nil {
		t.Fatal(err)
	}
	if exp.Scope != "crm" || exp.Attributes["email"] != "filip@example.com" {
		t.Fatalf("export payload wrong: %+v", exp)
	}
}

func TestDSREraseOrgWideWithSignedWebhook(t *testing.T) {
	e, credDPO := gdprEnv(t)
	ctx := context.Background()
	cid := registerFilip(t, e)
	rec, out := e.do(t, e.credCRM, "POST", "/v1/contacts/"+cid+"/scopes", map[string]string{"scope": "billing"})
	if rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	billingCID := out["cid"]

	// Register a webhook for the crm scope and capture deliveries.
	var mu sync.Mutex
	var gotBody []byte
	var gotSig string
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		gotBody, _ = io.ReadAll(r.Body)
		gotSig = r.Header.Get("X-Sunder-Signature")
		w.WriteHeader(200)
	}))
	defer hook.Close()
	secret := "hook-secret-for-test"
	if _, err := e.srv.Store.Pool.Exec(ctx,
		`INSERT INTO webhooks (scope, url, secret) VALUES ('crm', $1, $2)`, hook.URL, secret); err != nil {
		t.Fatal(err)
	}

	rec, _ = e.do(t, credDPO, "POST", "/v1/dsr/erase", map[string]string{"cid": cid})
	if rec.Code != 200 {
		t.Fatalf("erase: %d %s", rec.Code, rec.Body.String())
	}
	var eraseResp struct {
		ErasureID int64 `json:"erasure_id"`
		Scopes    int   `json:"scopes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &eraseResp); err != nil || eraseResp.Scopes != 2 {
		t.Fatalf("erase response: %s (%v)", rec.Body.String(), err)
	}

	// Blobs gone in every scope; lookups miss; person tombstoned.
	rec, _ = e.do(t, e.credCRM, "GET", "/v1/contacts/"+cid+"/attributes/email?purpose=newsletter", nil)
	if rec.Code != 404 {
		t.Fatalf("attributes must be gone after erase: %d", rec.Code)
	}
	rec, _ = e.do(t, e.credCRM, "POST", "/v1/lookup", map[string]string{"email": "filip@example.com"})
	if rec.Code != 404 {
		t.Fatalf("lookup must miss after erase: %d", rec.Code)
	}
	var erasedAt *string
	if err := e.srv.Store.Pool.QueryRow(ctx,
		`SELECT p.erased_at::text FROM persons p JOIN cids c ON c.person_id=p.id WHERE c.cid=$1`, cid).
		Scan(&erasedAt); err != nil || erasedAt == nil {
		t.Fatalf("person not tombstoned: %v %v", erasedAt, err)
	}

	// The crm webhook received a correctly signed erase event.
	mu.Lock()
	body, sig := gotBody, gotSig
	mu.Unlock()
	if len(body) == 0 {
		t.Fatal("webhook did not receive a delivery")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	if hex.EncodeToString(mac.Sum(nil)) != sig {
		t.Fatal("webhook signature does not verify")
	}
	var payload struct {
		Event, Scope, CID string
	}
	if err := json.Unmarshal(body, &payload); err != nil || payload.Event != "erase" || payload.CID != cid {
		t.Fatalf("unexpected payload: %s", body)
	}

	// billing has no webhook: its event is marked NO_WEBHOOK; crm DELIVERED.
	var delivered, noHook int
	if err := e.srv.Store.Pool.QueryRow(ctx,
		`SELECT count(*) FILTER (WHERE status='DELIVERED'), count(*) FILTER (WHERE status='NO_WEBHOOK')
		 FROM erasure_events WHERE cid IN ($1,$2)`, cid, billingCID).Scan(&delivered, &noHook); err != nil {
		t.Fatal(err)
	}
	if delivered != 1 || noHook != 1 {
		t.Fatalf("expected 1 DELIVERED + 1 NO_WEBHOOK, got %d/%d", delivered, noHook)
	}

	// Re-registering the same identifiers creates a brand-new person/CID.
	rec, out = e.do(t, e.credCRM, "POST", "/v1/contacts", map[string]any{"email": "filip@example.com"})
	if rec.Code != 201 || out["cid"] == cid {
		t.Fatalf("post-erase registration must mint a new CID: %d %s", rec.Code, out["cid"])
	}
}

// A foreign-scope CID with a withdrawn consent must read as 404, not 403 -
// otherwise the 403/404 split is an oracle for foreign-CID existence and
// consent state.
func TestConsentHookNoForeignCIDOracle(t *testing.T) {
	e, _ := gdprEnv(t)
	cid := registerFilip(t, e)
	rec, _ := e.do(t, e.credCRM, "POST", "/v1/consent", map[string]any{
		"cid": cid, "purpose": "analytics", "granted": false})
	if rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	// DWH (foreign scope, has purpose "analytics" granted) probes the CRM CID.
	rec, out := e.do(t, e.credDWH, "GET", "/v1/contacts/"+cid+"/attributes/email?purpose=analytics", nil)
	if rec.Code != 404 {
		t.Fatalf("foreign CID with withdrawn consent must be 404 (got %d %s) - 403 would leak existence+consent", rec.Code, out["error"])
	}
}

// An OTI issued before erasure must not survive it: verification after the
// erase must fail (and never mint a fresh CID for the forgotten person).
func TestEraseRevokesOutstandingOTIs(t *testing.T) {
	e, credDPO := gdprEnv(t)
	ctx := context.Background()
	credERP, err := auth.Create(ctx, e.srv.Store.Pool, auth.Client{
		ID: "erp3", Name: "ERP3", Scope: "erp",
		AllowedActions:  []string{auth.ActOTIVerify},
		AllowedPurposes: []string{"create_order"}, RateLimit: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	cid := registerFilip(t, e)
	rec, out := e.do(t, e.credCRM, "POST", "/v1/oti", map[string]string{
		"cid": cid, "purpose": "create_order", "audience": "erp"})
	if rec.Code != 201 {
		t.Fatal(rec.Code)
	}
	token := out["token"]

	rec, _ = e.do(t, credDPO, "POST", "/v1/dsr/erase", map[string]string{"cid": cid})
	if rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	rec, out = e.do(t, credERP, "POST", "/v1/oti/verify", map[string]string{
		"token": token, "purpose": "create_order", "audience": "erp"})
	if rec.Code != 400 || out["error"] != "token_invalid" {
		t.Fatalf("pre-erasure OTI must be revoked: %d %s", rec.Code, rec.Body.String())
	}
	// No new CID may have been minted in the erp scope for the erased person.
	var n int
	if err := e.srv.Store.Pool.QueryRow(ctx,
		`SELECT count(*) FROM cids c JOIN persons p ON p.id=c.person_id
		 WHERE p.erased_at IS NOT NULL AND c.scope='erp'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("erased person re-linked into verifier scope (%d cids)", n)
	}
	// Erase is not repeatable on a tombstone.
	rec, _ = e.do(t, credDPO, "POST", "/v1/dsr/erase", map[string]string{"cid": cid})
	if rec.Code != 400 {
		t.Fatalf("second erase must be a validation error: %d", rec.Code)
	}
}

// Omitting "granted" must be a validation error, not a silent withdrawal.
func TestConsentGrantedFieldRequired(t *testing.T) {
	e, _ := gdprEnv(t)
	cid := registerFilip(t, e)
	rec, out := e.do(t, e.credCRM, "POST", "/v1/consent", map[string]any{
		"cid": cid, "purpose": "newsletter"})
	if rec.Code != 400 || out["error"] != "validation" {
		t.Fatalf("missing granted must be 400 validation: %d %s", rec.Code, rec.Body.String())
	}
}

func TestRetentionSweep(t *testing.T) {
	e, _ := gdprEnv(t)
	ctx := context.Background()
	cid := registerFilip(t, e)
	if _, err := e.srv.Store.Pool.Exec(ctx,
		`INSERT INTO retention_policies (scope, contacts_ttl_days) VALUES ('crm', 0)`); err != nil {
		t.Fatal(err)
	}
	// TTL 0 days: everything qualifies immediately.
	wiped, _, err := service.RunRetention(ctx, e.srv.Store.Pool)
	if err != nil {
		t.Fatal(err)
	}
	if wiped < 1 {
		t.Fatalf("expected at least 1 wiped blob, got %d", wiped)
	}
	rec, _ := e.do(t, e.credCRM, "GET", "/v1/contacts/"+cid+"/attributes/email?purpose=newsletter", nil)
	if rec.Code != 404 {
		t.Fatalf("blob must be gone after retention sweep: %d", rec.Code)
	}
	// Tokens survive a retention wipe (it is not an erasure): lookup still hits.
	rec, _ = e.do(t, e.credCRM, "POST", "/v1/lookup", map[string]string{"email": "filip@example.com"})
	if rec.Code != 200 {
		t.Fatalf("retention must not delete search tokens: %d", rec.Code)
	}
}

// Error-branch coverage for the GDPR handlers and services.
func TestGDPRHandlerErrorBranches(t *testing.T) {
	e, credDPO := gdprEnv(t)
	cid := registerFilip(t, e)

	// consent list / set / export without the action -> forbidden (DPO has
	// only dsr.access + dsr.erase).
	rec, _ := e.do(t, credDPO, "GET", "/v1/consent/"+cid, nil)
	if rec.Code != 403 {
		t.Fatalf("consent list without action: %d", rec.Code)
	}
	rec, _ = e.do(t, credDPO, "POST", "/v1/consent", map[string]any{
		"cid": cid, "purpose": "x", "granted": true})
	if rec.Code != 403 {
		t.Fatalf("consent set without action: %d", rec.Code)
	}
	rec, _ = e.do(t, credDPO, "GET", "/v1/dsr/export?cid="+cid, nil)
	if rec.Code != 403 {
		t.Fatalf("export without action: %d", rec.Code)
	}
	// consent set with empty purpose -> validation.
	rec, _ = e.do(t, e.credCRM, "POST", "/v1/consent", map[string]any{
		"cid": cid, "granted": true})
	if rec.Code != 400 {
		t.Fatalf("consent without purpose: %d", rec.Code)
	}
	// consent on a foreign/unknown CID -> not found.
	rec, _ = e.do(t, e.credCRM, "POST", "/v1/consent", map[string]any{
		"cid": "CID-DOESNOTEXIST", "purpose": "x", "granted": true})
	if rec.Code != 404 {
		t.Fatalf("consent on unknown cid: %d", rec.Code)
	}
	rec, _ = e.do(t, e.credCRM, "GET", "/v1/consent/CID-DOESNOTEXIST", nil)
	if rec.Code != 404 {
		t.Fatalf("consent list on unknown cid: %d", rec.Code)
	}
	// scopes.issue with empty scope -> validation; bad JSON -> bad_json.
	rec, _ = e.do(t, e.credCRM, "POST", "/v1/contacts/"+cid+"/scopes", map[string]string{})
	if rec.Code != 400 {
		t.Fatalf("empty scope: %d", rec.Code)
	}
	req := httptest.NewRequest("POST", "/v1/contacts/"+cid+"/scopes", strings.NewReader("{nope"))
	req.Header.Set("Authorization", "Bearer "+e.credCRM)
	rr := httptest.NewRecorder()
	e.srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 400 {
		t.Fatalf("bad json: %d", rr.Code)
	}
}

// The FAILED path: a permanently broken webhook exhausts its attempts and
// the event is closed out with an audited FAILED record.
func TestEraseDeliveryFailsClosedAfterAttempts(t *testing.T) {
	e, credDPO := gdprEnv(t)
	ctx := context.Background()
	cid := registerFilip(t, e)
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer dead.Close()
	if _, err := e.srv.Store.Pool.Exec(ctx,
		`INSERT INTO webhooks (scope, url, secret) VALUES ('crm', $1, 's')`, dead.URL); err != nil {
		t.Fatal(err)
	}
	rec, _ := e.do(t, credDPO, "POST", "/v1/dsr/erase", map[string]string{"cid": cid})
	if rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	for i := 0; i < 12; i++ {
		if _, err := e.srv.GDPR.DeliverPending(ctx); err != nil {
			t.Fatal(err)
		}
	}
	var status string
	var attempts int
	if err := e.srv.Store.Pool.QueryRow(ctx,
		`SELECT status, attempts FROM erasure_events WHERE cid=$1`, cid).Scan(&status, &attempts); err != nil {
		t.Fatal(err)
	}
	if status != "FAILED" || attempts < 10 {
		t.Fatalf("expected FAILED after attempts cap, got %s/%d", status, attempts)
	}
	var audited int
	if err := e.srv.Store.Pool.QueryRow(ctx,
		`SELECT count(*) FROM audit WHERE action='dsr.erase.failed'`).Scan(&audited); err != nil {
		t.Fatal(err)
	}
	if audited != 1 {
		t.Fatalf("FAILED transition must be audited once, got %d", audited)
	}
}
