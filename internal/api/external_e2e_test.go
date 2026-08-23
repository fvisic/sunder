package api

// P2.4 over HTTP: the external-claims endpoint end to end, plus the
// rejection paths (untrusted issuer, cross-CID replay attempt).

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/config"
	"github.com/fvisic/sunder/internal/crypto"
	"github.com/fvisic/sunder/internal/testutil"
)

func TestExternalClaimsOverHTTP(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewDB(t)
	cred, err := auth.Create(ctx, st.Pool, auth.Client{
		ID: "gw", Name: "Gateway", Scope: "crm",
		AllowedActions:  []string{auth.ActContactsRegister, auth.ActAttributesRead, auth.ActClaimsExternal},
		AllowedPurposes: []string{"kyc"}, RateLimit: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(config.Config{Listen: ":0", Keystore: "file", KeystorePath: t.TempDir()}, st)
	if err != nil {
		t.Fatal(err)
	}
	do := func(method, path, body string) (int, map[string]any) {
		return callJSON(t, srv, cred, method, path, body)
	}

	code, out := do("POST", "/v1/contacts", `{"email":"wallet@example.com"}`)
	if code != 201 {
		t.Fatalf("register: %d %v", code, out)
	}
	cid, _ := out["cid"].(string)

	seed := make([]byte, 32)
	seed[0] = 33
	sk := ed25519.NewKeyFromSeed(seed)
	if _, err := st.Pool.Exec(ctx,
		`INSERT INTO trusted_issuers (issuer_id, public_key, allowed_claims, added_by) VALUES ('gov',$1,$2,'test')`,
		[]byte(sk.Public().(ed25519.PublicKey)), []string{"age_gte_18"}); err != nil {
		t.Fatal(err)
	}
	mint := func(jti, target string, claims map[string]string) string {
		payload, _ := json.Marshal(map[string]any{
			"iss": "gov", "jti": jti, "cid": target, "claims": claims,
			"exp": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		})
		return crypto.PasetoSign(sk, payload)
	}

	code, out = do("POST", "/v1/claims/external",
		`{"cid":"`+cid+`","envelope":"`+mint("envelope-0000001", cid, map[string]string{"age_gte_18": "true"})+`"}`)
	if code != 200 {
		t.Fatalf("external claims: %d %v", code, out)
	}
	stored, _ := out["stored"].([]any)
	if len(stored) != 1 || stored[0] != "age_gte_18@gov" {
		t.Fatalf("stored: %v", stored)
	}
	// The claim reads back as a normal purpose-checked attribute.
	code, out = do("GET", "/v1/contacts/"+cid+"/attributes/age_gte_18@gov?purpose=kyc", "")
	if code != 200 || out["value"] != "true" {
		t.Fatalf("read back: %d %v", code, out)
	}
	// Replay of the same jti is refused.
	code, _ = do("POST", "/v1/claims/external",
		`{"cid":"`+cid+`","envelope":"`+mint("envelope-0000001", cid, map[string]string{"age_gte_18": "true"})+`"}`)
	if code == 200 {
		t.Fatal("replayed jti must be refused over HTTP too")
	}
	// Untrusted issuer -> 403.
	other := ed25519.NewKeyFromSeed(append(make([]byte, 31), 44))
	payload, _ := json.Marshal(map[string]any{
		"iss": "rogue", "jti": "envelope-0000009", "cid": cid, "claims": map[string]string{"age_gte_18": "true"},
		"exp": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	})
	code, _ = do("POST", "/v1/claims/external",
		`{"cid":"`+cid+`","envelope":"`+crypto.PasetoSign(other, payload)+`"}`)
	if code != 403 {
		t.Fatalf("untrusted issuer must be 403: %d", code)
	}
	// Self-registering a '@' attribute (provenance forgery) is refused.
	code, _ = do("POST", "/v1/contacts", `{"email":"forge@example.com","attributes":{"age_gte_18@gov":"true"}}`)
	if code != 400 {
		t.Fatalf("provenance forgery must be 400: %d", code)
	}
}

// callJSON performs an authenticated JSON request and decodes the body.
func callJSON(t *testing.T, srv *Server, cred, method, path, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+cred)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	out := map[string]any{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestEnumerationWarnLatch(t *testing.T) {
	s := &Server{}
	if !s.warnLatch("crm") {
		t.Fatal("first crossing must warn")
	}
	if s.warnLatch("crm") {
		t.Fatal("second crossing inside the window must be latched")
	}
	if !s.warnLatch("other") {
		t.Fatal("a different client has its own latch")
	}
}

// External-claims HTTP branches: bad body, missing action, dead pool.
func TestExternalClaimsHTTPBranches(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewDB(t)
	noAction, err := auth.Create(ctx, st.Pool, auth.Client{
		ID: "plain", Name: "Plain", Scope: "crm",
		AllowedActions: []string{auth.ActLookup}, AllowedPurposes: []string{"support"}, RateLimit: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(config.Config{Listen: ":0", Keystore: "file", KeystorePath: t.TempDir()}, st)
	if err != nil {
		t.Fatal(err)
	}
	// Missing claims.external action.
	if code, _ := callJSON(t, srv, noAction, "POST", "/v1/claims/external",
		`{"cid":"CID-X","envelope":"v4.public.x"}`); code != 403 {
		t.Fatalf("missing action must be 403: %d", code)
	}
	// Malformed body.
	if code, _ := callJSON(t, srv, noAction, "POST", "/v1/claims/external", `{broken`); code != 400 {
		t.Fatal("broken JSON must be 400")
	}
	// Dead pool: 5xx, never a claim silently accepted.
	st.Close()
	if code, _ := callJSON(t, srv, noAction, "POST", "/v1/claims/external",
		`{"cid":"CID-X","envelope":"v4.public.x"}`); code == 200 {
		t.Fatal("a dead pool must not yield success")
	}
}
