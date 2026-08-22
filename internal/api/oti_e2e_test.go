package api

import (
	"context"
	"strings"
	"testing"

	"github.com/fvisic/sunder/internal/auth"
)

// otiEnv extends the base env with issue/verify grants and an ERP verifier.
func otiEnv(t *testing.T) (*e2eEnv, string) {
	t.Helper()
	e := newE2E(t)
	ctx := context.Background()
	if _, err := e.srv.Store.Pool.Exec(ctx,
		`UPDATE clients SET allowed_actions = allowed_actions || '{oti.issue}',
		                    allowed_purposes = allowed_purposes || '{create_order}'
		 WHERE client_id='crm'`); err != nil {
		t.Fatal(err)
	}
	// "refund" is granted so a purpose-mismatch test can distinguish
	// claims-vs-request mismatch (token_invalid) from a missing grant
	// (purpose_not_allowed, tested separately).
	credERP, err := auth.Create(ctx, e.srv.Store.Pool, auth.Client{
		ID: "erp", Name: "ERP", Scope: "erp",
		AllowedActions:  []string{auth.ActOTIVerify},
		AllowedPurposes: []string{"create_order", "refund"}, RateLimit: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	return e, credERP
}

func TestOTIHandoffFlow(t *testing.T) {
	e, credERP := otiEnv(t)
	crmCID := registerFilip(t, e)

	// CRM issues an OTI addressed to the ERP for one purpose.
	rec, out := e.do(t, e.credCRM, "POST", "/v1/oti", map[string]string{
		"cid": crmCID, "purpose": "create_order", "audience": "erp"})
	if rec.Code != 201 || out["token"] == "" || out["expires_at"] == "" {
		t.Fatalf("issue: %d %s", rec.Code, rec.Body.String())
	}
	token := out["token"]
	if !strings.HasPrefix(token, "v4.public.") {
		t.Fatalf("not a PASETO v4.public token: %s", token[:20])
	}

	// ERP verifies and receives ITS OWN scoped CID, different from CRM's.
	rec, out = e.do(t, credERP, "POST", "/v1/oti/verify", map[string]string{
		"token": token, "purpose": "create_order", "audience": "erp"})
	if rec.Code != 200 || out["cid"] == "" {
		t.Fatalf("verify: %d %s", rec.Code, rec.Body.String())
	}
	if out["cid"] == crmCID {
		t.Fatal("verifier received the issuer's CID — scope boundary crossed")
	}

	// Single use: the second verification must report token_used.
	rec, out = e.do(t, credERP, "POST", "/v1/oti/verify", map[string]string{
		"token": token, "purpose": "create_order", "audience": "erp"})
	if rec.Code != 409 || out["error"] != "token_used" {
		t.Fatalf("replay: %d %s", rec.Code, rec.Body.String())
	}
}

func TestOTIBindingChecks(t *testing.T) {
	e, credERP := otiEnv(t)
	crmCID := registerFilip(t, e)
	issue := func() string {
		t.Helper()
		rec, out := e.do(t, e.credCRM, "POST", "/v1/oti", map[string]string{
			"cid": crmCID, "purpose": "create_order", "audience": "erp"})
		if rec.Code != 201 {
			t.Fatalf("issue: %d", rec.Code)
		}
		return out["token"]
	}

	// Wrong purpose at verification (granted to the verifier, but the token
	// is bound to create_order): claims mismatch -> token_invalid.
	rec, out := e.do(t, credERP, "POST", "/v1/oti/verify", map[string]string{
		"token": issue(), "purpose": "refund", "audience": "erp"})
	if rec.Code != 400 || out["error"] != "token_invalid" {
		t.Fatalf("wrong purpose: %d %s", rec.Code, rec.Body.String())
	}
	// A verifier cannot claim an audience that is not its own scope.
	rec, out = e.do(t, credERP, "POST", "/v1/oti/verify", map[string]string{
		"token": issue(), "purpose": "create_order", "audience": "billing"})
	if rec.Code != 403 || out["error"] != "audience_mismatch" {
		t.Fatalf("foreign audience: %d %s", rec.Code, rec.Body.String())
	}
	// Tampered token fails signature.
	tok := issue()
	rec, out = e.do(t, credERP, "POST", "/v1/oti/verify", map[string]string{
		"token": tok[:len(tok)-4] + "AAAA", "purpose": "create_order", "audience": "erp"})
	if rec.Code != 400 || out["error"] != "token_invalid" {
		t.Fatalf("tampered: %d %s", rec.Code, rec.Body.String())
	}
	// Issuing for a foreign CID is indistinguishable from absence.
	rec, _ = e.do(t, e.credCRM, "POST", "/v1/oti", map[string]string{
		"cid": "CID-DOESNOTEXIST", "purpose": "create_order", "audience": "erp"})
	if rec.Code != 404 {
		t.Fatalf("foreign cid issue: %d", rec.Code)
	}
	// Purpose not granted to the issuer.
	rec, out = e.do(t, e.credCRM, "POST", "/v1/oti", map[string]string{
		"cid": crmCID, "purpose": "not-granted", "audience": "erp"})
	if rec.Code != 403 || out["error"] != "purpose_not_allowed" {
		t.Fatalf("ungranted purpose: %d %s", rec.Code, rec.Body.String())
	}
}

func TestOTIExpiredToken(t *testing.T) {
	e, credERP := otiEnv(t)
	crmCID := registerFilip(t, e)
	rec, out := e.do(t, e.credCRM, "POST", "/v1/oti", map[string]string{
		"cid": crmCID, "purpose": "create_order", "audience": "erp"})
	if rec.Code != 201 {
		t.Fatal(rec.Code)
	}
	// Expire it in the database (the DB check fires even when the embedded
	// exp claim would still pass — the row is the authority).
	if _, err := e.srv.Store.Pool.Exec(context.Background(),
		`UPDATE oti SET expires_at = now() - interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	rec, out = e.do(t, credERP, "POST", "/v1/oti/verify", map[string]string{
		"token": out["token"], "purpose": "create_order", "audience": "erp"})
	if rec.Code != 410 || out["error"] != "token_expired" {
		t.Fatalf("expired: %d %s", rec.Code, rec.Body.String())
	}
}

func TestKeyRotationKeepsLookupAndDedupWorking(t *testing.T) {
	e := newE2E(t)
	ctx := context.Background()
	if _, err := e.srv.Store.Pool.Exec(ctx,
		`UPDATE clients SET allowed_actions = allowed_actions || '{lookup}' WHERE client_id='crm'`); err != nil {
		t.Fatal(err)
	}
	cid := registerFilip(t, e)

	// Rotate the email HMAC key; the keyring cache is refreshed by Rotate.
	ring := e.srv.Contacts.Ring
	ks := OpenKeystore(e.srv.Cfg)
	if v, err := ring.Rotate(ctx, ks, "hmac-email"); err != nil || v != "v2" {
		t.Fatalf("rotate: %v %v", v, err)
	}

	// Lookup by email still matches (old-version token in the window).
	rec, out := e.do(t, e.credCRM, "POST", "/v1/lookup", map[string]string{"email": "filip@example.com"})
	if rec.Code != 200 || out["cid"] != cid {
		t.Fatalf("post-rotation lookup: %d %s", rec.Code, rec.Body.String())
	}
	// Re-registration dedups onto the same person AND re-keys the token.
	rec, out = e.do(t, e.credCRM, "POST", "/v1/contacts", map[string]any{"email": "filip@example.com"})
	if rec.Code != 201 || out["cid"] != cid {
		t.Fatalf("post-rotation dedup: %d %s", rec.Code, rec.Body.String())
	}
	// The stored token now differs from any v1 token (re-key on touch):
	// verify by computing the v2 token directly.
	tok2, err := e.srv.Contacts.Tok.EmailToken(ctx, "v2", "filip@example.com")
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := e.srv.Store.Pool.QueryRow(ctx,
		`SELECT count(*) FROM persons WHERE email_token=$1`, tok2).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("token not re-keyed to v2 (matches: %d)", n)
	}
}

func TestKeyRingUnknownKind(t *testing.T) {
	e := newE2E(t)
	if _, err := e.srv.Contacts.Ring.Rotate(context.Background(), OpenKeystore(e.srv.Cfg), "nope"); err == nil {
		t.Fatal("unknown kind must be rejected")
	}
	if _, err := e.srv.Contacts.Ring.Versions(context.Background(), "nope"); err == nil {
		t.Fatal("unknown kind must have no versions")
	}
}
