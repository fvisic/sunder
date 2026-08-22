package api

import (
	"context"
	"testing"

	"github.com/fvisic/sunder/internal/auth"
)

// TestCrossScopeEnrichmentBlocked pins the fix for the M2 review's critical
// finding: a client must NOT be able to register a known identifier, dedup
// onto a person another scope created, and then read attributes that other
// scope stored. Blobs are per-scope, so the attacker sees only what it
// contributed itself.
func TestCrossScopeEnrichmentBlocked(t *testing.T) {
	e := newE2E(t)
	ctx := context.Background()

	// CRM registers Filip with a sensitive attribute.
	rec, _ := e.do(t, e.credCRM, "POST", "/v1/contacts", map[string]any{
		"email": "filip@example.com", "name": "Filip Visic",
		"attributes": map[string]string{"iban": "HR12-SECRET"},
	})
	if rec.Code != 201 {
		t.Fatalf("crm register: %d", rec.Code)
	}

	// Attacker scope knows only the email and has register+read.
	credAtk, err := auth.Create(ctx, e.srv.Store.Pool, auth.Client{
		ID: "webshop", Name: "Webshop", Scope: "webshop",
		AllowedActions:  []string{auth.ActContactsRegister, auth.ActAttributesRead},
		AllowedPurposes: []string{"newsletter"}, RateLimit: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	rec, out := e.do(t, credAtk, "POST", "/v1/contacts", map[string]any{"email": "filip@example.com"})
	if rec.Code != 201 {
		t.Fatalf("webshop register: %d", rec.Code)
	}
	atkCID := out["cid"]

	// The attacker's own scope blob holds only what it sent (the email);
	// CRM's attributes must be unreachable.
	for _, name := range []string{"iban", "name"} {
		rec, _ = e.do(t, credAtk, "GET", "/v1/contacts/"+atkCID+"/attributes/"+name+"?purpose=newsletter", nil)
		if rec.Code != 404 {
			t.Fatalf("cross-scope attribute %q leaked: got %d", name, rec.Code)
		}
	}
	rec, out = e.do(t, credAtk, "GET", "/v1/contacts/"+atkCID+"/attributes/email?purpose=newsletter", nil)
	if rec.Code != 200 || out["value"] != "filip@example.com" {
		t.Fatalf("own attribute must be readable: %d %s", rec.Code, rec.Body.String())
	}
}

func TestReRegisterMergesAttributes(t *testing.T) {
	e := newE2E(t)
	rec, out := e.do(t, e.credCRM, "POST", "/v1/contacts", map[string]any{
		"email": "a@example.com", "attributes": map[string]string{"tier": "gold", "city": "Zagreb"},
	})
	if rec.Code != 201 {
		t.Fatal(rec.Code)
	}
	cid := out["cid"]
	// Second registration adds a phone, updates tier, leaves city intact.
	rec, out = e.do(t, e.credCRM, "POST", "/v1/contacts", map[string]any{
		"email": "a@example.com", "phone": "+385911111111",
		"attributes": map[string]string{"tier": "platinum"},
	})
	if rec.Code != 201 || out["cid"] != cid {
		t.Fatalf("re-register: %d cid=%s want %s", rec.Code, out["cid"], cid)
	}
	for name, want := range map[string]string{"tier": "platinum", "city": "Zagreb", "phone": "+385911111111"} {
		rec, out = e.do(t, e.credCRM, "GET", "/v1/contacts/"+cid+"/attributes/"+name+"?purpose=newsletter", nil)
		if rec.Code != 200 || out["value"] != want {
			t.Fatalf("attribute %s: got %d %q want %q", name, rec.Code, out["value"], want)
		}
	}
}

func TestPhoneOnlyRegistrationAndDedup(t *testing.T) {
	e := newE2E(t)
	rec, out := e.do(t, e.credCRM, "POST", "/v1/contacts", map[string]any{"phone": "+385 92 000 1111"})
	if rec.Code != 201 {
		t.Fatalf("phone-only register: %d", rec.Code)
	}
	cid := out["cid"]
	rec, out = e.do(t, e.credCRM, "POST", "/v1/contacts", map[string]any{"phone": "0038592 000-1111"})
	if rec.Code != 201 || out["cid"] != cid {
		t.Fatalf("phone dedup across formats failed: %d %s want %s", rec.Code, out["cid"], cid)
	}
}

func TestReservedAttributeNamesRejected(t *testing.T) {
	e := newE2E(t)
	rec, out := e.do(t, e.credCRM, "POST", "/v1/contacts", map[string]any{
		"email": "x@example.com", "attributes": map[string]string{"email": "fake@evil.com"},
	})
	if rec.Code != 400 || out["error"] != "validation" {
		t.Fatalf("reserved attribute must be rejected: %d %s", rec.Code, rec.Body.String())
	}
}

func TestPIIFreeRegistration(t *testing.T) {
	// A contact registered with identifiers only still yields a usable CID;
	// identifier attributes are stored, nothing else exists.
	e := newE2E(t)
	rec, out := e.do(t, e.credCRM, "POST", "/v1/contacts", map[string]any{"email": "min@example.com"})
	if rec.Code != 201 {
		t.Fatal(rec.Code)
	}
	rec, _ = e.do(t, e.credCRM, "GET", "/v1/contacts/"+out["cid"]+"/attributes/nonexistent?purpose=newsletter", nil)
	if rec.Code != 404 {
		t.Fatalf("missing attribute must 404, got %d", rec.Code)
	}
}
