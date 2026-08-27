package api

import (
	"context"
	"testing"
)

func grantLookup(t *testing.T, e *e2eEnv, clientID string) {
	t.Helper()
	if _, err := e.srv.Store.Pool.Exec(context.Background(),
		`UPDATE clients SET allowed_actions = allowed_actions || '{lookup}' WHERE client_id=$1`, clientID); err != nil {
		t.Fatal(err)
	}
}

// A contact with several emails and phones is searchable by every one of
// them, dedups across all of them, and serves each as an attribute.
func TestMultiValueIdentifiers(t *testing.T) {
	e := newE2E(t)
	grantLookup(t, e, "crm")

	rec, out := e.do(t, e.credCRM, "POST", "/v1/contacts", map[string]any{
		"email":  "primary@example.com",
		"emails": []string{"work@example.com", "Private@Example.com"},
		"phone":  "+385911111111",
		"phones": []string{"+385 1 4666-000"},
		"name":   "Multi Person",
	})
	if rec.Code != 201 {
		t.Fatalf("register: %d %s", rec.Code, rec.Body.String())
	}
	cid := out["cid"]

	// Every identifier resolves to the same CID.
	for _, q := range []map[string]string{
		{"email": "primary@example.com"},
		{"email": "work@example.com"},
		{"email": "private@example.com"}, // normalization across case
		{"phone": "+385911111111"},
		{"phone": "+38514666000"},
		{"name": "multi person", "phone": "+38514666000"},
	} {
		rec, out = e.do(t, e.credCRM, "POST", "/v1/lookup", q)
		if rec.Code != 200 || out["cid"] != cid {
			t.Fatalf("lookup %v: %d %s want cid %s", q, rec.Code, rec.Body.String(), cid)
		}
	}

	// Indexed attributes: email (primary), email_2, email_3, phone, phone_2.
	for name, want := range map[string]string{
		"email": "primary@example.com", "email_2": "work@example.com", "email_3": "private@example.com",
		"phone": "+385911111111", "phone_2": "+38514666000",
	} {
		rec, out = e.do(t, e.credCRM, "GET", "/v1/contacts/"+cid+"/attributes/"+name+"?purpose=newsletter", nil)
		if rec.Code != 200 || out["value"] != want {
			t.Fatalf("attribute %s: %d %q want %q", name, rec.Code, out["value"], want)
		}
	}

	// Re-registering via a SECONDARY identifier dedups onto the same person;
	// per the documented merge policy (new values win) the new registration's
	// primary becomes the stored "email".
	rec, out = e.do(t, e.credCRM, "POST", "/v1/contacts", map[string]any{"email": "work@example.com"})
	if rec.Code != 201 || out["cid"] != cid {
		t.Fatalf("dedup via secondary email: %d cid=%s want %s", rec.Code, out["cid"], cid)
	}
	rec, out = e.do(t, e.credCRM, "GET", "/v1/contacts/"+cid+"/attributes/email?purpose=newsletter", nil)
	if rec.Code != 200 || out["value"] != "work@example.com" {
		t.Fatalf("merge policy (new wins) not applied: %d %q", rec.Code, out["value"])
	}

	// Reserved generated names are rejected as caller attributes.
	rec, _ = e.do(t, e.credCRM, "POST", "/v1/contacts", map[string]any{
		"email": "x1@example.com", "attributes": map[string]string{"email_2": "fake@evil.com"}})
	if rec.Code != 400 {
		t.Fatalf("reserved email_2 attribute must be rejected: %d", rec.Code)
	}
}

// An identifier already owned by one person is never silently stolen by a
// later registration that also claims it.
func TestIdentifierOwnershipNotStolen(t *testing.T) {
	e := newE2E(t)
	grantLookup(t, e, "crm")

	rec, out := e.do(t, e.credCRM, "POST", "/v1/contacts", map[string]any{"email": "owner@example.com"})
	if rec.Code != 201 {
		t.Fatal(rec.Code)
	}
	emailOwner := out["cid"]
	rec, out = e.do(t, e.credCRM, "POST", "/v1/contacts", map[string]any{"phone": "+385920000001"})
	if rec.Code != 201 {
		t.Fatal(rec.Code)
	}
	phoneOwner := out["cid"]
	if phoneOwner == emailOwner {
		t.Fatal("distinct persons collapsed")
	}

	// An ambiguous claim (email of person A + phone of person B) resolves by
	// the documented email-priority rule to A - and B's phone is NOT stolen.
	rec, out = e.do(t, e.credCRM, "POST", "/v1/contacts", map[string]any{
		"phone": "+385920000001", "emails": []string{"owner@example.com"}})
	if rec.Code != 201 || out["cid"] != emailOwner {
		t.Fatalf("ambiguous claim must resolve to the email owner: %d %s want %s", rec.Code, out["cid"], emailOwner)
	}
	rec, out = e.do(t, e.credCRM, "POST", "/v1/lookup", map[string]string{"email": "owner@example.com"})
	if rec.Code != 200 || out["cid"] != emailOwner {
		t.Fatalf("email ownership moved: %d %s", rec.Code, out["cid"])
	}
	rec, out = e.do(t, e.credCRM, "POST", "/v1/lookup", map[string]string{"phone": "+385920000001"})
	if rec.Code != 200 || out["cid"] != phoneOwner {
		t.Fatalf("phone ownership stolen: %d %s want %s", rec.Code, out["cid"], phoneOwner)
	}
}

// Retiring an HMAC key version purges its token rows: identifiers stored
// only under that version stop matching until re-registered.
func TestRetirePurgesTokenRows(t *testing.T) {
	e := newE2E(t)
	grantLookup(t, e, "crm")
	ctx := context.Background()

	rec, out := e.do(t, e.credCRM, "POST", "/v1/contacts", map[string]any{"email": "purge@example.com"})
	if rec.Code != 201 {
		t.Fatal(rec.Code)
	}
	original := out["cid"]
	var personsBefore int
	if err := e.srv.Store.Pool.QueryRow(ctx, `SELECT count(*) FROM persons`).Scan(&personsBefore); err != nil {
		t.Fatal(err)
	}
	if _, err := e.srv.Contacts.Ring.Rotate(ctx, OpenEngine(e.srv.Cfg), "hmac-email"); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.Contacts.Ring.Retire(ctx, "hmac-email", "v1"); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := e.srv.Store.Pool.QueryRow(ctx,
		`SELECT count(*) FROM person_tokens WHERE kind='email' AND key_version='v1'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("retired-version token rows not purged: %d left", n)
	}
	// v1-only identifier no longer matches (documented consequence).
	rec, _ = e.do(t, e.credCRM, "POST", "/v1/lookup", map[string]string{"email": "purge@example.com"})
	if rec.Code != 404 {
		t.Fatalf("v1-only identifier must stop matching after retire: %d", rec.Code)
	}
	// Re-registration under v2 restores it - as a NEW person. That fork is
	// the real consequence of retiring the only key version an identifier
	// was stored under, and the test used to discard the returned cid and
	// never count `persons`, so it was neither asserted nor documented
	// (TESTS-16). Assert it explicitly: it is a behaviour a maintainer must
	// change deliberately, not discover.
	rec, out = e.do(t, e.credCRM, "POST", "/v1/contacts", map[string]any{"email": "purge@example.com"})
	if rec.Code != 201 {
		t.Fatal(rec.Code)
	}
	if out["cid"] == original {
		t.Fatal("unexpected: the pre-retire person was reused - if Retire now re-mints identifier tokens under the newest ACTIVE version, this test and the docs both need updating")
	}
	var personsAfter int
	if err := e.srv.Store.Pool.QueryRow(ctx, `SELECT count(*) FROM persons`).Scan(&personsAfter); err != nil {
		t.Fatal(err)
	}
	if personsAfter != personsBefore+1 {
		t.Fatalf("re-registration after a retire forks the person: expected %d persons, got %d",
			personsBefore+1, personsAfter)
	}
	rec, _ = e.do(t, e.credCRM, "POST", "/v1/lookup", map[string]string{"email": "purge@example.com"})
	if rec.Code != 200 {
		t.Fatalf("re-registered identifier must match again: %d", rec.Code)
	}
}
