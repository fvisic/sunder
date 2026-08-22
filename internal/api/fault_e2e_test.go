package api

// Fault-injection coverage: the failure branches that never fire in happy
// e2e runs — broken key material, corrupted ciphertext, and a database that
// dies mid-flight. Every operation must fail CLOSED with an error, never
// return partial data.

import (
	"context"
	"testing"

	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/crypto"
	"github.com/fvisic/sunder/internal/service"
)

// brokenContacts shares the live pool but has a keystore with no keys: every
// token computation and every decrypt fails.
func brokenContacts(t *testing.T, e *e2eEnv) (*service.Contacts, *service.OTI) {
	t.Helper()
	empty := &crypto.FileKeystore{Dir: t.TempDir()} // strict: no keys, no minting
	c := &service.Contacts{
		Pool: e.srv.Store.Pool,
		Tok:  crypto.NewTokenizer(empty),
		PII:  crypto.NewPIIBox(empty),
		Ring: e.srv.Contacts.Ring,
	}
	o := &service.OTI{Pool: e.srv.Store.Pool, KS: empty, Ring: e.srv.Contacts.Ring, Contacts: c}
	return c, o
}

func TestBrokenKeystoreFailsClosed(t *testing.T) {
	e, _ := gdprEnv(t)
	ctx := context.Background()
	cid := registerFilip(t, e)
	bc, bo := brokenContacts(t, e)
	crm := mustClient(t, e, "crm")

	if _, err := bc.Register(ctx, crm, service.RegisterInput{Email: "x@example.com"}); err == nil {
		t.Fatal("register with no keys must fail")
	}
	if _, err := bc.Lookup(ctx, crm, service.LookupInput{Email: "filip@example.com"}); err == nil {
		t.Fatal("lookup with no keys must fail")
	}
	if _, err := bc.Lookup(ctx, crm, service.LookupInput{Phone: "+385911234567"}); err == nil {
		t.Fatal("phone lookup with no keys must fail")
	}
	if _, err := bc.Lookup(ctx, crm, service.LookupInput{Name: "Filip Visic", Email: "filip@example.com"}); err == nil {
		t.Fatal("name lookup with no keys must fail")
	}
	if _, err := bc.GetAttribute(ctx, crm, cid, "email", "newsletter"); err == nil {
		t.Fatal("attribute read with no keys must fail")
	}
	if _, _, err := bo.Issue(ctx, crm, cid, "newsletter", "erp", nil); err == nil {
		t.Fatal("oti issue with no signing key must fail")
	}
}

func TestCorruptBlobFailsClosed(t *testing.T) {
	e, credDPO := gdprEnv(t)
	ctx := context.Background()
	cid := registerFilip(t, e)
	if _, err := e.srv.Store.Pool.Exec(ctx,
		`UPDATE cids SET pii_encrypted = 'garbage-not-a-ciphertext'::bytea WHERE cid=$1`, cid); err != nil {
		t.Fatal(err)
	}
	rec, _ := e.do(t, e.credCRM, "GET", "/v1/contacts/"+cid+"/attributes/email?purpose=newsletter", nil)
	if rec.Code != 500 {
		t.Fatalf("corrupt blob must be a hard error, got %d", rec.Code)
	}
	rec, _ = e.do(t, credDPO, "GET", "/v1/dsr/access?cid="+cid, nil)
	if rec.Code != 500 {
		t.Fatalf("access over corrupt blob must fail, got %d", rec.Code)
	}
	rec, _ = e.do(t, e.credCRM, "GET", "/v1/dsr/export?cid="+cid, nil)
	if rec.Code != 500 {
		t.Fatalf("export over corrupt blob must fail, got %d", rec.Code)
	}
	// Re-registration must fail rather than silently drop the old attributes
	// it cannot merge.
	rec, _ = e.do(t, e.credCRM, "POST", "/v1/contacts", map[string]any{"email": "filip@example.com"})
	if rec.Code != 500 {
		t.Fatalf("merge over corrupt blob must fail, got %d", rec.Code)
	}
	// The rekey sweep counts it as skipped instead of dying.
	stats, err := e.srv.Contacts.Rekey(ctx, true, 100)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Skipped < 1 {
		t.Fatalf("rekey must count undecryptable blobs: %+v", stats)
	}
}

func TestDeadPoolFailsClosedEverywhere(t *testing.T) {
	e, credDPO := gdprEnv(t)
	ctx := context.Background()
	cid := registerFilip(t, e)
	crm := mustClient(t, e, "crm")
	dpo := mustClient(t, e, "dpo")
	svc := e.srv.Contacts
	gdpr := e.srv.GDPR
	oti := e.srv.OTI
	_ = credDPO

	e.srv.Store.Close() // the database goes away mid-flight

	if _, err := svc.Register(ctx, crm, service.RegisterInput{Email: "dead@example.com"}); err == nil {
		t.Fatal("register on dead pool")
	}
	if _, err := svc.Lookup(ctx, crm, service.LookupInput{Email: "filip@example.com"}); err == nil {
		t.Fatal("lookup on dead pool")
	}
	if _, err := svc.GetAttribute(ctx, crm, cid, "email", "newsletter"); err == nil {
		t.Fatal("attribute on dead pool")
	}
	if _, err := svc.IssueScopedCid(ctx, crm, cid, "billing"); err == nil {
		t.Fatal("scopes on dead pool")
	}
	if _, _, err := oti.Issue(ctx, crm, cid, "newsletter", "erp", nil); err == nil {
		t.Fatal("oti issue on dead pool")
	}
	if _, err := oti.Verify(ctx, crm, "v4.public.junk", "x", "crm"); err == nil {
		t.Fatal("oti verify on dead pool")
	}
	if err := gdpr.SetConsent(ctx, crm, cid, "x", true); err == nil {
		t.Fatal("consent set on dead pool")
	}
	if _, err := gdpr.ListConsents(ctx, crm, cid); err == nil {
		t.Fatal("consent list on dead pool")
	}
	if _, err := gdpr.Access(ctx, dpo, cid); err == nil {
		t.Fatal("access on dead pool")
	}
	if _, err := gdpr.Export(ctx, crm, cid); err == nil {
		t.Fatal("export on dead pool")
	}
	if _, _, err := gdpr.Erase(ctx, dpo, cid); err == nil {
		t.Fatal("erase on dead pool")
	}
	if _, err := gdpr.DeliverPending(ctx); err == nil {
		t.Fatal("deliver on dead pool")
	}
	if _, _, err := service.RunRetention(ctx, e.srv.Store.Pool); err == nil {
		t.Fatal("retention on dead pool")
	}
	if _, err := svc.Rekey(ctx, true, 10); err == nil {
		t.Fatal("rekey on dead pool")
	}
	if _, err := svc.Ring.Rotate(ctx, OpenKeystore(e.srv.Cfg), "hmac-email"); err == nil {
		t.Fatal("rotate on dead pool")
	}
	if err := svc.Ring.Retire(ctx, "hmac-email", "v1"); err == nil {
		t.Fatal("retire on dead pool")
	}
	// The ring cache may still serve versions; force a refresh to hit the DB.
	svc.Ring.Invalidate()
	if _, err := svc.Ring.Versions(ctx, "hmac-email"); err == nil {
		t.Fatal("keyring refresh on dead pool")
	}
}

// mustClient loads the auth.Client row the way the middleware would.
func mustClient(t *testing.T, e *e2eEnv, id string) *auth.Client {
	t.Helper()
	var c auth.Client
	err := e.srv.Store.Pool.QueryRow(context.Background(),
		`SELECT client_id, name, scope, allowed_actions, allowed_purposes, rate_limit FROM clients WHERE client_id=$1`, id).
		Scan(&c.ID, &c.Name, &c.Scope, &c.AllowedActions, &c.AllowedPurposes, &c.RateLimit)
	if err != nil {
		t.Fatal(err)
	}
	return &c
}
