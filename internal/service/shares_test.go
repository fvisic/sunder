package service_test

import (
	"context"
	"errors"
	"testing"

	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/service"
)

func sharesEnv(t *testing.T) (*faultEnv, *service.Shares, *auth.Client, string) {
	t.Helper()
	e := newFaultEnv(t)
	sh := &service.Shares{Pool: e.admin.Pool, Contacts: e.svc}
	client := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions:  []string{auth.ActSharesCreate, auth.ActContactsRegister, auth.ActConsentManage, auth.ActDSRErase},
		AllowedPurposes: []string{"support"}}
	ctx := context.Background()
	cid, err := e.svc.Register(ctx, client, service.RegisterInput{
		Email: "ana@example.com", Attributes: map[string]string{"iban": "HR12", "tier": "gold"}})
	if err != nil {
		t.Fatal(err)
	}
	return e, sh, client, cid
}

func TestShareLifecycle(t *testing.T) {
	_, sh, client, cid := sharesEnv(t)
	ctx := context.Background()
	uuid, exp, err := sh.Create(ctx, client, service.ShareInput{
		CID: cid, Fields: []string{"iban"}, PartnerLabel: "acme-bank", TTLSeconds: 3600})
	if err != nil || uuid == "" || exp.IsZero() {
		t.Fatalf("create: %q %v", uuid, err)
	}
	// Fetch returns only the listed field (not tier).
	out, err := sh.Fetch(ctx, "partner", uuid)
	if err != nil || out["iban"] != "HR12" || out["tier"] != "" {
		t.Fatalf("fetch must project only listed fields: %+v %v", out, err)
	}
	// Revoke, then fetch is a miss.
	if err := sh.Revoke(ctx, client, uuid); err != nil {
		t.Fatal(err)
	}
	if _, err := sh.Fetch(ctx, "partner", uuid); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("revoked share must miss: %v", err)
	}
	if err := sh.Revoke(ctx, client, uuid); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("double revoke must be a miss: %v", err)
	}
}

func TestShareGuards(t *testing.T) {
	_, sh, client, cid := sharesEnv(t)
	ctx := context.Background()
	// Permission.
	noPerm := &auth.Client{ID: "np", Scope: "crm"}
	if _, _, err := sh.Create(ctx, noPerm, service.ShareInput{CID: cid, Fields: []string{"iban"}, PartnerLabel: "x", TTLSeconds: 60}); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("create without action: %v", err)
	}
	// No fields, too many fields, no label, bad TTL.
	bad := []service.ShareInput{
		{CID: cid, Fields: nil, PartnerLabel: "x", TTLSeconds: 60},
		{CID: cid, Fields: []string{"iban"}, PartnerLabel: "", TTLSeconds: 60},
		{CID: cid, Fields: []string{"iban"}, PartnerLabel: "x", TTLSeconds: 0},
		{CID: cid, Fields: []string{"iban"}, PartnerLabel: "x", TTLSeconds: 100 * 24 * 3600},
	}
	for i, in := range bad {
		if _, _, err := sh.Create(ctx, client, in); !errors.Is(err, service.ErrValidation) {
			t.Fatalf("bad input %d must be validation: %v", i, err)
		}
	}
	// A narrowed client cannot share a field it may not read (F3 allowlist).
	narrowed := &auth.Client{ID: "n", Scope: "crm",
		AllowedActions: []string{auth.ActSharesCreate}, AllowedAttributes: []string{"tier"}}
	if _, _, err := sh.Create(ctx, narrowed, service.ShareInput{CID: cid, Fields: []string{"iban"}, PartnerLabel: "x", TTLSeconds: 60}); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("sharing a forbidden field must be refused: %v", err)
	}
	// Unknown cid.
	if _, _, err := sh.Create(ctx, client, service.ShareInput{CID: "CID-NO", Fields: []string{"iban"}, PartnerLabel: "x", TTLSeconds: 60}); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("unknown cid: %v", err)
	}
	// Fetch of an unknown uuid is a miss.
	if _, err := sh.Fetch(ctx, "partner", "00000000-0000-4000-8000-000000000000"); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("unknown share fetch: %v", err)
	}
	// Revoke without action, and cross-scope revoke, are refused/missed.
	if err := sh.Revoke(ctx, noPerm, "00000000-0000-4000-8000-000000000000"); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("revoke without action: %v", err)
	}
}

func TestShareExpiryIsAMiss(t *testing.T) {
	e, sh, client, cid := sharesEnv(t)
	ctx := context.Background()
	uuid, _, err := sh.Create(ctx, client, service.ShareInput{CID: cid, Fields: []string{"iban"}, PartnerLabel: "x", TTLSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.admin.Pool.Exec(ctx, `UPDATE shared_records SET expires_at = now() - interval '1 hour' WHERE uuid=$1`, uuid); err != nil {
		t.Fatal(err)
	}
	if _, err := sh.Fetch(ctx, "partner", uuid); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("expired share must miss: %v", err)
	}
	// Prune removes long-expired shares.
	if _, err := e.admin.Pool.Exec(ctx, `UPDATE shared_records SET expires_at = now() - interval '40 days' WHERE uuid=$1`, uuid); err != nil {
		t.Fatal(err)
	}
	n, err := service.PruneShares(ctx, e.admin.Pool)
	if err != nil || n != 1 {
		t.Fatalf("prune: %d %v", n, err)
	}
}

func TestShareRevokedByErasureAndConsent(t *testing.T) {
	e, sh, client, cid := sharesEnv(t)
	ctx := context.Background()

	// Consent withdrawal revokes standing shares.
	u1, _, err := sh.Create(ctx, client, service.ShareInput{CID: cid, Fields: []string{"iban"}, PartnerLabel: "p1", TTLSeconds: 3600})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.gdpr.SetConsent(ctx, client, cid, "support", false); err != nil {
		t.Fatal(err)
	}
	if _, err := sh.Fetch(ctx, "p1", u1); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("consent withdrawal must revoke the share: %v", err)
	}

	// Erasure revokes standing shares.
	cid2, err := e.svc.Register(ctx, client, service.RegisterInput{Email: "bob@example.com", Attributes: map[string]string{"iban": "HR99"}})
	if err != nil {
		t.Fatal(err)
	}
	u2, _, err := sh.Create(ctx, client, service.ShareInput{CID: cid2, Fields: []string{"iban"}, PartnerLabel: "p2", TTLSeconds: 3600})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.gdpr.Erase(ctx, client, cid2); err != nil {
		t.Fatal(err)
	}
	if _, err := sh.Fetch(ctx, "p2", u2); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("erasure must revoke the share: %v", err)
	}
}

func TestShareFailsClosed(t *testing.T) {
	e := newFaultEnv(t, "shared_records")
	sh := &service.Shares{Pool: e.svc.Pool, Contacts: e.svc}
	client := &auth.Client{ID: "crm", Scope: "crm", AllowedActions: []string{auth.ActSharesCreate}}
	ctx := context.Background()
	cid := e.register(t)
	if _, _, err := sh.Create(ctx, client, service.ShareInput{CID: cid, Fields: []string{"iban"}, PartnerLabel: "x", TTLSeconds: 60}); err == nil {
		t.Fatal("create must fail when shared_records is denied")
	}
	if _, err := sh.Fetch(ctx, "p", "00000000-0000-4000-8000-000000000000"); err == nil {
		t.Fatal("fetch must fail when shared_records is denied")
	}
	if err := sh.Revoke(ctx, client, "00000000-0000-4000-8000-000000000000"); err == nil {
		t.Fatal("revoke must fail when shared_records is denied")
	}
}

func TestShareFetchDecryptFault(t *testing.T) {
	e, sh, client, cid := sharesEnv(t)
	ctx := context.Background()
	uuid, _, err := sh.Create(ctx, client, service.ShareInput{CID: cid, Fields: []string{"iban"}, PartnerLabel: "x", TTLSeconds: 3600})
	if err != nil {
		t.Fatal(err)
	}
	// Break cids so decryptCID fails during fetch.
	if _, err := e.admin.Pool.Exec(ctx, `ALTER TABLE cids RENAME TO cids_share_gone`); err != nil {
		t.Fatal(err)
	}
	if _, err := sh.Fetch(ctx, "p", uuid); err == nil {
		t.Fatal("fetch must surface a decrypt/query error")
	}
}

func TestShareFieldCountCap(t *testing.T) {
	_, sh, client, cid := sharesEnv(t)
	ctx := context.Background()
	many := make([]string, 33)
	for i := range many {
		many[i] = "f"
	}
	if _, _, err := sh.Create(ctx, client, service.ShareInput{CID: cid, Fields: many, PartnerLabel: "x", TTLSeconds: 60}); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("over-cap fields must be rejected: %v", err)
	}
	// A long partner label is rejected too.
	long := make([]byte, 200)
	for i := range long {
		long[i] = 'a'
	}
	if _, _, err := sh.Create(ctx, client, service.ShareInput{CID: cid, Fields: []string{"iban"}, PartnerLabel: string(long), TTLSeconds: 60}); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("over-long label must be rejected: %v", err)
	}
}

func TestShareEmptyBlobAndAuditFaults(t *testing.T) {
	e, sh, client, _ := sharesEnv(t)
	ctx := context.Background()
	// A person with NO attributes: the share fetch returns an empty map
	// (decryptCID's empty-blob branch), not an error.
	bare, err := e.svc.Register(ctx, client, service.RegisterInput{Email: "bare@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	u, _, err := sh.Create(ctx, client, service.ShareInput{CID: bare, Fields: []string{"iban"}, PartnerLabel: "x", TTLSeconds: 3600})
	if err != nil {
		t.Fatal(err)
	}
	out, err := sh.Fetch(ctx, "p", u)
	if err != nil || len(out) != 0 {
		t.Fatalf("empty-blob share must fetch an empty map: %+v %v", out, err)
	}

	// Audit denied: a fetch that would audit-on-hit must fail closed.
	e2 := newFaultEnv(t, "audit", "audit_read_buckets")
	sh2 := &service.Shares{Pool: e2.svc.Pool, Contacts: e2.svc}
	cid := e2.register(t)
	// Seed a live share row via the admin pool (Create would fail on audit).
	if _, err := e2.admin.Pool.Exec(ctx, `
		INSERT INTO shared_records (uuid, cid, scope, fields, partner_label, expires_at, created_by)
		VALUES ('00000000-0000-4000-8000-00000000abcd', $1, 'crm', ARRAY['x'], 'p', now()+interval '1 hour', 'crm')`, cid); err != nil {
		t.Fatal(err)
	}
	if _, err := sh2.Fetch(ctx, "p", "00000000-0000-4000-8000-00000000abcd"); err == nil {
		t.Fatal("fetch must fail closed when the read cannot be audited")
	}
	// Create must also fail closed when the chained audit cannot be written.
	client2 := &auth.Client{ID: "crm", Scope: "crm", AllowedActions: []string{auth.ActSharesCreate}}
	if _, _, err := sh2.Create(ctx, client2, service.ShareInput{CID: cid, Fields: []string{"x"}, PartnerLabel: "p", TTLSeconds: 60}); err == nil {
		t.Fatal("create must fail closed when the audit is denied")
	}
}
