package service_test

// GDPR-ERASURE-5 / GDPR-ERASURE-6 / DB-TXN-3.
//
// Four person-scoped writers resolved the person on the POOL and then
// inserted inside a transaction with no lock and no re-check. Under READ
// COMMITTED that liveness answer is already stale: an erasure committing in
// the gap deleted rows that did not exist yet, so the write survived the
// sweep the erasure code promises empties those tables. The fix is a locking
// re-read inside the transaction, taking exactly erasePerson's lock prefix -
// which also removes the ABBA cycle OTI verification closed with it.

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/service"
)

func countRows(t *testing.T, e *faultEnv, q string, args ...any) int {
	t.Helper()
	var n int
	if err := e.admin.Pool.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Each writer must refuse once the person is a tombstone, and must leave no
// row behind. The non-racing form pins the invariant; the racing form below
// pins that the window is actually closed.
func TestPersonScopedWritersRefuseTombstones(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()

	shares := &service.Shares{Pool: e.svc.Pool, Contacts: e.svc}
	links := &service.Links{Pool: e.svc.Pool, Contacts: e.svc}
	sharer := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions: []string{auth.ActContactsRegister, auth.ActSharesCreate,
			auth.ActLinksManage, auth.ActAttributesRead},
		AllowedPurposes: []string{"support"}}

	cid := e.register(t)
	other, err := e.svc.Register(ctx, e.crm, service.RegisterInput{Email: "counterparty@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.gdpr.Erase(ctx, e.crm, cid); err != nil {
		t.Fatal(err)
	}
	e.gdpr.Drain()

	if err := e.gdpr.SetConsent(ctx, e.crm, cid, "support", true); err == nil {
		t.Error("SetConsent must refuse a tombstoned person")
	}
	if _, _, err := shares.Create(ctx, sharer, service.ShareInput{
		CID: cid, Fields: []string{"tier"}, PartnerLabel: "p", Purpose: "support", TTLSeconds: 3600,
	}); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("Shares.Create must refuse a tombstoned person with ErrNotFound, got %v", err)
	}
	if err := links.Link(ctx, sharer, other, cid, "guardian"); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("Links.Link must refuse a tombstoned endpoint with ErrNotFound, got %v", err)
	}
	if _, _, err := e.oti.Issue(ctx, e.crm, cid, "support", "billing", nil); err == nil {
		t.Error("OTI.Issue must refuse a tombstoned person")
	}

	if n := countRows(t, e, `SELECT count(*) FROM consents WHERE cid=$1`, cid); n != 0 {
		t.Errorf("%d consent row(s) written for an erased person", n)
	}
	if n := countRows(t, e, `SELECT count(*) FROM shared_records WHERE cid=$1`, cid); n != 0 {
		t.Errorf("%d share(s) written for an erased person", n)
	}
	if n := countRows(t, e, `SELECT count(*) FROM oti WHERE cid=$1 AND status='VALID'`, cid); n != 0 {
		t.Errorf("%d VALID OTI(s) for an erased person", n)
	}
}

// Readers must not surface a row that outlived its subject, whatever wrote
// it. This is the defence-in-depth half.
func TestReadersHideRowsOfErasedPersons(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	shares := &service.Shares{Pool: e.svc.Pool, Contacts: e.svc}
	links := &service.Links{Pool: e.svc.Pool, Contacts: e.svc}
	// shares.create + links.manage are not in the default fault-env client.
	sharer := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions: []string{auth.ActContactsRegister, auth.ActSharesCreate,
			auth.ActLinksManage, auth.ActAttributesRead},
		AllowedPurposes: []string{"support"}}

	cid := e.register(t)
	other, err := e.svc.Register(ctx, e.crm, service.RegisterInput{Email: "survivor@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if err := links.Link(ctx, sharer, other, cid, "guardian"); err != nil {
		t.Fatal(err)
	}
	shareID, _, err := shares.Create(ctx, sharer, service.ShareInput{
		CID: cid, Fields: []string{"tier"}, PartnerLabel: "p", Purpose: "support", TTLSeconds: 3600})
	if err != nil {
		t.Fatal(err)
	}
	// Tombstone the person WITHOUT running the erasure's deletes: exactly
	// the state the race used to leave behind.
	if _, err := e.admin.Pool.Exec(ctx,
		`UPDATE persons SET erased_at=now() WHERE id=(SELECT person_id FROM cids WHERE cid=$1)`, cid); err != nil {
		t.Fatal(err)
	}
	if _, err := shares.Fetch(ctx, "crm", shareID); err != service.ErrNotFound {
		t.Fatalf("a share whose subject is erased must 404, got %v", err)
	}
	listed, err := links.List(ctx, sharer, other)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range listed {
		if l.CID == cid {
			t.Fatal("the surviving side's link listing exposed the erased person's pseudonym")
		}
	}
}

// The race itself: N writers against a concurrent erasure. Whatever the
// interleaving, no row for the erased person may survive - and nothing may
// come back as a deadlock (DB-TXN-3).
func TestConcurrentWritersAndErasureLeaveNothingBehind(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	shares := &service.Shares{Pool: e.svc.Pool, Contacts: e.svc}
	sharer := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions:  []string{auth.ActSharesCreate, auth.ActAttributesRead},
		AllowedPurposes: []string{"support"}}

	for round := 0; round < 12; round++ {
		cid, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
			Email: "race-writer@example.com", Name: "Race Writer"})
		if err != nil {
			t.Fatal(err)
		}
		var start sync.WaitGroup
		start.Add(1)
		var wg sync.WaitGroup
		errs := make([]error, 3)
		wg.Add(3)
		go func() {
			defer wg.Done()
			start.Wait()
			_, _, errs[0] = e.gdpr.Erase(ctx, e.crm, cid)
		}()
		go func() {
			defer wg.Done()
			start.Wait()
			errs[1] = e.gdpr.SetConsent(ctx, e.crm, cid, "support", true)
		}()
		go func() {
			defer wg.Done()
			start.Wait()
			_, _, errs[2] = shares.Create(ctx, sharer, service.ShareInput{
				CID: cid, Fields: []string{"tier"}, PartnerLabel: "p",
				Purpose: "support", TTLSeconds: 3600})
		}()
		start.Done()
		wg.Wait()
		e.gdpr.Drain()

		for i, err := range errs {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "40P01" {
				t.Fatalf("round %d writer %d surfaced a deadlock: %v", round, i, err)
			}
		}
		// The erasure either won (nothing survives) or lost to an
		// already-erased guard; either way no row may reference the person
		// once erased_at is set.
		var erased bool
		if err := e.admin.Pool.QueryRow(ctx,
			`SELECT erased_at IS NOT NULL FROM persons WHERE id=(SELECT person_id FROM cids WHERE cid=$1)`,
			cid).Scan(&erased); err != nil {
			t.Fatal(err)
		}
		if !erased {
			t.Fatalf("round %d: erasure did not happen: %v", round, errs[0])
		}
		if n := countRows(t, e, `SELECT count(*) FROM consents WHERE cid=$1`, cid); n != 0 {
			t.Fatalf("round %d: %d consent row(s) survived the erasure", round, n)
		}
		if n := countRows(t, e, `SELECT count(*) FROM shared_records WHERE cid=$1`, cid); n != 0 {
			t.Fatalf("round %d: %d share(s) survived the erasure", round, n)
		}
	}
}

// DB-TXN-3: an OTI verification for a scope the person has no cid in, racing
// an erasure of that person. Neither side may come back as SQLSTATE 40P01.
func TestOTIVerifyAndErasureDoNotDeadlock(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	verifier := &auth.Client{ID: "gov", Scope: "gov",
		AllowedActions:  []string{auth.ActOTIVerify, auth.ActAttributesRead},
		AllowedPurposes: []string{"support"}}

	for round := 0; round < 12; round++ {
		cid, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
			Email: "race-oti@example.com", Name: "Race OTI",
			Attributes: map[string]string{"tier": "gold"}})
		if err != nil {
			t.Fatal(err)
		}
		tok, _, err := e.oti.Issue(ctx, e.crm, cid, "support", "gov", []string{"tier"})
		if err != nil {
			t.Fatal(err)
		}
		var start sync.WaitGroup
		start.Add(1)
		var wg sync.WaitGroup
		wg.Add(2)
		var verifyErr, eraseErr error
		go func() {
			defer wg.Done()
			start.Wait()
			_, verifyErr = e.oti.Verify(ctx, verifier, tok, "support", "gov")
		}()
		go func() {
			defer wg.Done()
			start.Wait()
			_, _, eraseErr = e.gdpr.Erase(ctx, e.crm, cid)
		}()
		start.Done()
		wg.Wait()
		e.gdpr.Drain()

		for _, err := range []error{verifyErr, eraseErr} {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "40P01" {
				t.Fatalf("round %d: deadlock surfaced to a caller: %v", round, err)
			}
		}
		if eraseErr != nil {
			t.Fatalf("round %d: the erasure must not be the victim: %v", round, eraseErr)
		}
		// However the race resolved, the erased person must not have gained
		// a live blob in the verifier's scope.
		if n := countRows(t, e,
			`SELECT count(*) FROM cids WHERE person_id=(SELECT person_id FROM cids WHERE cid=$1)
			   AND pii_encrypted IS NOT NULL`, cid); n != 0 {
			t.Fatalf("round %d: %d live blob(s) after the erasure", round, n)
		}
	}
}
