package service_test

// H2 regression: registration dedup was a check-then-act under READ
// COMMITTED whose only enforcement - the partial unique index
// person_tokens_ident_uq - was disarmed by an unarbitrated ON CONFLICT DO
// NOTHING. The loser committed a second person holding no identifier token,
// invisible to lookup, to the portal and to erasure.

import (
	"context"
	"sync"
	"testing"

	"github.com/fvisic/sunder/internal/service"
)

// TestConcurrentRegisterSameEmailYieldsOnePerson: N writers, one identifier,
// one person. Fails before the fix with 2+ persons rows.
func TestConcurrentRegisterSameEmailYieldsOnePerson(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()

	const writers = 8
	var start sync.WaitGroup
	start.Add(1)
	var wg sync.WaitGroup
	cids := make([]string, writers)
	errs := make([]error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			start.Wait()
			cids[i], errs[i] = e.svc.Register(ctx, e.crm, service.RegisterInput{
				Email: "race@example.com", Name: "Race Case",
				Attributes: map[string]string{"tier": "gold"},
			})
		}(i)
	}
	start.Done()
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("writer %d: %v", i, err)
		}
	}
	for i, cid := range cids {
		if cid != cids[0] {
			t.Fatalf("writer %d got cid %q, writer 0 got %q - the dedup race minted a second person",
				i, cid, cids[0])
		}
	}
	var persons, tokens int
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT (SELECT count(*) FROM persons),
		        (SELECT count(*) FROM person_tokens WHERE kind='email')`).Scan(&persons, &tokens); err != nil {
		t.Fatal(err)
	}
	if persons != 1 {
		t.Fatalf("one identifier must mint exactly one person, got %d", persons)
	}
	if tokens != 1 {
		t.Fatalf("expected exactly one email token row, got %d", tokens)
	}
}

// TestRegisterDedupRaceInterleaved drives the exact statement order that
// produced the duplicate: A probes, B probes, A inserts, B inserts (and
// blocks), A commits, B unblocks. The unarbitrated DO NOTHING turned B's
// blocked insert into a silent no-op; the explicit PK arbiter makes it the
// 23505 the retry loop was always written to consume.
func TestRegisterDedupRaceInterleaved(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()

	txA, err := e.admin.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = txA.Rollback(ctx) }()
	txB, err := e.admin.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = txB.Rollback(ctx) }()

	const tok = "tok-race"
	// Both probe and find nothing.
	var scratch string
	if err := txA.QueryRow(ctx,
		`SELECT person_id FROM person_tokens WHERE kind='email' AND token=$1`, tok).Scan(&scratch); err == nil {
		t.Fatal("precondition: token must not exist")
	}
	if err := txB.QueryRow(ctx,
		`SELECT person_id FROM person_tokens WHERE kind='email' AND token=$1`, tok).Scan(&scratch); err == nil {
		t.Fatal("precondition: token must not exist")
	}

	var personA, personB string
	if err := txA.QueryRow(ctx, `INSERT INTO persons (id) VALUES (gen_random_uuid()) RETURNING id`).Scan(&personA); err != nil {
		t.Fatal(err)
	}
	if err := txB.QueryRow(ctx, `INSERT INTO persons (id) VALUES (gen_random_uuid()) RETURNING id`).Scan(&personB); err != nil {
		t.Fatal(err)
	}
	if _, err := txA.Exec(ctx,
		`INSERT INTO person_tokens (person_id, kind, token, key_version) VALUES ($1,'email',$2,'v1')
		 ON CONFLICT (person_id, kind, token) DO NOTHING`, personA, tok); err != nil {
		t.Fatal(err)
	}

	// B's insert blocks on A's speculative insertion; run it concurrently.
	berr := make(chan error, 1)
	go func() {
		_, err := txB.Exec(ctx,
			`INSERT INTO person_tokens (person_id, kind, token, key_version) VALUES ($1,'email',$2,'v1')
			 ON CONFLICT (person_id, kind, token) DO NOTHING`, personB, tok)
		berr <- err
	}()
	if err := txA.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-berr; err == nil {
		t.Fatal("B's insert of an identifier owned by A must raise 23505, not be silently dropped")
	}
	_ = txB.Rollback(ctx)

	var persons int
	if err := e.admin.Pool.QueryRow(ctx, `SELECT count(*) FROM persons`).Scan(&persons); err != nil {
		t.Fatal(err)
	}
	if persons != 1 {
		t.Fatalf("the loser must abort, leaving one person; got %d", persons)
	}
}

// TestEraseAfterDedupRaceLeavesNoBlob: whatever the race does, erasing by
// the cid the caller can find must leave no PII blob anywhere.
func TestEraseAfterDedupRaceLeavesNoBlob(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()

	const writers = 6
	var start sync.WaitGroup
	start.Add(1)
	var wg sync.WaitGroup
	cids := make([]string, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			start.Wait()
			cid, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
				Email: "erase-race@example.com", Name: "Erase Race",
			})
			if err != nil {
				t.Error(err)
				return
			}
			cids[i] = cid
		}(i)
	}
	start.Done()
	wg.Wait()

	if _, _, err := e.gdpr.Erase(ctx, e.crm, cids[0]); err != nil {
		t.Fatal(err)
	}
	e.gdpr.Drain()
	var live int
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM cids WHERE pii_encrypted IS NOT NULL`).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live != 0 {
		t.Fatalf("erasing the findable cid left %d PII blob(s) behind", live)
	}
}

// TestAmbiguousClaimStillDoesNotStealOrFail pins the OTHER half of the
// conflict semantics: when the dedup probe DID find an owner, a secondary
// identifier belonging to a third party is skipped (not stolen, not fatal).
// The H2 fix must not turn this documented behaviour into a 500.
func TestAmbiguousClaimStillDoesNotStealOrFail(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()

	emailOwner, err := e.svc.Register(ctx, e.crm, service.RegisterInput{Email: "owner@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	phoneOwner, err := e.svc.Register(ctx, e.crm, service.RegisterInput{Phone: "+385920000001"})
	if err != nil {
		t.Fatal(err)
	}
	if emailOwner == phoneOwner {
		t.Fatal("distinct persons collapsed")
	}
	// E-mail priority resolves to the e-mail owner; the phone stays with its
	// owner rather than aborting the registration.
	got, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
		Email: "owner@example.com", Phone: "+385920000001"})
	if err != nil {
		t.Fatalf("an ambiguous claim must not fail: %v", err)
	}
	if got != emailOwner {
		t.Fatalf("ambiguous claim resolved to %s, want the e-mail owner %s", got, emailOwner)
	}
	hit, err := e.svc.Lookup(ctx, e.crm, service.LookupInput{Phone: "+385920000001"})
	if err != nil {
		t.Fatal(err)
	}
	if hit != phoneOwner {
		t.Fatalf("phone ownership moved to %s, want %s", hit, phoneOwner)
	}
}
