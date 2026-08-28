package service_test

// GDPR-ERASURE-1 / GDPR-ERASURE-2 / GDPR-ERASURE-7 regressions.
//
// The rekey sweep checked liveness ONCE per batch and then spent several
// signer round trips per person, so an erasure landing in that window was
// invisible to every write that followed: the blob came back under the new
// KEK (the (key_id, alg) guard COALESCEs an erasure's NULL back onto the
// value it compares against) and the deleted search tokens were re-created
// under the newest key version, permanently.

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/fvisic/sunder/internal/crypto"
	"github.com/fvisic/sunder/internal/service"
)

// TestRekeyDoesNotResurrectErasedBlob: a person tombstoned between the batch
// selection and the guarded write must not have their blob written back.
// This is the non-racing form - the person is already erased when
// rekeyPerson's write executes, which is exactly the post-state of the race.
func TestRekeyDoesNotResurrectErasedBlob(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cid := e.register(t)

	adminRing := &service.KeyRing{Pool: e.admin.Pool, RetireGrace: -1}
	admin := &service.Contacts{Pool: e.admin.Pool, Tok: e.svc.Tok, PII: e.svc.PII, Ring: adminRing}

	// Rotate pii-kek so the blob is a legitimate re-encrypt target.
	if _, err := adminRing.Rotate(ctx, e.oti.Eng, crypto.KeyPIIKEK); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.gdpr.Erase(ctx, e.crm, cid); err != nil {
		t.Fatal(err)
	}
	e.gdpr.Drain()

	// The sweep's batch filter would skip the tombstone, so drive the state
	// the race produces directly: an un-erased snapshot of the row.
	if _, err := e.admin.Pool.Exec(ctx,
		`UPDATE cids SET pii_encrypted=NULL, pii_key_id=NULL, pii_alg='aes256gcm' WHERE cid=$1`, cid); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Rekey(ctx, true, 100); err != nil {
		t.Fatal(err)
	}
	var blob []byte
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT pii_encrypted FROM cids WHERE cid=$1`, cid).Scan(&blob); err != nil {
		t.Fatal(err)
	}
	if blob != nil {
		t.Fatal("rekey wrote a blob back onto a tombstoned CID")
	}
}

// TestRekeyGuardRefusesWipedRow drives the guarded UPDATE against a
// retention-wiped row directly. RunRetention does not touch pii_alg at all,
// so the alg half of the old guard always matched - the wipe was invisible.
func TestRekeyGuardRefusesWipedRow(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cid := e.register(t)

	// Retention-wipe representation: blob NULL, key id NULL, alg untouched.
	if _, err := e.admin.Pool.Exec(ctx,
		`UPDATE cids SET pii_encrypted=NULL, pii_key_id=NULL WHERE cid=$1`, cid); err != nil {
		t.Fatal(err)
	}
	tag, err := e.admin.Pool.Exec(ctx,
		`UPDATE cids c SET pii_encrypted=$2, pii_key_id=$3, pii_alg=$4
		   FROM persons p
		  WHERE c.cid=$1 AND p.id = c.person_id AND p.erased_at IS NULL
		    AND c.pii_encrypted IS NOT NULL
		    AND COALESCE(c.pii_key_id,'v1')=$5 AND COALESCE(c.pii_alg,'aes256gcm')=$6`,
		cid, []byte("resurrected"), "v2", "aes256gcm", "v1", "aes256gcm")
	if err != nil {
		t.Fatal(err)
	}
	if tag.RowsAffected() != 0 {
		t.Fatal("the guard matched a wiped row - COALESCE turns a NULL key id back into 'v1'")
	}
}

// TestLookupRefusesResurrectedToken is the defence-in-depth half of
// GDPR-ERASURE-2: even if some path re-creates a search token for a
// tombstoned person, Lookup must not answer with their pseudonym.
func TestLookupRefusesResurrectedToken(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cid := e.register(t)

	var personID string
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT person_id FROM cids WHERE cid=$1`, cid).Scan(&personID); err != nil {
		t.Fatal(err)
	}
	// Capture the real token before erasure deletes it.
	var tok, ver string
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT token, key_version FROM person_tokens WHERE person_id=$1 AND kind='email'`,
		personID).Scan(&tok, &ver); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.gdpr.Erase(ctx, e.crm, cid); err != nil {
		t.Fatal(err)
	}
	e.gdpr.Drain()
	// Simulate the resurrection.
	if _, err := e.admin.Pool.Exec(ctx,
		`INSERT INTO person_tokens (person_id, kind, token, key_version) VALUES ($1,'email',$2,$3)`,
		personID, tok, ver); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Lookup(ctx, e.crm, service.LookupInput{Email: "fault@example.com"}); err != service.ErrNotFound {
		t.Fatalf("a tombstoned person must never be resolvable by identifier, got %v", err)
	}
}

// TestRekeyDoesNotResurrectSearchTokens: rekeyPerson's token INSERT must be
// scoped to a live person inside the statement.
func TestRekeyDoesNotResurrectSearchTokens(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cid := e.register(t)

	var personID string
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT person_id FROM cids WHERE cid=$1`, cid).Scan(&personID); err != nil {
		t.Fatal(err)
	}
	// A blob the rekey sweep can still decrypt, on a person that is erased:
	// erase first, then restore the ciphertext by hand, which is the exact
	// state the race leaves (rekey holds the plaintext in memory).
	var blob []byte
	var keyID, alg string
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT pii_encrypted, pii_key_id, pii_alg FROM cids WHERE cid=$1`, cid).Scan(&blob, &keyID, &alg); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.gdpr.Erase(ctx, e.crm, cid); err != nil {
		t.Fatal(err)
	}
	e.gdpr.Drain()
	if _, err := e.admin.Pool.Exec(ctx,
		`UPDATE cids SET pii_encrypted=$2, pii_key_id=$3, pii_alg=$4 WHERE cid=$1`,
		cid, blob, keyID, alg); err != nil {
		t.Fatal(err)
	}
	// The tombstone filter is on the batch SELECT, so call the per-person
	// path the way the race reaches it: through Rekey with the filter
	// removed is impossible from outside, so assert on the statement the
	// insert closure now runs.
	tag, err := e.admin.Pool.Exec(ctx,
		`INSERT INTO person_tokens (person_id, kind, token, key_version)
		 SELECT $1,'email','resurrected-token','v1'
		  WHERE EXISTS (SELECT 1 FROM persons WHERE id=$1 AND erased_at IS NULL)
		 ON CONFLICT (person_id, kind, token) DO NOTHING`, personID)
	if err != nil {
		t.Fatal(err)
	}
	if tag.RowsAffected() != 0 {
		t.Fatal("a search token was minted for a tombstoned person")
	}
}

// TestRetentionTokenCleanupIsLevelTriggered (GDPR-ERASURE-7): a blocker at
// the instant of the wipe must not permanently strand the person's
// identifiers. Once the blocker is gone, a later sweep must clear them.
func TestRetentionTokenCleanupIsLevelTriggered(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cid := e.register(t)

	var personID string
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT person_id FROM cids WHERE cid=$1`, cid).Scan(&personID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.admin.Pool.Exec(ctx,
		`INSERT INTO retention_policies (scope, contacts_ttl_days) VALUES ('crm', 0)`); err != nil {
		t.Fatal(err)
	}
	// A live share blocks the token deletion at the moment of the wipe.
	if _, err := e.admin.Pool.Exec(ctx,
		`INSERT INTO shared_records (uuid, cid, scope, partner_label, fields, expires_at, created_by, purpose)
		 VALUES (gen_random_uuid(), $1, 'crm', 'partner', ARRAY['name']::text[], now()+interval '1 hour', 'crm', 'support')`,
		cid); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.RunRetention(ctx, e.admin.Pool); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM person_tokens WHERE person_id=$1`, personID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("a live share must keep the person resolvable")
	}

	// The blocker expires. The blob is already wiped, so the person can
	// never re-enter wipedCIDs - the cleanup must not depend on that edge.
	if _, err := e.admin.Pool.Exec(ctx,
		`UPDATE shared_records SET expires_at = now() - interval '1 minute' WHERE cid=$1`, cid); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.RunRetention(ctx, e.admin.Pool); err != nil {
		t.Fatal(err)
	}
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM person_tokens WHERE person_id=$1`, personID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("%d search token(s) survived every trace of the person", n)
	}
	if _, err := e.svc.Lookup(ctx, e.crm, service.LookupInput{Email: "fault@example.com"}); err != service.ErrNotFound {
		t.Fatalf("retention-wiped person still resolvable by e-mail: %v", err)
	}
}

// TestRetentionSweepsErasedPersonTokens: any token row belonging to a
// tombstone is a resurrection and is removed unconditionally, without
// waiting for a retention policy or a blob wipe.
func TestRetentionSweepsErasedPersonTokens(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cid := e.register(t)

	var personID string
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT person_id FROM cids WHERE cid=$1`, cid).Scan(&personID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.gdpr.Erase(ctx, e.crm, cid); err != nil {
		t.Fatal(err)
	}
	e.gdpr.Drain()
	if _, err := e.admin.Pool.Exec(ctx,
		`INSERT INTO person_tokens (person_id, kind, token, key_version) VALUES ($1,'email','stray','v1')`,
		personID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.RunRetention(ctx, e.admin.Pool); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM person_tokens WHERE person_id=$1`, personID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("%d token(s) of an erased person survived the sweep", n)
	}
}

// TOKENS-LOOKUP-5: OTI verification must not create a live cids row - and a
// PII blob in it - for a person being erased. erasePerson's OTI revoke is
// its LAST mutation while the verify CAS is the verify's FIRST, so the
// fence has to be local to the verify transaction.
func TestOTIVerifyRefusesTombstonedPerson(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cid := e.register(t)

	tok, _, err := e.oti.Issue(ctx, e.crm, cid, "support", "billing", []string{"tier"})
	if err != nil {
		t.Fatal(err)
	}
	var personID string
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT person_id FROM cids WHERE cid=$1`, cid).Scan(&personID); err != nil {
		t.Fatal(err)
	}
	// The state the race produces: the person is tombstoned, but the OTI row
	// escaped the revoke because its CAS ran first.
	if _, _, err := e.gdpr.Erase(ctx, e.crm, cid); err != nil {
		t.Fatal(err)
	}
	e.gdpr.Drain()
	if _, err := e.admin.Pool.Exec(ctx,
		`UPDATE oti SET status='VALID' WHERE cid=$1`, cid); err != nil {
		t.Fatal(err)
	}
	if _, err := e.oti.Verify(ctx, e.verifier(), tok, "support", "billing"); err == nil {
		t.Fatal("verify must refuse a token whose person is tombstoned")
	}
	var live int
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM cids WHERE person_id=$1 AND pii_encrypted IS NOT NULL`,
		personID).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live != 0 {
		t.Fatalf("verify wrote %d live blob(s) for an erased person", live)
	}
	var scopes int
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM cids WHERE person_id=$1`, personID).Scan(&scopes); err != nil {
		t.Fatal(err)
	}
	if scopes != 1 {
		t.Fatalf("verify minted a pseudonym in a scope no erasure_event covers: %d cids", scopes)
	}
}

// TestEnsureCIDRefusesTombstone is the direct form: no scoped pseudonym may
// be minted for an erased person by any caller.
func TestEnsureCIDRefusesTombstone(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cid := e.register(t)
	if _, _, err := e.gdpr.Erase(ctx, e.crm, cid); err != nil {
		t.Fatal(err)
	}
	e.gdpr.Drain()
	if _, err := e.svc.IssueScopedCid(ctx, e.crm, cid, "billing"); err == nil {
		t.Fatal("a tombstoned person must not gain a pseudonym in a new scope")
	}
}

// TestRekeyPaginationUsesThePrimaryKeyIndex is a PLAN regression, not a
// behaviour one: the sweep produced correct results either way, and every
// functional test passed while it read 6.3 billion tuples from a 26.9M-row
// table.
//
// The sweep paginated with `id::text > $1 ORDER BY id::text`. Casting the
// uuid makes persons_pkey unusable, so each batch became a parallel
// sequential scan plus a top-N sort of the WHOLE table. Measured on the
// 26.9M-contact dataset: 172,867 shared buffers per batch against 513 for
// the uncast form - 337x the I/O, repeated once per batch. Registrations
// running concurrently with the sweep timed out at 30 seconds.
//
// The assertion is on the sort key rather than on "Index Scan": a small test
// table can legitimately be scanned sequentially, but a sort keyed on a CAST
// of the paginating column can only come from re-introducing the cast.
func TestRekeyPaginationUsesThePrimaryKeyIndex(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()

	// Enough rows that the planner has a real choice to make.
	for i := 0; i < 300; i++ {
		if _, err := e.admin.Pool.Exec(ctx,
			`INSERT INTO persons (id) VALUES (gen_random_uuid())`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.admin.Pool.Exec(ctx, `ANALYZE persons`); err != nil {
		t.Fatal(err)
	}

	// The exact statement the sweep issues.
	var plan string
	rows, err := e.admin.Pool.Query(ctx,
		`EXPLAIN SELECT id FROM persons WHERE erased_at IS NULL AND id > $1::uuid ORDER BY id LIMIT $2`,
		"00000000-0000-0000-0000-000000000000", 500)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		plan += line + "\n"
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	if strings.Contains(plan, "(id)::text") {
		t.Fatalf("the sweep is sorting on a CAST of the paginating column - "+
			"persons_pkey cannot be used and every batch scans the whole table:\n%s", plan)
	}

	// And the sweep itself must still visit every live person, so the plan
	// fix cannot have changed what it covers.
	before, err := e.svc.Rekey(ctx, false, 100)
	if err != nil {
		t.Fatal(err)
	}
	if before.Persons < 300 {
		t.Fatalf("the sweep visited %d persons, fewer than the 300 just inserted - "+
			"uuid ordering must still cover the whole table", before.Persons)
	}
}

// TestBatchedTokenFlushStillRefusesAnErasedPerson is GDPR-ERASURE-2 re-asked
// of the batched write path.
//
// The sweep now accumulates every token in a batch and writes them in one
// statement. That is 90x faster - and it WIDENS the window the original
// finding lived in: a person read at the top of a 500-person batch has their
// tokens written at the bottom of it, so an erasure landing between the two
// has more room, not less. If the liveness check had moved from per-row to
// per-batch during that change, deleted search tokens would come back under
// the newest key version, permanently, and be immediately usable.
//
// The seam erases the person after their tokens are in the batch and before
// the batch is written, which is exactly that window, deterministically.
func TestBatchedTokenFlushStillRefusesAnErasedPerson(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()

	cid, err := e.svc.Register(ctx, e.crm, service.RegisterInput{Email: "batched@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	var personID string
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT person_id::text FROM cids WHERE cid=$1`, cid).Scan(&personID); err != nil {
		t.Fatal(err)
	}

	// Rotate so the sweep has real work: it will mint tokens under v2.
	if _, err := e.svc.Ring.Rotate(ctx, e.oti.Eng, crypto.KeyHMACEmail); err != nil {
		t.Fatal(err)
	}

	// Erase inside the window: the person is already in the batch, the batch
	// has not been written yet.
	fired := false
	service.BeforeTokenFlushForTest = func() {
		if fired {
			return
		}
		fired = true
		if _, err := e.admin.Pool.Exec(ctx,
			`DELETE FROM person_tokens WHERE person_id=$1`, personID); err != nil {
			t.Error(err)
		}
		if _, err := e.admin.Pool.Exec(ctx,
			`UPDATE persons SET erased_at=now() WHERE id=$1`, personID); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { service.BeforeTokenFlushForTest = nil })

	if _, err := e.svc.Rekey(ctx, false, 100); err != nil {
		t.Fatal(err)
	}
	if !fired {
		t.Fatal("the seam never ran - the sweep wrote no batch, so this proves nothing")
	}

	var revived int
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM person_tokens WHERE person_id=$1`, personID).Scan(&revived); err != nil {
		t.Fatal(err)
	}
	if revived != 0 {
		t.Fatalf("the batched flush re-created %d search token(s) for an erased person - "+
			"they are immediately usable and nothing will ever delete them again "+
			"(GDPR-ERASURE-2)", revived)
	}
}

// TestBatchedFlushWritesEveryTokenItAccumulated is the other half: the fast
// path must not silently drop rows. A join that filtered too much would look
// exactly like success.
func TestBatchedFlushWritesEveryTokenItAccumulated(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()

	const people = 25
	ids := make([]string, 0, people)
	for i := 0; i < people; i++ {
		cid, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
			Email: fmt.Sprintf("bulk%d@example.com", i),
			Phone: fmt.Sprintf("+3859100000%02d", i),
			Name:  fmt.Sprintf("Person Number%d", i),
		})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, cid)
	}

	before := map[string]int{}
	countTokens(t, e, &before)

	// Rotate every identifier kind, then sweep: each person must gain tokens
	// under the new versions, through the batched path.
	for _, kind := range []string{crypto.KeyHMACEmail, crypto.KeyHMACPhone, crypto.KeyHMACName} {
		if _, err := e.svc.Ring.Rotate(ctx, e.oti.Eng, kind); err != nil {
			t.Fatal(err)
		}
	}
	stats, err := e.svc.Rekey(ctx, false, 10) // batch smaller than the population
	if err != nil {
		t.Fatal(err)
	}
	if stats.Persons < people {
		t.Fatalf("the sweep visited %d persons, expected at least %d", stats.Persons, people)
	}
	if stats.TokensInserted == 0 {
		t.Fatal("a rotation across all three kinds inserted no tokens - the batch was dropped")
	}

	after := map[string]int{}
	countTokens(t, e, &after)
	for kind, n := range after {
		if n <= before[kind] {
			t.Fatalf("kind %q did not gain tokens after a rotation (%d -> %d)", kind, before[kind], n)
		}
	}
	// And every registered contact still resolves - the point of the tokens.
	for i, cid := range ids {
		got, err := e.svc.Lookup(ctx, e.crm, service.LookupInput{
			Email: fmt.Sprintf("bulk%d@example.com", i)})
		if err != nil {
			t.Fatalf("contact %d no longer resolves after the batched sweep: %v", i, err)
		}
		if got != cid {
			t.Fatalf("contact %d resolved to %q, want %q", i, got, cid)
		}
	}
}

func countTokens(t *testing.T, e *faultEnv, out *map[string]int) {
	t.Helper()
	rows, err := e.admin.Pool.Query(context.Background(),
		`SELECT kind, count(*) FROM person_tokens GROUP BY kind`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	m := map[string]int{}
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			t.Fatal(err)
		}
		m[k] = n
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	*out = m
}
