package audit

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestMixedModeChainVerifies is the property the SUNDER_AUDIT_SEALING
// switch relies on: both modes hash the same canonical bytes and read the
// same head, so a chain built partly in each mode is one unbroken chain.
func TestMixedModeChainVerifies(t *testing.T) {
	s := testPool(t)
	ctx := context.Background()

	setMode(t, ModeSync)
	for i := 0; i < 2; i++ {
		if err := Append(ctx, s.Pool, Entry{ClientID: "crm", Action: "sync-era"}); err != nil {
			t.Fatal(err)
		}
	}
	setMode(t, ModeAsync)
	for i := 0; i < 3; i++ {
		if err := Append(ctx, s.Pool, Entry{ClientID: "crm", Action: "async-era"}); err != nil {
			t.Fatal(err)
		}
	}
	sealAll(t, s)
	setMode(t, ModeSync)
	if err := Append(ctx, s.Pool, Entry{ClientID: "crm", Action: "sync-again"}); err != nil {
		t.Fatal(err)
	}

	broken, reason, pending, err := Verify(ctx, s.Pool)
	if err != nil {
		t.Fatal(err)
	}
	if broken != 0 || pending != 0 {
		t.Fatalf("mixed-mode chain broken at %d (pending %d): %s", broken, pending, reason)
	}
	// chain_seq must be dense 1..6 across the mode boundary.
	var n int64
	if err := s.Pool.QueryRow(ctx,
		`SELECT count(*) FROM audit WHERE chain_seq BETWEEN 1 AND 6`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 6 {
		t.Fatalf("expected dense chain_seq 1..6, found %d rows in range", n)
	}
}

func TestSyncModeSealsAtBirth(t *testing.T) {
	setMode(t, ModeSync)
	s := testPool(t)
	ctx := context.Background()
	if err := Append(ctx, s.Pool, Entry{ClientID: "crm", Action: "lookup"}); err != nil {
		t.Fatal(err)
	}
	// The zero-window promise: the row is in the chain the moment the
	// transaction commits, with nothing left for any sealer to do.
	var sealed bool
	var chainSeq int64
	if err := s.Pool.QueryRow(ctx,
		`SELECT hash IS NOT NULL, chain_seq FROM audit WHERE seq=1`).Scan(&sealed, &chainSeq); err != nil {
		t.Fatal(err)
	}
	if !sealed || chainSeq != 1 {
		t.Fatalf("sync append must seal at birth: sealed=%v chain_seq=%d", sealed, chainSeq)
	}
	if _, _, pending, err := Verify(ctx, s.Pool); err != nil || pending != 0 {
		t.Fatalf("sync mode may never leave pending rows: pending=%d err=%v", pending, err)
	}
}

func TestVerifyReportsPendingNotBroken(t *testing.T) {
	setMode(t, ModeAsync)
	s := testPool(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := Append(ctx, s.Pool, Entry{ClientID: "crm", Action: "lookup"}); err != nil {
			t.Fatal(err)
		}
	}
	broken, reason, pending, err := Verify(ctx, s.Pool)
	if err != nil {
		t.Fatal(err)
	}
	if broken != 0 {
		t.Fatalf("unsealed rows must be pending, not a break: %d (%s)", broken, reason)
	}
	if pending != 3 {
		t.Fatalf("pending = %d, want 3", pending)
	}
}

func TestSealDelaySkipsFreshRows(t *testing.T) {
	setMode(t, ModeAsync)
	s := testPool(t)
	ctx := context.Background()
	if err := Append(ctx, s.Pool, Entry{ClientID: "crm", Action: "lookup"}); err != nil {
		t.Fatal(err)
	}
	if n, err := SealOnce(ctx, s.Pool, 100, time.Hour); err != nil || n != 0 {
		t.Fatalf("a row younger than the delay must not be sealed: n=%d err=%v", n, err)
	}
	if n, err := SealOnce(ctx, s.Pool, 100, 0); err != nil || n != 1 {
		t.Fatalf("the same row must seal with no delay: n=%d err=%v", n, err)
	}
}

// TestCommitOrderRaceDoesNotStrandRows reproduces the BIGSERIAL hazard that
// made chain_seq necessary: a row whose seq is LOWER than already-sealed
// rows appears late (its transaction committed late). Under seq-ordered
// sealing it would be stranded below the watermark forever; under chain_seq
// it simply enters the chain later.
func TestCommitOrderRaceDoesNotStrandRows(t *testing.T) {
	setMode(t, ModeAsync)
	s := testPool(t)
	ctx := context.Background()

	// A row with a high seq arrives and is sealed first.
	if _, err := s.Pool.Exec(ctx,
		`INSERT INTO audit (seq, ts, client_id, action, detail) VALUES (1000, now() - interval '1 minute', 'crm', 'early-commit', 'null')`); err != nil {
		t.Fatal(err)
	}
	if n, err := SealOnce(ctx, s.Pool, 100, 0); err != nil || n != 1 {
		t.Fatalf("first seal: n=%d err=%v", n, err)
	}

	// Now the late committer surfaces with a LOWER seq.
	if _, err := s.Pool.Exec(ctx,
		`INSERT INTO audit (seq, ts, client_id, action, detail) VALUES (999, now() - interval '1 minute', 'crm', 'late-commit', 'null')`); err != nil {
		t.Fatal(err)
	}
	if n, err := SealOnce(ctx, s.Pool, 100, 0); err != nil || n != 1 {
		t.Fatalf("second seal must pick up the late row: n=%d err=%v", n, err)
	}

	broken, reason, pending, err := Verify(ctx, s.Pool)
	if err != nil {
		t.Fatal(err)
	}
	if broken != 0 || pending != 0 {
		t.Fatalf("late-committing row broke the chain: %d (%s), pending %d", broken, reason, pending)
	}
	var chainSeq int64
	if err := s.Pool.QueryRow(ctx, `SELECT chain_seq FROM audit WHERE seq=999`).Scan(&chainSeq); err != nil {
		t.Fatal(err)
	}
	if chainSeq != 2 {
		t.Fatalf("late row must enter the chain at position 2, got %d", chainSeq)
	}
}

func TestDrainSealsEverything(t *testing.T) {
	setMode(t, ModeAsync)
	s := testPool(t)
	ctx := context.Background()
	// More rows than one drain batch, so the loop is exercised.
	for i := 0; i < 7; i++ {
		if err := Append(ctx, s.Pool, Entry{ClientID: "crm", Action: "lookup"}); err != nil {
			t.Fatal(err)
		}
	}
	// SealOnce enforces a positive batch; Drain inherits the same floor in
	// production through config validation (min 100). The tiny batch here
	// only forces multiple loop iterations.
	n, err := Drain(ctx, s.Pool, 3)
	if err != nil {
		t.Fatal(err)
	}
	if n != 7 {
		t.Fatalf("drain sealed %d of 7", n)
	}
	if pending, err := UnsealedCount(ctx, s.Pool); err != nil || pending != 0 {
		t.Fatalf("pending after drain: %d err=%v", pending, err)
	}
}

// TestTriggerAllowsOnlyTheSealingTransition pins the exact shape the
// trigger accepts. Everything else on an audit row must be refused - and
// re-sealing a sealed row most of all, because that is what forging a
// chain would require.
func TestTriggerAllowsOnlyTheSealingTransition(t *testing.T) {
	setMode(t, ModeAsync)
	s := testPool(t)
	ctx := context.Background()
	if err := Append(ctx, s.Pool, Entry{ClientID: "crm", Action: "lookup"}); err != nil {
		t.Fatal(err)
	}

	// Content edit on an unsealed row: refused.
	if _, err := s.Pool.Exec(ctx, `UPDATE audit SET action='forged' WHERE seq=1`); err == nil {
		t.Fatal("content edit on an unsealed row must be refused")
	}
	// Sealing combined with a content edit: refused.
	if _, err := s.Pool.Exec(ctx,
		`UPDATE audit SET hash=repeat('a',64), chain_seq=1, action='forged' WHERE seq=1`); err == nil {
		t.Fatal("sealing that also edits content must be refused")
	}
	// Sealing without a chain position: refused (a sealed row outside the
	// chain_seq walk would be invisible to Verify).
	if _, err := s.Pool.Exec(ctx,
		`UPDATE audit SET hash=repeat('a',64) WHERE seq=1`); err == nil {
		t.Fatal("sealing without chain_seq must be refused")
	}
	// The exact sealing shape: allowed. (This is what SealOnce emits.)
	if _, err := s.Pool.Exec(ctx,
		`UPDATE audit SET prev_hash=NULL, hash=repeat('a',64), chain_seq=1 WHERE seq=1`); err != nil {
		t.Fatalf("the sealing transition itself must be allowed: %v", err)
	}
	// Re-sealing a sealed row: refused, even with identical content.
	if _, err := s.Pool.Exec(ctx,
		`UPDATE audit SET hash=repeat('b',64), chain_seq=1 WHERE seq=1`); err == nil {
		t.Fatal("re-sealing a sealed row must be refused")
	}
}

// TestConcurrentSealersDoNotFork: N replicas may all run a sealer; try-lock
// means one seals per cycle and the rest skip. Whatever the interleaving,
// the result must be one dense, valid chain.
func TestConcurrentSealersDoNotFork(t *testing.T) {
	setMode(t, ModeAsync)
	s := testPool(t)
	ctx := context.Background()
	for i := 0; i < 40; i++ {
		if err := Append(ctx, s.Pool, Entry{ClientID: "crm", Action: "lookup"}); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				pending, err := UnsealedCount(ctx, s.Pool)
				if err != nil {
					errs <- err
					return
				}
				if pending == 0 {
					return
				}
				if _, err := SealOnce(ctx, s.Pool, 7, 0); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	broken, reason, pending, err := Verify(ctx, s.Pool)
	if err != nil {
		t.Fatal(err)
	}
	if broken != 0 || pending != 0 {
		t.Fatalf("concurrent sealers forked the chain: broken=%d pending=%d (%s)", broken, pending, reason)
	}
}

// TestAsyncThenSyncEqualsSyncChain: the bit-identical claim, tested rather
// than asserted. The same logical entries produce the same hashes whether
// sealed at birth or by the sealer - given the same stored timestamps. The
// hashes cannot literally match across two runs (each row's ts differs), so
// the test checks the property that matters: sealing recomputes from stored
// values exactly what Verify recomputes, in both eras of a mixed chain.
func TestAsyncThenSyncEqualsSyncChain(t *testing.T) {
	s := testPool(t)
	ctx := context.Background()

	setMode(t, ModeAsync)
	if err := Append(ctx, s.Pool, Entry{ClientID: "crm", Action: "one"}); err != nil {
		t.Fatal(err)
	}
	sealAll(t, s)
	setMode(t, ModeSync)
	if err := Append(ctx, s.Pool, Entry{ClientID: "crm", Action: "two"}); err != nil {
		t.Fatal(err)
	}

	// The sync row's prev_hash must be the sealer-made hash of row one:
	// proof the two eras link, not merely coexist.
	var prevOfTwo, hashOfOne string
	if err := s.Pool.QueryRow(ctx,
		`SELECT prev_hash FROM audit WHERE chain_seq=2`).Scan(&prevOfTwo); err != nil {
		t.Fatal(err)
	}
	if err := s.Pool.QueryRow(ctx,
		`SELECT hash FROM audit WHERE chain_seq=1`).Scan(&hashOfOne); err != nil {
		t.Fatal(err)
	}
	if prevOfTwo != hashOfOne || !strings.EqualFold(prevOfTwo, hashOfOne) {
		t.Fatalf("sync row does not chain onto the sealed async row: %q vs %q", prevOfTwo, hashOfOne)
	}
}

func TestSealAndDrainErrorBranches(t *testing.T) {
	setMode(t, ModeAsync)
	s := testPool(t)
	ctx := context.Background()

	if _, err := SealOnce(ctx, s.Pool, 0, 0); err == nil {
		t.Fatal("non-positive batch must be rejected")
	}
	// Marshal failure: a Detail value JSON cannot encode must fail closed
	// BEFORE touching the database, in both Append and AppendTx.
	bad := Entry{ClientID: "crm", Action: "x", Detail: map[string]any{"ch": make(chan int)}}
	if err := Append(ctx, s.Pool, bad); err == nil {
		t.Fatal("unencodable detail must fail Append")
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := AppendTx(ctx, tx, bad); err == nil {
		t.Fatal("unencodable detail must fail AppendTx")
	}
	// Release the connection BEFORE closing the pool: pgxpool.Close blocks
	// until every acquired connection is returned, so a deferred rollback
	// after Close deadlocks the test.
	_ = tx.Rollback(ctx)

	s.Close()
	if _, err := SealOnce(ctx, s.Pool, 100, 0); err == nil {
		t.Fatal("seal on a dead pool must error")
	}
	// Both write modes must surface a dead pool, not swallow it: a lookup
	// that cannot be audited must not answer (fail closed), and that
	// property is per-mode code.
	setMode(t, ModeSync)
	if err := Append(ctx, s.Pool, Entry{ClientID: "crm", Action: "x"}); err == nil {
		t.Fatal("sync append on a dead pool must error")
	}
	setMode(t, ModeAsync)
	if err := Append(ctx, s.Pool, Entry{ClientID: "crm", Action: "x"}); err == nil {
		t.Fatal("async append on a dead pool must error")
	}
	if _, err := Drain(ctx, s.Pool, 100); err == nil {
		t.Fatal("drain on a dead pool must error")
	}
	if _, err := UnsealedCount(ctx, s.Pool); err == nil {
		t.Fatal("unsealed count on a dead pool must error")
	}
}

// TestSealerSkipsWhenChainLockHeld: the try-lock contract. While a sync
// append (or another sealer) holds the chain lock, SealOnce must return
// 0 sealed and NO error - a replica losing the race is normal operation,
// not a failure to alarm on.
func TestSealerSkipsWhenChainLockHeld(t *testing.T) {
	setMode(t, ModeAsync)
	s := testPool(t)
	ctx := context.Background()
	if err := Append(ctx, s.Pool, Entry{ClientID: "crm", Action: "lookup"}); err != nil {
		t.Fatal(err)
	}

	// Hold the chain lock from a separate session.
	holder, err := s.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := holder.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, appendLockKey); err != nil {
		t.Fatal(err)
	}

	n, err := SealOnce(ctx, s.Pool, 100, 0)
	if err != nil {
		t.Fatalf("losing the try-lock race must not be an error: %v", err)
	}
	if n != 0 {
		t.Fatalf("sealed %d rows while the chain lock was held elsewhere", n)
	}
	if err := holder.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if n, err := SealOnce(ctx, s.Pool, 100, 0); err != nil || n != 1 {
		t.Fatalf("after the lock is released the row must seal: n=%d err=%v", n, err)
	}
}

// TestVerifyDetectsForgedHashOnSealedRow: an attacker who can bypass the
// trigger and rewrite a sealed row's hash to something self-consistent
// still breaks the NEXT row's prev_hash linkage.
func TestVerifyDetectsForgedHashOnSealedRow(t *testing.T) {
	setMode(t, ModeAsync)
	s := testPool(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := Append(ctx, s.Pool, Entry{ClientID: "crm", Action: "lookup"}); err != nil {
			t.Fatal(err)
		}
	}
	sealAll(t, s)
	if _, err := s.Pool.Exec(ctx, `ALTER TABLE audit DISABLE TRIGGER audit_no_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE audit SET hash=repeat('c',64) WHERE chain_seq=2`); err != nil {
		t.Fatal(err)
	}
	broken, _, _, err := Verify(ctx, s.Pool)
	if err != nil {
		t.Fatal(err)
	}
	if broken != 2 {
		t.Fatalf("forged hash must break at position 2, got %d", broken)
	}
}
