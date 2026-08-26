package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fvisic/sunder/internal/store"
	"github.com/fvisic/sunder/internal/testutil"
)

func testPool(t *testing.T) *store.Store { return testutil.NewDB(t) }

// sealAll drains the unsealed backlog so a test can assert on the sealed
// chain regardless of which mode the CI matrix selected. In sync mode it is
// a no-op that must still succeed.
func sealAll(t *testing.T, s *store.Store) {
	t.Helper()
	if _, err := Drain(context.Background(), s.Pool, 1000); err != nil {
		t.Fatalf("drain: %v", err)
	}
}

// setMode pins the write mode for one test and restores the matrix-selected
// mode afterwards, so mode-specific tests do not leak into the rest.
func setMode(t *testing.T, m string) {
	t.Helper()
	old := Mode()
	SetMode(m)
	t.Cleanup(func() { SetMode(old) })
}

func TestChainAppendsAndVerifies(t *testing.T) {
	s := testPool(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		err := Append(ctx, s.Pool, Entry{ClientID: "crm", Action: "lookup", Detail: map[string]any{"n": i}})
		if err != nil {
			t.Fatal(err)
		}
	}
	sealAll(t, s)
	broken, reason, pending, err := Verify(ctx, s.Pool)
	if err != nil {
		t.Fatal(err)
	}
	if broken != 0 {
		t.Fatalf("fresh chain reported broken at %d: %s", broken, reason)
	}
	if pending != 0 {
		t.Fatalf("nothing may stay pending after a drain, got %d", pending)
	}
}

func TestTamperDetected(t *testing.T) {
	s := testPool(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := Append(ctx, s.Pool, Entry{ClientID: "crm", Action: "lookup"}); err != nil {
			t.Fatal(err)
		}
	}
	sealAll(t, s)
	// A privileged attacker first removes the append-only trigger (they can),
	// then quietly rewrites record 2 - the chain must still expose it.
	if _, err := s.Pool.Exec(ctx, `ALTER TABLE audit DISABLE TRIGGER audit_no_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE audit SET action='nothing-here' WHERE seq=2`); err != nil {
		t.Fatal(err)
	}
	broken, reason, _, err := Verify(ctx, s.Pool)
	if err != nil {
		t.Fatal(err)
	}
	if broken != 2 {
		t.Fatalf("expected break at chain position 2, got %d (%s)", broken, reason)
	}
}

func TestDeletionDetected(t *testing.T) {
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
	if _, err := s.Pool.Exec(ctx, `DELETE FROM audit WHERE seq=2`); err != nil {
		t.Fatal(err)
	}
	broken, _, _, err := Verify(ctx, s.Pool)
	if err != nil {
		t.Fatal(err)
	}
	// The chain_seq density check fires first: position 2 is missing, so the
	// row now carrying chain_seq 3 is where the walk detects the deletion.
	if broken != 3 {
		t.Fatalf("expected break at chain position 3 after deleting position 2, got %d", broken)
	}
}

func TestAppendOnlyTriggerBlocksTampering(t *testing.T) {
	s := testPool(t)
	ctx := context.Background()
	if err := Append(ctx, s.Pool, Entry{ClientID: "crm", Action: "lookup"}); err != nil {
		t.Fatal(err)
	}
	// Both while unsealed and after sealing, a content edit must be refused.
	if _, err := s.Pool.Exec(ctx, `UPDATE audit SET action='x' WHERE seq=1`); err == nil {
		t.Fatal("UPDATE on an unsealed audit row must be blocked by trigger")
	}
	sealAll(t, s)
	if _, err := s.Pool.Exec(ctx, `UPDATE audit SET action='x' WHERE seq=1`); err == nil {
		t.Fatal("UPDATE on a sealed audit row must be blocked by trigger")
	}
	if _, err := s.Pool.Exec(ctx, `DELETE FROM audit WHERE seq=1`); err == nil {
		t.Fatal("DELETE on audit must be blocked by trigger")
	}
}

func TestHead(t *testing.T) {
	s := testPool(t)
	ctx := context.Background()
	head, err := Head(ctx, s.Pool)
	if err != nil || head != "" {
		t.Fatalf("empty log: head=%q err=%v", head, err)
	}
	if err := Append(ctx, s.Pool, Entry{ClientID: "crm", Action: "lookup"}); err != nil {
		t.Fatal(err)
	}
	sealAll(t, s)
	head, err = Head(ctx, s.Pool)
	if err != nil || len(head) != 64 {
		t.Fatalf("head after append+seal: %q err=%v", head, err)
	}
	var last string
	if err := s.Pool.QueryRow(ctx,
		`SELECT hash FROM audit WHERE hash IS NOT NULL ORDER BY chain_seq DESC LIMIT 1`).Scan(&last); err != nil {
		t.Fatal(err)
	}
	if head != last {
		t.Fatal("Head does not match the newest sealed hash")
	}
}

func TestHeadIgnoresUnsealedRows(t *testing.T) {
	setMode(t, ModeAsync)
	s := testPool(t)
	ctx := context.Background()
	if err := Append(ctx, s.Pool, Entry{ClientID: "crm", Action: "lookup"}); err != nil {
		t.Fatal(err)
	}
	sealAll(t, s)
	sealed, err := Head(ctx, s.Pool)
	if err != nil {
		t.Fatal(err)
	}
	// A newer, still-unsealed row must not move the head: anchoring stamps
	// the head, and an anchor must never point past what the chain proves.
	if err := Append(ctx, s.Pool, Entry{ClientID: "crm", Action: "lookup"}); err != nil {
		t.Fatal(err)
	}
	head, err := Head(ctx, s.Pool)
	if err != nil {
		t.Fatal(err)
	}
	if head != sealed {
		t.Fatalf("head moved past the sealed watermark: %q vs %q", head, sealed)
	}
}

func TestConcurrentAppendsKeepChainIntact(t *testing.T) {
	s := testPool(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- Append(ctx, s.Pool, Entry{ClientID: "crm", Action: "concurrent"})
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	sealAll(t, s)
	broken, reason, pending, err := Verify(ctx, s.Pool)
	if err != nil {
		t.Fatal(err)
	}
	if broken != 0 || pending != 0 {
		t.Fatalf("chain broken at %d (pending %d) after concurrent appends: %s", broken, pending, reason)
	}
}

// TestUserIDIsTamperEvident (review medium): user_id was the ONE audited
// field a database attacker could edit without tripping verification - the
// field that says who did it. It is now inside the v2 canonical tuple; rows
// sealed before the change (hash_v=1) keep verifying under the old tuple.
func TestUserIDIsTamperEvident(t *testing.T) {
	setMode(t, "sync")
	s := testPool(t)
	ctx := context.Background()

	if err := Append(ctx, s.Pool, Entry{ClientID: "crm", Action: "attributes.read",
		CID: "CID-U", UserID: "agent-7", Detail: map[string]any{"k": "v"}}); err != nil {
		t.Fatal(err)
	}
	if broken, why, _, err := Verify(ctx, s.Pool); err != nil || broken != 0 {
		t.Fatalf("fresh chain must verify: %d %s %v", broken, why, err)
	}

	// The database attacker edits WHO did it (trigger disabled, as every
	// tamper simulation here does).
	if _, err := s.Pool.Exec(ctx, `ALTER TABLE audit DISABLE TRIGGER audit_no_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE audit SET user_id='someone-else' WHERE user_id='agent-7'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `ALTER TABLE audit ENABLE TRIGGER audit_no_update`); err != nil {
		t.Fatal(err)
	}
	broken, why, _, err := Verify(ctx, s.Pool)
	if err != nil || broken == 0 || !strings.Contains(why, "does not match its hash") {
		t.Fatalf("an edited user_id must break verification: %d %q %v", broken, why, err)
	}
}

// TestV1RowsKeepVerifying: a row sealed BEFORE 0033 was hashed WITHOUT
// user_id (hash_v=1). Verification must recompute it under its own tuple
// version, or the upgrade itself would flip every existing chain to
// "tampered" - the exact failure mode the H12 grandfathering exists for.
func TestV1RowsKeepVerifying(t *testing.T) {
	setMode(t, "sync")
	s := testPool(t)
	ctx := context.Background()

	// Hand-seal a v1 row: hash over the OLD tuple (no user_id), hash_v=1 -
	// byte-identical to what a pre-0033 deployment left behind.
	ts := time.Now().UTC().Truncate(time.Microsecond)
	e := Entry{ClientID: "crm", Action: "lookup", CID: "CID-OLD"}
	detail := []byte(`{"legacy":true}`)
	sum := sha256.Sum256([]byte(canonical(1, "", ts, e, detail)))
	if _, err := s.Pool.Exec(ctx, `
		INSERT INTO audit (ts, client_id, action, cid, detail, prev_hash, hash, chain_seq, user_id, hash_v)
		VALUES ($1,'crm','lookup','CID-OLD',$2,NULL,$3,1,'legacy-agent',1)`,
		ts, string(detail), hex.EncodeToString(sum[:])); err != nil {
		t.Fatal(err)
	}
	// A v2 row chains on top through the normal path.
	if err := Append(ctx, s.Pool, Entry{ClientID: "crm", Action: "lookup",
		CID: "CID-NEW", UserID: "agent-9"}); err != nil {
		t.Fatal(err)
	}
	if broken, why, _, err := Verify(ctx, s.Pool); err != nil || broken != 0 {
		t.Fatalf("a mixed v1+v2 chain must verify: %d %s %v", broken, why, err)
	}
}

// TestSealerSurvivesAppClockAhead (review medium): the sealer's age filter
// compared the APP-stamped ts to the DATABASE clock, so an app clock ahead
// by more than the delay stalled sealing silently. The filter now uses
// db_ts (database clock at insert): a row whose app ts is an hour in the
// future still seals once its DB age passes the delay.
func TestSealerSurvivesAppClockAhead(t *testing.T) {
	setMode(t, "async")
	s := testPool(t)
	ctx := context.Background()

	if _, err := s.Pool.Exec(ctx, `
		INSERT INTO audit (ts, client_id, action, detail, db_ts)
		VALUES (now() + interval '1 hour', 'crm', 'lookup', '{}', now() - interval '1 minute')`); err != nil {
		t.Fatal(err)
	}
	n, err := SealOnce(ctx, s.Pool, 100, 2*time.Second)
	if err != nil || n != 1 {
		t.Fatalf("a DB-old row must seal regardless of its app timestamp: sealed=%d err=%v", n, err)
	}
	if broken, why, pending, err := Verify(ctx, s.Pool); err != nil || broken != 0 || pending != 0 {
		t.Fatalf("chain after skewed seal: %d %s pending=%d err=%v", broken, why, pending, err)
	}
}
