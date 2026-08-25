package audit

import (
	"context"
	"sync"
	"testing"

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
