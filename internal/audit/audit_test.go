package audit

import (
	"context"
	"sync"
	"testing"

	"github.com/fvisic/sunder/internal/store"
	"github.com/fvisic/sunder/internal/testutil"
)

func testPool(t *testing.T) *store.Store { return testutil.NewDB(t) }

func TestChainAppendsAndVerifies(t *testing.T) {
	s := testPool(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		err := Append(ctx, s.Pool, Entry{ClientID: "crm", Action: "lookup", Detail: map[string]any{"n": i}})
		if err != nil {
			t.Fatal(err)
		}
	}
	broken, reason, err := Verify(ctx, s.Pool)
	if err != nil {
		t.Fatal(err)
	}
	if broken != 0 {
		t.Fatalf("fresh chain reported broken at %d: %s", broken, reason)
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
	// A privileged attacker first removes the append-only trigger (they can),
	// then quietly rewrites record 2 — the chain must still expose it.
	if _, err := s.Pool.Exec(ctx, `ALTER TABLE audit DISABLE TRIGGER audit_no_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE audit SET action='nothing-here' WHERE seq=2`); err != nil {
		t.Fatal(err)
	}
	broken, reason, err := Verify(ctx, s.Pool)
	if err != nil {
		t.Fatal(err)
	}
	if broken != 2 {
		t.Fatalf("expected break at seq 2, got %d (%s)", broken, reason)
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
	if _, err := s.Pool.Exec(ctx, `ALTER TABLE audit DISABLE TRIGGER audit_no_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `DELETE FROM audit WHERE seq=2`); err != nil {
		t.Fatal(err)
	}
	broken, _, err := Verify(ctx, s.Pool)
	if err != nil {
		t.Fatal(err)
	}
	if broken != 3 {
		t.Fatalf("expected break at seq 3 after deleting seq 2, got %d", broken)
	}
}

func TestAppendOnlyTriggerBlocksTampering(t *testing.T) {
	s := testPool(t)
	ctx := context.Background()
	if err := Append(ctx, s.Pool, Entry{ClientID: "crm", Action: "lookup"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE audit SET action='x' WHERE seq=1`); err == nil {
		t.Fatal("UPDATE on audit must be blocked by trigger")
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
	head, err = Head(ctx, s.Pool)
	if err != nil || len(head) != 64 {
		t.Fatalf("head after append: %q err=%v", head, err)
	}
	var last string
	if err := s.Pool.QueryRow(ctx, `SELECT hash FROM audit ORDER BY seq DESC LIMIT 1`).Scan(&last); err != nil {
		t.Fatal(err)
	}
	if head != last {
		t.Fatal("Head does not match last row hash")
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
	broken, reason, err := Verify(ctx, s.Pool)
	if err != nil {
		t.Fatal(err)
	}
	if broken != 0 {
		t.Fatalf("chain broken at %d after concurrent appends: %s", broken, reason)
	}
}
