package audit

// AUDIT-CHAIN-1 / AUDIT-CHAIN-2 / AUDIT-CHAIN-3.
//
// The threat model recommends granting the API role INSERT (and not UPDATE)
// on `audit`, calling that posture strictly stronger. These tests pin that
// the recommended privilege cannot, by itself, destroy the chain.

import (
	"context"
	"strings"
	"testing"
)

// A sealed-looking row with a NULL chain_seq sorts to the head under
// ORDER BY chain_seq DESC (NULLS FIRST) and used to break sealedHead,
// Verify, SealOnce, Head and - in sync mode - every audited mutation,
// permanently and unrepairably.
func TestForgedSealedInsertIsRefused(t *testing.T) {
	// Async: the sealer is what stamps chain_seq, and this is a test about
	// what a forged INSERT can do to it.
	setMode(t, ModeAsync)
	setReads(t, ReadsChained)
	s := testPool(t)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if err := Append(ctx, s.Pool, Entry{ClientID: "crm", Action: "lookup"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Drain(ctx, s.Pool, 100); err != nil {
		t.Fatal(err)
	}

	_, err := s.Pool.Exec(ctx,
		`INSERT INTO audit (ts, client_id, action, detail, hash) VALUES (now(),'x','x','null','deadbeef')`)
	if err == nil {
		t.Fatal("a row with a hash and no chain_seq must be refused (audit_seal_consistent)")
	}
	if !strings.Contains(err.Error(), "audit_seal_consistent") {
		t.Fatalf("refused, but not by the intended constraint: %v", err)
	}

	// The non-NULL variant: a sealed row must be inserted only at the dense
	// head, or Verify reports an unrepairable permanent gap.
	_, err = s.Pool.Exec(ctx,
		`INSERT INTO audit (ts, client_id, action, detail, hash, chain_seq)
		 VALUES (now(),'x','x','null','deadbeef', 1000000000)`)
	if err == nil {
		t.Fatal("a sealed row with an out-of-sequence chain_seq must be refused")
	}
	if !strings.Contains(err.Error(), "chain head") {
		t.Fatalf("refused, but not by the head guard: %v", err)
	}

	// The machinery is untouched by the attempts.
	if broken, reason, _, err := Verify(ctx, s.Pool); err != nil || broken != 0 {
		t.Fatalf("chain must still verify: broken=%d %s err=%v", broken, reason, err)
	}
	if _, err := Head(ctx, s.Pool); err != nil {
		t.Fatalf("Head must still work: %v", err)
	}
}

// With the constraint bypassed once (a row written before migration 0036),
// verification must DEGRADE TO A VERDICT and the machinery must keep
// working. An error would answer HTTP 500 and exit non-zero with no reason -
// indistinguishable from the verifier itself being down, which is the state
// a forger wants.
func TestForgedSealedRowDegradesToAVerdict(t *testing.T) {
	setMode(t, ModeAsync)
	setReads(t, ReadsChained)
	s := testPool(t)
	ctx := context.Background()

	if err := Append(ctx, s.Pool, Entry{ClientID: "crm", Action: "lookup"}); err != nil {
		t.Fatal(err)
	}
	if _, err := Drain(ctx, s.Pool, 100); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx,
		`ALTER TABLE audit DROP CONSTRAINT audit_seal_consistent`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx,
		`INSERT INTO audit (ts, client_id, action, detail, hash) VALUES (now(),'x','x','null','deadbeef')`); err != nil {
		t.Fatal(err)
	}

	broken, reason, _, err := Verify(ctx, s.Pool)
	if err != nil {
		t.Fatalf("a forged row must be a verdict, not an error: %v", err)
	}
	if broken == 0 || !strings.Contains(reason, "no chain_seq") {
		t.Fatalf("forged row not reported: broken=%d reason=%q", broken, reason)
	}
	// Head and sealing still work: one forged row degrades the verdict,
	// never the machinery.
	if _, err := Head(ctx, s.Pool); err != nil {
		t.Fatalf("Head must survive a forged row: %v", err)
	}
	if err := Append(ctx, s.Pool, Entry{ClientID: "crm", Action: "lookup"}); err != nil {
		t.Fatal(err)
	}
	if n, err := Drain(ctx, s.Pool, 100); err != nil || n != 1 {
		t.Fatalf("sealing must continue after a forged row: %d %v", n, err)
	}
}

// AUDIT-CHAIN-2: a forged hour marker must not be able to keep a real hour's
// read buckets out of the chain forever.
func TestForgedHourMarkerIsRefusedAndSurfaced(t *testing.T) {
	setMode(t, ModeAsync)
	setReads(t, ReadsBucketed)
	s := testPool(t)
	ctx := context.Background()

	// A genuine finished hour with open buckets.
	if _, err := s.Pool.Exec(ctx,
		`INSERT INTO audit_read_buckets (client_id, user_id, cid, action, bucket_start, count, first_seen, last_seen)
		 VALUES ('crm','op1','CID-A','attributes.read', date_trunc('hour', now()-interval '2 hours'), 7, now(), now())`); err != nil {
		t.Fatal(err)
	}
	var hour string
	if err := s.Pool.QueryRow(ctx,
		`SELECT to_char(date_trunc('hour', now()-interval '2 hours') AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"')`).Scan(&hour); err != nil {
		t.Fatal(err)
	}

	// The closer seals the hour and writes its marker.
	if n, err := CloseReadBuckets(ctx, s.Pool); err != nil || n != 1 {
		t.Fatalf("the genuine hour must close: %d %v", n, err)
	}
	// A forged second marker for that hour is refused outright.
	if _, err := s.Pool.Exec(ctx,
		`INSERT INTO audit (ts, client_id, action, detail)
		 VALUES (now(),'_audit','audit.reads_hourly', $1)`,
		`{"hour":"`+hour+`","buckets":0,"events":0,"digest":"00"}`); err == nil {
		t.Fatal("a duplicate hour marker must be refused")
	}
	if bad, why, _, err := VerifyReadBuckets(ctx, s.Pool); err != nil || bad != "" {
		t.Fatalf("read buckets must verify: %q %s %v", bad, why, err)
	}
}

// The suppression shape itself: an hour that has a marker AND open buckets
// must be reported by verification with its own distinguishable reason,
// because that is a state no legitimate path produces.
func TestSuppressedHourIsReportedDistinctly(t *testing.T) {
	setMode(t, ModeAsync)
	setReads(t, ReadsBucketed)
	s := testPool(t)
	ctx := context.Background()

	if _, err := s.Pool.Exec(ctx,
		`INSERT INTO audit_read_buckets (client_id, user_id, cid, action, bucket_start, count, first_seen, last_seen)
		 VALUES ('crm','op1','CID-A','attributes.read', date_trunc('hour', now()-interval '2 hours'), 7, now(), now())`); err != nil {
		t.Fatal(err)
	}
	var hour string
	if err := s.Pool.QueryRow(ctx,
		`SELECT to_char(date_trunc('hour', now()-interval '2 hours') AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"')`).Scan(&hour); err != nil {
		t.Fatal(err)
	}
	// Forge the marker BEFORE the closer ever reaches the hour.
	if _, err := s.Pool.Exec(ctx,
		`INSERT INTO audit (ts, client_id, action, detail)
		 VALUES (now(),'_audit','audit.reads_hourly', $1)`,
		`{"hour":"`+hour+`","buckets":0,"events":0,"digest":"00"}`); err != nil {
		t.Fatal(err)
	}
	if n, err := CloseReadBuckets(ctx, s.Pool); err != nil || n != 0 {
		t.Fatalf("the suppressed hour cannot be closed: %d %v", n, err)
	}
	bad, why, _, err := VerifyReadBuckets(ctx, s.Pool)
	if err != nil {
		t.Fatal(err)
	}
	if bad != hour || !strings.Contains(why, "still OPEN") {
		t.Fatalf("a suppressed hour must be reported with its own reason: %q %q", bad, why)
	}
}
