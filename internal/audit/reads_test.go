package audit

import (
	"context"
	"strings"
	"testing"
)

// setReads pins the read-audit mode for one test and restores the
// matrix-selected mode afterwards.
func setReads(t *testing.T, m string) {
	t.Helper()
	old := ReadsMode()
	SetReadsMode(m)
	t.Cleanup(func() { SetReadsMode(old) })
}

func TestReadEventBucketsAndCounts(t *testing.T) {
	setReads(t, ReadsBucketed)
	s := testPool(t)
	ctx := context.Background()

	// Same operator, same person, same action, four screens: ONE bucket.
	for i := 0; i < 4; i++ {
		if err := ReadEvent(ctx, s.Pool, Entry{
			ClientID: "crm", Action: "lookup", CID: "CID-A", UserID: "agent-7"}); err != nil {
			t.Fatal(err)
		}
	}
	// A different operator is a different bucket - that is the whole point
	// of the user_id key column.
	if err := ReadEvent(ctx, s.Pool, Entry{
		ClientID: "crm", Action: "lookup", CID: "CID-A", UserID: "agent-9"}); err != nil {
		t.Fatal(err)
	}

	var buckets, events int64
	if err := s.Pool.QueryRow(ctx,
		`SELECT count(*), COALESCE(sum(count),0) FROM audit_read_buckets`).Scan(&buckets, &events); err != nil {
		t.Fatal(err)
	}
	if buckets != 2 || events != 5 {
		t.Fatalf("want 2 buckets carrying 5 events, got %d/%d", buckets, events)
	}
	// No per-event chained rows were written in bucketed mode.
	var chained int64
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM audit`).Scan(&chained); err != nil {
		t.Fatal(err)
	}
	if chained != 0 {
		t.Fatalf("bucketed mode must not write per-event audit rows, found %d", chained)
	}
}

func TestReadEventChainedModeWritesRows(t *testing.T) {
	setReads(t, ReadsChained)
	s := testPool(t)
	ctx := context.Background()
	if err := ReadEvent(ctx, s.Pool, Entry{
		ClientID: "crm", Action: "lookup", CID: "CID-A", UserID: "agent-7"}); err != nil {
		t.Fatal(err)
	}
	var n int64
	var userID string
	if err := s.Pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_read_buckets`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("chained mode must not bucket, found %d buckets", n)
	}
	if err := s.Pool.QueryRow(ctx,
		`SELECT COALESCE(user_id,'') FROM audit WHERE action='lookup'`).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	if userID != "agent-7" {
		t.Fatalf("chained row must carry the user_id column, got %q", userID)
	}
}

// TestCloseAndVerifyReadBuckets drives the full P4.2 loop: bucket, close
// the finished hour into one chained row, verify digests, and prove that
// an edit to a sealed bucket is detected even when the trigger is
// bypassed.
func TestCloseAndVerifyReadBuckets(t *testing.T) {
	setReads(t, ReadsBucketed)
	s := testPool(t)
	ctx := context.Background()

	// Buckets in a PAST hour, planted directly (ReadEvent always writes to
	// the current hour, which the closer would rightly skip).
	if _, err := s.Pool.Exec(ctx, `
		INSERT INTO audit_read_buckets (client_id, user_id, cid, action, bucket_start, count, first_seen, last_seen)
		VALUES ('crm','agent-7','CID-A','lookup', date_trunc('hour', now() - interval '1 hour'), 3, now() - interval '70 minutes', now() - interval '61 minutes'),
		       ('erp','','CID-B','attributes.read', date_trunc('hour', now() - interval '1 hour'), 1, now() - interval '65 minutes', now() - interval '65 minutes')`); err != nil {
		t.Fatal(err)
	}

	hours, err := CloseReadBuckets(ctx, s.Pool)
	if err != nil {
		t.Fatal(err)
	}
	if hours != 1 {
		t.Fatalf("want 1 closed hour, got %d", hours)
	}
	// Closing an already-closed backlog is a no-op, not a duplicate.
	if hours, err = CloseReadBuckets(ctx, s.Pool); err != nil || hours != 0 {
		t.Fatalf("second close: hours=%d err=%v", hours, err)
	}

	// The hour produced exactly one chained row, and the chain verifies.
	sealAll(t, s)
	var hourly int64
	if err := s.Pool.QueryRow(ctx,
		`SELECT count(*) FROM audit WHERE action='audit.reads_hourly'`).Scan(&hourly); err != nil {
		t.Fatal(err)
	}
	if hourly != 1 {
		t.Fatalf("want exactly one hourly row, got %d", hourly)
	}
	if broken, reason, _, err := Verify(ctx, s.Pool); err != nil || broken != 0 {
		t.Fatalf("chain after close: broken=%d err=%v (%s)", broken, err, reason)
	}
	if bad, why, pending, err := VerifyReadBuckets(ctx, s.Pool); err != nil || bad != "" || pending != 0 {
		t.Fatalf("bucket verify: bad=%q pending=%d err=%v (%s)", bad, pending, err, why)
	}

	// A DBA-level attacker edits a sealed bucket under the digest: caught.
	if _, err := s.Pool.Exec(ctx, `ALTER TABLE audit_read_buckets DISABLE TRIGGER audit_read_buckets_no_edit`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx,
		`UPDATE audit_read_buckets SET count = count - 1 WHERE client_id='crm'`); err != nil {
		t.Fatal(err)
	}
	bad, why, _, err := VerifyReadBuckets(ctx, s.Pool)
	if err != nil {
		t.Fatal(err)
	}
	if bad == "" || !strings.Contains(why, "do not match") {
		t.Fatalf("edited sealed bucket must be detected, got bad=%q (%s)", bad, why)
	}
}

func TestLateEventForSealedHourFallsBackToChain(t *testing.T) {
	setReads(t, ReadsBucketed)
	s := testPool(t)
	ctx := context.Background()

	// A sealed bucket already exists for the CURRENT hour (as if the
	// closer raced a clock anomaly) - the conditional upsert would match
	// zero rows.
	if _, err := s.Pool.Exec(ctx, `
		INSERT INTO audit_read_buckets (client_id, user_id, cid, action, bucket_start, count, sealed_at)
		VALUES ('crm','agent-7','CID-A','lookup', date_trunc('hour', now()), 2, now())`); err != nil {
		t.Fatal(err)
	}
	if err := ReadEvent(ctx, s.Pool, Entry{
		ClientID: "crm", Action: "lookup", CID: "CID-A", UserID: "agent-7"}); err != nil {
		t.Fatal(err)
	}
	// The event must exist SOMEWHERE: as a chained row, since the bucket
	// was closed. Silent loss is the one forbidden outcome.
	var n int64
	if err := s.Pool.QueryRow(ctx,
		`SELECT count(*) FROM audit WHERE action='lookup' AND user_id='agent-7'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("late event must fall back to a chained row, found %d", n)
	}
}

func TestBucketTriggerRefusesEdits(t *testing.T) {
	setReads(t, ReadsBucketed)
	s := testPool(t)
	ctx := context.Background()
	if err := ReadEvent(ctx, s.Pool, Entry{ClientID: "crm", Action: "lookup", CID: "CID-A"}); err != nil {
		t.Fatal(err)
	}
	// Counting down, rekeying, deleting: all refused on an open bucket.
	if _, err := s.Pool.Exec(ctx, `UPDATE audit_read_buckets SET count = 0`); err == nil {
		t.Fatal("counting down must be refused")
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE audit_read_buckets SET cid = 'CID-FORGED'`); err == nil {
		t.Fatal("rekeying a bucket must be refused")
	}
	if _, err := s.Pool.Exec(ctx, `DELETE FROM audit_read_buckets`); err == nil {
		t.Fatal("deleting buckets must be refused")
	}
	// Sealing (the closer's move) is allowed; editing after it is not.
	if _, err := s.Pool.Exec(ctx, `UPDATE audit_read_buckets SET sealed_at = now()`); err != nil {
		t.Fatalf("sealing must be allowed: %v", err)
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE audit_read_buckets SET count = count + 1`); err == nil {
		t.Fatal("editing a sealed bucket must be refused")
	}
}

func TestVerifyReadBucketsDetectsMissingAndOrphanHours(t *testing.T) {
	setReads(t, ReadsBucketed)
	s := testPool(t)
	ctx := context.Background()

	// Sealed buckets WITHOUT their chained hourly row: broken.
	if _, err := s.Pool.Exec(ctx, `
		INSERT INTO audit_read_buckets (client_id, user_id, cid, action, bucket_start, count, sealed_at)
		VALUES ('crm','','CID-A','lookup', date_trunc('hour', now() - interval '2 hours'), 1, now())`); err != nil {
		t.Fatal(err)
	}
	bad, why, _, err := VerifyReadBuckets(ctx, s.Pool)
	if err != nil || bad == "" || !strings.Contains(why, "missing") {
		t.Fatalf("sealed buckets without an hourly row must be detected: %q (%s) err=%v", bad, why, err)
	}

	// Repair by closing properly, then verify passes and reports pending
	// finished hours (an OPEN bucket in a past hour) correctly.
	if _, err := s.Pool.Exec(ctx, `ALTER TABLE audit_read_buckets DISABLE TRIGGER audit_read_buckets_no_edit`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `DELETE FROM audit_read_buckets`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `ALTER TABLE audit_read_buckets ENABLE TRIGGER audit_read_buckets_no_edit`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `
		INSERT INTO audit_read_buckets (client_id, user_id, cid, action, bucket_start, count)
		VALUES ('crm','','CID-A','lookup', date_trunc('hour', now() - interval '3 hours'), 1)`); err != nil {
		t.Fatal(err)
	}
	bad, why, pendingHours, err := VerifyReadBuckets(ctx, s.Pool)
	if err != nil || bad != "" {
		t.Fatalf("open past-hour buckets are pending, not broken: %q (%s) err=%v", bad, why, err)
	}
	if pendingHours != 1 {
		t.Fatalf("want 1 pending finished hour, got %d", pendingHours)
	}

	// An hourly row whose sealed buckets are gone: broken. Plant one via a
	// legitimate close, then delete the buckets under a disabled trigger.
	if n, err := CloseReadBuckets(ctx, s.Pool); err != nil || n != 1 {
		t.Fatalf("close: %d %v", n, err)
	}
	if _, err := s.Pool.Exec(ctx, `ALTER TABLE audit_read_buckets DISABLE TRIGGER audit_read_buckets_no_edit`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `DELETE FROM audit_read_buckets WHERE sealed_at IS NOT NULL`); err != nil {
		t.Fatal(err)
	}
	bad, why, _, err = VerifyReadBuckets(ctx, s.Pool)
	if err != nil || bad == "" || !strings.Contains(why, "gone") {
		t.Fatalf("hourly row without its buckets must be detected: %q (%s) err=%v", bad, why, err)
	}
}

func TestReadBucketFunctionsOnDeadPool(t *testing.T) {
	setReads(t, ReadsBucketed)
	s := testPool(t)
	s.Close()
	ctx := context.Background()
	if err := ReadEvent(ctx, s.Pool, Entry{ClientID: "c", Action: "lookup"}); err == nil {
		t.Fatal("read event on a dead pool must error (fail closed)")
	}
	if _, err := CloseReadBuckets(ctx, s.Pool); err == nil {
		t.Fatal("close on a dead pool must error")
	}
	if _, _, _, err := VerifyReadBuckets(ctx, s.Pool); err == nil {
		t.Fatal("verify on a dead pool must error")
	}
}

func TestVerifyReadBucketsDetectsBadHourlyRows(t *testing.T) {
	setReads(t, ReadsBucketed)
	s := testPool(t)
	ctx := context.Background()

	// An hourly row whose detail cannot be parsed: flagged, not skipped.
	if err := Append(ctx, s.Pool, Entry{
		ClientID: "_audit", Action: "audit.reads_hourly",
		Detail: map[string]any{"note": "no hour field"}}); err != nil {
		t.Fatal(err)
	}
	bad, why, _, err := VerifyReadBuckets(ctx, s.Pool)
	if err != nil || bad != "?" || !strings.Contains(why, "unparseable") {
		t.Fatalf("unparseable hourly detail must be flagged: %q (%s) err=%v", bad, why, err)
	}
}

func TestVerifyReadBucketsDetectsDuplicateHour(t *testing.T) {
	setReads(t, ReadsBucketed)
	s := testPool(t)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if err := Append(ctx, s.Pool, Entry{
			ClientID: "_audit", Action: "audit.reads_hourly",
			Detail: map[string]any{"hour": "2026-08-25T10:00:00Z", "digest": "d"}}); err != nil {
			t.Fatal(err)
		}
	}
	bad, why, _, err := VerifyReadBuckets(ctx, s.Pool)
	if err != nil || bad == "" || !strings.Contains(why, "twice") {
		t.Fatalf("duplicated hourly row must be flagged: %q (%s) err=%v", bad, why, err)
	}
}

func TestUserIDContextHelpers(t *testing.T) {
	ctx := context.Background()
	if got := UserIDFromContext(ctx); got != "" {
		t.Fatalf("empty context must yield no user id, got %q", got)
	}
	// An empty id must not allocate a context value at all.
	if got := UserIDFromContext(WithUserID(ctx, "")); got != "" {
		t.Fatalf("empty id must stay empty, got %q", got)
	}
	if got := UserIDFromContext(WithUserID(ctx, "agent-1")); got != "agent-1" {
		t.Fatalf("round trip failed, got %q", got)
	}
	setReads(t, ReadsChained)
	if ReadsMode() != ReadsChained {
		t.Fatal("mode must read back as chained")
	}
	setReads(t, ReadsBucketed)
	if ReadsMode() != ReadsBucketed {
		t.Fatal("mode must read back as bucketed")
	}
}

// TestReadEventBucketsByDatabaseClock pins the F-fix from the P4.2 review:
// the bucket hour must come from the database clock, because the closer
// decides "finished" by the database clock. An application timestamp here
// reopens closed hours across app/DB clock skew at hour boundaries, and a
// reopened hour gets summarized twice - a permanent false verify failure.
func TestReadEventBucketsByDatabaseClock(t *testing.T) {
	setReads(t, ReadsBucketed)
	s := testPool(t)
	ctx := context.Background()
	if err := ReadEvent(ctx, s.Pool, Entry{ClientID: "crm", Action: "lookup", CID: "CID-A"}); err != nil {
		t.Fatal(err)
	}
	var matches bool
	if err := s.Pool.QueryRow(ctx, `
		SELECT bucket_start = date_trunc('hour', now())
		   AND first_seen  >= now() - interval '1 minute'
		   AND last_seen   >= now() - interval '1 minute'
		  FROM audit_read_buckets LIMIT 1`).Scan(&matches); err != nil {
		t.Fatal(err)
	}
	if !matches {
		t.Fatal("bucket timestamps must come from the database clock, not the application clock")
	}
}
