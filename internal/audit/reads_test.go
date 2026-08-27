package audit

import (
	"context"
	"strings"
	"testing"

	"github.com/fvisic/sunder/internal/store"
	"time"
)

// setReads pins the read-audit mode for one test and restores the
// matrix-selected mode afterwards.
func setReads(t *testing.T, m string) {
	t.Helper()
	old := ReadsMode()
	SetReadsMode(m)
	t.Cleanup(func() { SetReadsMode(old) })
}

// insertSealedRow plants an ALREADY-SEALED bucket row directly - the forgery
// the audit_read_buckets_open_insert guard exists to refuse - by disabling
// that guard around the statement, the way other tests simulate a
// database-level attacker.
func insertSealedRow(t *testing.T, s *store.Store, sql string, args ...any) {
	t.Helper()
	ctx := context.Background()
	if _, err := s.Pool.Exec(ctx, `ALTER TABLE audit_read_buckets DISABLE TRIGGER audit_read_buckets_open_insert`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, sql, args...); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `ALTER TABLE audit_read_buckets ENABLE TRIGGER audit_read_buckets_open_insert`); err != nil {
		t.Fatal(err)
	}
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
	insertSealedRow(t, s, `
		INSERT INTO audit_read_buckets (client_id, user_id, cid, action, bucket_start, count, sealed_at)
		VALUES ('crm','agent-7','CID-A','lookup', date_trunc('hour', now()), 2, now())`)
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
	insertSealedRow(t, s, `
		INSERT INTO audit_read_buckets (client_id, user_id, cid, action, bucket_start, count, sealed_at)
		VALUES ('crm','','CID-A','lookup', date_trunc('hour', now() - interval '2 hours'), 1, now())`)
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
	if err := Append(ctx, s.Pool, Entry{
		ClientID: "_audit", Action: "audit.reads_hourly",
		Detail: map[string]any{"hour": "2026-08-25T10:00:00Z", "digest": "d"}}); err != nil {
		t.Fatal(err)
	}
	// AUDIT-CHAIN-2: a second marker for the same hour is refused by the
	// unique index (migration 0036) rather than silently poisoning
	// verification - and rather than letting a forged marker suppress a real
	// hour's sealing forever.
	if err := Append(ctx, s.Pool, Entry{
		ClientID: "_audit", Action: "audit.reads_hourly",
		Detail: map[string]any{"hour": "2026-08-25T10:00:00Z", "digest": "d2"}}); err == nil {
		t.Fatal("a duplicate audit.reads_hourly marker must be refused by the database")
	}
	// The verify branch still has to hold for rows written before that index
	// existed: drop it, create the duplicate, and assert the verdict.
	if _, err := s.Pool.Exec(ctx, `DROP INDEX audit_reads_hourly_idx`); err != nil {
		t.Fatal(err)
	}
	if err := Append(ctx, s.Pool, Entry{
		ClientID: "_audit", Action: "audit.reads_hourly",
		Detail: map[string]any{"hour": "2026-08-25T10:00:00Z", "digest": "d2"}}); err != nil {
		t.Fatal(err)
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

func TestReadBucketFuncsSurfaceQueryErrors(t *testing.T) {
	setReads(t, ReadsBucketed)
	s := testPool(t)
	ctx := context.Background()
	// Break the buckets table so the Query in CloseReadBuckets and
	// VerifyReadBuckets fails, exercising their error returns.
	if _, err := s.Pool.Exec(ctx, `ALTER TABLE audit_read_buckets RENAME TO arb_gone`); err != nil {
		t.Fatal(err)
	}
	if _, err := CloseReadBuckets(ctx, s.Pool); err == nil {
		t.Fatal("close must surface the query error")
	}
	if _, _, _, err := VerifyReadBuckets(ctx, s.Pool); err == nil {
		t.Fatal("verify must surface the query error")
	}
	if err := ReadEvent(ctx, s.Pool, Entry{ClientID: "c", Action: "lookup"}); err == nil {
		t.Fatal("read event must surface the query error")
	}
}

// TestVerifyReadBucketsDetectsTampering plants a past hour, seals it, then
// edits a sealed bucket's count - VerifyReadBuckets must catch the digest
// mismatch (the tamper-evidence the hourly digest exists for).
func TestVerifyReadBucketsDetectsTampering(t *testing.T) {
	setReads(t, ReadsBucketed)
	s := testPool(t)
	ctx := context.Background()
	if _, err := s.Pool.Exec(ctx, `
		INSERT INTO audit_read_buckets (client_id, user_id, cid, action, bucket_start, count, first_seen, last_seen)
		VALUES ('crm','a','CID-A','lookup', date_trunc('hour', now() - interval '2 hour'), 5, now() - interval '130 minutes', now() - interval '121 minutes')`); err != nil {
		t.Fatal(err)
	}
	if _, err := CloseReadBuckets(ctx, s.Pool); err != nil {
		t.Fatal(err)
	}
	// Clean verify first.
	if _, reason, _, err := VerifyReadBuckets(ctx, s.Pool); err != nil || reason != "" {
		t.Fatalf("clean verify: reason=%q err=%v", reason, err)
	}
	// Tamper out-of-band: an attacker with direct DB write disables the
	// append-only trigger and edits a sealed bucket. The digest still
	// catches it - that is the point of the chained hourly digest.
	if _, err := s.Pool.Exec(ctx, `ALTER TABLE audit_read_buckets DISABLE TRIGGER USER`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx,
		`UPDATE audit_read_buckets SET count = count + 1 WHERE sealed_at IS NOT NULL`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `ALTER TABLE audit_read_buckets ENABLE TRIGGER USER`); err != nil {
		t.Fatal(err)
	}
	_, reason, _, err := VerifyReadBuckets(ctx, s.Pool)
	if err != nil {
		t.Fatal(err)
	}
	if reason == "" {
		t.Fatal("an edited sealed bucket must be detected as a digest mismatch")
	}
}

// TestHourDigestIndependentOfRowOrder (H12): the digest must depend on the
// bucket CONTENT only, never on the order rows arrive - the old code let the
// database's text collation pick the order at seal AND at verify, so a
// dump/restore into a differently collated cluster (or a glibc collation
// change) flipped every previously sealed hour to "tampered". sortBuckets
// pins a byte-wise total order in Go.
func TestHourDigestIndependentOfRowOrder(t *testing.T) {
	// client ids chosen where common collations disagree with byte order:
	// '-' (0x2D) < '.' (0x2E) < '_' (0x5F), while e.g. en_US often sorts
	// punctuation-insensitively.
	mk := func() []bucketRow {
		return []bucketRow{
			{ClientID: "a_b", Action: "lookup", Count: 1},
			{ClientID: "a-b", Action: "lookup", Count: 2},
			{ClientID: "a.b", Action: "lookup", Count: 3},
			{ClientID: "a-b", UserID: "z", Action: "lookup", Count: 4},
			{ClientID: "A", Action: "lookup", Count: 5},
		}
	}
	a := mk()
	b := mk()
	// Reverse b: a different arrival order for the same set.
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	sortBuckets(a)
	sortBuckets(b)
	if hourDigest(a) != hourDigest(b) {
		t.Fatal("digest must be independent of row arrival order")
	}
	// Byte-wise order, explicitly: 'A'(0x41) < 'a-b' < 'a.b' < 'a_b'.
	want := []string{"A", "a-b", "a-b", "a.b", "a_b"}
	for i, r := range a {
		if r.ClientID != want[i] {
			t.Fatalf("canonical order must be byte-wise: position %d = %q, want %q", i, r.ClientID, want[i])
		}
	}
}

// TestSealDigestCoversExactlyTheSealedRows (H11): the chained hourly digest
// and the set of rows marked sealed must be the SAME set - the old two-
// statement close let a concurrent upsert slip between the digest SELECT and
// the sealing UPDATE, permanently breaking verification. The seal is now one
// UPDATE ... RETURNING; this test pins the property the fix guarantees: a
// sealed row that the digest does not cover is reported as tampering.
func TestSealDigestCoversExactlyTheSealedRows(t *testing.T) {
	setReads(t, ReadsBucketed)
	s := testPool(t)
	ctx := context.Background()

	if _, err := s.Pool.Exec(ctx, `
		INSERT INTO audit_read_buckets (client_id, user_id, cid, action, bucket_start, count)
		VALUES ('crm','','CID-H11','lookup', date_trunc('hour', now() - interval '2 hours'), 3)`); err != nil {
		t.Fatal(err)
	}
	if n, err := CloseReadBuckets(ctx, s.Pool); err != nil || n != 1 {
		t.Fatalf("close: %d %v", n, err)
	}
	if bad, why, _, err := VerifyReadBuckets(ctx, s.Pool); err != nil || bad != "" {
		t.Fatalf("freshly sealed hour must verify: %q (%s) err=%v", bad, why, err)
	}

	// Simulate the race's aftermath: a row that is sealed but was never in
	// the digest (the trigger allows INSERT, so a database attacker - or the
	// old racy close - can produce exactly this). Verification must flag it.
	insertSealedRow(t, s, `
		INSERT INTO audit_read_buckets (client_id, user_id, cid, action, bucket_start, count, sealed_at)
		VALUES ('crm','','CID-H11-EXTRA','lookup', date_trunc('hour', now() - interval '2 hours'), 1, now())`)
	bad, why, _, err := VerifyReadBuckets(ctx, s.Pool)
	if err != nil || bad == "" || !strings.Contains(why, "do not match") {
		t.Fatalf("a sealed row outside the digest must be reported: %q (%s) err=%v", bad, why, err)
	}
}

// TestDigestMatchesGrandfathersLegacyOrder: hours sealed before the Go-sort
// change carry digests computed in the database's collation order. Verify
// must accept those (in the order the rows arrive from its ORDER BY) as well
// as the canonical byte-wise order - otherwise the H12 fix itself would flip
// every pre-existing sealed hour to "tampered" on upgrade.
func TestDigestMatchesGrandfathersLegacyOrder(t *testing.T) {
	rows := []bucketRow{
		{ClientID: "a_b", Action: "lookup", Count: 1},
		{ClientID: "a-b", Action: "lookup", Count: 2},
		{ClientID: "a.b", Action: "lookup", Count: 3},
	}
	// A "legacy" digest: whatever order the old SQL ORDER BY produced -
	// simulate a collation that sorts differently from byte order.
	legacyOrder := []bucketRow{rows[0], rows[2], rows[1]} // a_b, a.b, a-b
	legacyDigest := hourDigest(legacyOrder)

	arrived := make([]bucketRow, len(legacyOrder))
	copy(arrived, legacyOrder)
	if !digestMatches(legacyDigest, arrived) {
		t.Fatal("a pre-fix hour digested in collation order must still verify")
	}
	// The canonical order matches too, of course.
	canonical := make([]bucketRow, len(rows))
	copy(canonical, rows)
	sortBuckets(canonical)
	arrived2 := []bucketRow{rows[1], rows[0], rows[2]}
	if !digestMatches(hourDigest(canonical), arrived2) {
		t.Fatal("the canonical byte-wise digest must verify regardless of arrival order")
	}
	// And a genuinely wrong digest still fails.
	if digestMatches("deadbeef", arrived2) {
		t.Fatal("a digest matching neither order must be reported")
	}
}

// TestForgedSealedBucketInsertRefused (review medium): the guard triggers
// covered UPDATE/DELETE/TRUNCATE but not INSERT - and INSERT is exactly the
// privilege the API role holds, so one forged SEALED row poisoned bucket
// verification permanently. Legitimate inserts are always open.
func TestForgedSealedBucketInsertRefused(t *testing.T) {
	s := testPool(t)
	ctx := context.Background()
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO audit_read_buckets (client_id, user_id, cid, action, bucket_start, count, sealed_at)
		VALUES ('evil','','CID-X','lookup', date_trunc('hour', now() - interval '3 hours'), 1, now())`)
	if err == nil || !strings.Contains(err.Error(), "inserted OPEN") {
		t.Fatalf("a pre-sealed bucket insert must be refused: %v", err)
	}
	// An OPEN insert (what ReadEvent does) still works.
	if _, err := s.Pool.Exec(ctx, `
		INSERT INTO audit_read_buckets (client_id, user_id, cid, action, bucket_start, count)
		VALUES ('ok','','CID-X','lookup', date_trunc('hour', now()), 1)`); err != nil {
		t.Fatal(err)
	}
}

// TestCloserSkipsAlreadySummarizedHour (review medium): open rows landing in
// an hour whose chained hourly row already exists must NOT be summarized
// again - a second audit.reads_hourly row is a permanent "hour summarized
// twice" verification poison. They stay unsealed (visible in the pending
// count) and every other hour keeps closing.
func TestCloserSkipsAlreadySummarizedHour(t *testing.T) {
	setReads(t, ReadsBucketed)
	setMode(t, "sync")
	s := testPool(t)
	ctx := context.Background()

	// A legitimately closed hour.
	if _, err := s.Pool.Exec(ctx, `
		INSERT INTO audit_read_buckets (client_id, user_id, cid, action, bucket_start, count)
		VALUES ('crm','','CID-A','lookup', date_trunc('hour', now() - interval '3 hours'), 2)`); err != nil {
		t.Fatal(err)
	}
	if n, err := CloseReadBuckets(ctx, s.Pool); err != nil || n != 1 {
		t.Fatalf("close: %d %v", n, err)
	}
	// A forged/late OPEN row lands in that same closed hour, and a normal
	// open row in a DIFFERENT past hour.
	if _, err := s.Pool.Exec(ctx, `
		INSERT INTO audit_read_buckets (client_id, user_id, cid, action, bucket_start, count)
		VALUES ('late','','CID-B','lookup', date_trunc('hour', now() - interval '3 hours'), 1),
		       ('crm','','CID-C','lookup', date_trunc('hour', now() - interval '2 hours'), 1)`); err != nil {
		t.Fatal(err)
	}
	if n, err := CloseReadBuckets(ctx, s.Pool); err != nil || n != 1 {
		t.Fatalf("only the fresh hour must close: %d %v", n, err)
	}
	var hourly int64
	if err := s.Pool.QueryRow(ctx,
		`SELECT count(*) FROM audit WHERE action='audit.reads_hourly'`).Scan(&hourly); err != nil {
		t.Fatal(err)
	}
	if hourly != 2 {
		t.Fatalf("the poisoned hour must NOT be summarized twice: %d hourly rows", hourly)
	}
	// Verification stays clean; the stranded row shows as pending, loudly.
	bad, why, pending, err := VerifyReadBuckets(ctx, s.Pool)
	if err != nil || bad != "" {
		t.Fatalf("verify must stay clean: %q (%s) %v", bad, why, err)
	}
	if pending != 1 {
		t.Fatalf("the stranded hour must be pending: %d", pending)
	}
}

// TESTS-7: TestSealDigestCoversExactlyTheSealedRows asserts that the
// VERIFIER detects a digest/sealed-set mismatch - it says nothing about
// whether closeOneHour can create one, so reverting the seal to the old
// two-statement form (SELECT the rows, digest them, then UPDATE sealed_at)
// leaves it green while silently reopening H11. This drives the
// interleaving: a ReadEvent upsert commits for the hour being closed, and
// the outcome must be all-or-nothing.
func TestCloseIsAtomicAgainstAConcurrentReadEvent(t *testing.T) {
	setMode(t, ModeAsync)
	setReads(t, ReadsBucketed)
	s := testPool(t)
	ctx := context.Background()
	hour := "date_trunc('hour', now()-interval '2 hours')"

	// One open bucket in a finished hour.
	if _, err := s.Pool.Exec(ctx, `
		INSERT INTO audit_read_buckets (client_id, user_id, cid, action, bucket_start, count, first_seen, last_seen)
		VALUES ('crm','op1','CID-A','attributes.read', `+hour+`, 3, now(), now())`); err != nil {
		t.Fatal(err)
	}

	// A competing upsert for the SAME hour, held uncommitted so it lands in
	// the middle of the close.
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_read_buckets (client_id, user_id, cid, action, bucket_start, count, first_seen, last_seen)
		VALUES ('crm','op2','CID-B','attributes.read', `+hour+`, 1, now(), now())`); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}

	closed := make(chan error, 1)
	go func() {
		_, err := CloseReadBuckets(ctx, s.Pool)
		closed <- err
	}()
	// Give the closer time to reach (and, in the two-statement form, get
	// past) its digest read before the competing row becomes visible.
	time.Sleep(150 * time.Millisecond)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	// Whatever the interleaving, the late row is either fully inside the
	// sealed set AND the digest, or fully outside both (still open, and so
	// reported as a pending hour) - never split.
	if bad, why, _, err := VerifyReadBuckets(ctx, s.Pool); err != nil || bad != "" {
		t.Fatalf("a concurrent read event split the sealed set from its digest: %q %s %v", bad, why, err)
	}
	// A second pass closes whatever was left open, and it still verifies.
	if _, err := CloseReadBuckets(ctx, s.Pool); err != nil {
		t.Fatal(err)
	}
	if bad, why, _, err := VerifyReadBuckets(ctx, s.Pool); err != nil || bad != "" {
		t.Fatalf("after the follow-up close: %q %s %v", bad, why, err)
	}
}
