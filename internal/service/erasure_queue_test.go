package service_test

// H1 regression: the erasure outbox commits its claim before the POST, so
// SENDING is a state with no owner. These tests pin the two things that
// return a claim to the queue - the worker releasing on cancellation, and
// the reaper recovering a claim its worker never released.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fvisic/sunder/internal/service"
)

// seedEvents queues n erasure events for scope "crm" pointed at url.
func seedEvents(t *testing.T, e *faultEnv, url string, n int) int64 {
	t.Helper()
	ctx := context.Background()
	if _, err := e.admin.Pool.Exec(ctx,
		`INSERT INTO webhooks (scope, url, secret) VALUES ('crm',$1,'sec')
		 ON CONFLICT (scope) DO UPDATE SET url=EXCLUDED.url`, url); err != nil {
		t.Fatal(err)
	}
	var personID string
	if err := e.admin.Pool.QueryRow(ctx,
		`INSERT INTO persons (id) VALUES (gen_random_uuid()) RETURNING id`).Scan(&personID); err != nil {
		t.Fatal(err)
	}
	var erasureID int64
	if err := e.admin.Pool.QueryRow(ctx,
		`INSERT INTO erasures (person_id, requested_by) VALUES ($1,'test') RETURNING id`,
		personID).Scan(&erasureID); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if _, err := e.admin.Pool.Exec(ctx,
			`INSERT INTO erasure_events (erasure_id, scope, cid) VALUES ($1,'crm',$2)`,
			erasureID, "CID-QUEUE"+string(rune('A'+i))+"0000000000000"); err != nil {
			t.Fatal(err)
		}
	}
	return erasureID
}

func statusCounts(t *testing.T, e *faultEnv) map[string]int {
	t.Helper()
	rows, err := e.admin.Pool.Query(context.Background(),
		`SELECT status, count(*) FROM erasure_events GROUP BY status`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var s string
		var n int
		if err := rows.Scan(&s, &n); err != nil {
			t.Fatal(err)
		}
		out[s] = n
	}
	return out
}

// TestDeliverPendingReleasesClaimsOnCancellation: cancelling the worker's
// context mid-batch must leave ZERO rows in SENDING, and a later sweep with
// a live context must deliver all of them. Before the fix the compensating
// UPDATE ran on the dead context, so every claimed row was stranded forever.
func TestDeliverPendingReleasesClaimsOnCancellation(t *testing.T) {
	e := newFaultEnv(t)

	entered := make(chan struct{}, 1)
	unblock := make(chan struct{})
	var served int
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served++
		select {
		case entered <- struct{}{}:
		default:
		}
		<-unblock
		w.WriteHeader(200)
	}))
	defer hook.Close()

	seedEvents(t, e, hook.URL, 3)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = e.gdpr.DeliverPending(ctx)
	}()

	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("webhook never entered - the claim was not committed")
	}
	// The claim is committed and visible: proof the strand window is open.
	if got := statusCounts(t, e)["SENDING"]; got != 3 {
		t.Fatalf("expected 3 claimed rows while the POST is in flight, got %d", got)
	}
	cancel()
	close(unblock)
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("DeliverPending did not return after cancellation")
	}

	if got := statusCounts(t, e)["SENDING"]; got != 0 {
		t.Fatalf("cancellation stranded %d row(s) in SENDING", got)
	}

	// A fresh sweep must be able to see and deliver every event.
	n, err := e.gdpr.DeliverPending(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("second sweep delivered %d/3", n)
	}
	if c := statusCounts(t, e); c["DELIVERED"] != 3 {
		t.Fatalf("expected 3 DELIVERED, got %v", c)
	}
}

// TestErasureEventReaperReturnsStrandedClaims is the counterpart to
// TestPortalReaperAndPendingPruning: an aged claim returns to the queue, a
// fresh one does not, and the requeued event delivers and audits.
func TestErasureEventReaperReturnsStrandedClaims(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()

	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer hook.Close()
	seedEvents(t, e, hook.URL, 2)

	var aged, fresh int64
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT min(id), max(id) FROM erasure_events`).Scan(&aged, &fresh); err != nil {
		t.Fatal(err)
	}
	if _, err := e.admin.Pool.Exec(ctx,
		`UPDATE erasure_events SET status='SENDING', claimed_at=now()-interval '30 minutes' WHERE id=$1`, aged); err != nil {
		t.Fatal(err)
	}
	if _, err := e.admin.Pool.Exec(ctx,
		`UPDATE erasure_events SET status='SENDING', claimed_at=now() WHERE id=$1`, fresh); err != nil {
		t.Fatal(err)
	}

	n, err := service.ReapStrandedErasureEvents(ctx, e.admin.Pool, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("reaper must requeue exactly the aged claim, got %d", n)
	}
	var freshStatus string
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT status FROM erasure_events WHERE id=$1`, fresh).Scan(&freshStatus); err != nil {
		t.Fatal(err)
	}
	if freshStatus != "SENDING" {
		t.Fatalf("a live claim must not be reaped, got %s", freshStatus)
	}

	// The requeued event delivers, and the delivery is on the audit chain.
	if _, err := e.gdpr.DeliverPending(ctx); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT status FROM erasure_events WHERE id=$1`, aged).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "DELIVERED" {
		t.Fatalf("requeued event must deliver, got %s", status)
	}
	var audited int
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM audit WHERE action='dsr.erase.delivered'`).Scan(&audited); err != nil {
		t.Fatal(err)
	}
	if audited == 0 {
		t.Fatal("delivery must be written to the audit chain")
	}
}

// TestReaperBackfillsPreMigrationClaims: rows stranded before 0035 have a
// NULL claimed_at and must still be recoverable.
func TestReaperBackfillsPreMigrationClaims(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	seedEvents(t, e, "http://127.0.0.1:1/never", 1)
	if _, err := e.admin.Pool.Exec(ctx,
		`UPDATE erasure_events SET status='SENDING', claimed_at=NULL`); err != nil {
		t.Fatal(err)
	}
	n, err := service.ReapStrandedErasureEvents(ctx, e.admin.Pool, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("a NULL claimed_at must be treated as stranded, got %d", n)
	}
}

// TestErasePersonDoesNotBlockOnWebhook: the post-erasure delivery is
// detached, so Erase returns without waiting for a slow receiver.
func TestErasePersonDoesNotBlockOnWebhook(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cid := e.register(t)

	release := make(chan struct{})
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		w.WriteHeader(200)
	}))
	defer hook.Close()
	defer close(release)
	if _, err := e.admin.Pool.Exec(ctx,
		`INSERT INTO webhooks (scope, url, secret) VALUES ('crm',$1,'sec')`, hook.URL); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	if _, _, err := e.gdpr.Erase(ctx, e.crm, cid); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("Erase waited %s on the webhook - delivery must be detached", elapsed)
	}
}

// The delivery worker's settle-after-success branch: the downstream system
// HAS deleted the record and only our bookkeeping failed. The claim must be
// recoverable so the next sweep re-delivers - at-least-once is the
// documented contract, and a receiver keyed on (scope, cid, erasure_id)
// absorbs the repeat.
func TestSettleFailureAfterASuccessfulPostIsRecoverable(t *testing.T) {
	e := newFaultEnv(t, "audit")
	ctx := context.Background()

	var delivered int
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		delivered++
		w.WriteHeader(200)
	}))
	defer hook.Close()
	seedEvents(t, e, hook.URL, 1)

	// The service pool cannot append to `audit`, so terminal() fails AFTER
	// the POST succeeded.
	if _, err := e.gdpr.DeliverPending(ctx); err != nil {
		t.Fatal(err)
	}
	if delivered != 1 {
		t.Fatalf("the POST must have been made, got %d", delivered)
	}
	var status string
	if err := e.admin.Pool.QueryRow(ctx, `SELECT status FROM erasure_events`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status == "DELIVERED" {
		t.Fatal("the settle failed, so the row cannot be marked delivered")
	}
	// Whatever state it is in, the reaper gets it back to the queue.
	if _, err := service.ReapStrandedErasureEvents(ctx, e.admin.Pool, time.Nanosecond); err != nil {
		t.Fatal(err)
	}
	if err := e.admin.Pool.QueryRow(ctx, `SELECT status FROM erasure_events`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "PENDING" {
		t.Fatalf("a claim whose settle failed must return to the queue, got %s", status)
	}
}

// A cancelled context AFTER the POST has failed must not charge an attempt:
// our own shutdown is not the endpoint's fault, and burning attempts on it
// walks a healthy scope towards the FAILED cap.
func TestCancellationAfterAFailedPostDoesNotChargeAnAttempt(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()

	ctx2, cancel := context.WithCancel(ctx)
	blocked := make(chan struct{})
	entered := make(chan struct{}, 1)
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-blocked
		w.WriteHeader(500)
	}))
	defer hook.Close()
	seedEvents(t, e, hook.URL, 2)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = e.gdpr.DeliverPending(ctx2)
	}()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the worker never reached the webhook")
	}
	cancel()
	close(blocked)
	<-done

	var maxAttempts int
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT COALESCE(max(attempts),0) FROM erasure_events`).Scan(&maxAttempts); err != nil {
		t.Fatal(err)
	}
	if maxAttempts != 0 {
		t.Fatalf("a POST that failed because OUR context died must not charge an attempt, got %d", maxAttempts)
	}
	var sending int
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM erasure_events WHERE status='SENDING'`).Scan(&sending); err != nil {
		t.Fatal(err)
	}
	if sending != 0 {
		t.Fatalf("%d claim(s) stranded by the cancellation", sending)
	}
}
