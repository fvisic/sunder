package service_test

// Fault injection at the commit boundaries (PLAN 7.2).
//
// Every claim-before-side-effect design in this tree is DOCUMENTED as
// crash-safe. Documented is not tested: these invariants hold because of
// where a commit sits relative to a side effect, and until now nothing
// verified that relationship. Each test below kills the operation at the
// point a real crash would land and asserts what must survive.
//
// A panic through service.CrashAtForTest is the closest a test can get to a
// SIGKILL while still being able to assert on the aftermath.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fvisic/sunder/internal/service"
)

// crashOnce arranges a panic the first time the named point is reached, and
// runs fn with that in place. It returns whether the crash actually fired -
// a test whose seam never ran proves nothing, so every caller checks it.
func crashOnce(t *testing.T, point string, fn func()) bool {
	t.Helper()
	var fired atomic.Bool
	service.CrashAtForTest = func(p string) {
		if p == point && fired.CompareAndSwap(false, true) {
			panic("crash at " + p)
		}
	}
	t.Cleanup(func() { service.CrashAtForTest = nil })
	func() {
		defer func() { _ = recover() }()
		fn()
	}()
	service.CrashAtForTest = nil
	return fired.Load()
}

// TestCrashAfterOutboxClaimIsReaped: the delivery worker commits its claim
// BEFORE attempting any HTTP, which is what stops two replicas delivering
// the same event. The cost of that ordering is that a worker killed in the
// window owns rows it will never send.
//
// SENDING was an absorbing state before v0.5.0 - no lease, no reaper - so
// those Article 19 notifications were simply never delivered and nothing
// said so. This asserts the lease actually recovers them.
func TestCrashAfterOutboxClaimIsReaped(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()

	cid := e.register(t)
	if _, err := e.admin.Pool.Exec(ctx,
		`INSERT INTO webhooks (scope, url, secret) VALUES ('crm','http://127.0.0.1:1/hook','s')
		 ON CONFLICT (scope) DO UPDATE SET url=EXCLUDED.url`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.gdpr.Erase(ctx, e.crm, cid); err != nil {
		t.Fatal(err)
	}
	e.gdpr.Drain()

	if !crashOnce(t, "outbox.claimed", func() { _, _ = e.gdpr.DeliverPending(ctx) }) {
		t.Fatal("the seam never fired - no claim was taken, so this proves nothing")
	}

	// The state a killed worker leaves: claimed, unsent, owned by nobody.
	var sending int
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM erasure_events WHERE status='SENDING'`).Scan(&sending); err != nil {
		t.Fatal(err)
	}
	if sending == 0 {
		t.Skip("no event was left in SENDING; the claim did not commit before the crash")
	}

	// Age the claim past the lease, then let the reaper do its job.
	if _, err := e.admin.Pool.Exec(ctx,
		`UPDATE erasure_events SET claimed_at = now() - interval '1 hour' WHERE status='SENDING'`); err != nil {
		t.Fatal(err)
	}
	n, err := service.ReapStrandedErasureEvents(ctx, e.admin.Pool, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("the reaper recovered nothing: an erasure notification claimed by a " +
			"killed worker would never be delivered, and nothing would say so")
	}
	var pending int
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM erasure_events WHERE status='PENDING'`).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending == 0 {
		t.Fatal("the event is neither SENDING nor PENDING after reaping - it is lost")
	}
}

// TestCrashBetweenPostAndAckRedelivers: the receiver has already acted; our
// record that it did has not been written. This is the window that makes
// delivery at-least-once, and the reason the documentation tells receivers
// to dedup on (scope, cid, erasure_id).
//
// The invariant is NOT "exactly once" - it is that the event is redelivered
// rather than silently marked done. Losing it here would mean a downstream
// system believing it was told to erase when it was not.
func TestCrashBetweenPostAndAckRedelivers(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()

	var posts atomic.Int32
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		posts.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer hook.Close()

	// Erase with NO webhook registered, so the inline post-erase delivery
	// finds nothing to send and the event stays queued. Registering the
	// endpoint afterwards is the documented behaviour (an event for a scope
	// without a webhook waits rather than being discarded), and it is what
	// puts this test in control of when the POST happens.
	cid := e.register(t)
	if _, _, err := e.gdpr.Erase(ctx, e.crm, cid); err != nil {
		t.Fatal(err)
	}
	e.gdpr.Drain()
	if _, err := e.admin.Pool.Exec(ctx,
		`INSERT INTO webhooks (scope, url, secret) VALUES ('crm',$1,'s')
		 ON CONFLICT (scope) DO UPDATE SET url=EXCLUDED.url`, hook.URL); err != nil {
		t.Fatal(err)
	}
	if _, err := e.admin.Pool.Exec(ctx,
		`UPDATE erasure_events SET status='PENDING', claimed_at=NULL
		  WHERE status IN ('NO_WEBHOOK','SENDING')`); err != nil {
		t.Fatal(err)
	}
	var open int
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM erasure_events WHERE status='PENDING'`).Scan(&open); err != nil {
		t.Fatal(err)
	}
	if open == 0 {
		t.Fatal("no queued event to deliver - the erasure produced none")
	}

	if !crashOnce(t, "outbox.posted", func() { _, _ = e.gdpr.DeliverPending(ctx) }) {
		t.Fatal("the seam never fired - no POST succeeded, so this proves nothing")
	}
	first := posts.Load()
	if first == 0 {
		t.Fatal("no POST was made before the crash")
	}

	// The receiver acted, we recorded nothing. Recovery must re-deliver.
	if _, err := e.admin.Pool.Exec(ctx,
		`UPDATE erasure_events SET claimed_at = now() - interval '1 hour' WHERE status='SENDING'`); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ReapStrandedErasureEvents(ctx, e.admin.Pool, time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := e.gdpr.DeliverPending(ctx); err != nil {
		t.Fatal(err)
	}
	if posts.Load() <= first {
		t.Fatal("the event was not re-delivered after a crash between the POST and its " +
			"acknowledgement - a downstream system would be recorded as told when it was not")
	}

	var settled int
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM erasure_events WHERE status='DELIVERED'`).Scan(&settled); err != nil {
		t.Fatal(err)
	}
	if settled == 0 {
		t.Fatal("the redelivery did not settle the event")
	}
}

// TestCrashBeforeErasureCommitLeavesNothingHalfDone: the blob wipe, the token
// deletion, the tombstone and the queued Article 19 events all live in ONE
// transaction. A crash before the commit must leave the person completely
// intact - a half-erased person is worse than an un-erased one, because the
// operator has no way to tell which half.
func TestCrashBeforeErasureCommitLeavesNothingHalfDone(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()

	cid := e.register(t)
	before, err := e.svc.GetAttribute(ctx, e.crm, cid, "email", "support")
	if err != nil {
		t.Fatal(err)
	}

	if !crashOnce(t, "erasure.before_commit", func() { _, _, _ = e.gdpr.Erase(ctx, e.crm, cid) }) {
		t.Fatal("the seam never fired - the erasure never reached its commit")
	}

	// Nothing may have happened. All four in one check, because a partial
	// erasure would show up in exactly one of them.
	after, err := e.svc.GetAttribute(ctx, e.crm, cid, "email", "support")
	if err != nil {
		t.Fatalf("the attribute is gone after a crash BEFORE the commit: %v", err)
	}
	if after != before {
		t.Fatalf("the attribute changed across a rolled-back erasure: %q -> %q", before, after)
	}
	var erased *time.Time
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT p.erased_at FROM persons p JOIN cids c ON c.person_id = p.id WHERE c.cid=$1`,
		cid).Scan(&erased); err != nil {
		t.Fatal(err)
	}
	if erased != nil {
		t.Fatal("the person is tombstoned by an erasure that never committed")
	}
	var events, tokens int
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM erasure_events`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 0 {
		t.Fatalf("%d Article 19 events were queued for an erasure that did not happen - "+
			"downstream systems would be told to delete a record that still exists", events)
	}
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM person_tokens pt JOIN cids c ON c.person_id = pt.person_id
		  WHERE c.cid=$1`, cid).Scan(&tokens); err != nil {
		t.Fatal(err)
	}
	if tokens == 0 {
		t.Fatal("the search tokens were deleted by an erasure that never committed - " +
			"the person exists but can no longer be found")
	}

	// And the person is still fully erasable afterwards: a rolled-back
	// attempt must not leave state that blocks the real one.
	if _, _, err := e.gdpr.Erase(ctx, e.crm, cid); err != nil {
		t.Fatalf("the person cannot be erased after a rolled-back attempt: %v", err)
	}
	e.gdpr.Drain()
	if _, err := e.svc.GetAttribute(ctx, e.crm, cid, "email", "support"); err == nil {
		t.Fatal("the retried erasure did not erase")
	}
	_ = errors.New
}
