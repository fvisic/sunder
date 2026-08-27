package api

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fvisic/sunder/internal/audit"
	"github.com/fvisic/sunder/internal/config"
	"github.com/fvisic/sunder/internal/testutil"
)

// pinMode pins the audit write mode for one test and restores the
// matrix-selected mode afterwards.
func pinMode(t *testing.T, m string) {
	t.Helper()
	old := audit.Mode()
	audit.SetMode(m)
	t.Cleanup(func() { audit.SetMode(old) })
}

// TestSyncStartupDrainsAsyncBacklog is the async -> sync switch: rows left
// unsealed by a previous async run must all be in the chain before a sync
// process serves traffic, or its first append would strand them above the
// sealed head forever.
func TestSyncStartupDrainsAsyncBacklog(t *testing.T) {
	pinMode(t, audit.ModeAsync)
	st := testutil.NewDB(t)
	// CANCELLED at the end of the test: startAuditSealing launches the
	// unsealed gauge (30s), the bucket closer (60s) and the sync backlog
	// sealer (10s), and testutil drops the database on cleanup - so a
	// context.Background() here leaked three tickers hammering a dropped
	// database for the rest of the package run (TESTS-10).
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	for i := 0; i < 5; i++ {
		if err := audit.Append(ctx, st.Pool, audit.Entry{ClientID: "crm", Action: "lookup"}); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := audit.UnsealedCount(ctx, st.Pool); err != nil || n != 5 {
		t.Fatalf("precondition: %d unsealed, err=%v", n, err)
	}

	srv, err := New(config.Config{
		Listen: ":0", Keystore: "file", KeystorePath: t.TempDir(),
		AuditSealing: audit.ModeSync,
	}, st)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.startAuditSealing(ctx); err != nil {
		t.Fatal(err)
	}

	if n, err := audit.UnsealedCount(ctx, st.Pool); err != nil || n != 0 {
		t.Fatalf("sync startup left %d rows unsealed (err=%v)", n, err)
	}
	broken, reason, pending, err := audit.Verify(ctx, st.Pool)
	if err != nil || broken != 0 || pending != 0 {
		t.Fatalf("chain after drain: broken=%d pending=%d err=%v (%s)", broken, pending, err, reason)
	}
	// And the process mode is now sync: the next append seals at birth.
	if audit.Mode() != audit.ModeSync {
		t.Fatalf("mode after sync startup = %q", audit.Mode())
	}
}

// TestAsyncSealerLoopSealsAndReportsGauge exercises the in-process sealer
// end to end: unsealed rows appear, the loop seals them within a few
// ticks, and the unsealed-rows gauge ends at zero.
func TestAsyncSealerLoopSealsAndReportsGauge(t *testing.T) {
	pinMode(t, audit.ModeAsync)
	st := testutil.NewDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := New(config.Config{
		Listen: ":0", Keystore: "file", KeystorePath: t.TempDir(),
		AuditSealing:      audit.ModeAsync,
		AuditSealInterval: 50 * time.Millisecond,
		AuditSealDelay:    100 * time.Millisecond,
		AuditSealBatch:    100,
	}, st)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.startAuditSealing(ctx); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 4; i++ {
		if err := audit.Append(ctx, st.Pool, audit.Entry{ClientID: "crm", Action: "lookup"}); err != nil {
			t.Fatal(err)
		}
	}

	deadline := time.Now().Add(10 * time.Second)
	for {
		n, err := audit.UnsealedCount(ctx, st.Pool)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("sealer loop did not drain the backlog: %d rows still unsealed", n)
		}
		time.Sleep(50 * time.Millisecond)
	}

	broken, reason, pending, err := audit.Verify(ctx, st.Pool)
	if err != nil || broken != 0 || pending != 0 {
		t.Fatalf("chain after sealer loop: broken=%d pending=%d err=%v (%s)", broken, pending, err, reason)
	}

	// The gauge is written on the tick AFTER sealing; give it one cycle.
	deadline = time.Now().Add(5 * time.Second)
	for {
		rec := httptest.NewRecorder()
		srv.Metrics.ServeHTTP(rec, nil)
		if strings.Contains(rec.Body.String(), "sunder_audit_unsealed_rows 0") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("gauge never reached zero:\n%s", rec.Body.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestEmptySealingConfigDoesNotOverrideProcessMode guards the CI matrix:
// a Config literal without AuditSealing (every existing test) must leave
// the environment-selected mode untouched.
func TestEmptySealingConfigDoesNotOverrideProcessMode(t *testing.T) {
	pinMode(t, audit.ModeSync)
	st := testutil.NewDB(t)
	srv, err := New(config.Config{Listen: ":0", Keystore: "file", KeystorePath: t.TempDir()}, st)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.startAuditSealing(ctx); err != nil {
		t.Fatal(err)
	}
	if audit.Mode() != audit.ModeSync {
		t.Fatalf("empty config overrode the process mode to %q", audit.Mode())
	}
}

// TestModeSwitchRestartLosesNothing simulates the only supported way to
// change SUNDER_AUDIT_SEALING - stop the instance, start it with the other
// value - in BOTH directions, and proves the property the operator needs:
// no audited row is ever left outside the chain by the transition. The
// pre-serve check is startAuditSealing itself: a sync start refuses to
// serve before the async backlog is drained.
func TestModeSwitchRestartLosesNothing(t *testing.T) {
	st := testutil.NewDB(t)
	total := int64(0)

	// countAll asserts the invariant after each "instance lifetime": every
	// row ever written is sealed, the chain verifies, and chain_seq is
	// dense from 1 to the row count - nothing stranded, nothing forked.
	countAll := func(stage string) {
		t.Helper()
		ctx := context.Background()
		broken, reason, pending, err := audit.Verify(ctx, st.Pool)
		if err != nil {
			t.Fatalf("%s: verify: %v", stage, err)
		}
		if broken != 0 || pending != 0 {
			t.Fatalf("%s: broken=%d pending=%d (%s)", stage, broken, pending, reason)
		}
		var rows, maxChain int64
		if err := st.Pool.QueryRow(ctx,
			`SELECT count(*), COALESCE(max(chain_seq),0) FROM audit`).Scan(&rows, &maxChain); err != nil {
			t.Fatal(err)
		}
		if rows != total || maxChain != total {
			t.Fatalf("%s: %d rows, max chain_seq %d, want both %d - a row fell out of the chain",
				stage, rows, maxChain, total)
		}
	}

	// Instance 1: async, sealer NOT running (external), then killed - the
	// worst case: it dies with its whole backlog unsealed.
	pinMode(t, audit.ModeAsync)
	ctx1, cancel1 := context.WithCancel(context.Background())
	srv1, err := New(config.Config{Listen: ":0", Keystore: "file", KeystorePath: t.TempDir(),
		AuditSealing: audit.ModeAsync, AuditSealExternal: true}, st)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv1.startAuditSealing(ctx1); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		if err := audit.Append(ctx1, st.Pool, audit.Entry{ClientID: "crm", Action: "async-era"}); err != nil {
			t.Fatal(err)
		}
		total++
	}
	cancel1() // the "crash": unsealed rows remain
	if n, err := audit.UnsealedCount(context.Background(), st.Pool); err != nil || n != 6 {
		t.Fatalf("precondition: want 6 unsealed after the crash, got %d (err=%v)", n, err)
	}

	// Instance 2: sync. The startup check must drain BEFORE serving, and
	// sync appends must then chain directly onto the drained rows.
	ctx2, cancel2 := context.WithCancel(context.Background())
	srv2, err := New(config.Config{Listen: ":0", Keystore: "file", KeystorePath: t.TempDir(),
		AuditSealing: audit.ModeSync}, st)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv2.startAuditSealing(ctx2); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := audit.Append(ctx2, st.Pool, audit.Entry{ClientID: "crm", Action: "sync-era"}); err != nil {
			t.Fatal(err)
		}
		total++
	}
	cancel2()
	countAll("after async->sync restart")

	// Instance 3: back to async with an in-process sealer; rows appended
	// here must all end sealed too (sync->async needs no special step).
	pinMode(t, audit.ModeAsync)
	ctx3, cancel3 := context.WithCancel(context.Background())
	defer cancel3()
	srv3, err := New(config.Config{Listen: ":0", Keystore: "file", KeystorePath: t.TempDir(),
		AuditSealing: audit.ModeAsync, AuditSealInterval: 50 * time.Millisecond,
		AuditSealDelay: 100 * time.Millisecond, AuditSealBatch: 100}, st)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv3.startAuditSealing(ctx3); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		if err := audit.Append(ctx3, st.Pool, audit.Entry{ClientID: "crm", Action: "async-again"}); err != nil {
			t.Fatal(err)
		}
		total++
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		n, err := audit.UnsealedCount(ctx3, st.Pool)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("sealer did not catch up after the switch back: %d pending", n)
		}
		time.Sleep(50 * time.Millisecond)
	}
	countAll("after sync->async restart")
}

// TestSealerLoopSurvivesTransientDBFailure: the loop logs and keeps
// ticking on an error instead of dying - the one process whose silent
// death grows the unsealed window must not be killed by a DB blip.
func TestSealerLoopSurvivesTransientDBFailure(t *testing.T) {
	pinMode(t, audit.ModeAsync)
	st := testutil.NewDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, err := New(config.Config{Listen: ":0", Keystore: "file", KeystorePath: t.TempDir(),
		AuditSealing: audit.ModeAsync, AuditSealInterval: 50 * time.Millisecond,
		AuditSealDelay: 100 * time.Millisecond, AuditSealBatch: 100}, st)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.startAuditSealing(ctx); err != nil {
		t.Fatal(err)
	}
	st.Close() // every SealOnce now errors
	time.Sleep(200 * time.Millisecond)
	// Nothing to assert beyond survival: a panic or an exited goroutine
	// would fail the test run itself; cancellation must still be clean.
	cancel()
	time.Sleep(60 * time.Millisecond)
}

// TestBucketCloserLoopClosesFinishedHours drives the in-process closer the
// way serve runs it, including survival of a transient DB failure.
func TestBucketCloserLoopClosesFinishedHours(t *testing.T) {
	pinMode(t, audit.ModeAsync)
	old := audit.ReadsMode()
	audit.SetReadsMode(audit.ReadsBucketed)
	t.Cleanup(func() { audit.SetReadsMode(old) })

	st := testutil.NewDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO audit_read_buckets (client_id, user_id, cid, action, bucket_start, count)
		VALUES ('crm','agent-1','CID-A','lookup', date_trunc('hour', now() - interval '1 hour'), 4)`); err != nil {
		t.Fatal(err)
	}
	srv, err := New(config.Config{Listen: ":0", Keystore: "file", KeystorePath: t.TempDir(),
		AuditSealing: audit.ModeAsync, AuditSealInterval: 50 * time.Millisecond,
		AuditSealDelay: 100 * time.Millisecond, AuditSealBatch: 100}, st)
	if err != nil {
		t.Fatal(err)
	}
	srv.closerInterval = 50 * time.Millisecond // test seam: a minute is too slow for CI
	if err := srv.startAuditSealing(ctx); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		var n int64
		if err := st.Pool.QueryRow(ctx,
			`SELECT count(*) FROM audit WHERE action='audit.reads_hourly'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("closer loop never closed the finished hour")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestBucketCloserSurvivesDBFailure mirrors the sealer-loop resilience
// test for the closer: a DB blip must be logged, never fatal.
func TestBucketCloserSurvivesDBFailure(t *testing.T) {
	pinMode(t, audit.ModeAsync)
	old := audit.ReadsMode()
	audit.SetReadsMode(audit.ReadsBucketed)
	t.Cleanup(func() { audit.SetReadsMode(old) })
	st := testutil.NewDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, err := New(config.Config{Listen: ":0", Keystore: "file", KeystorePath: t.TempDir(),
		AuditSealing: audit.ModeAsync, AuditSealInterval: 50 * time.Millisecond,
		AuditSealDelay: 100 * time.Millisecond, AuditSealBatch: 100}, st)
	if err != nil {
		t.Fatal(err)
	}
	srv.closerInterval = 50 * time.Millisecond
	if err := srv.startAuditSealing(ctx); err != nil {
		t.Fatal(err)
	}
	st.Close()
	time.Sleep(200 * time.Millisecond)
	cancel()
	time.Sleep(60 * time.Millisecond)
}

// AUDIT-CHAIN-7: a rolling async -> sync restart drains only in the FIRST
// process to switch; replicas still on async keep inserting unsealed rows
// after it, and once the last one stops there is no sealer left in the
// fleet. Those rows are stranded outside the chain indefinitely - verify
// fails hard and the only cure is running the sealer under a different mode
// than the one configured. Sync mode therefore keeps a low-frequency
// backlog sealer of its own.
func TestSyncModeSealsRowsThatAppearAfterStartup(t *testing.T) {
	pinMode(t, audit.ModeSync)
	st := testutil.NewDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	srv, err := New(config.Config{Keystore: "file", KeyRetireGrace: -1, KeystorePath: t.TempDir(),
		AuditSealing: audit.ModeSync, AuditSealBatch: 100}, st)
	if err != nil {
		t.Fatal(err)
	}
	srv.syncBacklogInterval = 50 * time.Millisecond
	if err := srv.startAuditSealing(ctx); err != nil {
		t.Fatal(err)
	}

	// A row inserted the way a still-async replica inserts them: unsealed,
	// after this process already drained at startup.
	if _, err := st.Pool.Exec(ctx,
		`INSERT INTO audit (ts, client_id, action, detail) VALUES (now(),'crm','lookup','null')`); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		n, err := audit.UnsealedCount(ctx, st.Pool)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d row(s) left outside the chain: a sync-mode process must still drain a backlog that appears after startup", n)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if broken, reason, _, err := audit.Verify(ctx, st.Pool); err != nil || broken != 0 {
		t.Fatalf("the chain must verify after the drain: %d %s %v", broken, reason, err)
	}
}

// The operational gauges are the whole detection story for three findings -
// a stalled sealer, stranded Article 19 notifications, and key material
// minted at runtime - and each one is a number nothing else reports. The
// loop that feeds them was never driven by a test.
func TestOperationalGaugesArePublished(t *testing.T) {
	st := testutil.NewDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	srv, err := New(config.Config{Keystore: "file", KeyRetireGrace: -1, KeystorePath: t.TempDir()}, st)
	if err != nil {
		t.Fatal(err)
	}
	srv.gaugeInterval = 20 * time.Millisecond

	// Something for each gauge to report.
	if _, err := st.Pool.Exec(ctx,
		`INSERT INTO persons (id) VALUES (gen_random_uuid())`); err != nil {
		t.Fatal(err)
	}
	var personID string
	if err := st.Pool.QueryRow(ctx, `SELECT id FROM persons LIMIT 1`).Scan(&personID); err != nil {
		t.Fatal(err)
	}
	var erasureID int64
	if err := st.Pool.QueryRow(ctx,
		`INSERT INTO erasures (person_id, requested_by) VALUES ($1,'t') RETURNING id`,
		personID).Scan(&erasureID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO erasure_events (erasure_id, scope, cid, status, claimed_at)
		VALUES ($1,'crm','CID-GAUGE000000000000000','SENDING', now()),
		       ($1,'erp','CID-GAUGE100000000000000','FAILED', NULL)`, erasureID); err != nil {
		t.Fatal(err)
	}
	srv.startUnsealedGauge(ctx)

	want := []string{
		"sunder_audit_unsealed_rows",
		"sunder_erasure_events_sending",
		"sunder_erasure_events_failed",
		"sunder_keystore_minted_total",
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		rec := httptest.NewRecorder()
		srv.Metrics.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
		body := rec.Body.String()
		missing := ""
		for _, m := range want {
			if !strings.Contains(body, m) {
				missing = m
			}
		}
		if missing == "" {
			// The values must be real, not zero placeholders.
			if !strings.Contains(body, "sunder_erasure_events_sending 1") ||
				!strings.Contains(body, "sunder_erasure_events_failed 1") {
				t.Fatalf("the erasure gauges must report the real queue depth:\n%s", body)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("gauge %q was never published:\n%s", missing, body)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
