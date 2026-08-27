package api

// QUEUE-WORKER-3 / CONCURRENCY-CORE-5 / TESTS-10: `Run` starts a delivery
// ticker, an unsealed gauge, a bucket closer and (in sync mode) a backlog
// sealer, and both listeners send on one channel. Nothing asserted that a
// cancelled context actually stops all of it, that an in-flight delivery
// settles or releases its claim rather than being abandoned, or that the
// second listener's send does not park a goroutine forever.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	"bytes"
	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/config"
	"github.com/fvisic/sunder/internal/testutil"
	"log/slog"
	"strings"
)

// settledGoroutines waits for the count to stop moving, so ordinary pool
// churn is not mistaken for a leak.
func settledGoroutines() int {
	last := runtime.NumGoroutine()
	for i := 0; i < 50; i++ {
		time.Sleep(20 * time.Millisecond)
		runtime.GC()
		n := runtime.NumGoroutine()
		if n == last {
			return n
		}
		last = n
	}
	return last
}

func TestRunStopsBackgroundWorkersOnShutdown(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewDB(t)
	cred, err := auth.Create(ctx, st.Pool, auth.Client{
		ID: "crm", Name: "CRM", Scope: "crm",
		AllowedActions:  []string{auth.ActContactsRegister, auth.ActDSRErase},
		AllowedPurposes: []string{"support"}, RateLimit: 100})
	if err != nil {
		t.Fatal(err)
	}
	// A webhook that blocks well past the shutdown, so a delivery really is
	// in flight when the context is cancelled.
	// The handler blocks until it is released once per request, so the test
	// controls exactly when a delivery is in flight.
	release := make(chan struct{}, 8)
	entered := make(chan struct{}, 8)
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		select {
		case <-release:
		case <-time.After(20 * time.Second):
		}
		w.WriteHeader(200)
	}))
	defer hook.Close()

	srv, err := New(config.Config{
		Keystore: "file", KeyRetireGrace: -1, KeystorePath: t.TempDir(),
		Listen: "127.0.0.1:0", PortalListen: "127.0.0.1:0", PortalEnabled: true,
		DeliverInterval: 50 * time.Millisecond,
	}, st)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx,
		`INSERT INTO webhooks (scope, url, secret) VALUES ('crm', $1, 's')`, hook.URL); err != nil {
		t.Fatal(err)
	}
	e := &e2eEnv{srv: srv, credCRM: cred}
	_, out := e.do(t, cred, "POST", "/v1/contacts", map[string]any{"email": "shutdown@example.com"})
	cid := out["cid"]
	if rec, _ := e.do(t, cred, "POST", "/v1/dsr/erase", map[string]string{"cid": cid}); rec.Code != 200 {
		t.Fatalf("erase: %d", rec.Code)
	}
	// Erase dispatches its own DETACHED delivery. Let it finish and requeue
	// the event, so the `entered` signal below can only come from the
	// ticker inside Run - otherwise the cancel can land while Run is still
	// in its startup drain, before any worker exists.
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the erase-time delivery never reached the webhook")
	}
	release <- struct{}{}
	srv.GDPR.Drain()
	if _, err := st.Pool.Exec(ctx,
		`UPDATE erasure_events SET status='PENDING', attempts=0, claimed_at=NULL`); err != nil {
		t.Fatal(err)
	}

	before := settledGoroutines()

	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- srv.Run(runCtx) }()

	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the delivery worker never reached the webhook")
	}
	cancel()
	release <- struct{}{}
	select {
	case err := <-done:
		// ErrServerClosed is the clean stop. context.Canceled is also
		// legitimate: under sync sealing Run drains the audit backlog before
		// it listens, and cancelling during that startup step aborts it -
		// which is the correct thing to do, not a leak.
		if err != nil && err != http.ErrServerClosed && !errors.Is(err, context.Canceled) {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}

	// The in-flight delivery must not have been abandoned mid-claim: either
	// it settled, or its claim was released back to PENDING.
	var sending int
	if err := st.Pool.QueryRow(ctx,
		`SELECT count(*) FROM erasure_events WHERE status='SENDING'`).Scan(&sending); err != nil {
		t.Fatal(err)
	}
	if sending != 0 {
		t.Fatalf("%d erasure event(s) abandoned in SENDING - shutdown must settle or release every claim", sending)
	}

	// And every worker Run started is gone: the delivery ticker, the
	// unsealed gauge, the bucket closer, and BOTH listener goroutines -
	// the second of which used to park forever on a one-slot channel.
	srv.GDPR.Drain()
	after := settledGoroutines()
	if after > before+4 {
		t.Fatalf("goroutines went from %d to %d across one Run/shutdown cycle - a background worker or a listener send survived", before, after)
	}
}

// The startup warnings. Each names a posture that is silently wrong
// otherwise: file ciphertext that only one replica can read (DOCS-4), a
// standing unlock grant left by the pre-fix bootstrap (AUTHZ-2), and an
// unauthenticated /metrics whose series carry client ids and the
// enumeration counter (AUTHZ-6).
func TestStartupWarnsAboutSilentlyWrongPostures(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewDB(t)

	// A client in the exact state the pre-fix bootstrap left behind. The new
	// CHECK is NOT VALID precisely so an upgrade does not refuse to start on
	// such a row - which is why the startup WARNING is the thing that has to
	// surface it. Recreate that state the way an upgrade finds it: the row
	// predates the constraint.
	if _, err := st.Pool.Exec(ctx,
		`ALTER TABLE clients DROP CONSTRAINT clients_unlock_needs_expiry`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO clients (client_id, name, key_hash, scope, allowed_actions, allowed_purposes, role, rate_limit)
		VALUES ('legacy-admin','Legacy','x','admin', ARRAY['admin.unlock'], ARRAY['admin'], 'custom', 10)`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		ALTER TABLE clients ADD CONSTRAINT clients_unlock_needs_expiry
		    CHECK (NOT ('admin.unlock' = ANY (allowed_actions)) OR credential_expires_at IS NOT NULL)
		    NOT VALID`); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	srv, err := New(config.Config{
		Keystore: "file", KeyRetireGrace: -1, KeystorePath: t.TempDir(),
		FilesStorage: "local", FilesDir: t.TempDir(), FilesMaxMB: 1,
		Listen: "127.0.0.1:0",
	}, st)
	if err != nil {
		t.Fatal(err)
	}
	srv.Log = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- srv.Run(runCtx) }()
	time.Sleep(300 * time.Millisecond)
	cancel()
	<-done

	logged := buf.String()
	for _, want := range []string{
		"SUNDER_FILES_STORAGE=local",     // single-instance only
		"SEPARATE BACKUP UNIT",           // and not in the DB backup
		"admin.unlock on a NON-EXPIRING", // the installed-base warning
		"/metrics is served WITHOUT a token",
		"serving WITHOUT TLS",
	} {
		if !strings.Contains(logged, want) {
			t.Errorf("startup must warn about %q. Logged:\n%s", want, logged)
		}
	}
	if !strings.Contains(logged, "legacy-admin") {
		t.Errorf("the standing-unlock warning must NAME the client so an operator can fix it:\n%s", logged)
	}
}
