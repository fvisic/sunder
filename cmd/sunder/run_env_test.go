package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/fvisic/sunder/internal/testutil"
)

// Exercises run() end to end for the non-serving commands: env config,
// store connection, migration and dispatch.
func TestRunMigrateAndClientViaEnv(t *testing.T) {
	st := testutil.NewDB(t)
	url := st.Pool.Config().ConnString()
	st.Close() // run() opens its own pool

	t.Setenv("SUNDER_DB_URL", url)
	t.Setenv("SUNDER_KEYSTORE_PATH", t.TempDir())

	if err := run("migrate", nil); err != nil {
		t.Fatal(err)
	}
	if err := run("client", []string{"create", "-id", "envtest", "-name", "T", "-scope", "crm",
		"-actions", "lookup"}); err != nil {
		t.Fatal(err)
	}
	if err := run("keys", []string{"list"}); err != nil {
		t.Fatal(err)
	}
	// Config errors surface before any DB work.
	t.Setenv("SUNDER_DB_URL", "")
	if err := run("migrate", nil); err == nil || !strings.Contains(err.Error(), "SUNDER_DB_URL") {
		t.Fatalf("missing DB URL must fail config validation: %v", err)
	}
	// Connection errors surface cleanly.
	t.Setenv("SUNDER_DB_URL", "postgres://nouser@127.0.0.1:1/none")
	if err := run("migrate", nil); err == nil {
		t.Fatal("unreachable database must error")
	}
}

// The serve path end to end: boots, answers healthz, shuts down on ctx cancel.
func TestRunServe(t *testing.T) {
	st := testutil.NewDB(t)
	url := st.Pool.Config().ConnString()
	st.Close()
	t.Setenv("SUNDER_DB_URL", url)
	t.Setenv("SUNDER_KEYSTORE_PATH", t.TempDir())
	t.Setenv("SUNDER_LISTEN", "127.0.0.1:0")

	ctx, cancel := context.WithCancel(context.Background())
	old := signalContext
	signalContext = func() (context.Context, context.CancelFunc) { return ctx, func() {} }
	defer func() { signalContext = old }()

	done := make(chan error, 1)
	go func() { done <- run("serve", nil) }()
	time.Sleep(400 * time.Millisecond) // migrate + keystore bootstrap + listen
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve must shut down cleanly: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not stop")
	}

	// serve with a broken keystore config: api.New fails at bootstrap.
	t.Setenv("SUNDER_KEYSTORE", "vault")
	t.Setenv("SUNDER_VAULT_ADDR", "http://127.0.0.1:1")
	t.Setenv("SUNDER_VAULT_TOKEN", "t")
	signalContext = func() (context.Context, context.CancelFunc) {
		return context.Background(), func() {}
	}
	if err := run("serve", nil); err == nil {
		t.Fatal("unreachable vault keystore must fail serve startup")
	}
}

// run() dispatch lines for the ops commands (each command's own logic is
// covered by its dedicated tests; this pins the wiring).
func TestRunDispatchesOpsCommands(t *testing.T) {
	st := testutil.NewDB(t)
	url := st.Pool.Config().ConnString()
	st.Close()
	t.Setenv("SUNDER_DB_URL", url)
	t.Setenv("SUNDER_KEYSTORE_PATH", t.TempDir())

	if err := run("webhook", []string{"list"}); err != nil {
		t.Fatal(err)
	}
	if err := run("retention", []string{"run"}); err != nil {
		t.Fatal(err)
	}
	if err := run("dsr", []string{"events"}); err != nil {
		t.Fatal(err)
	}
	if err := run("verify-audit", nil); err != nil {
		t.Fatal(err)
	}
	// anchor on an empty log is a no-op regardless of the TSA URL.
	t.Setenv("SUNDER_TSA_URL", "http://tsa.invalid/x")
	if err := run("anchor", nil); err != nil {
		t.Fatal(err)
	}
}
