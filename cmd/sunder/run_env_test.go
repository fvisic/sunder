package main

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fvisic/sunder/internal/crypto"
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
	// A concrete free port (not :0) so the readiness poll below has an
	// address to dial.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen := probe.Addr().String()
	_ = probe.Close()
	t.Setenv("SUNDER_LISTEN", listen)

	ctx, cancel := context.WithCancel(context.Background())
	old := signalContext
	signalContext = func() (context.Context, context.CancelFunc) { return ctx, func() {} }
	defer func() { signalContext = old }()

	done := make(chan error, 1)
	go func() { done <- run("serve", nil) }()
	// Poll for the listener instead of a fixed sleep: migrate + keystore
	// bootstrap + listen is slower on loaded CI.
	deadline := time.Now().Add(20 * time.Second)
	for {
		if c, err := net.DialTimeout("tcp", listen, 100*time.Millisecond); err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("serve never bound its port")
		}
		select {
		case err := <-done:
			t.Fatalf("serve exited before binding: %v", err)
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
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

// The signer subcommand needs the keystore, never the database.
func TestRunSignerWithoutDB(t *testing.T) {
	t.Setenv("SUNDER_DB_URL", "")
	t.Setenv("SUNDER_KEYSTORE_PATH", t.TempDir())

	// Missing socket: specific error, not a DB complaint.
	if err := run("signer", nil); err == nil || !strings.Contains(err.Error(), "socket") {
		t.Fatalf("signer without a socket must say so: %v", err)
	}

	// With a socket it serves until the signal context is cancelled.
	dir, err := os.MkdirTemp("", "sgn")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := dir + "/s.sock"
	ctx, cancel := context.WithCancel(context.Background())
	old := signalContext
	signalContext = func() (context.Context, context.CancelFunc) { return ctx, cancel }
	t.Cleanup(func() { signalContext = old })
	done := make(chan error, 1)
	go func() { done <- run("signer", []string{"-socket", sock}) }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("signer socket never appeared")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// It answers over the wire.
	eng := crypto.NewRemoteEngine(sock)
	if err := eng.Ensure(ctx, "hmac-email/v1"); err != nil {
		t.Fatal(err)
	}
	if sum, err := eng.MAC(ctx, "hmac-email/v1", []byte("x")); err != nil || len(sum) != 32 {
		t.Fatalf("mac over CLI-started signer: %d %v", len(sum), err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("signer shutdown must be clean: %v", err)
	}
}

func TestGetenvDefaultFallsBackOnEmpty(t *testing.T) {
	const key = "SUNDER_TEST_GETENV_DEFAULT"
	t.Setenv(key, "")
	if got := getenvDefault(key, "fallback"); got != "fallback" {
		t.Fatalf("empty env must fall back, got %q", got)
	}
	t.Setenv(key, "set")
	if got := getenvDefault(key, "fallback"); got != "set" {
		t.Fatalf("set env must win, got %q", got)
	}
}
