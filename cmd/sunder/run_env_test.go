package main

import (
	"strings"
	"testing"

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
