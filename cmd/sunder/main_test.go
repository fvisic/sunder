package main

import (
	"context"
	"strings"
	"testing"

	"github.com/fvisic/sunder/internal/testutil"
)

func TestRunRejectsUnknownCommandWithoutDB(t *testing.T) {
	// Must fail fast on the command name, before requiring config or a DB.
	t.Setenv("SUNDER_DB_URL", "")
	if err := run("frobnicate", nil); err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("got %v", err)
	}
}

func TestClientCmdCreateAndValidation(t *testing.T) {
	st := testutil.NewDB(t)
	ctx := context.Background()

	if err := clientCmd(ctx, st, []string{"create", "-id", "crm", "-name", "CRM", "-scope", "crm",
		"-actions", "lookup,attributes.read", "-purposes", "newsletter"}); err != nil {
		t.Fatal(err)
	}
	var actions []string
	if err := st.Pool.QueryRow(ctx,
		`SELECT allowed_actions FROM clients WHERE client_id='crm'`).Scan(&actions); err != nil {
		t.Fatal(err)
	}
	if len(actions) != 2 {
		t.Fatalf("actions not stored: %v", actions)
	}

	// Typo'd action is rejected up front.
	err := clientCmd(ctx, st, []string{"create", "-id", "x", "-name", "X", "-scope", "x", "-actions", "lokup"})
	if err == nil || !strings.Contains(err.Error(), "unknown action") {
		t.Fatalf("got %v", err)
	}
	// Dotted id would break credential parsing; must be rejected.
	err = clientCmd(ctx, st, []string{"create", "-id", "asee.web", "-name", "X", "-scope", "x"})
	if err == nil {
		t.Fatal("dotted client id must be rejected")
	}
	// Missing required flags.
	if err := clientCmd(ctx, st, []string{"create", "-id", "y"}); err == nil {
		t.Fatal("missing -name/-scope must error")
	}
	// Unknown subcommand.
	if err := clientCmd(ctx, st, []string{"delete"}); err == nil {
		t.Fatal("unknown subcommand must error")
	}
}

func TestSplitCSV(t *testing.T) {
	got := splitCSV(" a, b ,,c ")
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("got %v", got)
	}
	if len(splitCSV("")) != 0 {
		t.Fatal("empty input must give empty slice")
	}
}
