package main

import (
	"os"
	"strings"
	"testing"
)

func TestRunRejectsBadFlags(t *testing.T) {
	if err := run([]string{"-nope"}); err == nil {
		t.Fatal("an unknown flag must be an error")
	}
	// The loopback guard is the one refusal that must survive a plain
	// invocation: a playground reachable by accident holds real
	// credentials.
	err := run([]string{"-listen", "0.0.0.0:0"})
	if err == nil || !strings.Contains(err.Error(), "-public") {
		t.Fatalf("expected the loopback guard to fire, got %v", err)
	}
}

func TestEnvHelpers(t *testing.T) {
	if got := env("PLAYGROUND_TEST_UNSET", "fallback"); got != "fallback" {
		t.Fatalf("env fallback: %q", got)
	}
	t.Setenv("PLAYGROUND_TEST_SET", "value")
	if got := env("PLAYGROUND_TEST_SET", "fallback"); got != "value" {
		t.Fatalf("env: %q", got)
	}
	if got := envInt("PLAYGROUND_TEST_UNSET", 7); got != 7 {
		t.Fatalf("envInt fallback: %d", got)
	}
	t.Setenv("PLAYGROUND_TEST_INT", "42")
	if got := envInt("PLAYGROUND_TEST_INT", 7); got != 42 {
		t.Fatalf("envInt: %d", got)
	}
	t.Setenv("PLAYGROUND_TEST_INT", "not-a-number")
	if got := envInt("PLAYGROUND_TEST_INT", 7); got != 7 {
		t.Fatalf("a malformed integer must fall back, got %d", got)
	}
	_ = os.Getenv
}
