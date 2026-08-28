package debugsrv

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// dial waits for the listener to accept, so the tests do not race the
// goroutine that starts serving.
func waitReady(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("debug listener at %s never accepted a connection", addr)
}

// TestEmptyAddrStartsNothing is the default, and the one that matters most:
// an unconfigured deployment must not open an unauthenticated port that
// serves stack traces and heap contents.
func TestEmptyAddrStartsNothing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := Start(ctx, "", nil); err != nil {
		t.Fatalf("an empty address must be a silent no-op, got %v", err)
	}
}

// TestServesProfilesWhenConfigured proves the thing exists for a reason: the
// goroutine dump has to actually come back, because that dump is what named
// the key-ring deadlock when every database measurement said the database
// was innocent.
func TestServesProfilesWhenConfigured(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close() // take the port, then hand it to Start

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := Start(ctx, addr, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatal(err)
	}
	waitReady(t, addr)

	// debug=2 is the form that prints every goroutine's stack - the one a
	// stall investigation needs.
	resp, err := http.Get("http://" + addr + "/debug/pprof/goroutine?debug=2")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("goroutine profile returned %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "goroutine ") {
		t.Fatalf("goroutine profile carries no stacks: %.120q", body)
	}

	// The index lists the profiles; a missing one is a diagnostic that is
	// not there when it is needed.
	idx, err := http.Get("http://" + addr + "/debug/pprof/")
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Body.Close()
	page, _ := io.ReadAll(idx.Body)
	for _, want := range []string{"goroutine", "heap", "profile"} {
		if !strings.Contains(string(page), want) {
			t.Errorf("the pprof index does not offer %q", want)
		}
	}
}

// TestUnusableAddressIsAnError. A misconfigured debug address must fail
// startup rather than leave the operator believing they can profile.
func TestUnusableAddressIsAnError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := Start(ctx, "definitely-not-a-host-port", nil); err == nil {
		t.Fatal("a malformed address must be an error, not a silent skip")
	}

	// And a port already taken by something else.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := Start(ctx, ln.Addr().String(), nil); err == nil {
		t.Fatal("binding an occupied port must be an error")
	}
}

// TestShutsDownWithTheContext keeps the listener from outliving the server.
func TestShutsDownWithTheContext(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	if err := Start(ctx, addr, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatal(err)
	}
	waitReady(t, addr)
	cancel()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := http.Get("http://" + addr + "/debug/pprof/"); err != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the debug listener still answers after its context was cancelled")
}
