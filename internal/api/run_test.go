package api

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fvisic/sunder/internal/config"
)

func mustNew(t *testing.T, cfg config.Config) *Server {
	t.Helper()
	s, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRunFailsOnUnreadableMTLSCA(t *testing.T) {
	s := mustNew(t, config.Config{Listen: "127.0.0.1:0", TLSCert: "/nope.pem", TLSKey: "/nope.key",
		MTLSCA: "/does/not/exist.pem"})
	if err := s.Run(context.Background()); err == nil {
		t.Fatal("expected error for missing CA file")
	}
}

func TestRunFailsOnEmptyMTLSCA(t *testing.T) {
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, []byte("not a cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := mustNew(t, config.Config{Listen: "127.0.0.1:0", TLSCert: "/nope.pem", TLSKey: "/nope.key", MTLSCA: ca})
	if err := s.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "no certificates") {
		t.Fatalf("expected 'no certificates' error, got %v", err)
	}
}

func TestRunShutsDownGracefully(t *testing.T) {
	s := mustNew(t, config.Config{Listen: "127.0.0.1:0"})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("graceful shutdown returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown timed out")
	}
}

func TestUnmatchedRouteMetricLabel(t *testing.T) {
	s := testServer()
	s.Handler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/no-such-route", nil))
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(rec.Body.String(), `handler="unmatched"`) {
		t.Fatalf("unmatched label missing:\n%s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `sunder_request_seconds_count`) {
		t.Fatal("latency histogram not emitted")
	}
}
