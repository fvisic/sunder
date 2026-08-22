package api

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fvisic/sunder/internal/config"
)

func testServer() *Server {
	// Store stays nil: healthz and metrics must not touch the database.
	return New(config.Config{Listen: ":0"}, nil)
}

func TestHealthz(t *testing.T) {
	s := testServer()
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != 200 || rec.Body.String() != "ok" {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
}

func TestMetricsEndpointCountsRequests(t *testing.T) {
	s := testServer()
	s.Handler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/healthz", nil))
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(rec.Body.String(), `sunder_requests_total{handler="GET /healthz",code="200"} 1`) {
		t.Fatalf("healthz request not counted:\n%s", rec.Body.String())
	}
}

func TestUnknownRouteIs404(t *testing.T) {
	s := testServer()
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/nope", nil))
	if rec.Code != 404 {
		t.Fatalf("got %d", rec.Code)
	}
}
