package playground

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestReferenceTabServesInstanceSpec(t *testing.T) {
	var fetches atomic.Int32
	instance := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/openapi.yaml" {
			http.NotFound(w, r)
			return
		}
		fetches.Add(1)
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write([]byte("openapi: 3.1.0\n"))
	}))
	defer instance.Close()
	pg := newTestServer(t, instance.URL, nil)
	defer pg.Close()

	resp, err := http.Get(pg.URL + "/reference")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(body), "<rapi-doc") {
		t.Fatal("the reference document was not served")
	}
	if !strings.Contains(string(body), `allow-try="false"`) {
		t.Fatal("browser-side try-it must stay off: there is no credential and no CORS grant")
	}
	// The looser CSP is confined to this document, and only for styles.
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "style-src 'self' 'unsafe-inline'") || strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
		t.Fatalf("reference CSP: %q", csp)
	}

	// The spec comes from the instance the walkthroughs run against, and is
	// cached rather than refetched per request.
	for i := 0; i < 3; i++ {
		r, err := http.Get(pg.URL + "/reference/openapi.yaml")
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		if r.StatusCode != 200 || !strings.HasPrefix(string(raw), "openapi:") {
			t.Fatalf("spec proxy: %d %q", r.StatusCode, raw)
		}
	}
	if got := fetches.Load(); got != 1 {
		t.Fatalf("expected the spec to be fetched once and cached, got %d fetches", got)
	}

	// The vendored bundle is served, and only by its exact name.
	r, err := http.Get(pg.URL + "/ui/vendor/rapidoc-min.js")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if r.StatusCode != 200 || len(raw) < 1000 {
		t.Fatalf("vendored bundle: %d, %d bytes", r.StatusCode, len(raw))
	}
}

func TestReferenceSpecFailureIsReported(t *testing.T) {
	instance := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer instance.Close()
	pg := newTestServer(t, instance.URL, nil)
	defer pg.Close()

	resp, err := http.Get(pg.URL + "/reference/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("an instance that cannot serve its contract must be a 502, got %d", resp.StatusCode)
	}
}
