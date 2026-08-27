package playground

import (
	"context"
	"io"
	"net/http"
	"sync"
	"time"
)

// The API-reference tab. The service already serves its own contract at
// GET /openapi.yaml (unauthenticated), so the playground proxies that
// rather than shipping a second copy that could drift from the instance the
// walkthroughs are actually running against.

const (
	specTTL      = time.Minute
	specMaxBytes = 4 << 20
)

type specCache struct {
	mu      sync.Mutex
	body    []byte
	fetched time.Time
}

// handleReference serves the RapiDoc document. Its CSP is looser than the
// app's in exactly one respect - inline styles, which the web component
// needs - which is why it is a separate document instead of a tab inside
// the app's own page.
func (s *Server) handleReference(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "+
			"connect-src 'self'; img-src 'self' data:; font-src 'self' data:; base-uri 'none'; form-action 'none'")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(s.reference)
}

func (s *Server) handleVendorAsset(w http.ResponseWriter, r *http.Request) {
	raw, err := s.uiFile("vendor/rapidoc-min.js")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	// Immutable third-party bundle, unlike the app's own files: caching it
	// keeps 800 KB off every reload.
	w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
	_, _ = w.Write(raw)
}

// handleSpec proxies the instance's own OpenAPI document.
func (s *Server) handleSpec(w http.ResponseWriter, r *http.Request) {
	body, err := s.spec(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{
			"error": "the instance did not serve its OpenAPI document: " + err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}

// spec serves the instance's OpenAPI document, cached for specTTL.
//
// The lock is held only around the cache reads and the publish - NEVER
// across the outbound fetch. Holding it across a 15-second HTTP call plus a
// 4 MiB ReadAll meant concurrent visitors queued on the mutex rather than
// the network, each pinning a handler goroutine for the full wait, and a
// perfectly good cached document from a minute ago was discarded rather
// than served when the upstream stopped answering (CONCURRENCY-CORE-7).
func (s *Server) spec(ctx context.Context) ([]byte, error) {
	s.specs.mu.Lock()
	cached, fetched := s.specs.body, s.specs.fetched
	s.specs.mu.Unlock()
	if cached != nil && time.Since(fetched) < specTTL {
		return cached, nil
	}

	raw, err := s.fetchSpec(ctx)
	if err != nil {
		// Serve STALE rather than fail: a dead upstream must not also cost
		// the visitor the copy we already have.
		if cached != nil {
			return cached, nil
		}
		return nil, err
	}
	s.specs.mu.Lock()
	s.specs.body, s.specs.fetched = raw, time.Now()
	s.specs.mu.Unlock()
	return raw, nil
}

func (s *Server) fetchSpec(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", s.cfg.BaseURL+"/openapi.yaml", nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.runner.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, errStatus(resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, specMaxBytes))
}

type errStatus int

func (e errStatus) Error() string { return http.StatusText(int(e)) }
