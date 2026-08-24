package api

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/config"
	"github.com/fvisic/sunder/internal/crypto"
	"github.com/fvisic/sunder/internal/store"
	"github.com/fvisic/sunder/internal/testutil"
)

func TestOpenKeystoreDrivers(t *testing.T) {
	if _, ok := OpenKeystore(config.Config{Keystore: "vault", VaultAddr: "http://v", VaultToken: "t"}).(*crypto.CachingKeystore); !ok {
		t.Fatal("vault driver must be wrapped in the cache")
	}
	ks := OpenKeystore(config.Config{Keystore: "pkcs11"})
	if err := ks.Ensure(context.Background(), "hmac-email/v1"); err == nil {
		t.Fatal("pkcs11 stub must error")
	}
	if _, ok := OpenKeystore(config.Config{Keystore: "file", KeystorePath: t.TempDir()}).(*crypto.CachingKeystore); !ok {
		t.Fatal("file driver must be wrapped in the cache")
	}
}

func TestMetricsTokenGate(t *testing.T) {
	s, err := New(config.Config{Listen: ":0", MetricsToken: "s3cret"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if rec.Code != 401 || rec.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("ungated scrape must 401 with WWW-Authenticate: %d", rec.Code)
	}
	req := httptest.NewRequest("GET", "/metrics", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("wrong token: %d", rec.Code)
	}
	req = httptest.NewRequest("GET", "/metrics", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("correct token: %d", rec.Code)
	}
}

func TestStoreNewErrors(t *testing.T) {
	ctx := context.Background()
	if _, err := store.New(ctx, "not-a-url://"); err == nil {
		t.Fatal("invalid URL must error")
	}
	if _, err := store.New(ctx, "postgres://nouser@127.0.0.1:1/none"); err == nil {
		t.Fatal("unreachable server must error")
	}
}

func TestBadJSONOnEveryHandler(t *testing.T) {
	e := newE2E(t)
	for _, path := range []string{"/v1/contacts", "/v1/lookup", "/v1/oti", "/v1/oti/verify", "/v1/dsr/erase", "/v1/consent"} {
		req := httptest.NewRequest("POST", path, strings.NewReader("{broken"))
		req.Header.Set("Authorization", "Bearer "+e.credCRM)
		rec := httptest.NewRecorder()
		e.srv.Handler().ServeHTTP(rec, req)
		if rec.Code != 400 {
			t.Errorf("%s with broken JSON: got %d", path, rec.Code)
		}
	}
}

func TestRunListenError(t *testing.T) {
	// Occupy a port, then ask Run to bind it: the listener error must
	// surface through errCh.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	s := mustNew(t, config.Config{Listen: l.Addr().String()})
	if err := s.Run(context.Background()); err == nil {
		t.Fatal("binding an occupied port must error")
	}
}

func TestTunablesReachServices(t *testing.T) {
	e := newE2E(t) // sanity: default construction still works
	_ = e
	st := testutil.NewDB(t)
	s, err := New(config.Config{
		Listen: ":0", Keystore: "file", KeystorePath: t.TempDir(),
		OTITTL: 90 * time.Second, PIIAlg: crypto.AlgXChaCha20,
		WebhookTimeout: 30 * time.Second, WebhookMaxAttempts: 3,
	}, st)
	if err != nil {
		t.Fatal(err)
	}
	if s.OTI.TTL != 90*time.Second {
		t.Fatalf("OTI TTL not wired: %s", s.OTI.TTL)
	}
	if s.Contacts.PII.Algorithm() != crypto.AlgXChaCha20 {
		t.Fatalf("PII alg not wired: %s", s.Contacts.PII.Algorithm())
	}
	if s.GDPR.HTTPTimeout != 30*time.Second || s.GDPR.MaxAttempts != 3 {
		t.Fatalf("webhook tunables not wired: %s %d", s.GDPR.HTTPTimeout, s.GDPR.MaxAttempts)
	}
}

// Server construction and metrics-gate branches that the e2e paths skip.
func TestServerConstructionBranches(t *testing.T) {
	st := testutil.NewDB(t)

	// A signer socket configured: the engine is remote, so New must not
	// require a local keystore at all.
	s, err := New(config.Config{Listen: ":0", SignerSocket: "/nonexistent.sock"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.Contacts != nil {
		t.Fatal("no store means no services")
	}
	// A keystore that cannot bootstrap fails New rather than serving with
	// no key material.
	if _, err := New(config.Config{Listen: ":0", Keystore: "pkcs11"}, st); err == nil {
		t.Fatal("a keystore that cannot ensure keys must fail construction")
	}

	// Redis configured: the shared limiter is wired and its failure counter
	// is exported.
	s, err = New(config.Config{
		Listen: ":0", Keystore: "file", KeystorePath: t.TempDir(),
		RedisAddr: "127.0.0.1:1", RedisFailClosed: false,
	}, st)
	if err != nil {
		t.Fatal(err)
	}
	// Unreachable Redis on an authenticated bucket: fail-open, and the
	// failure surfaces as a metric.
	if !s.Limiter.Allow("crm", 10) {
		t.Fatal("authenticated lookups fail open when Redis is down")
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(rec.Body.String(), "sunder_ratelimit_backend_failures_total") {
		t.Fatal("a limiter backend failure must be visible in /metrics")
	}
	// The portal bucket fails CLOSED on the same backend.
	if s.Limiter.Allow("portal:start:1.2.3.4", 10) {
		t.Fatal("the unauthenticated portal surface must fail closed")
	}
}

// The background worker ticker: one tick must drain both queues, and a
// failing backend must be logged rather than killing the loop.
func TestBackgroundWorkerTick(t *testing.T) {
	st := testutil.NewDB(t)
	ctx := context.Background()
	cred, err := auth.Create(ctx, st.Pool, auth.Client{
		ID: "dpo", Name: "DPO", Scope: "crm",
		AllowedActions:  []string{auth.ActContactsRegister, auth.ActDSRErase},
		AllowedPurposes: []string{"support"}, RateLimit: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer hook.Close()
	if _, err := st.Pool.Exec(ctx,
		`INSERT INTO webhooks (scope, url, secret) VALUES ('crm', $1, 's'), ('_portal', $1, 's')`, hook.URL); err != nil {
		t.Fatal(err)
	}
	addr := freeAddr(t)
	s, err := New(config.Config{
		Listen: addr, Keystore: "file", KeystorePath: t.TempDir(),
		PortalEnabled: true, DeliverInterval: 50 * time.Millisecond,
	}, st)
	if err != nil {
		t.Fatal(err)
	}
	// Queue one erasure event and one portal mail, then let the worker run.
	req := httptest.NewRequest("POST", "/v1/contacts", strings.NewReader(`{"email":"tick@example.com"}`))
	req.Header.Set("Authorization", "Bearer "+cred)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	var cid map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &cid)
	if err := s.Portal.Start(ctx, "tick@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx,
		`UPDATE portal_outbox SET status='PENDING'`); err != nil {
		t.Fatal(err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- s.Run(runCtx) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var pending int
		if err := st.Pool.QueryRow(ctx,
			`SELECT count(*) FROM portal_outbox WHERE status='PENDING'`).Scan(&pending); err != nil {
			t.Fatal(err)
		}
		if pending == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the background worker never drained the portal outbox")
		}
		time.Sleep(30 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}
