package service_test

// Tests for the deployment tunables: configurable OTI TTL, webhook delivery
// caps, and the live algorithm migration (aes256gcm -> xchacha20poly1305 via
// the rekey sweep).

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fvisic/sunder/internal/crypto"
	"github.com/fvisic/sunder/internal/service"
)

func TestOTITTLConfigurable(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cid := e.register(t)

	// Custom TTL is reflected in the returned expiry.
	e.oti.TTL = 90 * time.Second
	_, exp, err := e.oti.Issue(ctx, e.crm, cid, "support", "billing", nil)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(exp); d < 80*time.Second || d > 91*time.Second {
		t.Fatalf("expiry must track the configured TTL, got %s away", d)
	}

	// A token minted with a (test-only) sub-second TTL expires for real.
	e.oti.TTL = 50 * time.Millisecond
	tok, _, err := e.oti.Issue(ctx, e.crm, cid, "support", "billing", nil)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(80 * time.Millisecond)
	if _, err := e.oti.Verify(ctx, e.verifier(), tok, "support", "billing"); err != service.ErrTokenExpired {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}

	// Zero falls back to the documented default.
	e.oti.TTL = 0
	_, exp, err = e.oti.Issue(ctx, e.crm, cid, "support", "billing", nil)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(exp); d < 4*time.Minute || d > 5*time.Minute+time.Second {
		t.Fatalf("zero TTL must mean the 5m default, got %s away", d)
	}
}

func TestWebhookMaxAttemptsConfigurable(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cid := e.register(t)

	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer dead.Close()
	if _, err := e.admin.Pool.Exec(ctx,
		`INSERT INTO webhooks (scope, url, secret) VALUES ('crm', $1, 's')`, dead.URL); err != nil {
		t.Fatal(err)
	}
	e.gdpr.MaxAttempts = 2
	if _, _, err := e.gdpr.Erase(ctx, e.crm, cid); err != nil { // attempt 1 (detached)
		t.Fatal(err)
	}
	e.gdpr.Drain()
	if _, err := e.gdpr.DeliverPending(ctx); err != nil { // attempt 2 -> cap
		t.Fatal(err)
	}
	var status string
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT status FROM erasure_events LIMIT 1`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "FAILED" {
		t.Fatalf("attempts cap 2 must mark FAILED after two failures, got %s", status)
	}
}

func TestWebhookTimeoutConfigurable(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cid := e.register(t)

	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.WriteHeader(200)
	}))
	defer slow.Close()
	if _, err := e.admin.Pool.Exec(ctx,
		`INSERT INTO webhooks (scope, url, secret) VALUES ('crm', $1, 's')`, slow.URL); err != nil {
		t.Fatal(err)
	}
	e.gdpr.HTTPTimeout = 50 * time.Millisecond
	if _, _, err := e.gdpr.Erase(ctx, e.crm, cid); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT status FROM erasure_events LIMIT 1`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "PENDING" {
		t.Fatalf("a delivery slower than the timeout must stay PENDING, got %s", status)
	}
}

// The headline scenario: data written under aes256gcm, the deployment is
// reconfigured to xchacha20poly1305, everything keeps working, and one
// rekey sweep converts the stored blobs to the new algorithm.
func TestAlgorithmMigrationLive(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cid := e.register(t) // written under the default aes256gcm

	assertAlg := func(want string) {
		t.Helper()
		var alg string
		if err := e.admin.Pool.QueryRow(ctx,
			`SELECT pii_alg FROM cids WHERE cid=$1`, cid).Scan(&alg); err != nil {
			t.Fatal(err)
		}
		if alg != want {
			t.Fatalf("pii_alg = %q, want %q", alg, want)
		}
	}
	assertAlg(crypto.AlgAES256GCM)

	// Reconfigure the running service to the new AEAD.
	e.svc.PII.Alg = crypto.AlgXChaCha20

	// Old blob still reads (stored algorithm wins on the read path).
	if v, err := e.svc.GetAttribute(ctx, e.crm, cid, "tier", "support"); err != nil || v != "gold" {
		t.Fatalf("aes blob must stay readable after reconfiguration: %q %v", v, err)
	}

	// New writes use the new algorithm.
	cid2, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
		Email: "new@example.com", Attributes: map[string]string{"tier": "silver"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var alg2 string
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT pii_alg FROM cids WHERE cid=$1`, cid2).Scan(&alg2); err != nil {
		t.Fatal(err)
	}
	if alg2 != crypto.AlgXChaCha20 {
		t.Fatalf("new blob must use the configured algorithm, got %q", alg2)
	}

	// The rekey sweep converts the aes backlog even though the KEK version
	// is already current.
	stats, err := e.svc.Rekey(ctx, true, 10)
	if err != nil {
		t.Fatal(err)
	}
	if stats.BlobsReenc == 0 {
		t.Fatal("rekey must re-encrypt algorithm-stale blobs")
	}
	assertAlg(crypto.AlgXChaCha20)

	// Converted blob decrypts under the new algorithm.
	if v, err := e.svc.GetAttribute(ctx, e.crm, cid, "tier", "support"); err != nil || v != "gold" {
		t.Fatalf("converted blob must read back: %q %v", v, err)
	}
	// A second sweep is a no-op: nothing left to convert.
	stats, err = e.svc.Rekey(ctx, true, 10)
	if err != nil || stats.BlobsReenc != 0 {
		t.Fatalf("second sweep must convert nothing: %+v %v", stats, err)
	}
}

// Attribute sharing across an aes-era issuer and an xchacha-era verifier -
// the mixed state a deployment lives in mid-migration.
func TestShareAcrossMixedAlgorithms(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cid := e.register(t) // aes blob

	e.svc.PII.Alg = crypto.AlgXChaCha20 // switch before the handoff
	tok, _, err := e.oti.Issue(ctx, e.crm, cid, "support", "billing", []string{"tier"})
	if err != nil {
		t.Fatal(err)
	}
	vcid, err := e.oti.Verify(ctx, e.verifier(), tok, "support", "billing")
	if err != nil {
		t.Fatal(err)
	}
	// The verifier-scope copy was written under the NEW algorithm and reads back.
	var alg string
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT pii_alg FROM cids WHERE cid=$1`, vcid).Scan(&alg); err != nil {
		t.Fatal(err)
	}
	if alg != crypto.AlgXChaCha20 {
		t.Fatalf("shared blob must use the configured algorithm, got %q", alg)
	}
	billing := e.verifier()
	billing.AllowedActions = append(billing.AllowedActions, "attributes.read")
	if v, err := e.svc.GetAttribute(ctx, billing, vcid, "tier", "support"); err != nil || v != "gold" {
		t.Fatalf("shared attribute must read in the verifier scope: %q %v", v, err)
	}
}
