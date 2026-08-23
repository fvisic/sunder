package api

// P2.2 short-lived credentials: an expired-but-correct secret returns 401
// credential_expired (distinct from plain unauthorized), rotation kills the
// old secret immediately, and expiry never leaks secret validity.

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/config"
	"github.com/fvisic/sunder/internal/testutil"
)

func TestCredentialExpiry(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewDB(t)
	srv, err := New(config.Config{Listen: ":0", Keystore: "file", KeystorePath: t.TempDir()}, st)
	if err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Minute)
	future := time.Now().Add(time.Hour)

	expired, err := auth.Create(ctx, st.Pool, auth.Client{
		ID: "old", Name: "Old", Scope: "crm",
		AllowedActions: []string{auth.ActLookup}, AllowedPurposes: []string{"support"},
		RateLimit: 100, CredentialExpiresAt: &past,
	})
	if err != nil {
		t.Fatal(err)
	}
	live, err := auth.Create(ctx, st.Pool, auth.Client{
		ID: "new", Name: "New", Scope: "crm",
		AllowedActions: []string{auth.ActLookup}, AllowedPurposes: []string{"support"},
		RateLimit: 100, CredentialExpiresAt: &future,
	})
	if err != nil {
		t.Fatal(err)
	}

	do := func(cred string) (int, string) {
		req := httptest.NewRequest("POST", "/v1/lookup", strings.NewReader(`{"email":"x@example.com"}`))
		req.Header.Set("Authorization", "Bearer "+cred)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}

	// Expired + correct secret: 401 credential_expired.
	code, body := do(expired)
	if code != 401 || !strings.Contains(body, "credential_expired") {
		t.Fatalf("expired credential: %d %s", code, body)
	}
	// Expired id + WRONG secret: plain unauthorized - expiry must not act
	// as a secret-validity oracle.
	code, body = do("old.wrong-secret")
	if code != 401 || strings.Contains(body, "credential_expired") {
		t.Fatalf("wrong secret on expired client must be plain 401: %d %s", code, body)
	}
	// Future expiry works.
	if code, _ = do(live); code == 401 {
		t.Fatal("unexpired credential must authenticate")
	}

	// Rotation: new credential works, the old one dies instantly.
	rotated, err := auth.RotateSecret(ctx, st.Pool, "new", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if code, _ = do(live); code != 401 {
		t.Fatal("old secret must stop working after rotation")
	}
	if code, _ = do(rotated); code == 401 {
		t.Fatal("rotated credential must authenticate")
	}
	if _, err := auth.RotateSecret(ctx, st.Pool, "ghost", nil, false); err == nil {
		t.Fatal("rotating an unknown client must error")
	}
}

// Review finding: authentication failures must be throttled per source IP.
func TestAuthFailureThrottle(t *testing.T) {
	st := testutil.NewDB(t)
	srv, err := New(config.Config{Listen: ":0", Keystore: "file", KeystorePath: t.TempDir()}, st)
	if err != nil {
		t.Fatal(err)
	}
	var got429 bool
	for i := 0; i < 80; i++ {
		req := httptest.NewRequest("POST", "/v1/lookup", strings.NewReader(`{}`))
		req.RemoteAddr = "198.51.100.9:4444"
		req.Header.Set("Authorization", "Bearer ghost.wrong")
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code == 429 {
			got429 = true
			break
		}
		if rec.Code != 401 {
			t.Fatalf("attempt %d: %d", i, rec.Code)
		}
	}
	if !got429 {
		t.Fatal("80 failed auth attempts from one IP must hit the throttle")
	}
	// A different IP is unaffected.
	req := httptest.NewRequest("POST", "/v1/lookup", strings.NewReader(`{}`))
	req.RemoteAddr = "198.51.100.10:4444"
	req.Header.Set("Authorization", "Bearer ghost.wrong")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("other IPs must not be throttled: %d", rec.Code)
	}
}
