package api

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/fvisic/sunder/internal/config"
	"github.com/fvisic/sunder/internal/crypto"
	"github.com/fvisic/sunder/internal/store"
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
