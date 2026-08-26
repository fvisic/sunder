package crypto

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestFileKeystoreRecoveryHelpers(t *testing.T) {
	dir := t.TempDir()
	ks := &FileKeystore{Dir: dir}
	// No keys yet: AllKeys errors.
	if _, err := ks.AllKeys(); err == nil {
		t.Fatal("AllKeys on an empty keystore must error")
	}
	// Create two keys via Ensure.
	if err := ks.Ensure(nil, "pii-kek/v1"); err != nil {
		t.Fatal(err)
	}
	if err := ks.Ensure(nil, "hmac-email/v1"); err != nil {
		t.Fatal(err)
	}
	entries, err := ks.AllKeys()
	if err != nil || len(entries) != 2 {
		t.Fatalf("AllKeys: %d %v", len(entries), err)
	}
	// A non-32-byte file makes AllKeys fail.
	if err := os.WriteFile(filepath.Join(dir, "bogus.key"), []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.AllKeys(); err == nil {
		t.Fatal("AllKeys must reject a wrong-sized key file")
	}
	os.Remove(filepath.Join(dir, "bogus.key"))

	// Bundle write/read round trip.
	if err := ks.WriteRecoveryBundle([]byte("ciphertext-blob")); err != nil {
		t.Fatal(err)
	}
	b, err := ks.ReadRecoveryBundle()
	if err != nil || !bytes.Equal(b, []byte("ciphertext-blob")) {
		t.Fatalf("bundle round trip: %q %v", b, err)
	}

	// RestoreKeys writes files back; a bad key size is rejected.
	if err := ks.RestoreKeys([]KeyEntry{{Name: "restored", Key: bytes.Repeat([]byte{5}, 32)}}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "restored.key"))
	if err != nil || !bytes.Equal(got, bytes.Repeat([]byte{5}, 32)) {
		t.Fatalf("restored key: %v", err)
	}
	if err := ks.RestoreKeys([]KeyEntry{{Name: "bad", Key: []byte{1}}}); err == nil {
		t.Fatal("RestoreKeys must reject a wrong-sized key")
	}
}

func TestVaultKeystoreErrorPaths(t *testing.T) {
	ctx := context.Background()
	// A server that returns whatever status/body the test sets.
	var status int
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	defer srv.Close()
	v := &VaultKeystore{Addr: srv.URL, Token: "t", HTTP: srv.Client()}

	// Invalid key name is rejected before any HTTP.
	if _, err := v.Key(ctx, "../etc/passwd"); err == nil {
		t.Fatal("bad key name must be rejected")
	}
	if err := v.Ensure(ctx, "../bad"); err == nil {
		t.Fatal("Ensure bad name must be rejected")
	}
	// 404 -> missing key.
	status, body = 404, ""
	if _, err := v.Key(ctx, "pii-kek/v1"); err == nil {
		t.Fatal("404 must map to a missing-key error")
	}
	// 500 on read -> surfaced.
	status, body = 500, "boom"
	if _, err := v.Key(ctx, "pii-kek/v1"); err == nil {
		t.Fatal("500 read must surface")
	}
	// Malformed material (200 with bad hex).
	status, body = 200, `{"data":{"data":{"key":"nothex"}}}`
	if _, err := v.Key(ctx, "pii-kek/v1"); err == nil {
		t.Fatal("malformed material must be rejected")
	}
	// Wrong-length material.
	status, body = 200, `{"data":{"data":{"key":"aabb"}}}`
	if _, err := v.Key(ctx, "pii-kek/v1"); err == nil {
		t.Fatal("short material must be rejected")
	}
	// Undecodable body.
	status, body = 200, `not-json`
	if _, err := v.Key(ctx, "pii-kek/v1"); err == nil {
		t.Fatal("bad JSON must be rejected")
	}
	// Ensure: read says 404, then write returns a hard error (403).
	callCount := 0
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.WriteHeader(404)
			return
		}
		callCount++
		w.WriteHeader(403) // a non-400 write error
	}))
	defer srv2.Close()
	v2 := &VaultKeystore{Addr: srv2.URL, Token: "t", HTTP: srv2.Client()}
	if err := v2.Ensure(ctx, "pii-kek/v1"); err == nil {
		t.Fatal("a 403 vault write must surface")
	}
}

func TestFileKeystoreWriteFailuresOnReadOnlyDir(t *testing.T) {
	dir := t.TempDir()
	ks := &FileKeystore{Dir: dir}
	// Seed one key, then make the directory read-only so CreateTemp fails
	// in writeKey / WriteRecoveryBundle / RestoreKeys.
	if err := ks.Ensure(nil, "pii-kek/v1"); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)

	// Ensure of a NEW key must fail (CreateTemp in a read-only dir).
	if err := ks.Ensure(nil, "hmac-email/v1"); err == nil {
		t.Fatal("Ensure into a read-only dir must fail")
	}
	if err := ks.WriteRecoveryBundle([]byte("x")); err == nil {
		t.Fatal("WriteRecoveryBundle into a read-only dir must fail")
	}
	if err := ks.RestoreKeys([]KeyEntry{{Name: "k", Key: bytes.Repeat([]byte{1}, 32)}}); err == nil {
		t.Fatal("RestoreKeys into a read-only dir must fail")
	}
}
