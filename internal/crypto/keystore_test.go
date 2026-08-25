package crypto

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"
)

// fakeVault emulates the KV v2 endpoints VaultKeystore touches.
type fakeVault struct {
	mu    sync.Mutex
	data  map[string]string // path -> hex key
	token string
}

func (f *fakeVault) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != f.token {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.Method {
		case "GET":
			hexKey, ok := f.data[r.URL.Path]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{"data": map[string]string{"key": hexKey}},
			})
		case "POST":
			var body struct {
				Data    map[string]string `json:"data"`
				Options struct {
					CAS int `json:"cas"`
				} `json:"options"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if _, exists := f.data[r.URL.Path]; exists && body.Options.CAS == 0 {
				w.WriteHeader(http.StatusBadRequest) // CAS conflict
				return
			}
			f.data[r.URL.Path] = body.Data["key"]
			w.WriteHeader(http.StatusOK)
		}
	})
}

func TestVaultKeystoreEnsureThenRead(t *testing.T) {
	fv := &fakeVault{data: map[string]string{}, token: "t0k"}
	srv := httptest.NewServer(fv.handler())
	defer srv.Close()
	ks := &VaultKeystore{Addr: srv.URL, Token: "t0k", Mount: "secret", HTTP: srv.Client()}

	ctx := context.Background()
	// Strict: reading before Ensure must fail, never mint.
	if _, err := ks.Key(ctx, "hmac-email/v1"); err == nil {
		t.Fatal("strict keystore must error on missing key")
	}
	if err := ks.Ensure(ctx, "hmac-email/v1"); err != nil {
		t.Fatal(err)
	}
	k1, err := ks.Key(ctx, "hmac-email/v1")
	if err != nil {
		t.Fatal(err)
	}
	if len(k1) != 32 {
		t.Fatalf("want 32 bytes, got %d", len(k1))
	}
	k2, err := ks.Key(ctx, "hmac-email/v1")
	if err != nil || string(k1) != string(k2) {
		t.Fatalf("second read differs: %v", err)
	}
}

func TestVaultKeystoreCASConflictReturnsWinner(t *testing.T) {
	fv := &fakeVault{data: map[string]string{}, token: "t0k"}
	srv := httptest.NewServer(fv.handler())
	defer srv.Close()
	ks := &VaultKeystore{Addr: srv.URL, Token: "t0k", HTTP: srv.Client()}

	// Pre-plant the winner's key at the path the driver will use (default
	// mount "secret"), so the driver's write CAS-conflicts and it must
	// return the existing key.
	winner := make([]byte, 32)
	for i := range winner {
		winner[i] = byte(i)
	}
	fv.data["/v1/secret/data/sunder/hmac-phone_v1"] = fmt.Sprintf("%x", winner)

	if err := ks.Ensure(context.Background(), "hmac-phone/v1"); err != nil {
		t.Fatal(err)
	}
	got, err := ks.Key(context.Background(), "hmac-phone/v1")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(winner) {
		t.Fatal("driver did not return the pre-existing (winner) key")
	}
}

func TestVaultKeystoreBadToken(t *testing.T) {
	fv := &fakeVault{data: map[string]string{}, token: "right"}
	srv := httptest.NewServer(fv.handler())
	defer srv.Close()
	ks := &VaultKeystore{Addr: srv.URL, Token: "wrong", HTTP: srv.Client()}
	if _, err := ks.Key(context.Background(), "x/v1"); err == nil {
		t.Fatal("expected error for bad token")
	}
}

func TestFileKeystoreConcurrentEnsure(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make([]error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Separate instances simulate separate processes on a shared dir.
			errs[i] = (&FileKeystore{Dir: dir}).Ensure(ctx, "race/v1")
		}(i)
	}
	wg.Wait()
	for i := 0; i < 16; i++ {
		if errs[i] != nil {
			t.Fatal(errs[i])
		}
	}
	if _, err := (&FileKeystore{Dir: dir}).Key(ctx, "race/v1"); err != nil {
		t.Fatal(err)
	}
}

func TestCachingKeystoreServesFromMemory(t *testing.T) {
	dir := t.TempDir()
	inner := &FileKeystore{Dir: dir}
	ks := NewCachingKeystore(inner)
	ctx := context.Background()
	if err := ks.Ensure(ctx, "hmac-email/v1"); err != nil {
		t.Fatal(err)
	}
	k1, err := ks.Key(ctx, "hmac-email/v1")
	if err != nil {
		t.Fatal(err)
	}
	// Remove the backing file: the cache must still serve the key (and this
	// proves the hot path no longer touches the keystore).
	if err := os.Remove(inner.path("hmac-email/v1")); err != nil {
		t.Fatal(err)
	}
	k2, err := ks.Key(ctx, "hmac-email/v1")
	if err != nil || string(k1) != string(k2) {
		t.Fatalf("cache miss after file removal: %v", err)
	}
	// Uncached names still go through the strict inner keystore.
	if _, err := ks.Key(ctx, "hmac-email/v9"); err == nil {
		t.Fatal("uncached missing key must error")
	}
}

func TestEnsureReclaimsStaleLock(t *testing.T) {
	dir := t.TempDir()
	ks := &FileKeystore{Dir: dir}
	ctx := context.Background()
	// A crashed generator left a lock file 10 minutes ago.
	lock := ks.path("hmac-email/v1") + ".lock"
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-10 * time.Minute)
	if err := os.Chtimes(lock, old, old); err != nil {
		t.Fatal(err)
	}
	if err := ks.Ensure(ctx, "hmac-email/v1"); err != nil {
		t.Fatalf("stale lock must be reclaimed: %v", err)
	}
	if _, err := ks.Key(ctx, "hmac-email/v1"); err != nil {
		t.Fatal(err)
	}
}

func TestKeystoreCorruptAndVaultFailures(t *testing.T) {
	ctx := context.Background()
	// File driver: a key file of the wrong size is a hard error.
	dir := t.TempDir()
	ks := &FileKeystore{Dir: dir}
	if err := os.WriteFile(ks.path("hmac-email/v1"), []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Key(ctx, "hmac-email/v1"); err == nil {
		t.Fatal("wrong-size key must error")
	}
	// Ensure with an existing wrong-size file regenerates cleanly is NOT
	// wanted - it must overwrite? No: Ensure reads, sees wrong size, and
	// regenerates via the lock path (len check fails -> writeKey).
	if err := ks.Ensure(ctx, "hmac-email/v1"); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Key(ctx, "hmac-email/v1"); err != nil {
		t.Fatal(err)
	}

	// Vault: server erroring on write; server returning malformed material.
	fail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.WriteHeader(404)
			return
		}
		w.WriteHeader(500)
	}))
	defer fail.Close()
	v := &VaultKeystore{Addr: fail.URL, Token: "t", HTTP: fail.Client()}
	if err := v.Ensure(ctx, "hmac-email/v1"); err == nil {
		t.Fatal("vault write failure must surface")
	}
	badKey := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"data":{"key":"zz-not-hex"}}}`))
	}))
	defer badKey.Close()
	v2 := &VaultKeystore{Addr: badKey.URL, Token: "t", HTTP: badKey.Client()}
	if _, err := v2.Key(ctx, "hmac-email/v1"); err == nil {
		t.Fatal("malformed vault key material must error")
	}
	garbage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	}))
	defer garbage.Close()
	v3 := &VaultKeystore{Addr: garbage.URL, Token: "t", HTTP: garbage.Client()}
	if _, err := v3.Key(ctx, "hmac-email/v1"); err == nil {
		t.Fatal("non-JSON vault response must error")
	}
}

func TestWriteKeyUnwritableDir(t *testing.T) {
	dir := t.TempDir()
	sub := dir + "/ro"
	if err := os.MkdirAll(sub, 0o500); err != nil { // no write permission
		t.Fatal(err)
	}
	ks := &FileKeystore{Dir: sub}
	if err := ks.Ensure(context.Background(), "hmac-email/v1"); err == nil {
		t.Fatal("unwritable keystore dir must error")
	}
}

func TestFileKeystoreEnsureFailsOnReadOnlyDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	ks := &FileKeystore{Dir: dir}
	if err := ks.Ensure(context.Background(), "hmac-email/v1"); err == nil {
		t.Fatal("a read-only keystore dir must fail Ensure, not silently mint nothing")
	}
}

func TestMustHexGuardsItsLiterals(t *testing.T) {
	// The small-order table is compiled-in data; a corrupted literal must
	// stop the process at init rather than weaken verification silently.
	defer func() {
		if recover() == nil {
			t.Fatal("bad literal must panic")
		}
	}()
	mustHex("zz")
}

func TestFileKeystoreKeyRejectsBadName(t *testing.T) {
	ks := &FileKeystore{Dir: t.TempDir()}
	if _, err := ks.Key(context.Background(), "../escape/v1"); err == nil {
		t.Fatal("path-traversal key names must be rejected")
	}
	if err := ks.Ensure(context.Background(), "../escape/v1"); err == nil {
		t.Fatal("path-traversal names must be rejected by Ensure too")
	}
}

func TestVaultKeystoreUnreachable(t *testing.T) {
	v := &VaultKeystore{Addr: "http://127.0.0.1:1", Token: "t", Mount: "secret"}
	ctx := context.Background()
	if err := v.Ensure(ctx, "hmac-email/v1"); err == nil {
		t.Fatal("an unreachable Vault must fail Ensure, never mint a local key")
	}
	if _, err := v.Key(ctx, "hmac-email/v1"); err == nil {
		t.Fatal("an unreachable Vault must fail Key")
	}
}
