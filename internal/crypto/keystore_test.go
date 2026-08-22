package crypto

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
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

func TestVaultKeystoreCreateThenRead(t *testing.T) {
	fv := &fakeVault{data: map[string]string{}, token: "t0k"}
	srv := httptest.NewServer(fv.handler())
	defer srv.Close()
	ks := &VaultKeystore{Addr: srv.URL, Token: "t0k", Mount: "secret", HTTP: srv.Client()}

	ctx := context.Background()
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

func TestFileKeystoreConcurrentFirstUse(t *testing.T) {
	ks := &FileKeystore{Dir: t.TempDir()}
	ctx := context.Background()
	var wg sync.WaitGroup
	keys := make([][]byte, 16)
	errs := make([]error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			keys[i], errs[i] = ks.Key(ctx, "race/v1")
		}(i)
	}
	wg.Wait()
	for i := 0; i < 16; i++ {
		if errs[i] != nil {
			t.Fatal(errs[i])
		}
		if string(keys[i]) != string(keys[0]) {
			t.Fatal("concurrent first use produced different keys")
		}
	}
}
