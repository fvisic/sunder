// Package crypto implements Sunder's cryptographic core: keystore drivers,
// HMAC search tokens, input normalization, PII envelope encryption, CID
// generation and (from M4) PASETO v4.public one-time identifiers.
//
// Everything here is Go stdlib only, per the "stdlib first" policy.
package crypto

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Keystore returns 32-byte key material by logical name (e.g. "hmac-email/v1").
// Drivers must generate a key on first request for a name (create-on-read),
// so deployments bootstrap without a separate key ceremony.
type Keystore interface {
	Key(ctx context.Context, name string) ([]byte, error)
}

// --- file driver -----------------------------------------------------------

// FileKeystore stores raw keys as 0600 files under a directory. Suitable for
// development and single-node pilots; production should prefer Vault.
type FileKeystore struct {
	Dir string
	mu  sync.Mutex
}

func (f *FileKeystore) path(name string) string {
	return filepath.Join(f.Dir, strings.ReplaceAll(name, "/", "_")+".key")
}

// Key generates on first use. The final path only ever appears via an atomic
// rename of a fully-written temp file, so readers see 32 bytes or nothing;
// an O_EXCL lock file elects a single generator across processes sharing the
// directory, and losers poll for the winner's rename.
func (f *FileKeystore) Key(ctx context.Context, name string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.path(name)
	if b, err := os.ReadFile(p); err == nil {
		if len(b) != 32 {
			return nil, fmt.Errorf("keystore: %s has %d bytes, want 32", p, len(b))
		}
		return b, nil
	}
	if err := os.MkdirAll(f.Dir, 0o700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(p+".lock", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if !os.IsExist(err) {
			return nil, err
		}
		// Another process is generating: wait for its atomic rename.
		for i := 0; i < 100; i++ {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(20 * time.Millisecond):
			}
			if b, err := os.ReadFile(p); err == nil && len(b) == 32 {
				return b, nil
			}
		}
		return nil, fmt.Errorf("keystore: timed out waiting for %s", p)
	}
	defer func() {
		_ = lock.Close()
		_ = os.Remove(p + ".lock")
	}()

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, key, 0o600); err != nil {
		_ = os.Remove(tmp)
		return nil, err
	}
	if err := os.Rename(tmp, p); err != nil {
		_ = os.Remove(tmp)
		return nil, err
	}
	return key, nil
}

// --- vault driver ----------------------------------------------------------

// VaultKeystore keeps key material in HashiCorp Vault KV v2 under
// <mount>/data/sunder/<name>. Implemented with plain HTTP to avoid the SDK
// dependency tree; only the token auth method is supported in v1.
type VaultKeystore struct {
	Addr  string
	Token string
	Mount string // KV v2 mount, default "secret"
	HTTP  *http.Client
}

func (v *VaultKeystore) client() *http.Client {
	if v.HTTP != nil {
		return v.HTTP
	}
	return &http.Client{Timeout: 10 * time.Second}
}

func (v *VaultKeystore) url(name string) string {
	mount := v.Mount
	if mount == "" {
		mount = "secret"
	}
	return fmt.Sprintf("%s/v1/%s/data/sunder/%s", strings.TrimSuffix(v.Addr, "/"), mount,
		strings.ReplaceAll(name, "/", "_"))
}

func (v *VaultKeystore) Key(ctx context.Context, name string) ([]byte, error) {
	key, err := v.read(ctx, name)
	if err == nil {
		return key, nil
	}
	if err != errNotFound {
		return nil, err
	}
	fresh := make([]byte, 32)
	if _, err := rand.Read(fresh); err != nil {
		return nil, err
	}
	// cas=0 makes the write fail if the secret appeared meanwhile; then the
	// concurrent winner's key is authoritative.
	body, _ := json.Marshal(map[string]any{
		"data":    map[string]string{"key": fmt.Sprintf("%x", fresh)},
		"options": map[string]any{"cas": 0},
	})
	req, err := http.NewRequestWithContext(ctx, "POST", v.url(name), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", v.Token)
	resp, err := v.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	// 400 usually means the CAS lost to a concurrent writer, whose key the
	// follow-up read returns; a read failure then surfaces both statuses.
	if resp.StatusCode >= 400 && resp.StatusCode != http.StatusBadRequest {
		return nil, fmt.Errorf("vault write %s: status %d", name, resp.StatusCode)
	}
	key, err = v.read(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("vault write %s gave status %d and re-read failed: %w", name, resp.StatusCode, err)
	}
	return key, nil
}

var errNotFound = fmt.Errorf("keystore: not found")

func (v *VaultKeystore) read(ctx context.Context, name string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", v.url(name), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", v.Token)
	resp, err := v.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, errNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vault read %s: status %d", name, resp.StatusCode)
	}
	var out struct {
		Data struct {
			Data map[string]string `json:"data"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, err
	}
	var key []byte
	if _, err := fmt.Sscanf(out.Data.Data["key"], "%x", &key); err != nil || len(key) != 32 {
		return nil, fmt.Errorf("vault key %s: malformed material", name)
	}
	return key, nil
}

// --- pkcs11 stub (decision D7) ----------------------------------------------

// PKCS11Keystore is an interface stub until the first compliance-driven demand.
type PKCS11Keystore struct{}

func (*PKCS11Keystore) Key(context.Context, string) ([]byte, error) {
	return nil, fmt.Errorf("keystore: pkcs11 driver not implemented in v1 (decision D7)")
}
