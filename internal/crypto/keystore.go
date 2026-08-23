// Package crypto implements Sunder's cryptographic core: keystore drivers,
// HMAC search tokens, input normalization, PII envelope encryption, CID
// generation and PASETO v4.public one-time identifiers.
//
// Everything here is Go stdlib only (plus x/text, already a transitive
// dependency), per the "stdlib first" policy.
package crypto

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Keystore returns 32-byte key material by logical name (e.g. "hmac-email/v1").
//
// Key is STRICT: a missing key is an error, never silently regenerated -
// a silently minted replacement would mask key loss (unmatchable search
// tokens, undecryptable PII) as healthy operation. Ensure is the only
// creation path and is called at bootstrap/rotation, not per request.
type Keystore interface {
	Key(ctx context.Context, name string) ([]byte, error)
	Ensure(ctx context.Context, name string) error
}

// keyName constrains logical names so the '/'->'_' flattening used by the
// drivers can never make two distinct names collide.
var keyName = regexp.MustCompile(`^[a-z0-9-]+/v[0-9]+$`)

func checkName(name string) error {
	if !keyName.MatchString(name) {
		return fmt.Errorf("keystore: invalid key name %q", name)
	}
	return nil
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

func (f *FileKeystore) Key(_ context.Context, name string) ([]byte, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(f.path(name))
	if err != nil {
		return nil, fmt.Errorf("keystore: key %s missing (run bootstrap/rotation, check SUNDER_KEYSTORE_PATH): %w", name, err)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("keystore: %s has %d bytes, want 32", name, len(b))
	}
	return b, nil
}

// Ensure generates the key if absent. The final path only ever appears via
// an atomic rename of a fully-written temp file; an O_EXCL lock file elects
// a single generator across processes sharing the directory.
func (f *FileKeystore) Ensure(ctx context.Context, name string) error {
	if err := checkName(name); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.path(name)
	if b, err := os.ReadFile(p); err == nil && len(b) == 32 {
		return nil
	}
	if err := os.MkdirAll(f.Dir, 0o700); err != nil {
		return err
	}
	lockPath := p + ".lock"
	lock, err := os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if !os.IsExist(err) {
			return err
		}
		// A crashed generator leaves a stale lock; reclaim it after 30s.
		if st, serr := os.Stat(lockPath); serr == nil && time.Since(st.ModTime()) > 30*time.Second {
			_ = os.Remove(lockPath)
			return f.ensureLocked(ctx, name)
		}
		// Another live process is generating: wait for its atomic rename.
		for i := 0; i < 100; i++ {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(20 * time.Millisecond):
			}
			if b, err := os.ReadFile(p); err == nil && len(b) == 32 {
				return nil
			}
		}
		return fmt.Errorf("keystore: timed out waiting for %s", name)
	}
	defer func() {
		_ = lock.Close()
		_ = os.Remove(lockPath)
	}()
	return f.writeKey(p)
}

// ensureLocked re-runs generation after reclaiming a stale lock (mutex held).
func (f *FileKeystore) ensureLocked(_ context.Context, name string) error {
	p := f.path(name)
	if b, err := os.ReadFile(p); err == nil && len(b) == 32 {
		return nil
	}
	return f.writeKey(p)
}

func (f *FileKeystore) writeKey(p string) error {
	key := make([]byte, 32)
	if _, err := randRead(key); err != nil {
		return err
	}
	// Unique temp name: after a stale-lock reclaim two processes may write
	// concurrently, and a shared "<name>.tmp" could transiently publish a
	// short key file (review finding F7).
	tf, err := os.CreateTemp(filepath.Dir(p), filepath.Base(p)+".tmp*")
	if err != nil {
		return err
	}
	tmp := tf.Name()
	defer func() { _ = os.Remove(tmp) }()
	if err := tf.Chmod(0o600); err != nil {
		_ = tf.Close()
		return err
	}
	if _, err := tf.Write(key); err != nil {
		_ = tf.Close()
		return err
	}
	if err := tf.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, p)
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
	if err := checkName(name); err != nil {
		return nil, err
	}
	key, err := v.read(ctx, name)
	if err == errNotFound {
		return nil, fmt.Errorf("keystore: key %s missing in vault (run bootstrap/rotation)", name)
	}
	return key, err
}

func (v *VaultKeystore) Ensure(ctx context.Context, name string) error {
	if err := checkName(name); err != nil {
		return err
	}
	if _, err := v.read(ctx, name); err == nil {
		return nil
	} else if err != errNotFound {
		return err
	}
	fresh := make([]byte, 32)
	if _, err := randRead(fresh); err != nil {
		return err
	}
	// cas=0 makes the write fail if the secret appeared meanwhile; then the
	// concurrent winner's key is authoritative.
	body, _ := json.Marshal(map[string]any{
		"data":    map[string]string{"key": hex.EncodeToString(fresh)},
		"options": map[string]any{"cas": 0},
	})
	req, err := http.NewRequestWithContext(ctx, "POST", v.url(name), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", v.Token)
	resp, err := v.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// 400 usually means the CAS lost to a concurrent writer; the follow-up
	// read must then succeed with the winner's key.
	if resp.StatusCode >= 400 && resp.StatusCode != http.StatusBadRequest {
		return fmt.Errorf("vault write %s: status %d", name, resp.StatusCode)
	}
	if _, err := v.read(ctx, name); err != nil {
		return fmt.Errorf("vault write %s gave status %d and re-read failed: %w", name, resp.StatusCode, err)
	}
	return nil
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
	key, err := hex.DecodeString(out.Data.Data["key"])
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("vault key %s: malformed material", name)
	}
	return key, nil
}

// --- caching wrapper ---------------------------------------------------------

// CachingKeystore memoizes key material in process memory. Safe because a
// key NAME's material is immutable: rotation mints new versioned names and
// retirement only stops a name from being requested (the keyring no longer
// lists it) - existing material never changes. Removes per-request keystore
// I/O (file reads / Vault round trips) from the hot path.
type CachingKeystore struct {
	Inner Keystore
	mu    sync.RWMutex
	keys  map[string][]byte
}

func NewCachingKeystore(inner Keystore) *CachingKeystore {
	return &CachingKeystore{Inner: inner, keys: map[string][]byte{}}
}

func (c *CachingKeystore) Key(ctx context.Context, name string) ([]byte, error) {
	c.mu.RLock()
	k, ok := c.keys[name]
	c.mu.RUnlock()
	if ok {
		return k, nil
	}
	k, err := c.Inner.Key(ctx, name)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.keys[name] = k
	c.mu.Unlock()
	return k, nil
}

func (c *CachingKeystore) Ensure(ctx context.Context, name string) error {
	return c.Inner.Ensure(ctx, name)
}

// --- pkcs11 stub --------------------------------------------------------------

// PKCS11Keystore is an interface stub until the first compliance-driven demand
// (production deployments needing an HSM front the file/vault drivers today).
type PKCS11Keystore struct{}

func (*PKCS11Keystore) Key(context.Context, string) ([]byte, error) {
	return nil, fmt.Errorf("keystore: pkcs11 driver not implemented yet")
}

func (*PKCS11Keystore) Ensure(context.Context, string) error {
	return fmt.Errorf("keystore: pkcs11 driver not implemented yet")
}
