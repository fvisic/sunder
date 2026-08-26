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
	"errors"
	"fmt"
	"io"
	"log/slog"
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

// validBundleName guards the ON-DISK base name a recovery bundle carries
// (slashes already folded to "_"): no path separators, no parent reference,
// no absolute path, and a conservative character set - enough that
// filepath.Join can never escape f.Dir.
func validBundleName(name string) bool {
	if name == "" || len(name) > 128 || name == "." || name == ".." {
		return false
	}
	if strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") || filepath.IsAbs(name) {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
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
	// short key file.
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
	slog.Warn("keystore: minting NEW key material in vault; if this key was expected to exist, the mount may be wrong and existing data unrecoverable",
		"name", name, "mount", v.Mount)
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

// --- F9 recovery helpers (file keystore only) ------------------------------

const recoveryBundleFile = "recovery.bundle"

// AllKeys reads every key file in the keystore as a recovery entry. Used by
// shamir-init/rotate to snapshot the keystore into a recovery bundle.
func (f *FileKeystore) AllKeys() ([]KeyEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ents, err := os.ReadDir(f.Dir)
	if err != nil {
		return nil, err
	}
	var out []KeyEntry
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".key") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(f.Dir, e.Name()))
		if err != nil {
			return nil, err
		}
		if len(b) != 32 {
			return nil, fmt.Errorf("keystore: %s has %d bytes, want 32", e.Name(), len(b))
		}
		// The stored file name reverses path()'s "/" -> "_" mapping only for
		// display; the recovery bundle stores the ON-DISK base name so
		// restore is a byte-for-byte round trip.
		name := strings.TrimSuffix(e.Name(), ".key")
		out = append(out, KeyEntry{Name: name, Key: b})
	}
	if len(out) == 0 {
		return nil, errors.New("keystore: no keys to protect (run bootstrap first)")
	}
	return out, nil
}

// WriteRecoveryBundle atomically writes the sealed bundle to the keystore
// directory (0600). It contains only ciphertext - safe to back up.
// ErrBundleExists is returned by WriteRecoveryBundle when a bundle already
// exists and force was not requested - overwriting silently invalidates
// every custodian's shares.
var ErrBundleExists = errors.New("keystore: a recovery bundle already exists")

func (f *FileKeystore) WriteRecoveryBundle(bundle []byte) error {
	return f.writeRecoveryBundle(bundle, false)
}

// WriteRecoveryBundleForce overwrites an existing bundle. shamir-rotate uses
// it deliberately (new shares supersede the old); shamir-init does not (a
// fresh init over a live bundle would silently strand the old custodians).
func (f *FileKeystore) WriteRecoveryBundleForce(bundle []byte) error {
	return f.writeRecoveryBundle(bundle, true)
}

func (f *FileKeystore) writeRecoveryBundle(bundle []byte, force bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := os.MkdirAll(f.Dir, 0o700); err != nil {
		return err
	}
	p := filepath.Join(f.Dir, recoveryBundleFile)
	if !force {
		if _, err := os.Stat(p); err == nil {
			return ErrBundleExists
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	tf, err := os.CreateTemp(f.Dir, recoveryBundleFile+".tmp*")
	if err != nil {
		return err
	}
	tmp := tf.Name()
	defer func() { _ = os.Remove(tmp) }()
	if err := tf.Chmod(0o600); err != nil {
		_ = tf.Close()
		return err
	}
	if _, err := tf.Write(bundle); err != nil {
		_ = tf.Close()
		return err
	}
	if err := tf.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// ReadRecoveryBundle reads the sealed bundle.
func (f *FileKeystore) ReadRecoveryBundle() ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return os.ReadFile(filepath.Join(f.Dir, recoveryBundleFile))
}

// RestoreKeys writes each recovered key file atomically. Existing keys of
// the same name are overwritten - recovery is the authoritative source
// after a keystore loss.
func (f *FileKeystore) RestoreKeys(entries []KeyEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := os.MkdirAll(f.Dir, 0o700); err != nil {
		return err
	}
	for _, e := range entries {
		if len(e.Key) != 32 {
			return fmt.Errorf("keystore: recovered key %q has %d bytes, want 32", e.Name, len(e.Key))
		}
		// A forged bundle could carry "../../etc/x" as a name. The bundle
		// stores the ON-DISK base name (slashes already folded to "_"), so
		// the guard here is a path-safety check, not checkName's slash form:
		// reject any separator, parent ref or absolute path so a name cannot
		// escape the keystore dir (L1, defense-in-depth).
		if !validBundleName(e.Name) {
			return fmt.Errorf("keystore: recovery bundle carries an unsafe key name %q", e.Name)
		}
		p := filepath.Join(f.Dir, e.Name+".key")
		tf, err := os.CreateTemp(f.Dir, filepath.Base(p)+".tmp*")
		if err != nil {
			return err
		}
		tmp := tf.Name()
		if err := tf.Chmod(0o600); err != nil {
			_ = tf.Close()
			_ = os.Remove(tmp)
			return err
		}
		if _, err := tf.Write(e.Key); err != nil {
			_ = tf.Close()
			_ = os.Remove(tmp)
			return err
		}
		if err := tf.Close(); err != nil {
			_ = os.Remove(tmp)
			return err
		}
		if err := os.Rename(tmp, p); err != nil {
			_ = os.Remove(tmp)
			return err
		}
	}
	return nil
}
