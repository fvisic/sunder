package storage

// Directory-backed driver: one file per key, no fan-out subdirectories
// (the vault holds thousands of objects, not millions, and a flat tree keeps
// Delete and backup trivially inspectable).
//
// Durability: writes go to a temp file in the same directory, are fsynced,
// then renamed over the target. Rename within a directory is atomic, so a
// crash can leave a stray temp file but never a half-written object that a
// later Get would decrypt into garbage. The temp file is removed on every
// error path.
//
// Permissions are deliberately tight - 0700 on the directory, 0600 on the
// files. The blobs are ciphertext, but the vault's threat model includes
// other local accounts on a shared host, and a world-readable vault turns an
// unrelated local read primitive into bulk exfiltration.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
)

// keyPattern is what a driver will accept as a key. Keys are server-generated
// (UUID-ish) and never user-controlled, so this should never fire - which is
// exactly why it is here. Path traversal through a blob key would be a
// filesystem write primitive, so the check is a whitelist and it fails
// closed: no separators, no dots-only names, bounded length.
var keyPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// ErrBadKey is returned for a key that fails sanitization.
var ErrBadKey = errors.New("storage: invalid key")

type localDriver struct {
	dir string
}

func newLocal(dir string) (Driver, error) {
	if dir == "" {
		return nil, fmt.Errorf("storage: local driver requires a directory")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("storage: resolve %q: %w", dir, err)
	}
	return &localDriver{dir: abs}, nil
}

// checkKey validates a key and returns its absolute path. "." and ".." pass
// the character class, so they are rejected explicitly.
func (d *localDriver) checkKey(key string) (string, error) {
	if !keyPattern.MatchString(key) || key == "." || key == ".." {
		return "", fmt.Errorf("%w: %q", ErrBadKey, key)
	}
	return filepath.Join(d.dir, key), nil
}

// ensureDir creates the vault directory on first use. Doing it lazily keeps
// Open side-effect free, so a process that never writes a blob does not
// leave an empty directory behind.
func (d *localDriver) ensureDir() error {
	if err := os.MkdirAll(d.dir, 0o700); err != nil {
		return fmt.Errorf("storage: create %q: %w", d.dir, err)
	}
	return nil
}

func (d *localDriver) Put(ctx context.Context, key string, r io.Reader, size int64) error {
	path, err := d.checkKey(key)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := d.ensureDir(); err != nil {
		return err
	}

	// Same directory as the target, so the rename cannot cross a filesystem.
	tmp, err := os.CreateTemp(d.dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("storage: create temp in %q: %w", d.dir, err)
	}
	tmpName := tmp.Name()
	// Cleanup is unconditional until the rename succeeds; the flag is
	// flipped only on the success path below.
	committed := false
	defer func() {
		if !committed {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("storage: chmod temp: %w", err)
	}
	n, err := io.Copy(tmp, r)
	if err != nil {
		return fmt.Errorf("storage: write %q: %w", key, err)
	}
	// A short read means the caller lied about the length or the source was
	// truncated mid-stream. Either way the object is not what the vault
	// thinks it is, so refuse to publish it.
	if size >= 0 && n != size {
		return fmt.Errorf("storage: write %q: got %d bytes, want %d", key, n, size)
	}
	// fsync before rename: rename is atomic with respect to the directory
	// entry, not to the data blocks behind it.
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("storage: sync %q: %w", key, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("storage: close temp for %q: %w", key, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("storage: commit %q: %w", key, err)
	}
	committed = true

	// Sync the directory so the rename itself survives a power loss. Best
	// effort: some filesystems reject a directory fsync, and the object is
	// already durable at this point.
	if dh, err := os.Open(d.dir); err == nil {
		_ = dh.Sync()
		_ = dh.Close()
	}
	return nil
}

func (d *localDriver) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	path, err := d.checkKey(key)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		// os.Open already wraps os.ErrNotExist, so errors.Is works for the
		// caller either way.
		return nil, fmt.Errorf("storage: open %q: %w", key, err)
	}
	return f, nil
}

// Delete removes a key. A missing key is an error (wrapping os.ErrNotExist),
// not a silent success: the vault's own bookkeeping decides whether a
// dangling reference is tolerable, and swallowing it here would hide index
// drift from the only layer that can repair it.
func (d *localDriver) Delete(ctx context.Context, key string) error {
	path, err := d.checkKey(key)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("storage: delete %q: %w", key, err)
	}
	return nil
}
