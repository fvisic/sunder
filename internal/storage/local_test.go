package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestLocal(t *testing.T) (Driver, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "vault")
	d, err := Open(Config{Kind: "local", Dir: dir})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return d, dir
}

func TestLocalRoundTrip(t *testing.T) {
	d, _ := newTestLocal(t)
	ctx := context.Background()
	payload := []byte("ciphertext-bytes-not-plaintext")

	if err := d.Put(ctx, "obj-1", bytes.NewReader(payload), int64(len(payload))); err != nil {
		t.Fatalf("Put: %v", err)
	}

	rc, err := d.Get(ctx, "obj-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if err := rc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("Get returned %q, want %q", got, payload)
	}

	if err := d.Delete(ctx, "obj-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := d.Get(ctx, "obj-1"); !IsNotExist(err) {
		t.Errorf("Get after Delete: got %v, want a not-exist error", err)
	}
}

// TestLocalPermissions checks the vault directory and its objects are not
// readable by other local accounts.
func TestLocalPermissions(t *testing.T) {
	d, dir := newTestLocal(t)
	if err := d.Put(context.Background(), "obj-1", strings.NewReader("x"), 1); err != nil {
		t.Fatalf("Put: %v", err)
	}

	di, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if perm := di.Mode().Perm(); perm != 0o700 {
		t.Errorf("directory mode = %o, want 700", perm)
	}
	fi, err := os.Stat(filepath.Join(dir, "obj-1"))
	if err != nil {
		t.Fatalf("stat object: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("object mode = %o, want 600", perm)
	}
}

func TestLocalGetMissing(t *testing.T) {
	d, _ := newTestLocal(t)
	_, err := d.Get(context.Background(), "nope")
	if err == nil {
		t.Fatal("Get of a missing key returned no error")
	}
	if !errors.Is(err, os.ErrNotExist) || !IsNotExist(err) {
		t.Errorf("Get of a missing key = %v, want os.ErrNotExist", err)
	}
}

// TestLocalDeleteMissing pins the deliberate choice: a missing key is an
// error, not a silent success, so the vault can see index drift.
func TestLocalDeleteMissing(t *testing.T) {
	d, _ := newTestLocal(t)
	err := d.Delete(context.Background(), "nope")
	if err == nil {
		t.Fatal("Delete of a missing key returned no error")
	}
	if !IsNotExist(err) {
		t.Errorf("Delete of a missing key = %v, want a wrapped os.ErrNotExist", err)
	}
}

// errReader fails partway through, standing in for a truncated upload.
type errReader struct {
	data []byte
	n    int
}

func (e *errReader) Read(p []byte) (int, error) {
	if e.n >= len(e.data) {
		return 0, fmt.Errorf("simulated source failure")
	}
	n := copy(p, e.data[e.n:])
	e.n += n
	return n, nil
}

// TestLocalCrashSafeTempCleanup asserts a failed Put leaves neither a
// partial object nor a stray temp file behind.
func TestLocalCrashSafeTempCleanup(t *testing.T) {
	d, dir := newTestLocal(t)
	ctx := context.Background()

	err := d.Put(ctx, "obj-1", &errReader{data: []byte("partial")}, 64)
	if err == nil {
		t.Fatal("Put with a failing reader returned no error")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		t.Errorf("leftover file after failed Put: %q", e.Name())
	}
	if _, err := d.Get(ctx, "obj-1"); !IsNotExist(err) {
		t.Errorf("a partial object was published: %v", err)
	}
}

// TestLocalShortWriteRejected covers the other truncation case: the reader
// ends cleanly but delivers fewer bytes than declared.
func TestLocalShortWriteRejected(t *testing.T) {
	d, dir := newTestLocal(t)
	ctx := context.Background()

	if err := d.Put(ctx, "obj-1", strings.NewReader("short"), 100); err == nil {
		t.Fatal("Put accepted a body shorter than the declared size")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		t.Errorf("leftover file after short Put: %q", e.Name())
	}
}

// TestLocalOverwriteIsAtomic checks a second Put replaces the object wholly.
func TestLocalOverwriteIsAtomic(t *testing.T) {
	d, _ := newTestLocal(t)
	ctx := context.Background()

	if err := d.Put(ctx, "obj-1", strings.NewReader("aaaaaaaaaa"), 10); err != nil {
		t.Fatalf("first Put: %v", err)
	}
	if err := d.Put(ctx, "obj-1", strings.NewReader("bb"), 2); err != nil {
		t.Fatalf("second Put: %v", err)
	}
	rc, err := d.Get(ctx, "obj-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer rc.Close()
	got, _ := io.ReadAll(rc)
	if string(got) != "bb" {
		t.Errorf("after overwrite got %q, want %q", got, "bb")
	}
}

// TestLocalKeySanitization is the traversal guard. Keys are server-generated
// today, so every one of these should be impossible - which is exactly the
// assumption this test exists to outlive.
func TestLocalKeySanitization(t *testing.T) {
	d, dir := newTestLocal(t)
	ctx := context.Background()

	bad := []string{
		"",
		".",
		"..",
		"../escape",
		"../../etc/passwd",
		"sub/dir",
		"/absolute",
		"trailing/",
		"has space",
		"weird\x00null",
		"unicode-é",
		"semi;colon",
		"tilde~",
		"back\\slash",
		strings.Repeat("a", 129),
	}
	for _, key := range bad {
		t.Run(fmt.Sprintf("%q", key), func(t *testing.T) {
			if err := d.Put(ctx, key, strings.NewReader("x"), 1); !errors.Is(err, ErrBadKey) {
				t.Errorf("Put(%q) = %v, want ErrBadKey", key, err)
			}
			if _, err := d.Get(ctx, key); !errors.Is(err, ErrBadKey) {
				t.Errorf("Get(%q) = %v, want ErrBadKey", key, err)
			}
			if err := d.Delete(ctx, key); !errors.Is(err, ErrBadKey) {
				t.Errorf("Delete(%q) = %v, want ErrBadKey", key, err)
			}
		})
	}

	// A rejected key must not have created the vault directory or anything
	// inside it.
	if entries, err := os.ReadDir(dir); err == nil && len(entries) > 0 {
		t.Errorf("rejected keys left %d entries behind", len(entries))
	}

	good := []string{
		"a",
		"0f8b1c2d-3e4f-5061-7283-94a5b6c7d8e9",
		"blob_2026.08.26-v1",
		strings.Repeat("a", 128),
	}
	for _, key := range good {
		if err := d.Put(ctx, key, strings.NewReader("x"), 1); err != nil {
			t.Errorf("Put(%q) = %v, want success", key, err)
		}
	}
}

// TestLocalPutUnknownSize allows a negative size to mean "length unknown",
// which the local driver can honour because it streams to disk.
func TestLocalPutUnknownSize(t *testing.T) {
	d, _ := newTestLocal(t)
	ctx := context.Background()
	if err := d.Put(ctx, "obj-1", strings.NewReader("stream"), -1); err != nil {
		t.Fatalf("Put with unknown size: %v", err)
	}
	rc, err := d.Get(ctx, "obj-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer rc.Close()
	got, _ := io.ReadAll(rc)
	if string(got) != "stream" {
		t.Errorf("got %q, want %q", got, "stream")
	}
}

func TestOpenValidation(t *testing.T) {
	if _, err := Open(Config{Kind: "local"}); err == nil {
		t.Error("local driver without a directory was accepted")
	}
	if _, err := Open(Config{Kind: "mystery", Dir: t.TempDir()}); err == nil {
		t.Error("unknown driver kind was accepted")
	}
	// The empty kind defaults to local.
	if _, err := Open(Config{Dir: t.TempDir()}); err != nil {
		t.Errorf("empty kind should default to local: %v", err)
	}
	// Kind matching is case- and space-insensitive.
	if _, err := Open(Config{Kind: " Local ", Dir: t.TempDir()}); err != nil {
		t.Errorf("kind %q should be accepted: %v", " Local ", err)
	}
}
