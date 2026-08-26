package crypto

import (
	"bytes"
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
