package crypto

// Algorithm-agility tests: both AEADs roundtrip, blobs carry their algorithm
// (reads follow the stored value), and neither transplant, tamper, nor
// cross-algorithm confusion decrypts.

import (
	"context"
	"testing"
)

func TestKnownAlg(t *testing.T) {
	if !KnownAlg(AlgAES256GCM) || !KnownAlg(AlgXChaCha20) {
		t.Fatal("both supported algorithms must be known")
	}
	for _, bad := range []string{"", "aes", "rot13", "AES256GCM"} {
		if KnownAlg(bad) {
			t.Errorf("KnownAlg(%q) must be false", bad)
		}
	}
}

func TestXChaChaRoundtripTamperTransplant(t *testing.T) {
	ctx := context.Background()
	box := NewPIIBox(fileKS(t))
	box.Alg = AlgXChaCha20
	attrs := map[string]string{"email": "x@example.com", "tier": "gold"}

	blob, err := box.Encrypt(ctx, "CID-A", "v1", attrs)
	if err != nil {
		t.Fatal(err)
	}
	got, err := box.Decrypt(ctx, "CID-A", blob, "v1", AlgXChaCha20)
	if err != nil || got["email"] != attrs["email"] {
		t.Fatalf("roundtrip: %v %v", got, err)
	}
	if _, err := box.Decrypt(ctx, "CID-B", blob, "v1", AlgXChaCha20); err == nil {
		t.Fatal("transplanted xchacha blob must fail authentication")
	}
	blob[len(blob)-1] ^= 0xFF
	if _, err := box.Decrypt(ctx, "CID-A", blob, "v1", AlgXChaCha20); err == nil {
		t.Fatal("tampered xchacha blob must fail authentication")
	}
}

func TestCrossAlgorithmConfusionFails(t *testing.T) {
	ctx := context.Background()
	ks := fileKS(t)

	aes := NewPIIBox(ks) // default aes256gcm
	cha := NewPIIBox(ks)
	cha.Alg = AlgXChaCha20
	attrs := map[string]string{"a": "b"}

	aesBlob, err := aes.Encrypt(ctx, "CID-A", "v1", attrs)
	if err != nil {
		t.Fatal(err)
	}
	chaBlob, err := cha.Encrypt(ctx, "CID-A", "v1", attrs)
	if err != nil {
		t.Fatal(err)
	}
	// Decrypting under the WRONG algorithm claim (what a malicious pii_alg
	// downgrade in the DB would attempt) must fail, both directions.
	if _, err := aes.Decrypt(ctx, "CID-A", aesBlob, "v1", AlgXChaCha20); err == nil {
		t.Fatal("aes blob must not open as xchacha")
	}
	if _, err := aes.Decrypt(ctx, "CID-A", chaBlob, "v1", AlgAES256GCM); err == nil {
		t.Fatal("xchacha blob must not open as aes")
	}
	// Unknown algorithm: clean error, not a panic.
	if _, err := aes.Decrypt(ctx, "CID-A", aesBlob, "v1", "rot13"); err == nil {
		t.Fatal("unknown algorithm must error")
	}
	if _, err := (&PIIBox{eng: ks, Alg: "rot13"}).Encrypt(ctx, "CID-A", "v1", attrs); err == nil {
		t.Fatal("encrypt with unknown algorithm must error")
	}
}

func TestAlgorithmDefault(t *testing.T) {
	box := NewPIIBox(fileKS(t))
	if box.Algorithm() != AlgAES256GCM {
		t.Fatalf("empty Alg must default to aes256gcm, got %q", box.Algorithm())
	}
	box.Alg = AlgXChaCha20
	if box.Algorithm() != AlgXChaCha20 {
		t.Fatal("configured Alg must win")
	}
}

// A blob written before the alg column existed (legacy two-part AAD) must
// still decrypt when read back as aes256gcm - the migration default.
func TestLegacyBlobStaysReadable(t *testing.T) {
	ctx := context.Background()
	box := NewPIIBox(fileKS(t))
	blob, err := box.Encrypt(ctx, "CID-A", "v1", map[string]string{"k": "v"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := box.Decrypt(ctx, "CID-A", blob, "v1", AlgAES256GCM)
	if err != nil || got["k"] != "v" {
		t.Fatalf("legacy-compatible decrypt: %v %v", got, err)
	}
}
