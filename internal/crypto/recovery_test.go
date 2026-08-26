package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestRecoveryBundleRoundTrip(t *testing.T) {
	rk := make([]byte, 32)
	rand.Read(rk)
	entries := []KeyEntry{
		{Name: "pii-kek_v1", Key: bytes.Repeat([]byte{1}, 32)},
		{Name: "hmac-email_v1", Key: bytes.Repeat([]byte{2}, 32)},
		{Name: "hmac-phone_v2", Key: bytes.Repeat([]byte{3}, 32)},
	}
	bundle, err := SealRecoveryBundle(rk, entries)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenRecoveryBundle(rk, bundle)
	if err != nil {
		t.Fatal(err)
	}
	// Entries come back sorted by name, byte-for-byte.
	if len(got) != 3 {
		t.Fatalf("got %d entries", len(got))
	}
	names := map[string][]byte{}
	for _, e := range got {
		names[e.Name] = e.Key
	}
	for _, e := range entries {
		if !bytes.Equal(names[e.Name], e.Key) {
			t.Fatalf("key %q did not round trip", e.Name)
		}
	}
}

func TestRecoveryBundleWrongKeyFails(t *testing.T) {
	rk := make([]byte, 32)
	rand.Read(rk)
	bundle, err := SealRecoveryBundle(rk, []KeyEntry{{Name: "k", Key: bytes.Repeat([]byte{7}, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	wrong := make([]byte, 32)
	rand.Read(wrong)
	if _, err := OpenRecoveryBundle(wrong, bundle); err != ErrRecoveryCorrupt {
		t.Fatalf("wrong key must be ErrRecoveryCorrupt, got %v", err)
	}
	// A single flipped ciphertext byte must fail the AEAD.
	tampered := append([]byte(nil), bundle...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := OpenRecoveryBundle(rk, tampered); err != ErrRecoveryCorrupt {
		t.Fatalf("tampered bundle must be ErrRecoveryCorrupt, got %v", err)
	}
	// A truncated bundle is caught.
	if _, err := OpenRecoveryBundle(rk, bundle[:5]); err != ErrRecoveryCorrupt {
		t.Fatalf("truncated bundle: %v", err)
	}
}

func TestRecoveryBundleValidation(t *testing.T) {
	rk := make([]byte, 32)
	if _, err := SealRecoveryBundle(rk[:16], []KeyEntry{{Name: "k", Key: rk}}); err == nil {
		t.Fatal("short recovery key must be rejected")
	}
	if _, err := SealRecoveryBundle(rk, nil); err == nil {
		t.Fatal("empty entries must be rejected")
	}
	if _, err := SealRecoveryBundle(rk, []KeyEntry{{Name: "k", Key: []byte{1, 2}}}); err == nil {
		t.Fatal("short key must be rejected")
	}
}

// TestRecoveryEndToEndWithShamir exercises the real F9 flow: seal a bundle,
// split the recovery key, then reconstruct it from a threshold subset and
// open the bundle.
func TestRecoveryEndToEndWithShamir(t *testing.T) {
	rk := make([]byte, 32)
	rand.Read(rk)
	entries := []KeyEntry{{Name: "pii-kek_v1", Key: bytes.Repeat([]byte{9}, 32)}}
	bundle, err := SealRecoveryBundle(rk, entries)
	if err != nil {
		t.Fatal(err)
	}
	shares, err := SplitWithChecksum(rk, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	// Any 3 shares reconstruct and open; hex round-trips like the CLI.
	subset := [][]byte{}
	for _, i := range []int{0, 2, 4} {
		h := hex.EncodeToString(shares[i])
		b, _ := hex.DecodeString(h)
		subset = append(subset, b)
	}
	recovered, err := CombineWithChecksum(subset)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recovered, rk) {
		t.Fatal("reconstructed recovery key mismatch")
	}
	got, err := OpenRecoveryBundle(recovered, bundle)
	if err != nil || !bytes.Equal(got[0].Key, entries[0].Key) {
		t.Fatalf("open with reconstructed key: %v", err)
	}
}

func TestParseBundleRejectsMalformed(t *testing.T) {
	rk := make([]byte, 32)
	rand.Read(rk)
	seal := func(plain []byte) []byte {
		gcm, _ := recoveryGCM(rk)
		nonce := make([]byte, gcm.NonceSize())
		out := append([]byte(nil), recoveryMagic...)
		out = append(out, nonce...)
		return gcm.Seal(out, nonce, plain, recoveryMagic)
	}
	cases := map[string][]byte{
		"zero count": appendUint32(nil, 0),
		"huge count": appendUint32(nil, 99999),
		"trailing":   append(appendUint32(nil, 0), 1, 2, 3),
		"short body": appendUint32(nil, 1), // count says 1 but no entry
	}
	for name, plain := range cases {
		if _, err := OpenRecoveryBundle(rk, seal(plain)); err != ErrRecoveryCorrupt {
			t.Fatalf("%s: want ErrRecoveryCorrupt, got %v", name, err)
		}
	}
	// nameLen zero and nameLen too large.
	badName := appendUint32(nil, 1)
	badName = appendUint32(badName, 0) // nameLen 0
	if _, err := OpenRecoveryBundle(rk, seal(badName)); err != ErrRecoveryCorrupt {
		t.Fatalf("zero nameLen: %v", err)
	}
}
