package crypto

// The forgery the earlier all-zero guard missed: a signature of 0x01
// followed by zeros verifies against the IDENTITY POINT for any message
// under Go's cofactorless verify. ValidEd25519PublicKey must reject every
// small-order encoding, at registration and at use.

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

func TestIdentityPointForgesAndIsRejected(t *testing.T) {
	identity, err := hex.DecodeString("0100000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	// The forged signature: R = identity, S = 0.
	forged := make([]byte, ed25519.SignatureSize)
	forged[0] = 1

	// Go accepts it for arbitrary messages - this is the class of bug.
	accepted := 0
	for _, msg := range [][]byte{[]byte("anything"), []byte(`{"iss":"gov"}`), {}} {
		if ed25519.Verify(identity, msg, forged) {
			accepted++
		}
	}
	if accepted == 0 {
		t.Skip("this Go version rejects small-order points; the guard is still required")
	}
	// Our guard must refuse the key outright.
	if err := ValidEd25519PublicKey(identity); err == nil {
		t.Fatal("the identity point must be rejected: it forges for any message")
	}
}

func TestValidEd25519PublicKey(t *testing.T) {
	// Every small-order encoding is refused.
	for i, bad := range smallOrderPoints {
		if err := ValidEd25519PublicKey(bad); err == nil {
			t.Fatalf("small-order point %d accepted", i)
		}
	}
	// Wrong lengths are refused before they can panic ed25519.Verify.
	for _, n := range []int{0, 1, 31, 33, 64} {
		if err := ValidEd25519PublicKey(make([]byte, n)); err == nil {
			t.Fatalf("a %d-byte key must be rejected", n)
		}
	}
	// A real key is accepted.
	_, pub, err := Ed25519FromSeed(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidEd25519PublicKey(pub); err != nil {
		t.Fatalf("a genuine key must be accepted: %v", err)
	}
}
