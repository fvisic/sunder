package crypto

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
)

// smallOrderPoints are the Ed25519 public-key encodings of points with
// small order. Go's ed25519.Verify is cofactorless and does NOT reject
// them: a 64-byte signature of `01` followed by zeros verifies against the
// identity point for ANY message, so a key registered from this set
// accepts arbitrary forged signatures.
//
// The list is the canonical libsodium blacklist (identity, zero, the two
// order-8 points, p-1, p, p+1). Rejecting the all-zero key alone - as an
// earlier guard did - misses the identity point, which is the encoding that
// actually forges.
var smallOrderPoints = [][]byte{
	mustHex("0000000000000000000000000000000000000000000000000000000000000000"),
	mustHex("0100000000000000000000000000000000000000000000000000000000000000"),
	mustHex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
	mustHex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
	mustHex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
	mustHex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
	mustHex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != ed25519.PublicKeySize {
		panic("crypto: bad small-order point literal")
	}
	return b
}

// ValidEd25519PublicKey rejects key material that cannot be safely used for
// verification: a wrong length (ed25519.Verify PANICS on those) and any
// small-order point (universally forgeable under a cofactorless verify).
//
// Apply it BOTH where a key is registered and where it is used - the
// registration check is the real defence, the verify-time check is what
// holds if a key reached the database another way.
func ValidEd25519PublicKey(pub []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("ed25519 public key must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	for _, bad := range smallOrderPoints {
		if subtleEqual(pub, bad) {
			return fmt.Errorf("ed25519 public key is a small-order point: signatures under it are universally forgeable")
		}
	}
	return nil
}

// subtleEqual compares without early exit. The values are public, so this
// is hygiene rather than a requirement.
func subtleEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
