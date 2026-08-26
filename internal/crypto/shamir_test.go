package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

// fixedReader fills every requested buffer with a constant byte. It is the
// deterministic stand-in for the CSPRNG that lets a split pin an exact vector.
type fixedReader byte

func (f fixedReader) read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(f)
	}
	return len(p), nil
}

// combinations yields every k-subset of the indices [0, n) as index slices.
func combinations(n, k int) [][]int {
	var out [][]int
	idx := make([]int, k)
	var rec func(start, depth int)
	rec = func(start, depth int) {
		if depth == k {
			pick := make([]int, k)
			copy(pick, idx)
			out = append(out, pick)
			return
		}
		for i := start; i < n; i++ {
			idx[depth] = i
			rec(i+1, depth+1)
		}
	}
	rec(0, 0)
	return out
}

func subset(shares [][]byte, pick []int) [][]byte {
	out := make([][]byte, len(pick))
	for i, j := range pick {
		out[i] = shares[j]
	}
	return out
}

// Test 1: GF(256) field axioms. Verify the tables were built correctly and
// that mul/inv obey the field laws on which the whole scheme rests.
func TestShamirFieldAxioms(t *testing.T) {
	// Tables round-trip: log and antilog are inverses over the non-zero group.
	if gfExp[0] != 1 {
		t.Fatalf("gfExp[0] = %#x, want 0x01", gfExp[0])
	}
	if gfExp[255] != gfExp[0] {
		t.Fatalf("gfExp period broken: gfExp[255]=%#x gfExp[0]=%#x", gfExp[255], gfExp[0])
	}
	for a := 1; a <= 255; a++ {
		if got := gfExp[gfLog[a]]; got != byte(a) {
			t.Fatalf("antilog(log(%#x)) = %#x, want %#x", a, got, a)
		}
	}

	// mul by 0 is 0; mul by 1 is identity.
	for a := 0; a <= 255; a++ {
		if gfMul(byte(a), 0) != 0 || gfMul(0, byte(a)) != 0 {
			t.Fatalf("mul by zero not zero at a=%#x", a)
		}
		if gfMul(byte(a), 1) != byte(a) || gfMul(1, byte(a)) != byte(a) {
			t.Fatalf("mul by one not identity at a=%#x", a)
		}
	}

	// Every non-zero element has a unique inverse with a * inv(a) == 1.
	seenInv := make(map[byte]bool)
	for a := 1; a <= 255; a++ {
		inv := gfInv(byte(a))
		if gfMul(byte(a), inv) != 1 {
			t.Fatalf("%#x * inv(%#x)=%#x != 1", a, a, inv)
		}
		if seenInv[inv] {
			t.Fatalf("inverse %#x is not unique (collided at a=%#x)", inv, a)
		}
		seenInv[inv] = true
	}

	// Commutativity and associativity on a fixed sample of field elements.
	sample := []byte{0x01, 0x02, 0x03, 0x53, 0x57, 0x83, 0xCA, 0xFF}
	for _, a := range sample {
		for _, b := range sample {
			if gfMul(a, b) != gfMul(b, a) {
				t.Fatalf("mul not commutative at %#x,%#x", a, b)
			}
			for _, c := range sample {
				if gfMul(gfMul(a, b), c) != gfMul(a, gfMul(b, c)) {
					t.Fatalf("mul not associative at %#x,%#x,%#x", a, b, c)
				}
			}
		}
	}

	// Spot-check against a textbook AES product: 0x57 * 0x83 = 0xC1.
	if got := gfMul(0x57, 0x83); got != 0xC1 {
		t.Fatalf("0x57 * 0x83 = %#x, want 0xC1", got)
	}
}

// Test 2: full round trip. Every 3-of-5 subset reconstructs the exact secret;
// a 2-of-5 subset does not (reported through the checksum, not garbage).
func TestShamirRoundTripAllSubsets(t *testing.T) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("rand: %v", err)
	}
	shares, err := SplitWithChecksum(secret, 5, 3)
	if err != nil {
		t.Fatalf("SplitWithChecksum: %v", err)
	}

	// All C(5,3)=10 three-share subsets must recover the exact secret.
	threes := combinations(5, 3)
	if len(threes) != 10 {
		t.Fatalf("expected 10 three-subsets, got %d", len(threes))
	}
	for _, pick := range threes {
		got, err := CombineWithChecksum(subset(shares, pick))
		if err != nil {
			t.Fatalf("combine subset %v: %v", pick, err)
		}
		if !bytes.Equal(got, secret) {
			t.Fatalf("subset %v reconstructed wrong secret", pick)
		}
	}

	// Every two-share subset is below threshold and must be rejected.
	twos := combinations(5, 2)
	for _, pick := range twos {
		_, err := CombineWithChecksum(subset(shares, pick))
		if !errors.Is(err, ErrInsufficientShares) {
			t.Fatalf("subset %v: want ErrInsufficientShares, got %v", pick, err)
		}
	}
}

// Test 3: known-answer vector with FIXED coefficients, computed by hand.
//
// Secret byte a_0 = 0x53, threshold k=2, single coefficient a_1 = 0x57, so
// the sharing polynomial is f(x) = 0x53 + 0x57*x over GF(2^8) mod 0x11B.
//
//	f(1) = 0x53 ^ (0x57 * 0x01) = 0x53 ^ 0x57 = 0x04
//	f(2) = 0x53 ^ (0x57 * 0x02) = 0x53 ^ 0xAE = 0xFD   (0x57<<1 = 0xAE, no reduction)
//	f(3) = 0x53 ^ (0x57 * 0x03) = 0x53 ^ 0xF9 = 0xAA   (0x57*0x03 = 0xAE ^ 0x57 = 0xF9)
//
// Combine at x=0 from shares (1,0x04) and (2,0xFD). Lagrange weights, using
// inv(0x03) = 0xF6 (since 0x03 * 0xF6 = 0x01):
//
//	L_1(0) = x_2 * inv(x_2 ^ x_1) = 0x02 * inv(0x03) = 0x02 * 0xF6 = 0xF7
//	L_2(0) = x_1 * inv(x_1 ^ x_2) = 0x01 * inv(0x03) = 0xF6
//	secret = 0x04*0xF7 ^ 0xFD*0xF6 = 0xF1 ^ 0xA2 = 0x53
func TestShamirKnownAnswer(t *testing.T) {
	shares, err := splitWithCoeffs([]byte{0x53}, 3, 2, fixedReader(0x57).read)
	if err != nil {
		t.Fatalf("splitWithCoeffs: %v", err)
	}
	want := [][2]byte{{1, 0x04}, {2, 0xFD}, {3, 0xAA}}
	for i, w := range want {
		if shares[i][0] != w[0] || shares[i][1] != w[1] {
			t.Fatalf("share %d = (x=%#x,y=%#x), want (x=%#x,y=%#x)",
				i, shares[i][0], shares[i][1], w[0], w[1])
		}
	}

	got, err := CombineShares([][]byte{shares[0], shares[1]})
	if err != nil {
		t.Fatalf("CombineShares: %v", err)
	}
	if len(got) != 1 || got[0] != 0x53 {
		t.Fatalf("combine = %#x, want 0x53", got)
	}

	// The by-hand intermediate results, asserted directly against the field.
	if gfInv(0x03) != 0xF6 {
		t.Fatalf("inv(0x03) = %#x, want 0xF6", gfInv(0x03))
	}
	if gfMul(0x02, 0xF6) != 0xF7 {
		t.Fatalf("0x02 * 0xF6 = %#x, want 0xF7", gfMul(0x02, 0xF6))
	}
	if gfMul(0x04, 0xF7) != 0xF1 {
		t.Fatalf("0x04 * 0xF7 = %#x, want 0xF1", gfMul(0x04, 0xF7))
	}
	if gfMul(0xFD, 0xF6) != 0xA2 {
		t.Fatalf("0xFD * 0xF6 = %#x, want 0xA2", gfMul(0xFD, 0xF6))
	}
}

// Test 4: boundary and validation errors on both split and combine.
func TestShamirValidation(t *testing.T) {
	secret := []byte{0x01, 0x02, 0x03}

	if _, err := SplitSecret(secret, 5, 1); err == nil {
		t.Fatal("k<2 should error")
	}
	if _, err := SplitSecret(secret, 3, 5); err == nil {
		t.Fatal("k>n should error")
	}
	if _, err := SplitSecret(secret, 256, 2); err == nil {
		t.Fatal("n>255 should error")
	}
	if _, err := SplitSecret([]byte{}, 5, 3); err == nil {
		t.Fatal("empty secret should error")
	}

	good, err := SplitSecret(secret, 3, 2)
	if err != nil {
		t.Fatalf("SplitSecret: %v", err)
	}

	if _, err := CombineShares(nil); err == nil {
		t.Fatal("zero shares should error")
	}
	// Duplicate X coordinate.
	if _, err := CombineShares([][]byte{good[0], good[0]}); err == nil {
		t.Fatal("duplicate X should error")
	}
	// Mismatched lengths.
	short := append([]byte{}, good[1][:len(good[1])-1]...)
	if _, err := CombineShares([][]byte{good[0], short}); err == nil {
		t.Fatal("mismatched lengths should error")
	}
	// X coordinate of 0 (reserved for the secret).
	zeroX := append([]byte{}, good[2]...)
	zeroX[0] = 0
	if _, err := CombineShares([][]byte{good[0], zeroX}); err == nil {
		t.Fatal("X of 0 should error")
	}
}

// Test 5: CombineWithChecksum pass/fail behaviour.
func TestShamirChecksum(t *testing.T) {
	secret := []byte("recovery-key-material-F9")
	shares, err := SplitWithChecksum(secret, 5, 3)
	if err != nil {
		t.Fatalf("SplitWithChecksum: %v", err)
	}

	// Exactly k correct shares succeed.
	got, err := CombineWithChecksum(shares[:3])
	if err != nil {
		t.Fatalf("k shares: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("k shares reconstructed wrong secret")
	}

	// k-1 shares are below threshold.
	if _, err := CombineWithChecksum(shares[:2]); !errors.Is(err, ErrInsufficientShares) {
		t.Fatalf("k-1 shares: want ErrInsufficientShares, got %v", err)
	}

	// k shares with one corrupted Y byte fail the checksum.
	corrupt := make([][]byte, 3)
	for i := range corrupt {
		corrupt[i] = append([]byte{}, shares[i]...)
	}
	corrupt[0][len(corrupt[0])-1] ^= 0xFF
	if _, err := CombineWithChecksum(corrupt); !errors.Is(err, ErrInsufficientShares) {
		t.Fatalf("corrupted share: want ErrInsufficientShares, got %v", err)
	}
}

// Test 6: the split is randomized, the reconstruction is not. Two splits of
// the same secret differ (fresh random coefficients) yet both reconstruct.
func TestShamirRandomizedSplit(t *testing.T) {
	secret := []byte("same secret, different shares")
	a, err := SplitSecret(secret, 4, 2)
	if err != nil {
		t.Fatalf("split a: %v", err)
	}
	b, err := SplitSecret(secret, 4, 2)
	if err != nil {
		t.Fatalf("split b: %v", err)
	}

	// The Y payloads must differ - identical shares would mean the random
	// coefficients were not actually applied.
	identical := true
	for i := range a {
		if !bytes.Equal(a[i][1:], b[i][1:]) {
			identical = false
			break
		}
	}
	if identical {
		t.Fatal("two splits produced identical shares - coefficients not random")
	}

	// Both still reconstruct the original secret.
	for _, shares := range [][][]byte{a, b} {
		got, err := CombineShares(shares[:2])
		if err != nil {
			t.Fatalf("combine: %v", err)
		}
		if !bytes.Equal(got, secret) {
			t.Fatal("reconstruction failed")
		}
	}
}
