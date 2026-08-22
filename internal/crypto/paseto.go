package crypto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
)

// Minimal PASETO v4.public implementation (sign/verify, empty footer and
// implicit assertion) — stdlib-only per the "stdlib first" policy, validated
// against the official PASETO test vectors in paseto_test.go. PASETO is used
// instead of JWT to eliminate the algorithm-confusion class of bugs: the
// version pins the algorithm (Ed25519), there is no negotiable "alg" header.

const pasetoHeader = "v4.public."

var b64 = base64.RawURLEncoding

// pae is PASETO's Pre-Authentication Encoding: an unambiguous serialization
// of the signed pieces (count, then length-prefixed items, little-endian).
func pae(pieces ...[]byte) []byte {
	var out bytes.Buffer
	le64 := func(n uint64) {
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], n&0x7FFFFFFFFFFFFFFF)
		out.Write(b[:])
	}
	le64(uint64(len(pieces)))
	for _, p := range pieces {
		le64(uint64(len(p)))
		out.Write(p)
	}
	return out.Bytes()
}

// PasetoSign signs payload (raw message bytes, JSON by convention) with an
// Ed25519 private key, producing a v4.public token.
func PasetoSign(sk ed25519.PrivateKey, payload []byte) string {
	m2 := pae([]byte(pasetoHeader), payload, nil, nil) // footer="", implicit=""
	sig := ed25519.Sign(sk, m2)
	return pasetoHeader + b64.EncodeToString(append(append([]byte{}, payload...), sig...))
}

// PasetoPayload returns the embedded payload WITHOUT verifying the
// signature. Only for reading the key id (kid) to select the verification
// key; every field must be treated as untrusted until PasetoVerify passes.
func PasetoPayload(token string) ([]byte, error) {
	body, ok := strings.CutPrefix(token, pasetoHeader)
	if !ok || strings.Contains(body, ".") {
		return nil, fmt.Errorf("paseto: not a footerless v4.public token")
	}
	raw, err := b64.DecodeString(body)
	if err != nil || len(raw) < ed25519.SignatureSize {
		return nil, fmt.Errorf("paseto: malformed token")
	}
	return raw[:len(raw)-ed25519.SignatureSize], nil
}

// PasetoVerify checks the signature and returns the embedded payload.
func PasetoVerify(pk ed25519.PublicKey, token string) ([]byte, error) {
	body, ok := strings.CutPrefix(token, pasetoHeader)
	if !ok || strings.Contains(body, ".") { // reject footers: we never issue them
		return nil, fmt.Errorf("paseto: not a footerless v4.public token")
	}
	raw, err := b64.DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("paseto: bad encoding")
	}
	if len(raw) < ed25519.SignatureSize {
		return nil, fmt.Errorf("paseto: token too short")
	}
	payload := raw[:len(raw)-ed25519.SignatureSize]
	sig := raw[len(raw)-ed25519.SignatureSize:]
	if !ed25519.Verify(pk, pae([]byte(pasetoHeader), payload, nil, nil), sig) {
		return nil, fmt.Errorf("paseto: signature invalid")
	}
	return payload, nil
}

// SigningKeyName is the keystore name for the OTI Ed25519 seed.
const SigningKeyName = "oti-sign"

// Ed25519FromSeed expands 32 keystore bytes into a signing keypair.
func Ed25519FromSeed(seed []byte) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, nil, fmt.Errorf("paseto: seed must be %d bytes", ed25519.SeedSize)
	}
	sk := ed25519.NewKeyFromSeed(seed)
	return sk, sk.Public().(ed25519.PublicKey), nil
}
