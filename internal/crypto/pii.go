package crypto

import (
	"context"
	"encoding/json"
)

// Supported PII encryption algorithms. Every blob's algorithm is stored
// alongside it (cids.pii_alg), so old and new algorithms coexist during a
// migration: reads use the stored value, writes use the configured one, and
// a `keys rekey` sweep converts the backlog (docs/RUNBOOK-ALG-MIGRATION.md).
const (
	AlgAES256GCM = "aes256gcm"         // AES-256-GCM, 12-byte nonce (default)
	AlgXChaCha20 = "xchacha20poly1305" // XChaCha20-Poly1305, 24-byte nonce
)

// KnownAlg reports whether alg names a supported AEAD.
func KnownAlg(alg string) bool {
	switch alg {
	case AlgAES256GCM, AlgXChaCha20:
		return true
	}
	return false
}

// PIIBox encrypts/decrypts an attribute map with an AEAD under the pii-kek
// key. The key never leaves this process: callers get decrypted fields,
// never key material.
//
// The AAD binds each blob to its CID row, key id and (for non-default
// algorithms) the algorithm itself, so an attacker with UPDATE access to the
// database cannot transplant person B's ciphertext into person A's row, and
// a key-id or algorithm downgrade is equally detectable. Legacy AES-256-GCM
// blobs keep the original two-part AAD so pre-existing data stays readable.
type PIIBox struct {
	eng Engine
	// Alg is the algorithm used for NEW blobs; empty means AlgAES256GCM.
	// Reads always follow the algorithm stored with the blob.
	Alg string
}

func NewPIIBox(eng Engine) *PIIBox { return &PIIBox{eng: eng} }

// Algorithm returns the algorithm this box writes with.
func (p *PIIBox) Algorithm() string {
	if p.Alg == "" {
		return AlgAES256GCM
	}
	return p.Alg
}

func aad(boundTo, keyID, alg string) []byte {
	if alg == AlgAES256GCM || alg == "" {
		return []byte(boundTo + "\x00" + keyID) // legacy layout, keeps v1 blobs readable
	}
	return []byte(boundTo + "\x00" + keyID + "\x00" + alg)
}

// Encrypt seals attrs as nonce||ciphertext bound to boundTo (the CID) under
// the given key version (the caller passes the keyring's newest pii-kek -
// hardcoding a version here would silently turn rotation into a no-op) and
// the box's configured algorithm. Key id and algorithm are stored alongside
// the blob so rotation and algorithm migration can decrypt old rows.
func (p *PIIBox) Encrypt(ctx context.Context, boundTo, keyID string, attrs map[string]string) (blob []byte, err error) {
	alg := p.Algorithm()
	plain, err := json.Marshal(attrs)
	if err != nil {
		return nil, err
	}
	return p.eng.Seal(ctx, KeyPIIKEK+"/"+keyID, alg, aad(boundTo, keyID, alg), plain)
}

// Decrypt opens a blob produced by Encrypt for the same boundTo/keyID/alg.
// alg is the algorithm STORED with the blob, not the configured one.
func (p *PIIBox) Decrypt(ctx context.Context, boundTo string, blob []byte, keyID, alg string) (map[string]string, error) {
	plain, err := p.eng.Open(ctx, KeyPIIKEK+"/"+keyID, alg, aad(boundTo, keyID, alg), blob)
	if err != nil {
		return nil, err
	}
	var attrs map[string]string
	if err := json.Unmarshal(plain, &attrs); err != nil {
		return nil, err
	}
	return attrs, nil
}
