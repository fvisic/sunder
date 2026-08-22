package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
)

// PIIBox encrypts/decrypts an attribute map with AES-256-GCM under the
// pii-kek key. The key never leaves this process (decision D4): callers get
// decrypted fields, never key material.
//
// The AAD binds each blob to its CID row and key id, so an attacker with
// UPDATE access to the database cannot transplant person B's ciphertext into
// person A's row (it fails authentication), and a key-id downgrade is
// equally detectable.
type PIIBox struct {
	ks Keystore
}

func NewPIIBox(ks Keystore) *PIIBox { return &PIIBox{ks: ks} }

func (p *PIIBox) gcm(ctx context.Context, keyID string) (cipher.AEAD, error) {
	key, err := p.ks.Key(ctx, KeyPIIKEK+"/"+keyID)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func aad(boundTo, keyID string) []byte { return []byte(boundTo + "\x00" + keyID) }

// Encrypt seals attrs as nonce||ciphertext bound to boundTo (the CID) and
// reports the key id used, stored alongside so rotation can decrypt old rows.
func (p *PIIBox) Encrypt(ctx context.Context, boundTo string, attrs map[string]string) (blob []byte, keyID string, err error) {
	keyID = "v1"
	g, err := p.gcm(ctx, keyID)
	if err != nil {
		return nil, "", err
	}
	plain, err := json.Marshal(attrs)
	if err != nil {
		return nil, "", err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, "", err
	}
	return g.Seal(nonce, nonce, plain, aad(boundTo, keyID)), keyID, nil
}

// Decrypt opens a blob produced by Encrypt for the same boundTo/keyID.
func (p *PIIBox) Decrypt(ctx context.Context, boundTo string, blob []byte, keyID string) (map[string]string, error) {
	g, err := p.gcm(ctx, keyID)
	if err != nil {
		return nil, err
	}
	if len(blob) < g.NonceSize() {
		return nil, fmt.Errorf("pii blob too short")
	}
	plain, err := g.Open(nil, blob[:g.NonceSize()], blob[g.NonceSize():], aad(boundTo, keyID))
	if err != nil {
		return nil, fmt.Errorf("pii decrypt: %w", err)
	}
	var attrs map[string]string
	if err := json.Unmarshal(plain, &attrs); err != nil {
		return nil, err
	}
	return attrs, nil
}
