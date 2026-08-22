package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
)

// PIIBox encrypts/decrypts a person's attribute map with AES-256-GCM under
// the pii-kek key. The key never leaves this process (decision D4): callers
// get decrypted fields, never key material.
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

// Encrypt seals attrs as nonce||ciphertext and reports the key id used,
// stored alongside so rotation can decrypt old rows.
func (p *PIIBox) Encrypt(ctx context.Context, attrs map[string]string) (blob []byte, keyID string, err error) {
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
	return g.Seal(nonce, nonce, plain, nil), keyID, nil
}

// Decrypt opens a blob produced by Encrypt.
func (p *PIIBox) Decrypt(ctx context.Context, blob []byte, keyID string) (map[string]string, error) {
	g, err := p.gcm(ctx, keyID)
	if err != nil {
		return nil, err
	}
	if len(blob) < g.NonceSize() {
		return nil, fmt.Errorf("pii blob too short")
	}
	plain, err := g.Open(nil, blob[:g.NonceSize()], blob[g.NonceSize():], nil)
	if err != nil {
		return nil, fmt.Errorf("pii decrypt: %w", err)
	}
	var attrs map[string]string
	if err := json.Unmarshal(plain, &attrs); err != nil {
		return nil, err
	}
	return attrs, nil
}
