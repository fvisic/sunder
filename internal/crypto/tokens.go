package crypto

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
)

// Search-token key names. Rotation (M4) appends /v2 etc.; ActiveVersions in
// the keys table decides which are computed on lookup (dual-key window).
const (
	KeyHMACEmail = "hmac-email"
	KeyHMACPhone = "hmac-phone"
	KeyHMACName  = "hmac-name"
	KeyPIIKEK    = "pii-kek"
)

// Tokenizer computes keyed-HMAC search tokens. Separate keys per attribute
// mean a leak of one key never enables dictionary attacks on the others.
type Tokenizer struct {
	ks Keystore
}

func NewTokenizer(ks Keystore) *Tokenizer { return &Tokenizer{ks: ks} }

func (t *Tokenizer) token(ctx context.Context, keyName, version, normalized string) (string, error) {
	key, err := t.ks.Key(ctx, keyName+"/"+version)
	if err != nil {
		return "", err
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte(normalized))
	return hex.EncodeToString(m.Sum(nil)), nil
}

// EmailToken/PhoneToken/NameToken take ALREADY-NORMALIZED input and a key
// version ("v1", "v2", ...). Callers normalize first so validation errors
// surface before any key material is touched.
func (t *Tokenizer) EmailToken(ctx context.Context, v, normalized string) (string, error) {
	return t.token(ctx, KeyHMACEmail, v, normalized)
}
func (t *Tokenizer) PhoneToken(ctx context.Context, v, normalized string) (string, error) {
	return t.token(ctx, KeyHMACPhone, v, normalized)
}
func (t *Tokenizer) NameToken(ctx context.Context, v, normalized string) (string, error) {
	return t.token(ctx, KeyHMACName, v, normalized)
}

// NewCID returns a fresh pseudonym: "CID-" + 26 base32 chars of 16 random
// bytes. Random, never derived from PII — nothing to reverse (PLAN section 3).
func NewCID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "CID-" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw), nil
}

// NewClientSecret returns a bearer secret with enough entropy for API keys.
func NewClientSecret() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw), nil
}

// HashSecret is the stored form of a client secret (never the secret itself).
func HashSecret(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// KeyVersions lists which versions of a search-token key are active, current
// first. v1-only until rotation ships in M4.
func KeyVersions() []string { return []string{"v1"} }
