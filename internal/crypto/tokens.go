package crypto

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
)

// randRead is a seam for tests; the kernel CSPRNG failing is otherwise
// nearly impossible to exercise.
var randRead = rand.Read

// Search-token key names. Rotation (M4) appends /v2 etc.; ActiveVersions in
// the keys table decides which are computed on lookup (dual-key window).
const (
	KeyHMACEmail = "hmac-email"
	KeyHMACPhone = "hmac-phone"
	KeyHMACName  = "hmac-name"
	// KeyHMACValue keys the value-token dedup hash. It has its OWN kind
	// because value tokens seal card numbers, IBANs and national ids:
	// borrowing hmac-email meant that leaking the e-mail SEARCH key handed
	// an attacker an offline dictionary attack over every tokenized value,
	// contradicting the separate-key-per-attribute rationale a few lines up
	// (CRYPTO-3).
	KeyHMACValue = "hmac-value"
	KeyPIIKEK    = "pii-kek"
)

// Tokenizer computes keyed-HMAC search tokens through the Engine boundary -
// it never sees key material. Separate keys per attribute mean a leak of one
// key never enables dictionary attacks on the others.
type Tokenizer struct {
	eng Engine
}

func NewTokenizer(eng Engine) *Tokenizer { return &Tokenizer{eng: eng} }

func (t *Tokenizer) token(ctx context.Context, keyName, version, normalized string) (string, error) {
	sum, err := t.eng.MAC(ctx, keyName+"/"+version, []byte(normalized))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sum), nil
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

// NamePhoneticToken tokenizes one ph1 phonetic word code (F1). The "ph1"
// domain prefix keeps phonetic tokens unlinkable to exact name tokens even
// under the same key, and versions the reduction: a future ph2 gets its
// own domain and coexists during a rollover.
func (t *Tokenizer) NamePhoneticToken(ctx context.Context, v, code string) (string, error) {
	return t.token(ctx, KeyHMACName, v, "ph1\x00"+code)
}

// PhoneSuffixToken tokenizes the last-8-digits key of a phone (F2), domain
// separated from full-number tokens for the same reason.
func (t *Tokenizer) PhoneSuffixToken(ctx context.Context, v, suffix string) (string, error) {
	return t.token(ctx, KeyHMACPhone, v, "sfx1\x00"+suffix)
}

// NewCID returns a fresh pseudonym: "CID-" + 26 base32 chars of 16 random
// bytes. Random, never derived from PII - nothing to reverse (docs/DESIGN.md).
func NewCID() (string, error) {
	raw := make([]byte, 16)
	if _, err := randRead(raw); err != nil {
		return "", err
	}
	return "CID-" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw), nil
}

// NewClientSecret returns a bearer secret with enough entropy for API keys.
func NewClientSecret() (string, error) {
	raw := make([]byte, 32)
	if _, err := randRead(raw); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw), nil
}

// HashSecret is the stored form of a client secret (never the secret itself).
func HashSecret(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// Which key versions are live is decided by the keys table via the service
// KeyRing (DB-driven, dual-key rotation window) - not hardcoded here.
