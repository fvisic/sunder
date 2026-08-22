package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// Engine is the ONLY cryptographic surface the rest of the codebase may
// use. Raw key bytes appear in no signature: an Engine implementation may
// hold keys in-process (LocalEngine) or in a separate signer process
// (RemoteEngine), and callers cannot tell the difference. This boundary is
// what makes the P2.1 signer split possible - compromise of the main
// process yields operation access, never key material.
type Engine interface {
	// MAC computes HMAC-SHA256 under the named key.
	MAC(ctx context.Context, key string, data []byte) ([]byte, error)
	// Seal encrypts plaintext under the named key with the given AEAD
	// algorithm (AlgAES256GCM / AlgXChaCha20), returning nonce||ciphertext.
	Seal(ctx context.Context, key, alg string, aad, plaintext []byte) ([]byte, error)
	// Open decrypts a Seal blob.
	Open(ctx context.Context, key, alg string, aad, blob []byte) ([]byte, error)
	// Sign returns a PASETO v4.public token over payload, signed by the
	// Ed25519 key derived from the named 32-byte seed.
	Sign(ctx context.Context, key string, payload []byte) (string, error)
	// VerifyToken checks a PASETO v4.public token against the named key and
	// returns its payload.
	VerifyToken(ctx context.Context, key, token string) ([]byte, error)
	// Ensure creates the named key if absent (bootstrap/rotation only).
	Ensure(ctx context.Context, key string) error
}

// LocalEngine implements Engine directly over a Keystore in-process - the
// default mode, byte-compatible with the pre-split behaviour.
type LocalEngine struct {
	KS Keystore
}

func NewLocalEngine(ks Keystore) *LocalEngine { return &LocalEngine{KS: ks} }

func (e *LocalEngine) MAC(ctx context.Context, key string, data []byte) ([]byte, error) {
	k, err := e.KS.Key(ctx, key)
	if err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, k)
	m.Write(data)
	return m.Sum(nil), nil
}

func (e *LocalEngine) aead(ctx context.Context, key, alg string) (cipher.AEAD, error) {
	k, err := e.KS.Key(ctx, key)
	if err != nil {
		return nil, err
	}
	switch alg {
	case AlgAES256GCM, "":
		block, err := aes.NewCipher(k)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	case AlgXChaCha20:
		return chacha20poly1305.NewX(k)
	default:
		return nil, fmt.Errorf("engine: unknown algorithm %q", alg)
	}
}

func (e *LocalEngine) Seal(ctx context.Context, key, alg string, aad, plaintext []byte) ([]byte, error) {
	g, err := e.aead(ctx, key, alg)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := randRead(nonce); err != nil {
		return nil, err
	}
	return g.Seal(nonce, nonce, plaintext, aad), nil
}

func (e *LocalEngine) Open(ctx context.Context, key, alg string, aad, blob []byte) ([]byte, error) {
	g, err := e.aead(ctx, key, alg)
	if err != nil {
		return nil, err
	}
	if len(blob) < g.NonceSize() {
		return nil, fmt.Errorf("engine: blob too short")
	}
	plain, err := g.Open(nil, blob[:g.NonceSize()], blob[g.NonceSize():], aad)
	if err != nil {
		return nil, fmt.Errorf("engine open: %w", err)
	}
	return plain, nil
}

func (e *LocalEngine) signingKeys(ctx context.Context, key string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	seed, err := e.KS.Key(ctx, key)
	if err != nil {
		return nil, nil, err
	}
	return Ed25519FromSeed(seed)
}

func (e *LocalEngine) Sign(ctx context.Context, key string, payload []byte) (string, error) {
	sk, _, err := e.signingKeys(ctx, key)
	if err != nil {
		return "", err
	}
	return PasetoSign(sk, payload), nil
}

func (e *LocalEngine) VerifyToken(ctx context.Context, key, token string) ([]byte, error) {
	_, pk, err := e.signingKeys(ctx, key)
	if err != nil {
		return nil, err
	}
	return PasetoVerify(pk, token)
}

func (e *LocalEngine) Ensure(ctx context.Context, key string) error {
	return e.KS.Ensure(ctx, key)
}
