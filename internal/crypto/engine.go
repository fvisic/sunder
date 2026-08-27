package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

// ErrVerifyFailed marks a GENUINE verification failure (bad signature,
// malformed token) as opposed to an environment failure (keystore or signer
// unreachable). Callers translate the former into 4xx and the latter into
// 5xx - an infrastructure outage must never read as "invalid token".
var ErrVerifyFailed = errors.New("token verification failed")

// ErrDecrypt marks a GENUINE AEAD failure: the ciphertext, its associated
// data or the key do not match. Permanent - retrying cannot help.
//
// ErrEngineUnavailable marks the opposite: the cryptography could not be
// ATTEMPTED because the signer process or the keystore was unreachable.
// Transient - retrying is exactly right.
//
// The distinction exists because Go's untyped error return made "this
// payload is corrupt" and "the signer is restarting" indistinguishable at
// the call site, and the portal outbox worker classified BOTH as permanent:
// one signer restart or Vault failover marked a queued login link FAILED,
// destroying the only copy of the token (QUEUE-WORKER-5).
var (
	ErrDecrypt           = errors.New("crypto: decryption failed")
	ErrEngineUnavailable = errors.New("crypto: engine unavailable")
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
		// The keystore could not answer. Under the vault driver this is an
		// HTTP call, so a reseal, failover or cold-cache blip lands here -
		// transient, not "this payload is unopenable".
		return nil, fmt.Errorf("%w: %v", ErrEngineUnavailable, err)
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
	countSeal(key, alg)
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
		return nil, fmt.Errorf("%w: blob too short", ErrDecrypt)
	}
	plain, err := g.Open(nil, blob[:g.NonceSize()], blob[g.NonceSize():], aad)
	if err != nil {
		// The AEAD itself rejected it: wrong key version, tampered
		// ciphertext, or associated data that does not match. Permanent.
		return nil, fmt.Errorf("%w: %v", ErrDecrypt, err)
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
		return nil, err // environment: key unavailable
	}
	payload, err := PasetoVerify(pk, token)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrVerifyFailed, err)
	}
	return payload, nil
}

func (e *LocalEngine) Ensure(ctx context.Context, key string) error {
	return e.KS.Ensure(ctx, key)
}

// --- nonce budget accounting (CRYPTO-8) ------------------------------------
//
// AES-256-GCM with 96-bit RANDOM nonces has a birthday bound: NIST SP
// 800-38D puts the safe budget at 2^32 invocations per key. One long-lived
// pii-kek seals attribute blobs, version history, value tokens, file DEKs
// and portal payloads - plus a full re-seal of the corpus on every rotation -
// and nothing counted, so an operator had no way to tell how close a key
// version was, nor any usage-based reason to rotate.
//
// XChaCha20-Poly1305's 192-bit nonces make random nonces unconditionally
// safe, which is why SUNDER_PII_ALG=xchacha20poly1305 needs no accounting;
// only the AES-GCM path is counted.

// SealBudget is the per-key-version invocation count at which an AES-GCM key
// should be rotated. Two orders of magnitude below the 2^32 bound, so the
// warning arrives long before the risk does.
const SealBudget = 1 << 30

var (
	sealCountsMu sync.Mutex
	sealCounts   = map[string]uint64{}
	sealWarned   = map[string]bool{}
)

func countSeal(key, alg string) {
	if alg != AlgAES256GCM && alg != "" {
		return // 192-bit nonces: no budget to track
	}
	sealCountsMu.Lock()
	sealCounts[key]++
	n := sealCounts[key]
	warn := n >= SealBudget && !sealWarned[key]
	if warn {
		sealWarned[key] = true
	}
	sealCountsMu.Unlock()
	if warn {
		slog.Warn("AES-256-GCM seal budget reached for a key version - random 96-bit nonces have a birthday bound; rotate this key (`sunder keys rotate`) or migrate to SUNDER_PII_ALG=xchacha20poly1305 (docs/RUNBOOK-ALG-MIGRATION.md)",
			"key", key, "seals", n, "budget", SealBudget)
	}
}

// SealCounts reports this PROCESS's AES-GCM seal count per key version, for
// the sunder_kek_seals_total gauge. Per-process and reset on restart: it is
// a usage signal, not an authoritative lifetime total.
func SealCounts() map[string]uint64 {
	sealCountsMu.Lock()
	defer sealCountsMu.Unlock()
	out := make(map[string]uint64, len(sealCounts))
	for k, v := range sealCounts {
		out[k] = v
	}
	return out
}
