package crypto

// Recovery bundle (Phase 3 / F9, file keystore only). A recovery bundle is
// every key file in the keystore, sealed as one blob under a random
// RECOVERY WRAPPING KEY. The recovery key never touches disk: it is split
// into Shamir shares handed to separate custodians (see shamir.go) and
// reassembled only to recover or rotate. The Vault driver delegates
// recovery to Vault's own unseal, so this is for the file driver alone.
//
// Bundle wire format (all lengths big-endian uint32):
//
//	magic "SUNDR9\x00" | version(1) | nonce(12) | ciphertext
//
// where the plaintext is:
//
//	count | [ nameLen | name | 32-byte-key ] * count
//
// sealed with AES-256-GCM under the recovery key, the magic+version as AAD.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
)

var recoveryMagic = []byte("SUNDR9\x00\x01") // magic + version 1, also the AAD

// ErrRecoveryCorrupt is returned when a bundle fails to open - a wrong
// recovery key (too few or wrong Shamir shares) or a tampered blob.
var ErrRecoveryCorrupt = errors.New("recovery bundle failed to open (wrong shares or corrupt)")

// KeyEntry is one keystore key in a recovery bundle.
type KeyEntry struct {
	Name string
	Key  []byte // exactly 32 bytes
}

// SealRecoveryBundle encrypts the keys under recoveryKey (32 bytes). Entries
// are sorted by name so the bundle is deterministic given the same inputs.
func SealRecoveryBundle(recoveryKey []byte, entries []KeyEntry) ([]byte, error) {
	if len(recoveryKey) != 32 {
		return nil, fmt.Errorf("recovery key must be 32 bytes, got %d", len(recoveryKey))
	}
	if len(entries) == 0 {
		return nil, errors.New("recovery bundle: no keys to seal")
	}
	sorted := append([]KeyEntry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	var plain []byte
	plain = appendUint32(plain, uint32(len(sorted)))
	for _, e := range sorted {
		if len(e.Key) != 32 {
			return nil, fmt.Errorf("recovery bundle: key %q has %d bytes, want 32", e.Name, len(e.Key))
		}
		plain = appendUint32(plain, uint32(len(e.Name)))
		plain = append(plain, e.Name...)
		plain = append(plain, e.Key...)
	}

	gcm, err := recoveryGCM(recoveryKey)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append([]byte(nil), recoveryMagic...)
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, plain, recoveryMagic), nil
}

// OpenRecoveryBundle decrypts a bundle under recoveryKey. A wrong key
// (insufficient/incorrect shares) or tampering returns ErrRecoveryCorrupt.
func OpenRecoveryBundle(recoveryKey, bundle []byte) ([]KeyEntry, error) {
	if len(recoveryKey) != 32 {
		return nil, fmt.Errorf("recovery key must be 32 bytes, got %d", len(recoveryKey))
	}
	if len(bundle) < len(recoveryMagic)+12 {
		return nil, ErrRecoveryCorrupt
	}
	if string(bundle[:len(recoveryMagic)]) != string(recoveryMagic) {
		return nil, ErrRecoveryCorrupt
	}
	gcm, err := recoveryGCM(recoveryKey)
	if err != nil {
		return nil, err
	}
	rest := bundle[len(recoveryMagic):]
	nonce, ct := rest[:gcm.NonceSize()], rest[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ct, recoveryMagic)
	if err != nil {
		return nil, ErrRecoveryCorrupt
	}
	return parseBundle(plain)
}

func parseBundle(plain []byte) ([]KeyEntry, error) {
	r := &reader{b: plain}
	count, ok := r.u32()
	if !ok || count == 0 || count > 4096 {
		return nil, ErrRecoveryCorrupt
	}
	out := make([]KeyEntry, 0, count)
	for i := uint32(0); i < count; i++ {
		nameLen, ok := r.u32()
		if !ok || nameLen == 0 || nameLen > 256 {
			return nil, ErrRecoveryCorrupt
		}
		name, ok := r.bytes(int(nameLen))
		if !ok {
			return nil, ErrRecoveryCorrupt
		}
		key, ok := r.bytes(32)
		if !ok {
			return nil, ErrRecoveryCorrupt
		}
		out = append(out, KeyEntry{Name: string(name), Key: append([]byte(nil), key...)})
	}
	if r.i != len(r.b) {
		return nil, ErrRecoveryCorrupt // trailing bytes: not a bundle we wrote
	}
	return out, nil
}

func recoveryGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func appendUint32(b []byte, v uint32) []byte {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], v)
	return append(b, n[:]...)
}

type reader struct {
	b []byte
	i int
}

func (r *reader) u32() (uint32, bool) {
	if r.i+4 > len(r.b) {
		return 0, false
	}
	v := binary.BigEndian.Uint32(r.b[r.i : r.i+4])
	r.i += 4
	return v, true
}

func (r *reader) bytes(n int) ([]byte, bool) {
	if n < 0 || r.i+n > len(r.b) {
		return nil, false
	}
	b := r.b[r.i : r.i+n]
	r.i += n
	return b, true
}
