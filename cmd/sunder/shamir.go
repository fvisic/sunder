package main

// F9 Shamir recovery operations, extracted from the keys CLI so their error
// paths are unit-testable against a fake keystore (see shamir_ops_test.go).

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/fvisic/sunder/internal/crypto"
)

// recoveryKeystore is the slice of the file keystore the recovery operations
// need; a fake implements it in tests to exercise every failure branch.
type recoveryKeystore interface {
	AllKeys() ([]crypto.KeyEntry, error)
	WriteRecoveryBundle([]byte) error
	WriteRecoveryBundleForce([]byte) error
	ReadRecoveryBundle() ([]byte, error)
	RestoreKeys([]crypto.KeyEntry) error
}

// shamirInit seals the keystore into a recovery bundle and returns the n
// shares (k required). The caller prints them; they are never stored.
func shamirInit(ks recoveryKeystore, n, k int, w io.Writer) error {
	entries, err := ks.AllKeys()
	if err != nil {
		return err
	}
	recoveryKey := make([]byte, 32)
	if _, err := randRead(recoveryKey); err != nil {
		return err
	}
	bundle, err := crypto.SealRecoveryBundle(recoveryKey, entries)
	if err != nil {
		return err
	}
	shares, err := crypto.SplitWithChecksum(recoveryKey, n, k)
	if err != nil {
		return err
	}
	// L2: refuse a fresh init over an existing bundle - it would silently
	// strand every current custodian's shares. Write BEFORE printing so a
	// write failure never leaves shares in the operator's scrollback for a
	// bundle that was not persisted.
	if err := ks.WriteRecoveryBundle(bundle); err != nil {
		if errors.Is(err, crypto.ErrBundleExists) {
			return fmt.Errorf("a recovery bundle already exists; shamir-init would strand the current custodians - use `keys shamir-rotate` to re-seal under fresh shares")
		}
		return err
	}
	// The recovery key and the shares are never stored - this is the only
	// time the shares are visible. Hand each to a SEPARATE custodian (five
	// shares in one vault is 1-of-1 in a costume).
	fmt.Fprintf(w, "Recovery bundle written for %d keys. %d-of-%d shares (store each with a DIFFERENT custodian, OFFLINE):\n\n", len(entries), k, n)
	for i, sh := range shares {
		fmt.Fprintf(w, "  share %d/%d: %s\n", i+1, n, hex.EncodeToString(sh))
	}
	fmt.Fprintln(w, "\nThese shares are shown ONCE and cannot be recovered. The recovery key was never written to disk.")
	return nil
}

// shamirRecover reassembles the recovery key from shares, opens the bundle
// and restores every key file.
func shamirRecover(ks recoveryKeystore, shares [][]byte, w io.Writer) error {
	recoveryKey, err := crypto.CombineWithChecksum(shares)
	if err != nil {
		return fmt.Errorf("recovery failed (too few or wrong shares): %w", err)
	}
	bundle, err := ks.ReadRecoveryBundle()
	if err != nil {
		return fmt.Errorf("read recovery bundle: %w", err)
	}
	entries, err := crypto.OpenRecoveryBundle(recoveryKey, bundle)
	if err != nil {
		return err
	}
	if err := ks.RestoreKeys(entries); err != nil {
		return err
	}
	fmt.Fprintf(w, "Recovered and restored %d keys.\n", len(entries))
	return nil
}

// shamirRotate re-seals the CURRENT keystore under the SAME recovery key
// (reassembled from the custodians' shares) - the annual drill that also
// picks up keys added since init. Shares are unchanged.
func shamirRotate(ks recoveryKeystore, shares [][]byte, w io.Writer) error {
	recoveryKey, err := crypto.CombineWithChecksum(shares)
	if err != nil {
		return fmt.Errorf("share reassembly failed: %w", err)
	}
	entries, err := ks.AllKeys()
	if err != nil {
		return err
	}
	bundle, err := crypto.SealRecoveryBundle(recoveryKey, entries)
	if err != nil {
		return err
	}
	// Rotate deliberately supersedes the existing bundle under the SAME
	// shares - Force is correct here (unlike init).
	if err := ks.WriteRecoveryBundleForce(bundle); err != nil {
		return err
	}
	fmt.Fprintf(w, "Recovery bundle re-sealed over %d keys under the existing shares.\n", len(entries))
	return nil
}
