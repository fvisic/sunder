package service

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/fvisic/sunder/internal/crypto"
)

// KeyRing resolves which key versions are live for each kind from the keys
// table. New material is written with the newest ACTIVE version; lookups
// compute tokens under every ACTIVE and RETIRING version (the dual-key
// rotation window, PLAN section 9.3).
type KeyRing struct {
	Pool *pgxpool.Pool

	mu        sync.Mutex
	cache     map[string][]string // kind -> versions, newest first
	fetchedAt time.Time
}

const keyRingTTL = 30 * time.Second

// Kinds every deployment must have; EnsureAll bootstraps their material.
func keyKinds() []string {
	return []string{crypto.KeyHMACEmail, crypto.KeyHMACPhone, crypto.KeyHMACName, crypto.KeyPIIKEK, crypto.SigningKeyName}
}

// Versions returns the live versions for kind, newest first.
func (k *KeyRing) Versions(ctx context.Context, kind string) ([]string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.cache == nil || time.Since(k.fetchedAt) > keyRingTTL {
		fresh := map[string][]string{}
		rows, err := k.Pool.Query(ctx,
			`SELECT kind, key_id FROM keys WHERE status IN ('ACTIVE','RETIRING') ORDER BY created_at DESC, key_id DESC`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var kd, id string
			if err := rows.Scan(&kd, &id); err != nil {
				return nil, err
			}
			fresh[kd] = append(fresh[kd], strings.TrimPrefix(id, kd+"/"))
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
		k.cache, k.fetchedAt = fresh, time.Now()
	}
	vs := k.cache[kind]
	if len(vs) == 0 {
		return nil, fmt.Errorf("keyring: no live versions for kind %q", kind)
	}
	return vs, nil
}

// Newest returns the version new material must be written with.
func (k *KeyRing) Newest(ctx context.Context, kind string) (string, error) {
	vs, err := k.Versions(ctx, kind)
	if err != nil {
		return "", err
	}
	return vs[0], nil
}

// EnsureAll creates keystore material for every live version of every kind.
// This is the only production path that mints keys (strict keystore).
func (k *KeyRing) EnsureAll(ctx context.Context, ks crypto.Keystore) error {
	for _, kind := range keyKinds() {
		vs, err := k.Versions(ctx, kind)
		if err != nil {
			return err
		}
		for _, v := range vs {
			if err := ks.Ensure(ctx, kind+"/"+v); err != nil {
				return err
			}
		}
	}
	return nil
}

// Rotate mints the next version for kind: keystore material first, then the
// metadata row (ACTIVE), demoting previous ACTIVE versions to RETIRING.
// Old versions keep matching on lookup until data is re-keyed.
func (k *KeyRing) Rotate(ctx context.Context, ks crypto.Keystore, kind string) (string, error) {
	valid := false
	for _, kd := range keyKinds() {
		valid = valid || kd == kind
	}
	if !valid {
		return "", fmt.Errorf("keyring: unknown kind %q (known: %s)", kind, strings.Join(keyKinds(), ", "))
	}
	tx, err := k.Pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM keys WHERE kind=$1`, kind).Scan(&n); err != nil {
		return "", err
	}
	version := fmt.Sprintf("v%d", n+1)
	if err := ks.Ensure(ctx, kind+"/"+version); err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, `UPDATE keys SET status='RETIRING' WHERE kind=$1 AND status='ACTIVE'`, kind); err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO keys (key_id, kind, status) VALUES ($1,$2,'ACTIVE')`,
		kind+"/"+version, kind); err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	k.mu.Lock()
	k.cache = nil // force refresh
	k.mu.Unlock()
	return version, nil
}
