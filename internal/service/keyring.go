package service

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/fvisic/sunder/internal/crypto"
)

// KeyRing resolves which key versions are live for each kind from the keys
// table. New material is written with the newest ACTIVE version; lookups
// compute tokens under every ACTIVE and RETIRING version (the dual-key
// rotation window; docs/DESIGN.md).
type KeyRing struct {
	Pool *pgxpool.Pool

	mu        sync.Mutex
	live      map[string][]string // kind -> ACTIVE+RETIRING versions, newest first
	active    map[string]string   // kind -> newest ACTIVE version
	fetchedAt time.Time
}

const keyRingTTL = 30 * time.Second

// Kinds every deployment must have; EnsureAll bootstraps their material.
func keyKinds() []string {
	return []string{crypto.KeyHMACEmail, crypto.KeyHMACPhone, crypto.KeyHMACName, crypto.KeyPIIKEK, crypto.SigningKeyName}
}

// versionNum parses "v<N>"; malformed versions sort last.
func versionNum(v string) int {
	var n int
	if _, err := fmt.Sscanf(v, "v%d", &n); err != nil {
		return -1
	}
	return n
}

// refreshLocked reloads the ring from the keys table (mutex held).
// Ordering is numeric on the version suffix - created_at would tie within
// one transaction and lexicographic order breaks at v10.
func (k *KeyRing) refreshLocked(ctx context.Context) error {
	live := map[string][]string{}
	active := map[string]string{}
	rows, err := k.Pool.Query(ctx,
		`SELECT kind, key_id, status FROM keys WHERE status IN ('ACTIVE','RETIRING')`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var kd, id, status string
		if err := rows.Scan(&kd, &id, &status); err != nil {
			return err
		}
		v := strings.TrimPrefix(id, kd+"/")
		live[kd] = append(live[kd], v)
		if status == "ACTIVE" && versionNum(v) > versionNum(active[kd]) {
			active[kd] = v
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for kd := range live {
		sort.Slice(live[kd], func(i, j int) bool {
			return versionNum(live[kd][i]) > versionNum(live[kd][j])
		})
	}
	k.live, k.active, k.fetchedAt = live, active, time.Now()
	return nil
}

// Invalidate forces the next call to re-read the keys table (used after
// rotation/retirement, and on unknown-kid verification misses).
func (k *KeyRing) Invalidate() {
	k.mu.Lock()
	k.live = nil
	k.mu.Unlock()
}

// Versions returns the live (ACTIVE + RETIRING) versions for kind, newest first.
func (k *KeyRing) Versions(ctx context.Context, kind string) ([]string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.live == nil || time.Since(k.fetchedAt) > keyRingTTL {
		if err := k.refreshLocked(ctx); err != nil {
			return nil, err
		}
	}
	vs := k.live[kind]
	if len(vs) == 0 {
		return nil, fmt.Errorf("keyring: no live versions for kind %q", kind)
	}
	return vs, nil
}

// Newest returns the ACTIVE version new material must be written with.
func (k *KeyRing) Newest(ctx context.Context, kind string) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.live == nil || time.Since(k.fetchedAt) > keyRingTTL {
		if err := k.refreshLocked(ctx); err != nil {
			return "", err
		}
	}
	v := k.active[kind]
	if v == "" {
		return "", fmt.Errorf("keyring: no ACTIVE version for kind %q", kind)
	}
	return v, nil
}

// EnsureAll creates keystore material for every live version of every kind.
// This is the only production path that mints keys (strict keystore).
func (k *KeyRing) EnsureAll(ctx context.Context, eng crypto.Engine) error {
	for _, kind := range keyKinds() {
		vs, err := k.Versions(ctx, kind)
		if err != nil {
			return err
		}
		for _, v := range vs {
			if err := eng.Ensure(ctx, kind+"/"+v); err != nil {
				return err
			}
		}
	}
	return nil
}

// Rotate mints the next version for kind: keystore material first, then the
// metadata row (ACTIVE), demoting previous ACTIVE versions to RETIRING.
// Old versions keep matching on lookup until data is re-keyed.
func (k *KeyRing) Rotate(ctx context.Context, eng crypto.Engine, kind string) (string, error) {
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
	if err := eng.Ensure(ctx, kind+"/"+version); err != nil {
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
	k.Invalidate()
	return version, nil
}

// Retire moves a RETIRING version to RETIRED - the cure for a leaked key:
// retired versions stop matching on lookup and stop verifying OTIs.
// The newest ACTIVE version cannot be retired (rotate first). For HMAC
// kinds, retire only after affected rows re-keyed (they re-key on touch);
// tokens still stored under a retired version stop matching.
func (k *KeyRing) Retire(ctx context.Context, kind, version string) error {
	tx, err := k.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx,
		`UPDATE keys SET status='RETIRED' WHERE key_id=$1 AND kind=$2 AND status='RETIRING'`,
		kind+"/"+version, kind)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("keyring: %s/%s is not RETIRING (only RETIRING versions can be retired; rotate first)", kind, version)
	}
	// Search-token rows under a retired version can never match again;
	// purging them keeps the table honest (and removes material derived
	// from a possibly-leaked key).
	if tokenKind, ok := strings.CutPrefix(kind, "hmac-"); ok {
		if _, err := tx.Exec(ctx,
			`DELETE FROM person_tokens WHERE kind=$1 AND key_version=$2`, tokenKind, version); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	k.Invalidate()
	return nil
}
