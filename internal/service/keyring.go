package service

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/fvisic/sunder/internal/audit"
	"github.com/fvisic/sunder/internal/crypto"
)

// KeyRing resolves which key versions are live for each kind from the keys
// table. New material is written with the newest ACTIVE version; lookups
// compute tokens under every ACTIVE and RETIRING version (the dual-key
// rotation window; docs/DESIGN.md).
type KeyRing struct {
	Pool *pgxpool.Pool

	// RetireGrace is how long a version must sit RETIRING before `Retire`
	// will purge it. Zero means DefaultRetireGracePeriod; NEGATIVE disables
	// the wait (a single-node deployment has no second replica to convince).
	// Wired from SUNDER_KEY_RETIRE_GRACE.
	RetireGrace time.Duration

	mu         sync.Mutex
	lastForced time.Time
	live       map[string][]string // kind -> ACTIVE+RETIRING versions, newest first
	active     map[string]string   // kind -> newest ACTIVE version
	fetchedAt  time.Time
	epoch      string
	epochAt    time.Time
}

const keyRingTTL = 30 * time.Second

// keyEpochInterval is how often a replica re-reads the cross-process epoch.
// Invalidate() only nils THIS process's map, but `keys rotate` / `keys
// retire` normally run from a separate CLI process against shared Postgres -
// so without this the running replicas served a stale ring for up to
// keyRingTTL, minting search tokens under a version that had already been
// retired AND purged (CONCURRENCY-CORE-4). One tiny aggregate per second per
// replica converges the fleet in about a second instead of thirty.
const keyEpochInterval = time.Second

// DefaultRetireGracePeriod is how long a version must have been RETIRING
// before it may be retired. It has to exceed the worst-case ring staleness,
// because Retire's purge is a ONE-SHOT DELETE: a replica still writing under
// the old version after the purge leaves rows nothing will ever delete or
// probe again. Narrowing the cache window shortens the race; this removes it.
const DefaultRetireGracePeriod = 2 * keyRingTTL

// retireGrace reports the active grace period for this ring.
func (k *KeyRing) retireGrace() time.Duration {
	switch {
	case k.RetireGrace < 0:
		return 0 // explicitly disabled (single node, or a test)
	case k.RetireGrace > 0:
		return k.RetireGrace
	}
	return DefaultRetireGracePeriod
}

// currentEpoch is a cheap fingerprint of the keys table. count catches an
// INSERT (rotate), max(updated_at) catches a status change (rotate's
// demotion, retire).
func (k *KeyRing) currentEpoch(ctx context.Context) (string, error) {
	var n int64
	var maxUpdated string
	if err := k.Pool.QueryRow(ctx,
		`SELECT count(*), COALESCE(max(updated_at)::text,'') FROM keys`).Scan(&n, &maxUpdated); err != nil {
		return "", err
	}
	return fmt.Sprintf("%d/%s", n, maxUpdated), nil
}

// staleLocked reports whether the cached ring must be reloaded (mutex held).
func (k *KeyRing) staleLocked(ctx context.Context) bool {
	if k.live == nil || time.Since(k.fetchedAt) > keyRingTTL {
		return true
	}
	if time.Since(k.epochAt) < keyEpochInterval {
		return false
	}
	epoch, err := k.currentEpoch(ctx)
	if err != nil {
		// The database is unreachable; serving the cached ring is strictly
		// better than failing every lookup, and the TTL still bounds it.
		return false
	}
	k.epochAt = time.Now()
	return epoch != k.epoch
}

// Kinds every deployment must have; EnsureAll bootstraps their material.
func keyKinds() []string {
	return []string{crypto.KeyHMACEmail, crypto.KeyHMACPhone, crypto.KeyHMACName,
		crypto.KeyHMACValue, crypto.KeyPIIKEK, crypto.SigningKeyName}
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
		if err := rows.Scan(&kd, &id, &status); err != nil { //coverage:defensive rows.Scan failure needs a DB fault injected at this exact statement
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
	if epoch, err := k.currentEpoch(ctx); err == nil {
		k.epoch, k.epochAt = epoch, time.Now()
	}
	return nil
}

// Invalidate forces the next call to re-read the keys table (used after
// rotation/retirement, and on unknown-kid verification misses).
// InvalidateThrottled forces at most one cache reload per cooldown window -
// the unknown-kid refresh path must not become a cache-busting vector.
func (k *KeyRing) InvalidateThrottled() {
	k.mu.Lock()
	defer k.mu.Unlock()
	if time.Since(k.lastForced) < 5*time.Second {
		return
	}
	k.lastForced = time.Now()
	k.live = nil
}

func (k *KeyRing) Invalidate() {
	k.mu.Lock()
	k.live = nil
	k.mu.Unlock()
}

// Versions returns the live (ACTIVE + RETIRING) versions for kind, newest first.
func (k *KeyRing) Versions(ctx context.Context, kind string) ([]string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.staleLocked(ctx) {
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
	if k.staleLocked(ctx) {
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
	return k.ensureAll(ctx, eng, false)
}

// EnsureAllAllowingMint is EnsureAll for the explicit operator acts that are
// SUPPOSED to create key material - `sunder bootstrap` on a fresh vault, and
// an operator who has decided to abandon the data under a lost key. `serve`
// must never take this path: minting on boot turns a lost keystore volume
// into a healthy-looking empty vault (OPS-CLI-CONFIG-1).
func (k *KeyRing) EnsureAllAllowingMint(ctx context.Context, eng crypto.Engine) error {
	return k.ensureAll(ctx, eng, true)
}

// keyProbe is a harmless operation that fails iff the material is absent.
// The strict keystore refuses to mint on Key(), and every engine op goes
// through Key(), so a MAC is a presence check that works for the local
// engine and across the signer socket alike - without ever returning key
// bytes to this process.
var keyProbe = []byte("sunder-keystore-presence-probe")

func (k *KeyRing) ensureAll(ctx context.Context, eng crypto.Engine, allowMint bool) error {
	for _, kind := range keyKinds() {
		vs, err := k.Versions(ctx, kind)
		if err != nil {
			return err
		}
		for _, v := range vs {
			name := kind + "/" + v
			if allowMint {
				if err := eng.Ensure(ctx, name); err != nil {
					return err
				}
				continue
			}
			// Material present: nothing to do, and nothing can be minted.
			if _, err := eng.MAC(ctx, name, keyProbe); err == nil {
				continue
			}
			// Material absent. If live data was written under this version,
			// minting fresh bytes does not recover anything - it manufactures
			// a vault that cannot read its own contents and reports healthy.
			// Refuse, and say which store is affected.
			refs, rerr := k.referencesFor(ctx, kind, v)
			if rerr != nil {
				return rerr
			}
			if len(refs) > 0 {
				return fmt.Errorf("keystore is missing material for %s, which %s still reference(s): "+
					"this is a lost or wrong keystore, not a fresh install - restore the correct keystore "+
					"(docs/RUNBOOK-BACKUP-DR.md). To mint new material anyway and permanently abandon that data, "+
					"run `sunder bootstrap` or set SUNDER_KEYSTORE_ALLOW_MINT=true",
					name, strings.Join(refs, ", "))
			}
			// Nothing references it: a genuine first boot. Mint, loudly.
			if err := eng.Ensure(ctx, name); err != nil {
				return err
			}
		}
	}
	return nil
}

// referencesFor names the stores holding data written under one key version.
func (k *KeyRing) referencesFor(ctx context.Context, kind, version string) ([]string, error) {
	if kind == crypto.KeyPIIKEK {
		return ReferencedKEKStores(ctx, k.Pool, version)
	}
	if kind == crypto.KeyHMACValue {
		var exists bool
		if err := k.Pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM value_tokens WHERE unique_key_version=$1)`,
			kind+"/"+version).Scan(&exists); err != nil {
			return nil, err
		}
		if exists {
			return []string{"value_tokens"}, nil
		}
		return nil, nil
	}
	if tokenKind, ok := strings.CutPrefix(kind, "hmac-"); ok {
		kinds := []string{tokenKind}
		switch tokenKind {
		case "name":
			kinds = append(kinds, "name_phonetic")
		case "phone":
			kinds = append(kinds, "phone_suffix")
		}
		var exists bool
		if err := k.Pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM person_tokens WHERE kind = ANY($1) AND key_version=$2)`,
			kinds, version).Scan(&exists); err != nil {
			return nil, err
		}
		if exists {
			return []string{"person_tokens"}, nil
		}
		return nil, nil
	}
	// oti-sign: an unexpired, unconsumed token is the only thing that stops
	// verifying, and those are short-lived by construction. Treat any
	// still-valid OTI as a reference so a restore mid-flight is not silent.
	var exists bool
	if err := k.Pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM oti WHERE status='VALID' AND expires_at > now())`).Scan(&exists); err != nil {
		return nil, err
	}
	if exists {
		return []string{"oti"}, nil
	}
	return nil, nil
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
	if _, err := tx.Exec(ctx,
		`UPDATE keys SET status='RETIRING', updated_at=now(), retiring_since=now()
		  WHERE kind=$1 AND status='ACTIVE'`, kind); err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO keys (key_id, kind, status) VALUES ($1,$2,'ACTIVE')`,
		kind+"/"+version, kind); err != nil {
		return "", err
	}
	if err := audit.AppendTx(ctx, tx, audit.Entry{
		ClientID: "operator", Action: "keys.rotate",
		Detail: map[string]any{"kind": kind, "version": version},
	}); err != nil {
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
	return k.RetireWithForce(ctx, kind, version, false)
}

// kekSealedStores are every table holding ciphertext sealed under a
// pii-kek version, with the column naming that version. Retiring a version
// any of them still references leaves that data decryptable ONLY by the
// retired (possibly leaked) key - the exact state `keys rekey -reencrypt-pii`
// exists to clear. The rekey sweep must cover every entry here; the
// information_schema guard test refuses a future table missing from both.
var kekSealedStores = []struct{ table, col string }{
	{"cids", "pii_key_id"},
	{"cid_blob_versions", "key_id"},
	{"value_tokens", "key_id"},
	{"person_record_keys", "key_id"},
	{"portal_outbox", "key_id"},
}

// ReferencedKEKStores names the stores still sealed under a pii-kek version.
func ReferencedKEKStores(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, version string) ([]string, error) {
	var out []string
	for _, st := range kekSealedStores {
		var exists bool
		if err := q.QueryRow(ctx,
			fmt.Sprintf(`SELECT EXISTS (SELECT 1 FROM %s WHERE %s = $1)`, st.table, st.col),
			version).Scan(&exists); err != nil {
			return nil, err
		}
		if exists {
			out = append(out, st.table)
		}
	}
	return out, nil
}

// RetireWithForce is Retire with an escape hatch. force skips the
// reference check - for the case where the operator has decided the
// remaining rows are expendable (and accepts that they become permanently
// unreadable), or is retiring a key whose material is already destroyed.
func (k *KeyRing) RetireWithForce(ctx context.Context, kind, version string, force bool) error {
	tx, err := k.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// The grace period. Retire's purge is a one-shot DELETE, and a replica
	// whose ring cache still lists this version as live keeps writing rows
	// under it - rows the purge cannot have covered and no later probe ever
	// computes again, so the person written in that window is permanently
	// unfindable and a re-registration mints a second person for one
	// identifier (CONCURRENCY-CORE-4). Waiting out the ring TTL makes that
	// impossible rather than unlikely.
	if !force {
		var since *time.Time
		if err := tx.QueryRow(ctx,
			`SELECT retiring_since FROM keys WHERE key_id=$1 AND kind=$2`,
			kind+"/"+version, kind).Scan(&since); err != nil && err != pgx.ErrNoRows {
			return err
		}
		// grace > 0 explicitly: the database clock stamps retiring_since and
		// may sit slightly ahead of this process's, so time.Since can be
		// negative and would trip a zero (disabled) grace period.
		if grace := k.retireGrace(); grace > 0 && since != nil && time.Since(*since) < grace {
			return fmt.Errorf("keyring: %s/%s became RETIRING %s ago; wait %s so every replica has observed the rotation before its token rows are purged (SUNDER_KEY_RETIRE_GRACE, or retire -force)",
				kind, version, time.Since(*since).Truncate(time.Second), grace)
		}
	}
	tag, err := tx.Exec(ctx,
		`UPDATE keys SET status='RETIRED', updated_at=now() WHERE key_id=$1 AND kind=$2 AND status='RETIRING'`,
		kind+"/"+version, kind)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("keyring: %s/%s is not RETIRING (only RETIRING versions can be retired; rotate first)", kind, version)
	}
	// Fail closed: a pii-kek version any store still references must not be
	// retired. Without this, a table the rekey sweep forgot (portal_outbox
	// was exactly that, for as long as it existed) is silently left
	// decryptable by the leaked key while the CLI reports success (GAP-1).
	if (kind == crypto.KeyPIIKEK || kind == crypto.KeyHMACValue) && !force {
		var refs []string
		var err error
		if kind == crypto.KeyPIIKEK {
			refs, err = ReferencedKEKStores(ctx, tx, version)
		} else {
			// hmac-value keys the value-token dedup index. Retiring a
			// version rows still key on silently breaks `unique:true` for
			// those values with no way to recompute the hash afterwards -
			// that needs the plaintext, which only the rekey sweep holds
			// (CRYPTO-3).
			var exists bool
			if err = tx.QueryRow(ctx,
				`SELECT EXISTS (SELECT 1 FROM value_tokens WHERE unique_key_version=$1)`,
				kind+"/"+version).Scan(&exists); err == nil && exists {
				refs = []string{"value_tokens.unique_hash"}
			}
		}
		if err != nil {
			return err
		}
		if len(refs) > 0 {
			return fmt.Errorf("keyring: %s/%s is still referenced by %s - run `sunder keys rekey -reencrypt-pii` first (or retire -force to accept that this data becomes unreadable)",
				kind, version, strings.Join(refs, ", "))
		}
	}
	// Search-token rows under a retired version can never match again;
	// purging them keeps the table honest (and removes material derived
	// from a possibly-leaked key).
	//
	// DERIVED kinds are purged with their base key: name_phonetic tokens are
	// minted from hmac-name and phone_suffix tokens from hmac-phone (they
	// carry the BASE key's version), so purging only the base kind left
	// material derived from a possibly-leaked HMAC key in the table forever,
	// still matching every fuzzy lookup (CRYPTO-2 / TOKENS-LOOKUP-3).
	if tokenKind, ok := strings.CutPrefix(kind, "hmac-"); ok {
		kinds := []string{tokenKind}
		switch tokenKind {
		case "name":
			kinds = append(kinds, "name_phonetic")
		case "phone":
			kinds = append(kinds, "phone_suffix")
		}
		if _, err := tx.Exec(ctx,
			`DELETE FROM person_tokens WHERE kind = ANY($1) AND key_version=$2`, kinds, version); err != nil {
			return err
		}
	}
	// Retiring a version stops it matching lookups and, for hmac kinds,
	// DELETEs the search-token rows minted under it. A destructive,
	// privilege-adjacent operation belongs in the chain (OPS-CLI-CONFIG-3).
	if err := audit.AppendTx(ctx, tx, audit.Entry{
		ClientID: "operator", Action: "keys.retire",
		Detail: map[string]any{"kind": kind, "version": version, "forced": force},
	}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	k.Invalidate()
	return nil
}
