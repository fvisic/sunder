package service

import (
	"context"
	"fmt"
	"log/slog"
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

	// mu guards the cached ring. It is an RWMutex and NOT held across any
	// database call - see refresh() for why that distinction is the whole
	// fix rather than a tidy-up.
	mu         sync.RWMutex
	lastForced time.Time
	// refresherOnce/refreshing record that a background refresher owns the
	// epoch check for this ring. When it does, the read path never touches
	// the database at all.
	refresherOnce sync.Once
	refreshing    bool
	live          map[string][]string // kind -> ACTIVE+RETIRING versions, newest first
	active        map[string]string   // kind -> newest ACTIVE version
	fetchedAt     time.Time
	epoch         string
	epochAt       time.Time
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

// keyEpochIntervalForTest lets the tests in this package wait a known number
// of refresher ticks without hard-coding the constant twice.
const KeyEpochIntervalForTest = keyEpochInterval

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

// Ordering is numeric on the version suffix - created_at would tie within
// one transaction and lexicographic order breaks at v10.
// load reads the ring from the database. It takes no locks: the caller
// swaps the result in afterwards, so a slow query never blocks a reader.
func (k *KeyRing) load(ctx context.Context) (map[string][]string, map[string]string, string, error) {
	live := map[string][]string{}
	active := map[string]string{}
	rows, err := k.Pool.Query(ctx,
		`SELECT kind, key_id, status FROM keys WHERE status IN ('ACTIVE','RETIRING')`)
	if err != nil {
		return nil, nil, "", err
	}
	defer rows.Close()
	for rows.Next() {
		var kd, id, status string
		if err := rows.Scan(&kd, &id, &status); err != nil { //coverage:defensive rows.Scan failure needs a DB fault injected at this exact statement
			return nil, nil, "", err
		}
		v := strings.TrimPrefix(id, kd+"/")
		live[kd] = append(live[kd], v)
		if status == "ACTIVE" && versionNum(v) > versionNum(active[kd]) {
			active[kd] = v
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, "", err
	}
	for kd := range live {
		sort.Slice(live[kd], func(i, j int) bool {
			return versionNum(live[kd][i]) > versionNum(live[kd][j])
		})
	}
	epoch, _ := k.currentEpoch(ctx)
	return live, active, epoch, nil
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
	if k.refreshing {
		k.epoch = ""
		return
	}
	k.live = nil
}

// Invalidate forces the ring to be reloaded.
//
// With a background refresher running it does NOT blank the cached ring: the
// request path must never be sent to the database (see usableLocked), so it
// marks the epoch dirty instead and the refresher reloads within one tick.
// Without a refresher - the CLI and the tests, where nothing holds a
// transaction across the call - it blanks as before, so the next read
// reloads synchronously and `keys rotate` is immediately visible.
func (k *KeyRing) Invalidate() {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.refreshing {
		k.epoch = ""
		return
	}
	k.live = nil
}

// Versions returns the live (ACTIVE + RETIRING) versions for kind, newest first.
func (k *KeyRing) Versions(ctx context.Context, kind string) ([]string, error) {
	if vs, ok := k.cachedVersions(kind); ok && !k.epochCheckDue(ctx) {
		return vs, nil
	}
	if err := k.errIfRefresherOwned("Versions", kind); err != nil {
		return nil, err
	}
	if err := k.refresh(ctx); err != nil {
		return nil, err
	}
	vs, _ := k.cachedVersions(kind)
	if len(vs) == 0 {
		return nil, fmt.Errorf("keyring: no live versions for kind %q", kind)
	}
	return vs, nil
}

// Newest returns the ACTIVE version new material must be written with.
func (k *KeyRing) Newest(ctx context.Context, kind string) (string, error) {
	if v, ok := k.cachedNewest(kind); ok && !k.epochCheckDue(ctx) {
		return v, nil
	}
	if err := k.errIfRefresherOwned("Newest", kind); err != nil {
		return "", err
	}
	if err := k.refresh(ctx); err != nil {
		return "", err
	}
	v, _ := k.cachedNewest(kind)
	if v == "" {
		return "", fmt.Errorf("keyring: no ACTIVE version for kind %q", kind)
	}
	return v, nil
}

// cachedVersions and cachedNewest are the read path, and the ONLY thing they
// do is read memory under a shared lock. They report ok=false when the ring
// has never been loaded or has aged past its TTL, which is the one case the
// caller has to go to the database for.
func (k *KeyRing) cachedVersions(kind string) ([]string, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if !k.usableLocked() {
		return nil, false
	}
	vs := k.live[kind]
	return vs, len(vs) > 0
}

func (k *KeyRing) cachedNewest(kind string) (string, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if !k.usableLocked() {
		return "", false
	}
	v := k.active[kind]
	return v, v != ""
}

// usableLocked decides whether the cached ring may answer WITHOUT a database
// round trip. Pure arithmetic - no query, deliberately.
//
// When a background refresher owns this ring, a loaded ring is ALWAYS usable:
// not merely fresh-within-TTL, but usable even when it has aged or been
// invalidated. That is the second half of the deadlock fix and it is not an
// optimisation.
//
// Removing the query from under the mutex was not enough. `keys rotate`
// calls Invalidate(), and an invalidated ring sent the very next writer to
// the database - from inside registerTx, holding a transaction, asking the
// pool for a SECOND connection. With every connection held by a writer in
// the same position, none can ever be released. A rotation under load was
// all it took, and the regression test reproduces exactly that.
//
// So the request path never queries. The refresher, which holds no
// transaction and runs on its own connection, is the only thing that
// reloads. The cost is bounded staleness - at most one keyEpochInterval
// behind a rotation - which is what the ring already tolerated between epoch
// checks, and which `keys retire` protects against with a grace period twice
// the TTL.
func (k *KeyRing) usableLocked() bool {
	if k.live == nil {
		return false
	}
	if k.refreshing {
		return true
	}
	return time.Since(k.fetchedAt) <= keyRingTTL
}

// epochCheckDue answers, for a ring with NO background refresher, whether it
// is time to re-read the cross-process epoch - and does that read here,
// holding no lock.
//
// A ring the refresher owns always answers false: the refresher does this on
// its own connection, and the request path must never query (usableLocked
// explains why). A ring without one - the CLI, `sunder import`, the tests -
// keeps the inline check, because CONCURRENCY-CORE-4 depends on it: a
// replica whose process never calls Invalidate must still notice, within
// about a second, that another process rotated and retired a version, or it
// mints search tokens under a version the purge has already swept and the
// person becomes permanently unfindable.
//
// That inline query is safe in exactly the callers that have it: none of
// them holds a database transaction across the call. `serve` does, which is
// why `serve` starts a refresher.
func (k *KeyRing) epochCheckDue(ctx context.Context) bool {
	k.mu.RLock()
	owned, since, known := k.refreshing, time.Since(k.epochAt), k.epoch
	k.mu.RUnlock()
	if owned || since < keyEpochInterval {
		return false
	}
	epoch, err := k.currentEpoch(ctx)
	if err != nil {
		// Unreachable database: serving the cached ring beats failing every
		// call, and keyRingTTL still bounds how long that can last.
		return false
	}
	k.mu.Lock()
	k.epochAt = time.Now()
	k.mu.Unlock()
	return epoch != known
}

// errIfRefresherOwned makes the no-database property STRUCTURAL rather than
// a promise.
//
// A refresher-owned ring is loaded synchronously before StartRefresher
// returns, so a cache miss here means something is genuinely wrong - a kind
// that has no key at all, or a ring whose initial load failed. Falling
// through to a query would put the request path back where the deadlock was:
// asking the pool for a connection from inside someone else's transaction.
// Failing the one request is the correct outcome, and it is loud.
func (k *KeyRing) errIfRefresherOwned(op, kind string) error {
	k.mu.RLock()
	owned, loaded := k.refreshing, k.live != nil
	k.mu.RUnlock()
	if !owned {
		return nil
	}
	if !loaded {
		return fmt.Errorf("keyring: %s(%q) on a ring whose initial load failed - "+
			"refusing to query from the request path", op, kind)
	}
	return fmt.Errorf("keyring: %s(%q) has no live version in the cached ring", op, kind)
}

// refresh reloads the ring WITHOUT holding the lock across the query.
//
// This is the fix for a deadlock that stalled writes for thirty seconds at a
// time, and both halves of it matter:
//
//  1. The old code held an exclusive mutex across a database round trip. With
//     fuzzy and suffix search enabled, one Register calls Newest a dozen
//     times (e-mail, phone, name, each phonetic code, the suffix, the PII
//     KEK), so every writer queued behind whichever one happened to be doing
//     the once-a-second epoch check.
//
//  2. Worse, that query asked the pool for a connection while the CALLER
//     already held one inside an open transaction (registerTx -> mergeIntoBlob
//     -> Newest). Once concurrency reached the pool size, every connection was
//     held by a goroutine waiting for this mutex, and the goroutine holding
//     the mutex was waiting for a connection that could never be freed. It
//     resolved only when client timeouts began cancelling requests.
//
// Measured on a 26.9M-contact dataset: writes went from 516 rps at c=8 to
// 18 rps with 150 timeouts at c=32, while the database sat at zero active
// queries and zero ungranted locks for ninety seconds.
func (k *KeyRing) refresh(ctx context.Context) error {
	live, active, epoch, err := k.load(ctx)
	if err != nil {
		return err
	}
	k.mu.Lock()
	k.live, k.active, k.fetchedAt = live, active, time.Now()
	k.epoch, k.epochAt = epoch, time.Now()
	k.mu.Unlock()
	return nil
}

// StartRefresher takes the epoch check off the request path entirely.
//
// The server calls this once at startup. From then on a single goroutine
// re-reads the cross-process epoch every keyEpochInterval on its OWN pool
// connection - never inside anyone else's transaction - and reloads the ring
// when it changes. Convergence after a `keys rotate` or `keys retire` in a
// separate CLI process is unchanged (about a second); what changes is that no
// request ever waits on it.
//
// Calling it twice is a no-op. Not calling it at all is supported and is what
// the CLI and the tests do: the read path then falls back to loading on
// demand, which is safe there because nothing holds a transaction open across
// the call.
func (k *KeyRing) StartRefresher(ctx context.Context, log *slog.Logger) {
	k.refresherOnce.Do(func() {
		if log == nil {
			log = slog.Default()
		}
		if k.Pool == nil {
			// A ring with no pool cannot refresh. Marking it owned anyway
			// keeps the read path off the database, which is the property
			// callers rely on; there is simply nothing to load.
			k.mu.Lock()
			k.refreshing = true
			k.mu.Unlock()
			return
		}
		// Load once, synchronously, BEFORE marking the ring refresher-owned.
		// A refresher-owned ring never queries from the request path, so it
		// has to be warm by the time requests arrive. This call happens at
		// startup with no transaction open, which is exactly the situation
		// the request path is not in.
		if err := k.refresh(ctx); err != nil {
			log.Error("initial key ring load", "err", err.Error())
		}
		k.mu.Lock()
		k.refreshing = true
		k.mu.Unlock()
		go k.runRefresher(ctx, log)
	})
}

func (k *KeyRing) runRefresher(ctx context.Context, log *slog.Logger) {
	t := time.NewTicker(keyEpochInterval)
	defer t.Stop()
	var warned bool
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		epoch, err := k.currentEpoch(ctx)
		if err != nil {
			// The database is unreachable. Serving the cached ring beats
			// failing every write, and the staleness is bounded by the fact
			// that `keys retire` refuses while any store still references a
			// version and then waits out its grace period. Say so once,
			// loudly, rather than degrading in silence.
			k.mu.RLock()
			age := time.Since(k.fetchedAt)
			k.mu.RUnlock()
			if age > keyRingTTL && !warned {
				warned = true
				log.Error("key ring has not refreshed within its TTL and the database is "+
					"unreachable - rotations and retirements will not be seen by this replica",
					"age", age.String(), "err", err.Error())
			}
			continue
		}
		warned = false
		k.mu.RLock()
		unchanged := k.live != nil && epoch == k.epoch && time.Since(k.fetchedAt) <= keyRingTTL
		k.mu.RUnlock()
		if unchanged {
			k.mu.Lock()
			k.epochAt = time.Now()
			k.mu.Unlock()
			continue
		}
		if err := k.refresh(ctx); err != nil {
			log.Error("key ring refresh", "err", err.Error())
		}
	}
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

// RefresherRunningForTest reports whether a background refresher owns this
// ring. It exists so the API package can assert that `serve` starts one -
// the condition the pool-inversion guard's single exemption rests on.
func (k *KeyRing) RefresherRunningForTest() bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.refreshing
}
