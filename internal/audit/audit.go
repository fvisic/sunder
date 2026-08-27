// Package audit writes the append-only, hash-chained audit log.
//
// Every record's hash covers the previous record's hash plus its own
// canonical content, so any edit, deletion or insertion breaks the chain at
// a provable position. There is deliberately no update or delete path -
// with one narrow exception enforced by trigger: sealing an unsealed row.
//
// Since P4.1 the log has two write modes (SUNDER_AUDIT_SEALING):
//
//   - async (default): audited operations INSERT rows with NULL
//     prev_hash/hash/chain_seq and take no lock; a single sealer chains
//     settled rows shortly after, thousands per lock acquisition. This is
//     what removes the instance-wide serialization measured in
//     benchmark/README.md (298 tps with the lock at c=32, 4,114 without).
//   - sync: the pre-P4.1 behaviour - the chain lock is taken inside the
//     business transaction and the row is born sealed. Zero sealing
//     window, serialized throughput.
//
// Both modes hash the same canonical bytes and read the chain head the
// same way, so a chain built partly in each mode verifies as one unbroken
// chain. The chain position is chain_seq, assigned at sealing time:
// BIGSERIAL seq does not guarantee commit order, so a row committing late
// simply enters the chain late instead of being stranded below the
// watermark. Verification and RFC 3161 anchoring live in this package too
// (M5); anchoring always anchors the sealed head, never past it.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// advisory lock key serializing chain writes. Held by every sync append and
// by each sealing transaction - never by an async request, which is the
// entire point of async mode.
const appendLockKey = 0x53554E44 // "SUND"

// Write modes. See the package comment; the default matches the config
// default in internal/config.
const (
	ModeAsync = "async"
	ModeSync  = "sync"
)

// mode is package-level rather than plumbed through every service struct:
// there are ~20 call sites and exactly one correct value per process. It is
// initialized from the environment so that a test suite run under the CI
// matrix (SUNDER_AUDIT_SEALING=async|sync) exercises the chosen mode in
// every package without further wiring; cmd/sunder re-sets it from the
// parsed config, which reads the same variable with the same default.
var syncMode atomic.Bool

func init() {
	syncMode.Store(os.Getenv("SUNDER_AUDIT_SEALING") == ModeSync)
}

// SetMode selects the write mode ("async" or "sync") for this process.
func SetMode(m string) {
	syncMode.Store(m == ModeSync)
}

// Mode reports the active write mode.
func Mode() string {
	if syncMode.Load() {
		return ModeSync
	}
	return ModeAsync
}

// Entry is one auditable action. Detail must never contain raw PII or raw
// search tokens - callers pass identifiers and outcomes only.
type Entry struct {
	ClientID string
	Action   string
	CID      string
	Detail   map[string]any
	// UserID identifies the OPERATOR inside the client system (the CRM
	// agent, the ERP user) - NEVER the data subject, who is always the
	// CID. An opaque ID, not a name, so the never-pruned log carries the
	// minimum about employees. It arrives as the "user_id" body field
	// (POST routes) or the X-Sunder-User-Id header (GET routes) and is
	// CLIENT-ASSERTED - Sunder cannot verify it. Stored as a real,
	// queryable column on audit rows and as a bucket key column, and PART
	// OF THE HASHED TUPLE for hash_v >= 2 (see canonical and hashV2): it
	// was the one audited field a database attacker could edit without
	// tripping verification. Rows sealed under v1 keep the v1 tuple
	// forever - a sealed chain cannot retroactively cover a new field - and
	// there the append-only trigger alone pins it.
	UserID string
}

// userCol renders UserID as its nullable column value.
func userCol(e Entry) any {
	if e.UserID == "" {
		return nil
	}
	return e.UserID
}

// hashV2 is the canonical-tuple version new rows seal under. v1 (pre-0033)
// excluded user_id - the one audited field a database attacker could edit
// without tripping verification. Rows carry their version (audit.hash_v) so
// every pre-existing chain keeps verifying under the tuple it was hashed
// over; flipping a row's version cannot hide an edit, because the stored
// hash matches only its own tuple and recomputing it breaks the prev_hash
// linkage the external anchor pins.
const hashV2 = 2

// canonical is an unambiguous encoding of the hashed tuple: JSON array, so a
// '|' (or anything else) inside a field can never shift content across field
// boundaries and produce a hash collision between different records.
// chain_seq is deliberately NOT part of the hash - integrity comes from
// prev_hash linkage walked in chain_seq order, and the trigger plus a UNIQUE
// index keep chain_seq itself honest.
func canonical(v int16, prevHash string, ts time.Time, e Entry, detailJSON []byte) string {
	fields := []string{
		prevHash, ts.UTC().Format(time.RFC3339Nano), e.ClientID, e.Action, e.CID, string(detailJSON),
	}
	if v >= hashV2 {
		fields = append(fields, e.UserID)
	}
	b, _ := json.Marshal(fields)
	return string(b)
}

// querier is the subset of pgx.Tx / *pgxpool.Pool both modes need.
type querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// sealedHead returns the newest sealed record ("" and 0 on an empty chain).
// Both modes and the sealer read the head through this one function: the
// old `ORDER BY seq DESC` head becomes wrong the moment unsealed rows can
// exist, because the newest row by seq may not be in the chain yet.
// The chain_seq IS NOT NULL predicate is not redundant with the
// audit_seal_consistent CHECK (migration 0036): a row that predates the
// migration, or one written while it was disabled, must degrade the VERDICT
// and never the machinery. ORDER BY chain_seq DESC is NULLS FIRST by
// default, so one such row sorted itself to the head and every consumer -
// sync AppendTx, the sealer, Head, anchoring - failed on "cannot scan NULL
// into *int64", permanently and unrepairably (AUDIT-CHAIN-1).
func sealedHead(ctx context.Context, q querier) (hash string, chainSeq int64, err error) {
	err = q.QueryRow(ctx,
		`SELECT hash, chain_seq FROM audit WHERE hash IS NOT NULL AND chain_seq IS NOT NULL
		  ORDER BY chain_seq DESC LIMIT 1`,
	).Scan(&hash, &chainSeq)
	if err == pgx.ErrNoRows {
		return "", 0, nil
	}
	return hash, chainSeq, err
}

// AppendTx writes one record inside the caller's transaction, so a business
// mutation and its audit record commit or roll back together - the log can
// never record what did not happen, nor miss what did. Fail-closed holds in
// both modes; what differs is when the row is chained.
func AppendTx(ctx context.Context, tx pgx.Tx, e Entry) error {
	detailJSON, err := json.Marshal(e.Detail)
	if err != nil {
		return err
	}
	var cidCol any
	if e.CID != "" {
		cidCol = e.CID
	}
	ts := time.Now().UTC().Truncate(time.Microsecond)

	if !syncMode.Load() {
		// Async: one INSERT, no lock, no head read. The sealer chains it.
		_, err = tx.Exec(ctx,
			`INSERT INTO audit (ts, client_id, action, cid, detail, user_id) VALUES ($1, $2, $3, $4, $5, $6)`,
			ts, e.ClientID, e.Action, cidCol, detailJSON, userCol(e))
		return err
	}

	// Sync: serialize on the chain lock and seal the row at birth.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, appendLockKey); err != nil {
		return err
	}
	prev, headSeq, err := sealedHead(ctx, tx)
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(canonical(hashV2, prev, ts, e, detailJSON)))
	hash := hex.EncodeToString(sum[:])
	var prevCol any
	if prev != "" {
		prevCol = prev
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO audit (ts, client_id, action, cid, detail, prev_hash, hash, chain_seq, user_id, hash_v)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		ts, e.ClientID, e.Action, cidCol, detailJSON, prevCol, hash, headSeq+1, userCol(e), hashV2)
	return err
}

// Append writes one record in its own transaction.
func Append(ctx context.Context, pool *pgxpool.Pool, e Entry) error {
	if !syncMode.Load() {
		// Async needs no explicit transaction: a single INSERT is atomic,
		// and skipping BEGIN/COMMIT saves two round trips on the hottest
		// audited path (lookup).
		detailJSON, err := json.Marshal(e.Detail)
		if err != nil {
			return err
		}
		var cidCol any
		if e.CID != "" {
			cidCol = e.CID
		}
		_, err = pool.Exec(ctx,
			`INSERT INTO audit (ts, client_id, action, cid, detail, user_id) VALUES ($1, $2, $3, $4, $5, $6)`,
			time.Now().UTC().Truncate(time.Microsecond), e.ClientID, e.Action, cidCol, detailJSON, userCol(e))
		return err
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := AppendTx(ctx, tx, e); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// SealOnce chains up to batch settled unsealed rows and returns how many it
// sealed. A row is settled when it is at least delay old: a transaction
// that inserted its row but has not committed is invisible to the sealer
// anyway (MVCC), and thanks to chain_seq a row that commits after later
// rows were sealed is not stranded - it simply enters the chain later. The
// delay only keeps chain order close to wall-clock order.
//
// The sealing transaction takes the same advisory lock sync appends use, so
// the two can never race; it uses try-lock so that N replicas each running
// a sealer degrade to "one seals, the rest skip the cycle" with no leader
// election and no queueing.
func SealOnce(ctx context.Context, pool *pgxpool.Pool, batch int, delay time.Duration) (int, error) {
	return sealBatch(ctx, pool, batch, delay, false)
}

// sealBatch is the one sealing implementation. blocking selects the lock
// discipline: the steady-state sealer tries and politely skips a held
// chain (a replica losing the race is normal), while Drain MUST hold the
// lock inside this same transaction - taking it in a separate transaction
// and re-trying here would open a window in which a competing sealer wins
// the lock, this call returns 0, and Drain concludes "done" with rows
// still unsealed. On the async -> sync switch those rows would then be
// stranded outside the chain forever.
func sealBatch(ctx context.Context, pool *pgxpool.Pool, batch int, delay time.Duration, blocking bool) (int, error) {
	if batch <= 0 {
		return 0, fmt.Errorf("seal batch must be positive")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if blocking {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, appendLockKey); err != nil {
			return 0, err
		}
	} else {
		var got bool
		if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, appendLockKey).Scan(&got); err != nil {
			return 0, err
		}
		if !got {
			return 0, nil // another sealer (or a sync append) holds the chain
		}
	}

	prev, chainSeq, err := sealedHead(ctx, tx)
	if err != nil {
		return 0, err
	}

	// The age filter compares the DATABASE clock to the DATABASE clock:
	// db_ts is stamped by the database at insert, so an application clock
	// running ahead can no longer stall sealing (rows forever "too young").
	// Pre-0033 rows have db_ts NULL and count as old - which they are.
	// delay <= 0 must still mean "no age filter": a drain that misses rows
	// strands them (see Drain).
	where := `hash IS NULL AND (db_ts IS NULL OR db_ts < now() - $1::interval)`
	args := []any{delay.String(), batch}
	if delay <= 0 {
		where, args = `hash IS NULL`, []any{batch}
	}
	rows, err := tx.Query(ctx,
		`SELECT seq, ts, COALESCE(client_id,''), action, COALESCE(cid,''), COALESCE(detail,'null'), COALESCE(user_id,'')
		   FROM audit
		  WHERE `+where+`
		  ORDER BY seq
		  LIMIT $`+fmt.Sprint(len(args)),
		args...)
	if err != nil {
		return 0, err
	}
	type sealRow struct {
		seq            int64
		prevHash, hash string
		chainSeq       int64
	}
	var seals []sealRow
	for rows.Next() {
		var (
			seq                                   int64
			ts                                    time.Time
			clientID, action, cid, detail, userID string
		)
		if err := rows.Scan(&seq, &ts, &clientID, &action, &cid, &detail, &userID); err != nil {
			rows.Close()
			return 0, err
		}
		// The exact recomputation Verify performs: hash over the stored
		// values, so a chain sealed here is indistinguishable from one
		// sealed synchronously at insert time.
		e := Entry{ClientID: clientID, Action: action, CID: cid, UserID: userID}
		sum := sha256.Sum256([]byte(canonical(hashV2, prev, ts, e, []byte(detail))))
		hash := hex.EncodeToString(sum[:])
		chainSeq++
		seals = append(seals, sealRow{seq: seq, prevHash: prev, hash: hash, chainSeq: chainSeq})
		prev = hash
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if len(seals) == 0 {
		return 0, nil
	}

	b := &pgx.Batch{}
	for _, s := range seals {
		var prevCol any
		if s.prevHash != "" {
			prevCol = s.prevHash
		}
		b.Queue(`UPDATE audit SET prev_hash=$1, hash=$2, chain_seq=$3, hash_v=$4 WHERE seq=$5`,
			prevCol, s.hash, s.chainSeq, int16(hashV2), s.seq)
	}
	if err := tx.SendBatch(ctx, b).Close(); err != nil {
		return 0, err
	}
	return len(seals), tx.Commit(ctx)
}

// Drain seals every unsealed row regardless of age and returns the total.
// It is the async -> sync switch step: a process starting in sync mode must
// drain first, or its first append would chain onto the sealed head and
// strand every unsealed row above it. Unlike SealOnce it blocks on the
// chain lock - a drain must finish, not politely skip.
func Drain(ctx context.Context, pool *pgxpool.Pool, batch int) (int, error) {
	total := 0
	for {
		n, err := sealBatch(ctx, pool, batch, 0, true)
		if err != nil {
			return total, err
		}
		total += n
		if n < batch {
			// The lock was HELD while this last batch found fewer rows
			// than the limit, so nothing was hiding behind a competing
			// lock holder - the backlog is genuinely empty.
			return total, nil
		}
	}
}

// UnsealedCount reports rows not yet in the chain - the operational gauge
// (sunder_audit_unsealed_rows) and the number verify-audit prints.
func UnsealedCount(ctx context.Context, pool *pgxpool.Pool) (int64, error) {
	var n int64
	err := pool.QueryRow(ctx, `SELECT count(*) FROM audit WHERE hash IS NULL`).Scan(&n)
	return n, err
}

// OldestUnsealed returns the age of the oldest row that has not entered the
// chain, or 0 when everything is sealed. It keys off db_ts (the DATABASE
// clock, as the sealer's own age filter does), so an application clock skew
// cannot make a stalled sealer look healthy.
func OldestUnsealed(ctx context.Context, pool *pgxpool.Pool) (time.Duration, error) {
	var secs *float64
	if err := pool.QueryRow(ctx,
		`SELECT EXTRACT(EPOCH FROM (now() - min(COALESCE(db_ts, ts)))) FROM audit WHERE hash IS NULL`).Scan(&secs); err != nil {
		return 0, err
	}
	if secs == nil {
		return 0, nil
	}
	return time.Duration(*secs * float64(time.Second)), nil
}

// Verify recomputes the whole sealed chain and returns the first broken
// chain position, or 0 if the chain is intact. Unsealed rows are pending,
// not broken: they are reported in pending and never counted as a failure
// here - the alarm for a stalled sealer is the unsealed-rows gauge, and
// the append-only trigger still protects pending rows from edits.
func Verify(ctx context.Context, pool *pgxpool.Pool) (brokenSeq int64, reason string, pending int64, err error) {
	// A row with a hash and a NULL chain_seq cannot be produced by any code
	// path and is refused by audit_seal_consistent, but one that predates
	// that constraint must be reported as a BREAK, not returned as a scan
	// error: an error here becomes HTTP 500 on /v1/admin/audit/verify and a
	// non-zero exit with no verdict from `sunder verify-audit`, which is
	// exactly the "verification machinery is down" state a forger wants
	// (AUDIT-CHAIN-1). ORDER BY puts it first, so it is reported first.
	rows, err := pool.Query(ctx,
		`SELECT chain_seq, seq, ts, COALESCE(client_id,''), action, COALESCE(cid,''),
		        COALESCE(detail,'null'), COALESCE(prev_hash,''), hash, COALESCE(user_id,''), hash_v
		 FROM audit WHERE hash IS NOT NULL ORDER BY chain_seq NULLS FIRST`)
	if err != nil {
		return 0, "", 0, err
	}
	defer rows.Close()
	prev := ""
	var expect int64
	for rows.Next() {
		var chainSeqNull *int64
		var seq int64
		var ts time.Time
		var clientID, action, cid, detail, prevHash, hash, userID string
		var hashV int16
		if err := rows.Scan(&chainSeqNull, &seq, &ts, &clientID, &action, &cid, &detail, &prevHash, &hash, &userID, &hashV); err != nil {
			return 0, "", 0, err
		}
		if chainSeqNull == nil {
			return -1, fmt.Sprintf("sealed row seq=%d has a hash but no chain_seq (forged insert)", seq), 0, nil
		}
		chainSeq := *chainSeqNull
		expect++
		if chainSeq != expect {
			// chain_seq is assigned densely from 1; a gap means a sealed
			// record was deleted even if the hashes were recomputed to
			// hide it - a second, independent tripwire.
			return chainSeq, fmt.Sprintf("chain_seq gap: expected %d (sealed record deleted?)", expect), 0, nil
		}
		if prevHash != prev {
			return chainSeq, "prev_hash does not match preceding record (insertion or deletion)", 0, nil
		}
		e := Entry{ClientID: clientID, Action: action, CID: cid, UserID: userID}
		sum := sha256.Sum256([]byte(canonical(hashV, prev, ts, e, []byte(detail))))
		if hex.EncodeToString(sum[:]) != hash {
			return chainSeq, "record content does not match its hash (record changed)", 0, nil
		}
		prev = hash
	}
	if err := rows.Err(); err != nil {
		return 0, "", 0, err
	}
	pending, err = UnsealedCount(ctx, pool)
	if err != nil {
		return 0, "", 0, err
	}
	return 0, "", pending, nil
}

// Head returns the current sealed chain head hash ("" when nothing is
// sealed). Anchoring stamps this value: an anchor must never point past
// what the chain can already prove.
func Head(ctx context.Context, pool *pgxpool.Pool) (string, error) {
	hash, _, err := sealedHead(ctx, pool)
	if err != nil {
		return "", fmt.Errorf("audit head: %w", err)
	}
	return hash, nil
}

// ChainRow is one sealed record as the read-only chain view exposes it:
// position, time, actor, action and the hash links. Deliberately WITHOUT
// the cid and the detail blob - the view exists to show that the chain is
// intact, and showing what happened to whom is a different privilege from
// showing that the record cannot have been altered.
type ChainRow struct {
	ChainSeq int64     `json:"chain_seq"`
	TS       time.Time `json:"ts"`
	ClientID string    `json:"client_id"`
	Action   string    `json:"action"`
	Hash     string    `json:"hash"`
	PrevHash string    `json:"prev_hash"`
}

// Tail returns the newest sealed records, oldest-first within the window so
// the hash links read in the direction they were computed.
func Tail(ctx context.Context, pool *pgxpool.Pool, limit int) ([]ChainRow, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 200 {
		limit = 200
	}
	rows, err := pool.Query(ctx,
		`SELECT chain_seq, ts, COALESCE(client_id,''), action, hash, COALESCE(prev_hash,'')
		 FROM (SELECT chain_seq, ts, client_id, action, hash, prev_hash
		       FROM audit WHERE hash IS NOT NULL ORDER BY chain_seq DESC LIMIT $1) t
		 ORDER BY chain_seq`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ChainRow
	for rows.Next() {
		var r ChainRow
		if err := rows.Scan(&r.ChainSeq, &r.TS, &r.ClientID, &r.Action, &r.Hash, &r.PrevHash); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Report is the complete verification verdict over every attestation
// mechanism the chain has: the per-record hash chain, and the hourly digests
// that attest read events under SUNDER_AUDIT_READS=bucketed.
//
// It exists so the CLI and the HTTP endpoint cannot drift apart. They did:
// `sunder verify-audit` checked read buckets and the endpoint did not, so
// the surface most likely to be wired to alerting answered ok:true while the
// CLI reported the read log - where lookup, attributes.read, files.read,
// shares.fetch, tokens.read and versions live - as tampered (AUDIT-CHAIN-3).
type Report struct {
	OK             bool   `json:"ok"`
	Reason         string `json:"reason,omitempty"`
	BrokenChainSeq int64  `json:"broken_chain_seq,omitempty"`
	BadHour        string `json:"bad_hour,omitempty"`
	Pending        int64  `json:"pending"`
	PendingHours   int64  `json:"pending_hours"`
	// OldestPendingSeconds is the age of the oldest row outside the chain.
	// Under async sealing a backlog is benign only if it is BOUNDED and
	// RECENT; a growing one is the stalled-sealer incident the threat model
	// describes, and every shipped detection path used to miss it
	// (OPS-CLI-CONFIG-8).
	OldestPendingSeconds float64 `json:"oldest_pending_seconds"`
	Sealing              string  `json:"sealing"`
	Reads                string  `json:"reads"`
}

// DefaultStaleUnsealed is how old the oldest unchained row may get before
// verification calls it a failure under async sealing. Generous relative to
// the default seal cadence (200ms interval, 2s delay): this is the "the
// sealer is gone" threshold, not a latency SLO.
const DefaultStaleUnsealed = 15 * time.Minute

// VerifyAll runs every check that does not need external material (anchor
// tokens need a CA bundle and an export directory, so they stay with the
// CLI, which has both). A broken chain is a VERDICT, never an error: an
// error here would answer HTTP 500 and exit non-zero with no reason, which
// is indistinguishable from the verifier itself being broken.
func VerifyAll(ctx context.Context, pool *pgxpool.Pool) (Report, error) {
	rep := Report{OK: true, Sealing: Mode(), Reads: ReadsMode()}
	broken, reason, pending, err := Verify(ctx, pool)
	if err != nil {
		return rep, err
	}
	rep.Pending = pending
	if broken != 0 {
		rep.OK, rep.BrokenChainSeq, rep.Reason = false, broken, reason
		return rep, nil
	}
	badHour, bucketReason, pendingHours, err := VerifyReadBuckets(ctx, pool)
	if err != nil {
		return rep, err
	}
	rep.PendingHours = pendingHours
	if badHour != "" {
		rep.OK, rep.BadHour, rep.Reason = false, badHour, bucketReason
		return rep, nil
	}
	// Under sync sealing a backlog cannot be in-flight work: sync seals at
	// insert. Rows pending there are stranded OUTSIDE the chain.
	if Mode() == ModeSync && pending > 0 {
		rep.OK = false
		rep.Reason = fmt.Sprintf("%d unsealed row(s) under sync sealing: outside the chain, "+
			"and they will not seal on their own - drain them with `sunder sealer -once` "+
			"under SUNDER_AUDIT_SEALING=async", pending)
		return rep, nil
	}
	// Under async sealing a backlog is normal - a STALE one is not. The
	// hard failure used to be gated on sync mode alone, so the daily
	// verify-audit CronJob exited 0 with an unbounded and growing async
	// backlog: every shipped detection path reported healthy while tamper
	// evidence was absent for everything written since the sealer stopped.
	oldest, err := OldestUnsealed(ctx, pool)
	if err != nil {
		return rep, err
	}
	rep.OldestPendingSeconds = oldest.Seconds()
	if pending > 0 && oldest > StaleUnsealedBound() {
		rep.OK = false
		rep.Reason = fmt.Sprintf("%d unsealed row(s), oldest %s outside the chain (limit %s): "+
			"the sealer is not making progress - check the `sunder sealer` process (or "+
			"SUNDER_AUDIT_SEAL_EXTERNAL) and the sunder_audit_unsealed_rows gauge",
			pending, oldest.Truncate(time.Second), StaleUnsealedBound())
	}
	return rep, nil
}

// staleUnsealed is the configurable bound behind StaleUnsealedBound.
var staleUnsealed atomic.Int64

// SetStaleUnsealedBound overrides how old the oldest unchained row may get
// before verification fails. Zero restores the default. Wired from
// SUNDER_AUDIT_STALE_UNSEALED.
func SetStaleUnsealedBound(d time.Duration) { staleUnsealed.Store(int64(d)) }

// StaleUnsealedBound reports the active bound.
func StaleUnsealedBound() time.Duration {
	if d := staleUnsealed.Load(); d > 0 {
		return time.Duration(d)
	}
	return DefaultStaleUnsealed
}
