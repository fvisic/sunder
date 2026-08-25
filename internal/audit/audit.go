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
}

// canonical is an unambiguous encoding of the hashed tuple: JSON array, so a
// '|' (or anything else) inside a field can never shift content across field
// boundaries and produce a hash collision between different records.
// chain_seq is deliberately NOT part of the hash - integrity comes from
// prev_hash linkage walked in chain_seq order, and the trigger plus a UNIQUE
// index keep chain_seq itself honest.
func canonical(prevHash string, ts time.Time, e Entry, detailJSON []byte) string {
	b, _ := json.Marshal([]string{
		prevHash, ts.UTC().Format(time.RFC3339Nano), e.ClientID, e.Action, e.CID, string(detailJSON),
	})
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
func sealedHead(ctx context.Context, q querier) (hash string, chainSeq int64, err error) {
	err = q.QueryRow(ctx,
		`SELECT hash, chain_seq FROM audit WHERE hash IS NOT NULL ORDER BY chain_seq DESC LIMIT 1`,
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
			`INSERT INTO audit (ts, client_id, action, cid, detail) VALUES ($1, $2, $3, $4, $5)`,
			ts, e.ClientID, e.Action, cidCol, detailJSON)
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
	sum := sha256.Sum256([]byte(canonical(prev, ts, e, detailJSON)))
	hash := hex.EncodeToString(sum[:])
	var prevCol any
	if prev != "" {
		prevCol = prev
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO audit (ts, client_id, action, cid, detail, prev_hash, hash, chain_seq)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		ts, e.ClientID, e.Action, cidCol, detailJSON, prevCol, hash, headSeq+1)
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
			`INSERT INTO audit (ts, client_id, action, cid, detail) VALUES ($1, $2, $3, $4, $5)`,
			time.Now().UTC().Truncate(time.Microsecond), e.ClientID, e.Action, cidCol, detailJSON)
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

	// delay <= 0 must mean "no age filter", not "ts < now()": ts is stamped
	// by the APPLICATION clock and now() by the DATABASE clock, so with an
	// app clock running ahead the youngest rows would silently escape a
	// drain - and a drain that misses rows strands them (see Drain).
	where := `hash IS NULL AND ts < now() - $1::interval`
	args := []any{delay.String(), batch}
	if delay <= 0 {
		where, args = `hash IS NULL`, []any{batch}
	}
	rows, err := tx.Query(ctx,
		`SELECT seq, ts, COALESCE(client_id,''), action, COALESCE(cid,''), COALESCE(detail,'null')
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
			seq                           int64
			ts                            time.Time
			clientID, action, cid, detail string
		)
		if err := rows.Scan(&seq, &ts, &clientID, &action, &cid, &detail); err != nil {
			rows.Close()
			return 0, err
		}
		// The exact recomputation Verify performs: hash over the stored
		// values, so a chain sealed here is indistinguishable from one
		// sealed synchronously at insert time.
		e := Entry{ClientID: clientID, Action: action, CID: cid}
		sum := sha256.Sum256([]byte(canonical(prev, ts, e, []byte(detail))))
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
		b.Queue(`UPDATE audit SET prev_hash=$1, hash=$2, chain_seq=$3 WHERE seq=$4`,
			prevCol, s.hash, s.chainSeq, s.seq)
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

// Verify recomputes the whole sealed chain and returns the first broken
// chain position, or 0 if the chain is intact. Unsealed rows are pending,
// not broken: they are reported in pending and never counted as a failure
// here - the alarm for a stalled sealer is the unsealed-rows gauge, and
// the append-only trigger still protects pending rows from edits.
func Verify(ctx context.Context, pool *pgxpool.Pool) (brokenSeq int64, reason string, pending int64, err error) {
	rows, err := pool.Query(ctx,
		`SELECT chain_seq, seq, ts, COALESCE(client_id,''), action, COALESCE(cid,''),
		        COALESCE(detail,'null'), COALESCE(prev_hash,''), hash
		 FROM audit WHERE hash IS NOT NULL ORDER BY chain_seq`)
	if err != nil {
		return 0, "", 0, err
	}
	defer rows.Close()
	prev := ""
	var expect int64
	for rows.Next() {
		var chainSeq, seq int64
		var ts time.Time
		var clientID, action, cid, detail, prevHash, hash string
		if err := rows.Scan(&chainSeq, &seq, &ts, &clientID, &action, &cid, &detail, &prevHash, &hash); err != nil {
			return 0, "", 0, err
		}
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
		e := Entry{ClientID: clientID, Action: action, CID: cid}
		sum := sha256.Sum256([]byte(canonical(prev, ts, e, []byte(detail))))
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
