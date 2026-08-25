package audit

// P4.2: read events (lookup, attributes.read) are the highest-volume
// audited actions and the least interesting individually. Under
// SUNDER_AUDIT_READS=bucketed (the default) they aggregate into hourly
// buckets keyed (client_id, user_id, cid, action, hour); a closer turns each
// finished hour into ONE chained audit row carrying a digest over the
// hour's buckets, so tamper evidence for reads holds at hour granularity
// while mutations stay chained per event. "chained" restores the pre-P4.2
// behaviour: every read is its own chained row.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// userCtxKey carries the request's client-asserted operator id. One
// extraction point (the API middleware) and no signature churn across the
// service layer: any audited read inside the request picks it up.
type userCtxKey struct{}

// WithUserID stores a validated user id in the context.
func WithUserID(ctx context.Context, id string) context.Context {
	if id == "" {
		return ctx
	}
	return context.WithValue(ctx, userCtxKey{}, id)
}

// UserIDFromContext returns the request's user id, or "".
func UserIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(userCtxKey{}).(string)
	return v
}

// Read-audit modes (SUNDER_AUDIT_READS).
const (
	ReadsBucketed = "bucketed"
	ReadsChained  = "chained"
)

// closer advisory lock: distinct from the chain lock on purpose - closing
// an hour is slow-ish (digest over many buckets) and must never delay
// sealing or sync appends.
const readCloseLockKey = 0x53554E45 // "SUNE"

var readsChained atomic.Bool

func init() {
	readsChained.Store(os.Getenv("SUNDER_AUDIT_READS") == ReadsChained)
}

// SetReadsMode selects how read events are audited ("bucketed" or "chained").
func SetReadsMode(m string) {
	readsChained.Store(m == ReadsChained)
}

// ReadsMode reports the active read-audit mode.
func ReadsMode() string {
	if readsChained.Load() {
		return ReadsChained
	}
	return ReadsBucketed
}

// ReadEvent records one read-class action (lookup, attributes.read). It is
// as fail-closed as Append: a read that cannot be audited must not answer.
// In bucketed mode the per-event Detail is deliberately dropped - that is
// what aggregation means - and what survives is who, whom, what, how many
// times, and the first/last time within the hour.
func ReadEvent(ctx context.Context, pool *pgxpool.Pool, e Entry) error {
	if e.UserID == "" {
		e.UserID = UserIDFromContext(ctx)
	}
	if readsChained.Load() {
		return Append(ctx, pool, e)
	}
	ts := time.Now().UTC().Truncate(time.Microsecond)
	tag, err := pool.Exec(ctx, `
		INSERT INTO audit_read_buckets (client_id, user_id, cid, action, bucket_start, count, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, date_trunc('hour', $5::timestamptz), 1, $5, $5)
		ON CONFLICT (client_id, user_id, cid, action, bucket_start)
		DO UPDATE SET count = audit_read_buckets.count + 1, last_seen = $5
		WHERE audit_read_buckets.sealed_at IS NULL`,
		e.ClientID, e.UserID, e.CID, e.Action, ts)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		// The bucket for this hour exists but is already sealed (a late
		// event racing the closer). The conditional upsert then does
		// NOTHING - silently, no error - and a silently dropped audit
		// event is the one outcome this package must never allow. Record
		// it as an ordinary chained row instead.
		return Append(ctx, pool, e)
	}
	return nil
}

// bucketRow is one bucket in the canonical digest ordering.
type bucketRow struct {
	ClientID  string `json:"client_id"`
	UserID    string `json:"user_id"`
	CID       string `json:"cid"`
	Action    string `json:"action"`
	Count     int64  `json:"count"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
}

// hourDigest is the deterministic digest over one hour's buckets: a sha256
// over the canonical JSON array of rows in primary-key order. Any edit to
// any sealed bucket changes it, which is what the chained hourly row
// proves against.
func hourDigest(rows []bucketRow) string {
	b, _ := json.Marshal(rows)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// CloseReadBuckets seals every finished hour: for each hour strictly older
// than the current one with open buckets, it writes ONE chained audit row
// (action "audit.reads_hourly") carrying the hour's digest and totals, and
// marks the hour's buckets sealed - both in one transaction, so a crash
// can never leave an hour half-summarized or summarized twice. Uses its
// own try-lock so N replicas degrade to one closer per cycle.
func CloseReadBuckets(ctx context.Context, pool *pgxpool.Pool) (hours int, err error) {
	for {
		closed, err := closeOneHour(ctx, pool)
		if err != nil || !closed {
			return hours, err
		}
		hours++
	}
}

func closeOneHour(ctx context.Context, pool *pgxpool.Pool) (bool, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var got bool
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, readCloseLockKey).Scan(&got); err != nil {
		return false, err
	}
	if !got {
		return false, nil // another replica is closing; skip this cycle
	}

	var hour time.Time
	err = tx.QueryRow(ctx, `
		SELECT bucket_start FROM audit_read_buckets
		 WHERE sealed_at IS NULL AND bucket_start < date_trunc('hour', now())
		 ORDER BY bucket_start LIMIT 1`).Scan(&hour)
	if err == pgx.ErrNoRows {
		return false, nil // no finished hour with open buckets
	}
	if err != nil {
		return false, err
	}

	rows, err := tx.Query(ctx, `
		SELECT client_id, user_id, cid, action, count, first_seen, last_seen
		  FROM audit_read_buckets
		 WHERE sealed_at IS NULL AND bucket_start = $1
		 ORDER BY client_id, user_id, cid, action`, hour)
	if err != nil {
		return false, err
	}
	var (
		buckets []bucketRow
		events  int64
	)
	for rows.Next() {
		var r bucketRow
		var first, last time.Time
		if err := rows.Scan(&r.ClientID, &r.UserID, &r.CID, &r.Action, &r.Count, &first, &last); err != nil {
			rows.Close()
			return false, err
		}
		r.FirstSeen = first.UTC().Format(time.RFC3339Nano)
		r.LastSeen = last.UTC().Format(time.RFC3339Nano)
		events += r.Count
		buckets = append(buckets, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return false, err
	}
	if len(buckets) == 0 {
		return false, nil
	}

	if err := AppendTx(ctx, tx, Entry{
		ClientID: "_audit", Action: "audit.reads_hourly",
		Detail: map[string]any{
			"hour":    hour.UTC().Format(time.RFC3339),
			"buckets": len(buckets),
			"events":  events,
			"digest":  hourDigest(buckets),
		},
	}); err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE audit_read_buckets SET sealed_at = now()
		 WHERE sealed_at IS NULL AND bucket_start = $1`, hour); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

// VerifyReadBuckets recomputes every sealed hour's digest from the stored
// buckets and compares it to the digest carried by that hour's chained
// audit row. It returns the first hour that fails (edited, added or
// removed sealed bucket - or a missing/duplicated hourly row), plus how
// many finished-but-unsealed hours are pending a closer pass.
func VerifyReadBuckets(ctx context.Context, pool *pgxpool.Pool) (badHour string, reason string, pendingHours int64, err error) {
	// Digests recorded in the chain, one per closed hour.
	recorded := map[string]string{}
	rows, err := pool.Query(ctx,
		`SELECT detail FROM audit WHERE action = 'audit.reads_hourly'`)
	if err != nil {
		return "", "", 0, err
	}
	for rows.Next() {
		var detail string
		if err := rows.Scan(&detail); err != nil {
			rows.Close()
			return "", "", 0, err
		}
		var d struct {
			Hour   string `json:"hour"`
			Digest string `json:"digest"`
		}
		if json.Unmarshal([]byte(detail), &d) != nil || d.Hour == "" {
			rows.Close()
			return "?", "unparseable audit.reads_hourly detail", 0, nil
		}
		if _, dup := recorded[d.Hour]; dup {
			rows.Close()
			return d.Hour, "hour summarized twice (duplicated hourly row)", 0, nil
		}
		recorded[d.Hour] = d.Digest
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return "", "", 0, err
	}

	// Recompute per sealed hour from the buckets themselves.
	hrows, err := pool.Query(ctx, `
		SELECT bucket_start, client_id, user_id, cid, action, count, first_seen, last_seen
		  FROM audit_read_buckets WHERE sealed_at IS NOT NULL
		 ORDER BY bucket_start, client_id, user_id, cid, action`)
	if err != nil {
		return "", "", 0, err
	}
	defer hrows.Close()
	var (
		curHour time.Time
		cur     []bucketRow
		started bool
	)
	check := func() (string, string) {
		key := curHour.UTC().Format(time.RFC3339)
		want, ok := recorded[key]
		if !ok {
			return key, "sealed buckets exist but the chained hourly row is missing"
		}
		delete(recorded, key)
		if hourDigest(cur) != want {
			return key, "sealed buckets do not match the chained digest (bucket edited, added or removed)"
		}
		return "", ""
	}
	for hrows.Next() {
		var r bucketRow
		var hour, first, last time.Time
		if err := hrows.Scan(&hour, &r.ClientID, &r.UserID, &r.CID, &r.Action, &r.Count, &first, &last); err != nil {
			return "", "", 0, err
		}
		r.FirstSeen = first.UTC().Format(time.RFC3339Nano)
		r.LastSeen = last.UTC().Format(time.RFC3339Nano)
		if started && !hour.Equal(curHour) {
			if h, why := check(); h != "" {
				return h, why, 0, nil
			}
			cur = cur[:0]
		}
		curHour, started = hour, true
		cur = append(cur, r)
	}
	if err := hrows.Err(); err != nil {
		return "", "", 0, err
	}
	if started {
		if h, why := check(); h != "" {
			return h, why, 0, nil
		}
	}
	for hour := range recorded {
		return hour, "chained hourly row exists but its sealed buckets are gone", 0, nil
	}

	err = pool.QueryRow(ctx, `
		SELECT count(DISTINCT bucket_start) FROM audit_read_buckets
		 WHERE sealed_at IS NULL AND bucket_start < date_trunc('hour', now())`).Scan(&pendingHours)
	if err != nil {
		return "", "", 0, err
	}
	return "", "", pendingHours, nil
}
