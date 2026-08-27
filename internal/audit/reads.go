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
	"log/slog"
	"os"
	"sort"
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
	// The bucket hour comes from the DATABASE clock, deliberately: the
	// closer also decides "finished" by the database clock, and mixing an
	// application timestamp in here reopens a closed hour whenever an app
	// clock trails the database across an hour boundary - the closer then
	// summarizes that hour twice and verification reports a false break
	// forever after.
	tag, err := pool.Exec(ctx, `
		INSERT INTO audit_read_buckets (client_id, user_id, cid, action, bucket_start, count, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, date_trunc('hour', now()), 1, now(), now())
		ON CONFLICT (client_id, user_id, cid, action, bucket_start)
		DO UPDATE SET count = audit_read_buckets.count + 1, last_seen = now()
		WHERE audit_read_buckets.sealed_at IS NULL`,
		e.ClientID, e.UserID, e.CID, e.Action)
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

// sortBuckets puts rows in the canonical digest order using Go's byte-wise
// string comparison, NOT a SQL ORDER BY (H12): the digest must not depend on
// the database's text collation, or a pg_dump/restore into a differently
// collated cluster - or a glibc collation upgrade - would reorder the rows
// and make every previously sealed hour report tampering. The primary key
// (client_id, user_id, cid, action) is unique within an hour, so this order
// is total.
func sortBuckets(rows []bucketRow) {
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.ClientID != b.ClientID {
			return a.ClientID < b.ClientID
		}
		if a.UserID != b.UserID {
			return a.UserID < b.UserID
		}
		if a.CID != b.CID {
			return a.CID < b.CID
		}
		return a.Action < b.Action
	})
}

// hourDigest is the deterministic digest over one hour's buckets: a sha256
// over the canonical JSON array of rows in primary-key order. Callers must
// sortBuckets first (the order is collation-independent, see above). Any edit
// to any sealed bucket changes it, which is what the chained hourly row
// proves against.
func hourDigest(rows []bucketRow) string {
	b, _ := json.Marshal(rows)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// digestMatches accepts an hour if its recorded digest matches the buckets in
// EITHER order: the canonical Go byte-wise order (every hour sealed since the
// H12 fix), or the order the rows arrived from the verify query's ORDER BY -
// the database's collation order, which is exactly how hours sealed BEFORE
// the fix were digested. Without the fallback, upgrading on a database whose
// collation disagrees with byte order (most en_* locales around '_', '-',
// '.') would flip every previously sealed hour to "tampered". rows is
// mutated (sorted); the legacy attempt uses a pre-sort copy.
func digestMatches(want string, rows []bucketRow) bool {
	legacy := make([]bucketRow, len(rows))
	copy(legacy, rows)
	sortBuckets(rows)
	return hourDigest(rows) == want || hourDigest(legacy) == want
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
			if err == nil {
				// An hour that carries a chained marker AND still has open
				// buckets is skipped forever by the filter in closeOneHour.
				// The only ways to reach that state are a forged
				// audit.reads_hourly INSERT (AUDIT-CHAIN-2) or an extreme
				// clock anomaly, and both mean real read events are being
				// kept out of the chain. Silence is what made it permanent;
				// say so on every pass.
				if n, cerr := suppressedHours(ctx, pool); cerr == nil && n > 0 {
					slog.Error("read-bucket hours are chained but still have OPEN buckets - their read events can never enter the hash chain; `sunder verify-audit` reports them BROKEN",
						"hours", n)
				}
			}
			return hours, err
		}
		hours++
	}
}

// suppressedHours counts finished hours that have both a chained hourly
// marker and still-open buckets.
func suppressedHours(ctx context.Context, pool *pgxpool.Pool) (int64, error) {
	var n int64
	err := pool.QueryRow(ctx, `
		SELECT count(DISTINCT b.bucket_start) FROM audit_read_buckets b
		 WHERE b.sealed_at IS NULL AND b.bucket_start < date_trunc('hour', now())
		   AND EXISTS (
			SELECT 1 FROM audit a
			 WHERE a.action = 'audit.reads_hourly'
			   AND (a.detail::jsonb)->>'hour' = to_char(b.bucket_start AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))`).Scan(&n)
	return n, err
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

	// Skip any hour whose chained hourly row ALREADY exists: open rows for
	// such an hour arrived after it was closed (a forged insert, or an
	// extreme clock anomaly), and summarizing them again would write a
	// second audit.reads_hourly row - poisoning verification permanently
	// ("hour summarized twice"). Left unsealed, they surface through the
	// pending count instead, and every later hour still closes normally.
	var hour time.Time
	err = tx.QueryRow(ctx, `
		SELECT b.bucket_start FROM audit_read_buckets b
		 WHERE b.sealed_at IS NULL AND b.bucket_start < date_trunc('hour', now())
		   AND NOT EXISTS (
			SELECT 1 FROM audit a
			 WHERE a.action = 'audit.reads_hourly'
			   AND (a.detail::jsonb)->>'hour' = to_char(b.bucket_start AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
		 ORDER BY b.bucket_start LIMIT 1`).Scan(&hour)
	if err == pgx.ErrNoRows {
		return false, nil // no finished hour with open buckets
	}
	if err != nil {
		return false, err
	}

	// Seal and digest in ONE statement (H11): the old code SELECTed the
	// buckets, wrote the digest, then UPDATEd sealed_at in a separate
	// statement. A ReadEvent upsert committing between the SELECT and the
	// UPDATE - incrementing a count or inserting a new bucket for this hour -
	// was caught by the UPDATE (sealed_at IS NULL) but NOT by the digest,
	// leaving a sealed row the chained digest did not cover, so
	// VerifyReadBuckets reported tampering forever. UPDATE ... RETURNING makes
	// the sealed set and the digested set the same set: any ReadEvent that
	// commits after this statement sees sealed_at IS NOT NULL and its
	// conditional upsert falls back to a chained row instead.
	rows, err := tx.Query(ctx, `
		UPDATE audit_read_buckets SET sealed_at = now()
		 WHERE sealed_at IS NULL AND bucket_start = $1
		 RETURNING client_id, user_id, cid, action, count, first_seen, last_seen`, hour)
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
	// Canonical order is computed in Go, never by the SQL RETURNING order
	// (which is unspecified) nor a collation-sensitive ORDER BY (H12).
	sortBuckets(buckets)

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
	// bucket_start (a timestamptz, collation-independent) groups rows into
	// hours; the WITHIN-hour canonical order is applied in Go by sortBuckets,
	// matching the sealer and independent of DB collation (H12). The
	// secondary ORDER BY is kept ONLY to reproduce the legacy digest order:
	// hours sealed before the Go-sort change were digested in the database's
	// collation order, and an upgrade must not flip them to "tampered" - see
	// the fallback in check(). (On a database RESTORED under a different
	// collation those legacy hours may still fail - that is the original H12
	// defect and cannot be repaired retroactively; hours sealed since are
	// portable.)
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
		if !digestMatches(want, cur) {
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
		// Distinguish the two ways an hour can be recorded without sealed
		// buckets: the buckets were removed, or they were never sealed
		// because a marker for that hour already existed when the closer
		// got there (AUDIT-CHAIN-2). The second is the forged-insert shape
		// and it is repairable - by sealing that hour - while the first is
		// not, so the operator must be able to tell them apart.
		var open int64
		if qerr := pool.QueryRow(ctx, `
			SELECT count(*) FROM audit_read_buckets
			 WHERE sealed_at IS NULL AND bucket_start = $1::timestamptz`, hour).Scan(&open); qerr == nil && open > 0 {
			return hour, "chained hourly row exists while that hour's buckets are still OPEN (forged audit.reads_hourly insert?)", 0, nil
		}
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
