// Package audit writes the append-only, hash-chained audit log.
//
// Every record's hash covers the previous record's hash plus its own
// canonical content, so any edit, deletion or insertion breaks the chain at
// a provable position. There is deliberately no update or delete path.
// Verification and RFC 3161 anchoring live in this package too (M5).
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// advisory lock key serializing appends; chained hashes require a total order.
const appendLockKey = 0x53554E44 // "SUND"

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
func canonical(prevHash string, ts time.Time, e Entry, detailJSON []byte) string {
	b, _ := json.Marshal([]string{
		prevHash, ts.UTC().Format(time.RFC3339Nano), e.ClientID, e.Action, e.CID, string(detailJSON),
	})
	return string(b)
}

// AppendTx writes one chained record inside the caller's transaction, so a
// business mutation and its audit record commit or roll back together -
// the log can never record what did not happen, nor miss what did.
func AppendTx(ctx context.Context, tx pgx.Tx, e Entry) error {
	detailJSON, err := json.Marshal(e.Detail)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, appendLockKey); err != nil {
		return err
	}
	var prev string
	err = tx.QueryRow(ctx, `SELECT hash FROM audit ORDER BY seq DESC LIMIT 1`).Scan(&prev)
	if err != nil && err != pgx.ErrNoRows {
		return err
	}
	// timestamptz keeps microseconds; hash over what the DB will give back.
	ts := time.Now().UTC().Truncate(time.Microsecond)
	sum := sha256.Sum256([]byte(canonical(prev, ts, e, detailJSON)))
	hash := hex.EncodeToString(sum[:])

	var prevCol any
	if prev != "" {
		prevCol = prev
	}
	var cidCol any
	if e.CID != "" {
		cidCol = e.CID
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO audit (ts, client_id, action, cid, detail, prev_hash, hash)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		ts, e.ClientID, e.Action, cidCol, detailJSON, prevCol, hash)
	return err
}

// Append writes one chained record in its own transaction.
func Append(ctx context.Context, pool *pgxpool.Pool, e Entry) error {
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

// Verify recomputes the whole chain and returns the first broken sequence
// number, or 0 if the chain is intact. Reason explains the failure mode.
func Verify(ctx context.Context, pool *pgxpool.Pool) (brokenSeq int64, reason string, err error) {
	rows, err := pool.Query(ctx,
		`SELECT seq, ts, COALESCE(client_id,''), action, COALESCE(cid,''),
		        COALESCE(detail,'null'), COALESCE(prev_hash,''), hash
		 FROM audit ORDER BY seq`)
	if err != nil {
		return 0, "", err
	}
	defer rows.Close()
	prev := ""
	for rows.Next() {
		var seq int64
		var ts time.Time
		var clientID, action, cid, detail, prevHash, hash string
		if err := rows.Scan(&seq, &ts, &clientID, &action, &cid, &detail, &prevHash, &hash); err != nil {
			return 0, "", err
		}
		if prevHash != prev {
			return seq, "prev_hash does not match preceding record (insertion or deletion)", nil
		}
		e := Entry{ClientID: clientID, Action: action, CID: cid}
		sum := sha256.Sum256([]byte(canonical(prev, ts, e, []byte(detail))))
		if hex.EncodeToString(sum[:]) != hash {
			return seq, "record content does not match its hash (record changed)", nil
		}
		prev = hash
	}
	if err := rows.Err(); err != nil {
		return 0, "", err
	}
	return 0, "", nil
}

// Head returns the current chain head hash ("" when the log is empty).
func Head(ctx context.Context, pool *pgxpool.Pool) (string, error) {
	var head string
	err := pool.QueryRow(ctx, `SELECT hash FROM audit ORDER BY seq DESC LIMIT 1`).Scan(&head)
	if err == pgx.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("audit head: %w", err)
	}
	return head, nil
}
