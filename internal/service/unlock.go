package service

// Unlock tokens (Phase 3 / F3, Databunker-style select security): a
// 60-second, single-use, purpose-bound SECOND credential required for
// operations with bulk potential. The point is not extra secrecy - the
// caller already holds a real credential - but deliberate friction plus a
// chained audit anchor proving explicit intent: bulk access can never be
// an accident or a quiet script.
//
// Default posture (SUNDER_SEARCH_UNLOCK=false): single-hit fuzzy/partial
// lookups do NOT require unlock - they answer about one person, are rate
// limited and audited, and requiring a pre-flight round trip on every
// caller-ID lookup would kill the flow the feature exists for. The strict
// posture (=true) mirrors Databunker and gates them too. Genuinely bulk
// surfaces (F4 bulk tokenization) always require unlock, regardless.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/fvisic/sunder/internal/audit"
	"github.com/fvisic/sunder/internal/auth"
)

// unlockTTL mirrors Databunker's 60-second window: long enough for one
// intended operation, short enough that a leaked token is stale by the
// time it travels anywhere.
const unlockTTL = 60 * time.Second

// ErrUnlockRequired is returned by consumers when the operation needs an
// unlock token and none (or an invalid one) was supplied.
var ErrUnlockRequired = fmt.Errorf("unlock token required")

// Unlock issues and consumes unlock tokens.
type Unlock struct {
	Pool *pgxpool.Pool
}

// Issue mints one unlock token for one purpose. The raw token is returned
// exactly once; only its hash is stored. Issuance is a chained audit
// record - it IS the declaration of bulk intent.
func (u *Unlock) Issue(ctx context.Context, client *auth.Client, purpose string) (token string, expiresAt time.Time, err error) {
	if !client.Can(auth.ActAdminUnlock) {
		return "", time.Time{}, ErrForbidden
	}
	if purpose == "" || len(purpose) > 64 {
		return "", time.Time{}, fmt.Errorf("%w: purpose must be 1-64 chars", ErrValidation)
	}
	var raw [20]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", time.Time{}, err
	}
	token = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw[:])
	sum := sha256.Sum256([]byte(token))

	tx, err := u.Pool.Begin(ctx)
	if err != nil {
		return "", time.Time{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// expires_at and its comparison in Consume both use the database
	// clock (review F6): an app clock a minute off would make every 60s
	// token dead on arrival or silently long-lived.
	if err := tx.QueryRow(ctx,
		`INSERT INTO unlock_tokens (token_hash, client_id, purpose, expires_at)
		 VALUES ($1,$2,$3, now() + make_interval(secs => $4)) RETURNING expires_at`,
		sum[:], client.ID, purpose, unlockTTL.Seconds()).Scan(&expiresAt); err != nil {
		return "", time.Time{}, err
	}
	if err := audit.AppendTx(ctx, tx, audit.Entry{
		ClientID: client.ID, Action: "admin.unlock",
		Detail: map[string]any{"purpose": purpose},
	}); err != nil {
		return "", time.Time{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", time.Time{}, err
	}
	return token, expiresAt, nil
}

// Consume atomically spends one token: it must belong to the SAME client,
// carry the SAME purpose, be unexpired and unused. Every failure mode is
// the same ErrUnlockRequired - an attacker probing tokens learns nothing
// about why one failed. Consumption is audited chained: intent declared,
// intent spent, both provable.
func (u *Unlock) Consume(ctx context.Context, client *auth.Client, purpose, token string) error {
	if token == "" {
		return ErrUnlockRequired
	}
	sum := sha256.Sum256([]byte(token))
	tx, err := u.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx,
		`UPDATE unlock_tokens SET used_at = now()
		  WHERE token_hash = $1 AND client_id = $2 AND purpose = $3
		    AND used_at IS NULL AND expires_at > now()`,
		sum[:], client.ID, purpose)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrUnlockRequired
	}
	if err := audit.AppendTx(ctx, tx, audit.Entry{
		ClientID: client.ID, Action: "admin.unlock.use",
		Detail: map[string]any{"purpose": purpose},
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// PruneUnlockTokens removes spent and expired rows (they are operational
// state, not audit data - the chain carries issue and use). Wired into
// `sunder retention run`.
func PruneUnlockTokens(ctx context.Context, pool *pgxpool.Pool) (int64, error) {
	tag, err := pool.Exec(ctx,
		`DELETE FROM unlock_tokens WHERE expires_at < now() - interval '1 hour'`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
