package service

// Value tokenization (Phase 3 / F4). See migration 0025 for the data
// model. Semantics that keep this consistent with the rest of Sunder:
//
//   - scope-bound: a token detokenizes only for clients of the scope that
//     minted it - a stolen token is worthless to any other tenant;
//   - fail closed: an unauditable read must not answer;
//   - reads are ReadEvents (bucketed under the default audit posture),
//     mutations are chained per event;
//   - bulk create/read ALWAYS require an unlock token (purpose
//     "bulk-tokens"), regardless of SUNDER_SEARCH_UNLOCK - bulk is where
//     Databunker requires theirs, and bulk is where quiet exfiltration
//     lives.

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/fvisic/sunder/internal/audit"
	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/crypto"
)

// maxTokenValueBytes bounds a single tokenized value: this is a vault for
// identifiers and short secrets, not a blob store (the file vault is F5).
const maxTokenValueBytes = 8 * 1024

// bulkTokenLimit bounds one bulk call; the cap is logged in the audit
// detail so a capped request is visible, never silent.
const bulkTokenLimit = 1000

// ValueTokens mints and redeems tokenized values.
type ValueTokens struct {
	Pool *pgxpool.Pool
	Eng  crypto.Engine
	Ring *KeyRing
	Tok  *crypto.Tokenizer
}

// TokenizeInput is one value to tokenize.
type TokenizeInput struct {
	Type  string `json:"type"` // "string" (default) | "card"
	Value string `json:"value"`
	// Unique dedups by keyed HMAC: the same value returns the same token
	// instead of breeding aliases, and a read refreshes sliding expiry.
	Unique bool `json:"unique"`
	// ExpiresFinal is a hard deadline (RFC3339); empty = none.
	ExpiresFinal string `json:"expires_final"`
	// SlidingSeconds extends life on every read; 0 = none.
	SlidingSeconds int64 `json:"sliding_seconds"`
}

func (v *ValueTokens) sealKey(ctx context.Context) (string, error) {
	return v.Ring.Newest(ctx, crypto.KeyPIIKEK)
}

// Tokenize mints one token for one value.
func (v *ValueTokens) Tokenize(ctx context.Context, client *auth.Client, in TokenizeInput) (string, error) {
	if !client.Can(auth.ActTokensCreate) {
		return "", ErrForbidden
	}
	if in.Value == "" {
		return "", fmt.Errorf("%w: value required", ErrValidation)
	}
	if len(in.Value) > maxTokenValueBytes {
		return "", fmt.Errorf("%w: value exceeds %d bytes (the file vault is for blobs)", ErrValidation, maxTokenValueBytes)
	}
	tokenType := in.Type
	if tokenType == "" {
		tokenType = "string"
	}
	if tokenType != "string" && tokenType != "card" {
		return "", fmt.Errorf("%w: type must be \"string\" or \"card\"", ErrValidation)
	}
	if tokenType == "card" {
		if !luhnValid(digitsOf(in.Value)) {
			return "", fmt.Errorf("%w: card value fails the Luhn check", ErrValidation)
		}
	}
	var expiresFinal *time.Time
	if in.ExpiresFinal != "" {
		t, err := time.Parse(time.RFC3339, in.ExpiresFinal)
		if err != nil {
			return "", fmt.Errorf("%w: expires_final must be RFC3339", ErrValidation)
		}
		expiresFinal = &t
	}
	if in.SlidingSeconds < 0 {
		return "", fmt.Errorf("%w: sliding_seconds must be >= 0", ErrValidation)
	}

	keyID, err := v.sealKey(ctx)
	if err != nil {
		return "", err
	}
	var uniqueHash []byte
	if in.Unique {
		// Keyed HMAC under the email HMAC key domain-separated for values:
		// dedup needs determinism, never reversibility.
		mac, err := v.Eng.MAC(ctx, crypto.KeyHMACEmail+"/"+keyID, []byte("valtok\x00"+client.Scope+"\x00"+in.Value))
		if err != nil {
			return "", err
		}
		uniqueHash = mac
	}

	for attempt := 0; attempt < 3; attempt++ {
		token, err := newValueToken(tokenType, in.Value)
		if err != nil {
			return "", err
		}
		// The ciphertext is bound to its token and scope: a row cannot be
		// re-pointed at another token or tenant without failing to open.
		sealed, err := v.Eng.Seal(ctx, crypto.KeyPIIKEK+"/"+keyID, "aes256gcm",
			[]byte("valtok\x00"+client.Scope+"\x00"+token), []byte(in.Value))
		if err != nil {
			return "", err
		}

		tx, err := v.Pool.Begin(ctx)
		if err != nil {
			return "", err
		}
		if in.Unique {
			var existing string
			err := tx.QueryRow(ctx,
				`SELECT token FROM value_tokens WHERE scope=$1 AND unique_hash=$2`,
				client.Scope, uniqueHash).Scan(&existing)
			if err == nil {
				// Dedup hit: same value, same token; a hit refreshes the
				// sliding window like a read would.
				_, err = tx.Exec(ctx, `UPDATE value_tokens SET last_used=now() WHERE token=$1`, existing)
				if err == nil {
					err = tx.Commit(ctx)
				}
				if err != nil {
					_ = tx.Rollback(ctx)
					return "", err
				}
				return existing, nil
			}
			if err != pgx.ErrNoRows {
				_ = tx.Rollback(ctx)
				return "", err
			}
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO value_tokens (token, scope, token_type, ciphertext, key_id, alg, unique_hash, expires_final, sliding_seconds)
			VALUES ($1,$2,$3,$4,$5,'aes256gcm',$6,$7,NULLIF($8,0))`,
			token, client.Scope, tokenType, sealed, keyID, uniqueHash, expiresFinal, in.SlidingSeconds)
		if err == nil {
			err = audit.AppendTx(ctx, tx, audit.Entry{
				ClientID: client.ID, Action: "tokens.create",
				Detail: map[string]any{"type": tokenType, "unique": in.Unique},
			})
		}
		if err == nil {
			if err = tx.Commit(ctx); err != nil {
				return "", err
			}
			return token, nil
		}
		_ = tx.Rollback(ctx)
		if isUniqueViolation(err) {
			continue // token collision (or a concurrent unique-dedup racer): retry fresh
		}
		return "", err
	}
	return "", fmt.Errorf("token space collision persisted across retries")
}

// Detokenize returns the sealed value and refreshes sliding expiry.
func (v *ValueTokens) Detokenize(ctx context.Context, client *auth.Client, token string) (string, error) {
	if !client.Can(auth.ActTokensRead) {
		return "", ErrForbidden
	}
	var (
		sealed         []byte
		keyID, alg     string
		expiresFinal   *time.Time
		slidingSeconds *int64
		lastUsed       time.Time
	)
	err := v.Pool.QueryRow(ctx, `
		SELECT ciphertext, key_id, alg, expires_final, sliding_seconds, last_used
		  FROM value_tokens WHERE token=$1 AND scope=$2`,
		token, client.Scope).Scan(&sealed, &keyID, &alg, &expiresFinal, &slidingSeconds, &lastUsed)
	if err == pgx.ErrNoRows {
		return "", v.auditMiss(ctx, client)
	}
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	if expiresFinal != nil && now.After(*expiresFinal) {
		return "", v.auditMiss(ctx, client)
	}
	if slidingSeconds != nil && now.After(lastUsed.Add(time.Duration(*slidingSeconds)*time.Second)) {
		return "", v.auditMiss(ctx, client)
	}

	plain, err := v.Eng.Open(ctx, crypto.KeyPIIKEK+"/"+keyID, alg,
		[]byte("valtok\x00"+client.Scope+"\x00"+token), sealed)
	if err != nil {
		return "", err
	}
	// Audit BEFORE release (fail closed), then refresh the sliding window.
	if err := audit.ReadEvent(ctx, v.Pool, audit.Entry{
		ClientID: client.ID, Action: "tokens.read",
		Detail: map[string]any{"matched": true},
	}); err != nil {
		return "", fmt.Errorf("audit append: %w", err)
	}
	if _, err := v.Pool.Exec(ctx, `UPDATE value_tokens SET last_used=now() WHERE token=$1`, token); err != nil {
		return "", err
	}
	return string(plain), nil
}

// auditMiss records a failed redemption identically for absent, foreign-
// scope and expired tokens - one answer, no oracle.
func (v *ValueTokens) auditMiss(ctx context.Context, client *auth.Client) error {
	if err := audit.ReadEvent(ctx, v.Pool, audit.Entry{
		ClientID: client.ID, Action: "tokens.read",
		Detail: map[string]any{"matched": false},
	}); err != nil {
		return fmt.Errorf("audit append: %w", err)
	}
	return ErrNotFound
}

// Delete removes one token (its scope's own only). Chained: destroying a
// mapping is a mutation someone may need to prove later.
func (v *ValueTokens) Delete(ctx context.Context, client *auth.Client, token string) error {
	if !client.Can(auth.ActTokensCreate) {
		return ErrForbidden
	}
	tx, err := v.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `DELETE FROM value_tokens WHERE token=$1 AND scope=$2`, token, client.Scope)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if err := audit.AppendTx(ctx, tx, audit.Entry{
		ClientID: client.ID, Action: "tokens.delete", Detail: map[string]any{}}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// isUniqueViolation reports a Postgres 23505.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// PruneValueTokens removes expired rows (final deadline passed, or the
// sliding window starved). Wired into `sunder retention run`.
func PruneValueTokens(ctx context.Context, pool *pgxpool.Pool) (int64, error) {
	tag, err := pool.Exec(ctx, `
		DELETE FROM value_tokens
		 WHERE (expires_final IS NOT NULL AND expires_final < now())
		    OR (sliding_seconds IS NOT NULL AND last_used + make_interval(secs => sliding_seconds) < now())`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// newValueToken mints the opaque or card-shaped token.
func newValueToken(tokenType, value string) (string, error) {
	if tokenType == "card" {
		return luhnToken(len(digitsOf(value)))
	}
	var raw [20]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "VT-" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw[:]), nil
}

// digitsOf strips everything but digits (cards arrive with spaces/dashes).
func digitsOf(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			out = append(out, s[i])
		}
	}
	return string(out)
}

// luhnValid checks the Luhn checksum over a digit string.
func luhnValid(digits string) bool {
	if len(digits) < 12 || len(digits) > 19 {
		return false
	}
	sum, alt := 0, false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

// luhnToken generates a random digit string of the given length with a
// valid Luhn check digit. No BIN preservation, deliberately: a preserved
// BIN leaks issuer and geography, defeating the point of tokenizing.
func luhnToken(length int) (string, error) {
	if length < 12 || length > 19 {
		return "", fmt.Errorf("%w: card number length %d outside 12-19", ErrValidation, length)
	}
	digits := make([]byte, length)
	raw := make([]byte, length)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	for i := 0; i < length-1; i++ {
		digits[i] = '0' + raw[i]%10
	}
	// Compute the check digit so the whole string satisfies Luhn.
	sum, alt := 0, true
	for i := length - 2; i >= 0; i-- {
		d := int(digits[i] - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	digits[length-1] = byte('0' + (10-sum%10)%10)
	return string(digits), nil
}

// TokenizeBulk mints tokens for up to bulkTokenLimit values in one call.
// The HANDLER has already spent an unlock token; here the batch is audited
// as one chained record carrying the count - bulk intent is provable
// without a row per item.
func (v *ValueTokens) TokenizeBulk(ctx context.Context, client *auth.Client, items []TokenizeInput) ([]string, error) {
	if !client.Can(auth.ActTokensCreate) {
		return nil, ErrForbidden
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("%w: items required", ErrValidation)
	}
	if len(items) > bulkTokenLimit {
		return nil, fmt.Errorf("%w: at most %d items per bulk call", ErrValidation, bulkTokenLimit)
	}
	out := make([]string, 0, len(items))
	for _, in := range items {
		token, err := v.Tokenize(ctx, client, in)
		if err != nil {
			// Fail the whole batch loudly: a partial bulk result with a
			// silent hole is how values get lost in migrations.
			return nil, fmt.Errorf("item %d: %w", len(out), err)
		}
		out = append(out, token)
	}
	if err := audit.Append(ctx, v.Pool, audit.Entry{
		ClientID: client.ID, Action: "tokens.bulk_create",
		Detail: map[string]any{"count": len(out)},
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// DetokenizeBulk redeems up to bulkTokenLimit tokens. Misses come back as
// empty strings at their positions - a bulk reader learns which of ITS OWN
// tokens are gone, nothing about why.
func (v *ValueTokens) DetokenizeBulk(ctx context.Context, client *auth.Client, tokens []string) ([]string, error) {
	if !client.Can(auth.ActTokensRead) {
		return nil, ErrForbidden
	}
	if len(tokens) == 0 {
		return nil, fmt.Errorf("%w: tokens required", ErrValidation)
	}
	if len(tokens) > bulkTokenLimit {
		return nil, fmt.Errorf("%w: at most %d tokens per bulk call", ErrValidation, bulkTokenLimit)
	}
	out := make([]string, len(tokens))
	for i, tok := range tokens {
		value, err := v.Detokenize(ctx, client, tok)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				continue // miss: empty slot, already audited by Detokenize
			}
			return nil, err
		}
		out[i] = value
	}
	if err := audit.Append(ctx, v.Pool, audit.Entry{
		ClientID: client.ID, Action: "tokens.bulk_read",
		Detail: map[string]any{"count": len(tokens)},
	}); err != nil {
		return nil, err
	}
	return out, nil
}
