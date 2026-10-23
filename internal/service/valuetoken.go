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
	// CID optionally binds this token to a person (a CID in the caller's
	// scope), so erasure of that person deletes the token (S4). Empty leaves
	// the token unattributed - reachable only by its own expiry, not by
	// erasure - which is the right choice for a scope-wide value that belongs
	// to no single subject.
	CID string `json:"cid"`
	// Unique dedups by keyed HMAC within one (scope, cid) slot: the same
	// value returns the same token instead of breeding aliases, and a read
	// refreshes sliding expiry. A cid-bearing call ADOPTS a live unattributed
	// row for the same value (upgrade boundary), so the surviving token is
	// the erasable one. Two different persons deliberately get two tokens -
	// each must be erasable on its own - and a caller that mixes cid and
	// no-cid tokenization of the same value creates one token per style.
	Unique bool `json:"unique"`
	// ExpiresFinal is a hard deadline (RFC3339); empty = none.
	ExpiresFinal string `json:"expires_final"`
	// SlidingSeconds extends life on every read; 0 = none.
	SlidingSeconds int64 `json:"sliding_seconds"`
}

func (v *ValueTokens) sealKey(ctx context.Context) (string, error) {
	return v.Ring.Newest(ctx, crypto.KeyPIIKEK)
}

// Tokenize mints one token for one value, in its own transaction.
func (v *ValueTokens) Tokenize(ctx context.Context, client *auth.Client, in TokenizeInput) (string, error) {
	if !client.Can(auth.ActTokensCreate) {
		return "", ErrForbidden
	}
	keyID, err := v.sealKey(ctx)
	if err != nil {
		return "", err
	}
	tx, err := v.Pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	token, err := v.tokenizeInTx(ctx, tx, client, keyID, in)
	if err != nil {
		return "", err
	}
	// CID on the entry, not only in the row: without it the chained
	// tokens.create is invisible to the Article 15 trail, which selects
	// `WHERE cid = ANY(<the person's cids>)` (TOKENS-LOOKUP-7).
	if err := audit.AppendTx(ctx, tx, audit.Entry{
		ClientID: client.ID, Action: "tokens.create", CID: in.CID,
		Detail: map[string]any{"type": in.Type, "unique": in.Unique},
	}); err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return token, nil
}

// valueAADCurrent is the AAD layout new rows are sealed under.
const valueAADCurrent int16 = 2

// valueAAD builds the associated data for a value token's ciphertext.
//
// aad_v 1 is the legacy layout, which named only the scope and the token.
// value_tokens.cid became load-bearing for Article 17 in migration 0032, but
// it stayed unauthenticated plaintext metadata that no read path checked - so
// one `UPDATE value_tokens SET cid=NULL` hid the row from the erasure sweep
// while the ciphertext still opened, and a completed, audited erasure left
// the person's IBAN readable through the ordinary API (CRYPTO-4). aad_v 2
// names the subject, so a repointed row fails to open instead of disclosing.
// The domain byte differs so the two layouts cannot be confused.
func valueAAD(aadV int16, scope, token, cid string) []byte {
	if aadV < 2 {
		return []byte("valtok\x00" + scope + "\x00" + token)
	}
	return []byte("valtok\x01" + scope + "\x00" + token + "\x00" + cid)
}

// Detokenize returns the sealed value and refreshes sliding expiry.
func (v *ValueTokens) Detokenize(ctx context.Context, client *auth.Client, token string) (string, error) {
	if !client.Can(auth.ActTokensRead) {
		return "", ErrForbidden
	}
	var (
		sealed         []byte
		keyID, alg     string
		cid            *string
		aadV           int16
		expiresFinal   *time.Time
		slidingSeconds *int64
		lastUsed       time.Time
	)
	// Expiry is decided by the DATABASE clock in the same read (L5): the
	// app clock must not straddle the pruner's clock. A row that fails the
	// live predicate is an indistinguishable miss.
	err := v.Pool.QueryRow(ctx, `
		SELECT ciphertext, key_id, alg, cid, aad_v, expires_final, sliding_seconds, last_used
		  FROM value_tokens WHERE token=$1 AND scope=$2
		    AND (expires_final IS NULL OR expires_final > now())
		    AND (sliding_seconds IS NULL OR last_used + make_interval(secs => sliding_seconds) > now())`,
		token, client.Scope).Scan(&sealed, &keyID, &alg, &cid, &aadV, &expiresFinal, &slidingSeconds, &lastUsed)
	if err == pgx.ErrNoRows {
		return "", v.auditMiss(ctx, client)
	}
	if err != nil {
		return "", err
	}

	boundCID := ""
	if cid != nil {
		boundCID = *cid
	}
	plain, err := v.Eng.Open(ctx, crypto.KeyPIIKEK+"/"+keyID, alg,
		valueAAD(aadV, client.Scope, token, boundCID), sealed)
	if err != nil {
		return "", err
	}
	// Audit BEFORE release (fail closed), then refresh the sliding window.
	//
	// boundCID matters here: under the default bucketed posture ReadEvent
	// upserts on (client_id, user_id, cid, action, hour), so without it
	// every tokens.read in an hour collapsed into ONE row with cid='' -
	// which the subject-access query can never match. A breach
	// investigation could see a per-client count and not WHICH subjects
	// were read (TOKENS-LOOKUP-7).
	if err := audit.ReadEvent(ctx, v.Pool, audit.Entry{
		ClientID: client.ID, Action: "tokens.read", CID: boundCID,
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
	if !client.Can(auth.ActTokensDelete) {
		return ErrForbidden
	}
	tx, err := v.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// RETURNING gives the audit record something to attribute: destroying
	// the only copy of a sealed value must say WHAT was destroyed and whose
	// mint it was, not land as an empty detail.
	var createdBy, boundCID *string
	err = tx.QueryRow(ctx,
		`DELETE FROM value_tokens WHERE token=$1 AND scope=$2 RETURNING created_by, cid`,
		token, client.Scope).Scan(&createdBy, &boundCID)
	if err == pgx.ErrNoRows {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	minter, subject := "", ""
	if createdBy != nil {
		minter = *createdBy
	}
	if boundCID != nil {
		subject = *boundCID
	}
	if err := audit.AppendTx(ctx, tx, audit.Entry{
		ClientID: client.ID, Action: "tokens.delete", CID: subject,
		Detail: map[string]any{"token": token, "created_by": minter}}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// mustRand fills b with CSPRNG bytes, panicking on failure - the kernel
// CSPRNG failing is not a recoverable state (same stance as newUUID).
func mustRand(b []byte) {
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
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
	mustRand(raw[:])
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

// uniformDigit returns a uniformly random decimal digit via rejection
// sampling, avoiding the modulo bias of byte%10.
func uniformDigit() byte {
	var b [1]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			// The CSPRNG failing is not a recoverable state (see newUUID).
			panic(err)
		}
		if b[0] < 250 { // 250 = 25*10, the largest multiple of 10 <= 255
			return b[0] % 10
		}
	}
}

// luhnToken generates a random digit string of the given length with a
// valid Luhn check digit. No BIN preservation, deliberately: a preserved
// BIN leaks issuer and geography, defeating the point of tokenizing.
func luhnToken(length int) (string, error) {
	if length < 12 || length > 19 {
		return "", fmt.Errorf("%w: card number length %d outside 12-19", ErrValidation, length)
	}
	// Rejection-sample each digit from the unbiased range [0,250) so every
	// digit 0-9 is equiprobable (L8: a plain byte%10 skews toward 0-5).
	digits := make([]byte, length)
	for i := 0; i < length-1; i++ {
		digits[i] = '0' + uniformDigit()
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

// TokenizeBulk mints tokens for up to bulkTokenLimit values in ONE
// transaction: a mid-batch failure rolls the whole batch back, so a
// migration can never leave sealed plaintext behind that nobody holds a
// handle to (M4). The batch is one chained audit record carrying the count.
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
	keyID, err := v.sealKey(ctx)
	if err != nil {
		return nil, err
	}
	tx, err := v.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	out := make([]string, 0, len(items))
	for i, in := range items {
		token, err := v.tokenizeInTx(ctx, tx, client, keyID, in)
		if err != nil {
			return nil, fmt.Errorf("item %d: %w", i, err)
		}
		out = append(out, token)
	}
	if err := audit.AppendTx(ctx, tx, audit.Entry{
		ClientID: client.ID, Action: "tokens.bulk_create",
		Detail: map[string]any{"count": len(out)},
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

// tokenizeInTx does one item's validation, dedup and insert inside a
// caller-supplied transaction. A token-PK collision retries inside a
// savepoint so it cannot abort the surrounding batch.
func (v *ValueTokens) tokenizeInTx(ctx context.Context, tx pgx.Tx, client *auth.Client, keyID string, in TokenizeInput) (string, error) {
	tokenType, expiresFinal, dk, err := v.validateAndHash(ctx, client, keyID, in)
	if err != nil {
		return "", err
	}
	// A token bound to a person (S4) must name a CID in the caller's own
	// scope - attributing it to a foreign-scope pseudonym would be wrong and
	// would let one tenant's erasure reach another's token. The predicate
	// lives IN the locking read, and the lock must be on PERSONS: under READ
	// COMMITTED, EvalPlanQual re-fetches only FOR UPDATE targets, so locking
	// cids alone re-evaluated erased_at against a STALE persons tuple and a
	// tokenize racing an erasure landed an unerasable token. The persons row
	// is the single serialization point with erasePerson (whose opening
	// guard locks it before any delete): either the erasure waits for us and
	// its value_tokens DELETE then removes our row, or we wait and the
	// re-fetched tuple shows the tombstone. Deliberately NOT "OF c, p": the
	// cids lock is not needed here, and taking it would invert the c -> p
	// order erasure uses - an ABBA deadlock.
	if in.CID != "" {
		if !validCIDShape(in.CID) {
			return "", ErrNotFound
		}
		var live bool
		// The /*sunder:tokenize-lock*/ marker is load-bearing for
		// TestS4_TokenizeRacingErasureCannotLandToken, which waits on
		// pg_stat_activity for this exact statement to park on the row
		// lock. Matching on "FOR UPDATE OF p" instead also matched the file
		// vault's identical clause, so the barrier could be satisfied by the
		// wrong query (TESTS-15). Do not remove it without updating that
		// test.
		err := tx.QueryRow(ctx, `/*sunder:tokenize-lock*/
			SELECT NOT p.erased_at IS NOT NULL FROM cids c JOIN persons p ON p.id = c.person_id
			 WHERE c.cid=$1 AND c.scope=$2 FOR UPDATE OF p`,
			in.CID, client.Scope).Scan(&live)
		if err == pgx.ErrNoRows {
			// Absent and foreign-scope are one indistinguishable miss, like
			// every other cid-addressed path (and like the tombstone below).
			return "", ErrNotFound
		}
		if err != nil {
			return "", err
		}
		if !live {
			// Indistinguishable from absent, like every CID-addressed path.
			return "", ErrNotFound
		}
	}
	// Dedup key includes the cid (COALESCE to '' for unattributed tokens), so
	// two people tokenizing the same value each get their own erasable token
	// while a no-cid caller keeps the old scope-wide dedup.
	cidKey := in.CID
	if in.Unique {
		var existing string
		// = ANY(match): a hit under an OLDER key version is still a hit.
		err := tx.QueryRow(ctx, `
			SELECT token FROM value_tokens
			 WHERE scope=$1 AND COALESCE(cid,'')=$2 AND unique_hash = ANY($3)
			   AND (expires_final IS NULL OR expires_final > now())
			   AND (sliding_seconds IS NULL OR last_used + make_interval(secs => sliding_seconds) > now())`,
			client.Scope, cidKey, dk.match).Scan(&existing)
		if err == nil {
			// Converge the row onto the current key version on touch, so the
			// rotation window closes itself for actively used tokens.
			if _, err := tx.Exec(ctx,
				`UPDATE value_tokens SET last_used=now(), unique_hash=$2, unique_key_version=$3 WHERE token=$1`,
				existing, dk.write, dk.version); err != nil {
				return "", err
			}
			return existing, nil
		}
		if err != pgx.ErrNoRows {
			return "", err
		}
		// No LIVE row in our slot, but an EXPIRED row may still hold this
		// unique_hash in the partial unique index. It is dead; remove it
		// FIRST - both a fresh insert and an adoption below re-point the
		// slot, and a dead row would fail either with a raw 23505 (N3).
		// The liveness predicate on the DELETE is load-bearing: a CONCURRENT
		// tokenize of the same value can commit between our SELECT miss and
		// this statement, and an unguarded DELETE would destroy the winner's
		// LIVE token (their caller keeps a dangling handle) instead of
		// letting our INSERT collide and return theirs.
		if _, err := tx.Exec(ctx, `
			DELETE FROM value_tokens
			 WHERE scope=$1 AND COALESCE(cid,'')=$2 AND unique_hash = ANY($3)
			   AND NOT ((expires_final IS NULL OR expires_final > now())
			        AND (sliding_seconds IS NULL OR last_used + make_interval(secs => sliding_seconds) > now()))`,
			client.Scope, cidKey, dk.match); err != nil {
			return "", err
		}
		// Upgrade boundary: a live UNATTRIBUTED row for the same value may
		// exist from before tokens carried a cid. Minting a second token
		// would breed an alias whose surviving copy erasure can never reach -
		// ADOPT the row instead: bind it to this cid, so the pre-existing
		// token becomes the person's erasable one. First claim wins; a second
		// person tokenizing the same value gets their own fresh token.
		if in.CID != "" {
			var adopted string
			err := tx.QueryRow(ctx, `
				UPDATE value_tokens SET cid=$3, last_used=now(), unique_hash=$4, unique_key_version=$5
				 WHERE scope=$1 AND cid IS NULL AND unique_hash = ANY($2)
				   AND (expires_final IS NULL OR expires_final > now())
				   AND (sliding_seconds IS NULL OR last_used + make_interval(secs => sliding_seconds) > now())
				RETURNING token`, client.Scope, dk.match, in.CID, dk.write, dk.version).Scan(&adopted)
			if err == nil {
				return adopted, nil
			}
			if err != pgx.ErrNoRows {
				return "", err
			}
		}
	}
	for attempt := 0; attempt < 3; attempt++ {
		token, err := newValueToken(tokenType, in.Value)
		if err != nil {
			return "", err
		}
		sealed, err := v.Eng.Seal(ctx, crypto.KeyPIIKEK+"/"+keyID, "aes256gcm",
			valueAAD(valueAADCurrent, client.Scope, token, in.CID), []byte(in.Value))
		if err != nil {
			return "", err
		}
		sp, err := tx.Begin(ctx) // savepoint
		if err != nil {
			return "", err
		}
		_, err = sp.Exec(ctx, `
			INSERT INTO value_tokens (token, scope, cid, token_type, ciphertext, key_id, alg, unique_hash, expires_final, sliding_seconds, created_by, aad_v, unique_key_version)
			VALUES ($1,$2,NULLIF($3,''),$4,$5,$6,'aes256gcm',$7,$8,NULLIF($9,0),$10,$11,NULLIF($12,''))`,
			token, client.Scope, in.CID, tokenType, sealed, keyID, dk.write, expiresFinal, in.SlidingSeconds, client.ID, valueAADCurrent, dk.version)
		if err == nil {
			return token, sp.Commit(ctx)
		}
		_ = sp.Rollback(ctx)
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			// WHICH constraint decides the retry strategy: a token-PK
			// collision wants a fresh random token, but a unique_hash
			// collision means a CONCURRENT tokenize of the same value won
			// the slot - minting again can never satisfy it (three raw-23505
			// retries ended in a 500, and in bulk with the unlock token
			// already burned). Return the winner's token: dedup semantics,
			// just decided by the database instead of our earlier SELECT.
			if pgErr.ConstraintName == "value_tokens_unique_uq" {
				var existing string
				werr := tx.QueryRow(ctx, `
					SELECT token FROM value_tokens
					 WHERE scope=$1 AND COALESCE(cid,'')=$2 AND unique_hash = ANY($3)
					   AND (expires_final IS NULL OR expires_final > now())
					   AND (sliding_seconds IS NULL OR last_used + make_interval(secs => sliding_seconds) > now())`,
					client.Scope, cidKey, dk.match).Scan(&existing)
				if werr == nil {
					return existing, nil
				}
				if werr != pgx.ErrNoRows {
					return "", werr
				}
				// The winner's row is already dead (sub-second expiry):
				// retry the mint against the now-free slot.
			}
			continue
		}
		return "", err
	}
	return "", fmt.Errorf("token space collision persisted across retries")
}

// validateAndHash performs the pure validation and the unique-hash
// computation shared by the single and bulk paths.
// validateShape does the PURE (no-crypto, no-DB) validation of one item and
// returns the resolved token type and parsed expiry. Exposed via
// ValidateInputs so the bulk path can reject a bad batch BEFORE spending the
// single-use unlock token (L9): a request that can never tokenize must not
// burn the token nor write an intent-spent audit row.
func validateShape(in TokenizeInput) (tokenType string, expiresFinal *time.Time, err error) {
	if in.Value == "" {
		return "", nil, fmt.Errorf("%w: value required", ErrValidation)
	}
	if len(in.Value) > maxTokenValueBytes {
		return "", nil, fmt.Errorf("%w: value exceeds %d bytes (the file vault is for blobs)", ErrValidation, maxTokenValueBytes)
	}
	tokenType = in.Type
	if tokenType == "" {
		tokenType = "string"
	}
	if tokenType != "string" && tokenType != "card" {
		return "", nil, fmt.Errorf("%w: type must be \"string\" or \"card\"", ErrValidation)
	}
	if tokenType == "card" && !luhnValid(digitsOf(in.Value)) {
		return "", nil, fmt.Errorf("%w: card value fails the Luhn check", ErrValidation)
	}
	if in.ExpiresFinal != "" {
		t, perr := time.Parse(time.RFC3339, in.ExpiresFinal)
		if perr != nil {
			return "", nil, fmt.Errorf("%w: expires_final must be RFC3339", ErrValidation)
		}
		expiresFinal = &t
	}
	if in.SlidingSeconds < 0 {
		return "", nil, fmt.Errorf("%w: sliding_seconds must be >= 0", ErrValidation)
	}
	return tokenType, expiresFinal, nil
}

// ValidateInputs shape-checks a whole batch (pure, no side effects). The bulk
// handler calls it before consuming the unlock token so a malformed item
// cannot burn a single-use token (L9).
func (v *ValueTokens) ValidateInputs(items []TokenizeInput) error {
	if len(items) == 0 {
		return fmt.Errorf("%w: items required", ErrValidation)
	}
	if len(items) > bulkTokenLimit {
		return fmt.Errorf("%w: at most %d items per bulk call", ErrValidation, bulkTokenLimit)
	}
	for i, in := range items {
		if _, _, err := validateShape(in); err != nil {
			return fmt.Errorf("item %d: %w", i, err)
		}
	}
	return nil
}

// dedupKey is everything the unique-dedup slot needs: the hash new rows are
// written with, the fully-qualified key version that produced it, and every
// hash a pre-existing row for the same value could carry.
//
// Matching spans versions for the same reason identifier lookup does
// (tokensAllVersions): a rotation must not break matching for the window in
// which old and new rows coexist. The write-time-only "newest version"
// discipline is what made `keys rotate -kind hmac-email` breed a second live
// token for a value that already had one (CRYPTO-3).
type dedupKey struct {
	write   []byte
	version string
	match   [][]byte
}

// legacyUniqueInput is the pre-CRYPTO-3 derivation, keyed by hmac-email.
// Recomputed only so rows written before the migration keep matching until
// `keys rekey` converges them.
func legacyUniqueInput(scope, tokenType, value string) []byte {
	return []byte("valtok\x00" + scope + "\x00" + tokenType + "\x00" + value)
}

func uniqueInput(scope, tokenType, value string) []byte {
	return []byte("valtok-uniq\x00" + scope + "\x00" + tokenType + "\x00" + value)
}

func (v *ValueTokens) dedupKeyFor(ctx context.Context, scope, tokenType, value string) (dedupKey, error) {
	var dk dedupKey
	newest, err := v.Ring.Newest(ctx, crypto.KeyHMACValue)
	if err != nil {
		return dk, err
	}
	dk.version = crypto.KeyHMACValue + "/" + newest
	if dk.write, err = v.Eng.MAC(ctx, dk.version, uniqueInput(scope, tokenType, value)); err != nil {
		return dk, err
	}
	dk.match = append(dk.match, dk.write)
	// Every OTHER live version of the value key...
	versions, err := v.Ring.Versions(ctx, crypto.KeyHMACValue)
	if err != nil {
		return dk, err
	}
	for _, ver := range versions {
		if ver == newest {
			continue
		}
		mac, err := v.Eng.MAC(ctx, crypto.KeyHMACValue+"/"+ver, uniqueInput(scope, tokenType, value))
		if err != nil {
			return dk, err
		}
		dk.match = append(dk.match, mac)
	}
	// ...plus the legacy hmac-email derivation, under every live version of
	// that key, so pre-migration rows still deduplicate.
	emailVersions, err := v.Ring.Versions(ctx, crypto.KeyHMACEmail)
	if err != nil {
		return dk, err
	}
	for _, ver := range emailVersions {
		mac, err := v.Eng.MAC(ctx, crypto.KeyHMACEmail+"/"+ver, legacyUniqueInput(scope, tokenType, value))
		if err != nil {
			return dk, err
		}
		dk.match = append(dk.match, mac)
	}
	return dk, nil
}

func (v *ValueTokens) validateAndHash(ctx context.Context, client *auth.Client, keyID string, in TokenizeInput) (tokenType string, expiresFinal *time.Time, dk dedupKey, err error) {
	tokenType, expiresFinal, err = validateShape(in)
	if err != nil {
		return "", nil, dk, err
	}
	if in.Unique {
		if dk, err = v.dedupKeyFor(ctx, client.Scope, tokenType, in.Value); err != nil {
			return "", nil, dedupKey{}, err
		}
	}
	return tokenType, expiresFinal, dk, nil
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
