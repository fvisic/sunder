package service

// Batch re-key: completes a key rotation without waiting for every contact
// to be "touched". Identifiers exist only inside the per-scope encrypted
// blobs, so the sweep decrypts each person's blobs, writes newest-version
// search tokens for every identifier found, and (optionally) re-encrypts
// blobs under the newest pii-kek. After a full sweep the old version can be
// retired (`sunder keys retire`), which also purges its token rows.
//
// A contact whose blobs were wiped by retention has no recoverable
// identifiers: its old-version token rows simply die with the retirement.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"time"

	"github.com/fvisic/sunder/internal/audit"
	"github.com/fvisic/sunder/internal/crypto"
)

var identAttr = regexp.MustCompile(`^(email|phone)(_[0-9]+)?$`)

// RekeyStats reports what one sweep did.
type RekeyStats struct {
	Persons              int64
	TokensInserted       int64
	BlobsReenc           int64
	Skipped              int64 // blobs that failed to decrypt (counted, not fatal)
	ValueTokensRewrapped int64 // F4 value tokens re-sealed under the newest KEK (M5)
	RecordKeysRewrapped  int64 // F5 per-person record keys re-wrapped (M5)
	VersionsRewrapped    int64 // F6 attribute-version blobs re-encrypted (S5)
	OutboxRewrapped      int64 // portal_outbox payloads re-sealed under the newest KEK (GAP-1)
	// Resumed reports that this run picked up a previous run's resume point
	// instead of starting from the first person, and PersonsSkipped is how
	// many that previous run had already covered. The operator needs both:
	// "persons: 500" after a resume means something very different from
	// "persons: 500" on a fresh sweep, and silently reporting the smaller
	// number would read as a sweep that had barely started.
	Resumed        bool
	PersonsSkipped int64
	// Raced counts blobs a concurrent writer touched between this sweep's
	// read and its write. They were NOT converted and a rerun is required -
	// distinct from Skipped, which means "could not be decrypted at all"
	// (TOKENS-LOOKUP-2).
	Raced int64
}

// rekeyScope fingerprints what a sweep is doing, so a resume point can only
// be honoured by a sweep doing the SAME work.
//
// This is the whole safety argument for resuming. The resume point says
// "persons below this uuid are done" - true only for the outstanding set the
// interrupted run was working through. Rotate a key, flip
// SUNDER_SEARCH_FUZZY_NAME, or rerun with -reencrypt-pii after a run
// without it, and persons BELOW the resume point now have work again.
// Fingerprinting every input that decides the outstanding set turns that
// from a rule someone has to remember into a string comparison.
func rekeyScope(newest map[string]string, newestKEK string, reencryptPII, fuzzyName, phoneSuffix bool) string {
	kinds := make([]string, 0, len(newest))
	for k := range newest {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds) // map order is not a fingerprint
	h := sha256.New()
	for _, k := range kinds {
		fmt.Fprintf(h, "%s=%s;", k, newest[k])
	}
	fmt.Fprintf(h, "kek=%s;pii=%t;fuzzy=%t;suffix=%t", newestKEK, reencryptPII, fuzzyName, phoneSuffix)
	return hex.EncodeToString(h.Sum(nil))
}

const rekeyStartID = "00000000-0000-0000-0000-000000000000"

// loadResumePoint returns where to start, and how many persons a previous
// run had already covered. A scope mismatch, or no row at all, starts over.
func (c *Contacts) loadResumePoint(ctx context.Context, scope string) (string, int64) {
	var last string
	var done int64
	err := c.Pool.QueryRow(ctx,
		`SELECT last_person_id::text, persons_done FROM rekey_progress WHERE id AND scope=$1`,
		scope).Scan(&last, &done)
	if err != nil || last == "" {
		return rekeyStartID, 0
	}
	return last, done
}

// saveResumePoint records the page boundary. Best-effort by design: losing
// it costs re-reading, never correctness, so a failure here must not abort a
// sweep that is otherwise making progress.
func (c *Contacts) saveResumePoint(ctx context.Context, scope, lastID string, done int64) {
	_, _ = c.Pool.Exec(ctx,
		`INSERT INTO rekey_progress (id, scope, last_person_id, persons_done, updated_at)
		 VALUES (TRUE, $1, $2::uuid, $3, now())
		 ON CONFLICT (id) DO UPDATE SET scope=EXCLUDED.scope,
		   last_person_id=EXCLUDED.last_person_id,
		   persons_done=EXCLUDED.persons_done, updated_at=now()`,
		scope, lastID, done)
}

// livePersonCount is for the progress line's ETA only. An estimate is
// enough - reltuples avoids a count(*) over 26.9M rows just to print a
// percentage - and a zero simply omits the ETA rather than failing a sweep.
func (c *Contacts) livePersonCount(ctx context.Context) (int64, error) {
	var n int64
	err := c.Pool.QueryRow(ctx,
		`SELECT GREATEST(reltuples, 0)::bigint FROM pg_class WHERE relname='persons'`).Scan(&n)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// clearResumePoint drops the row once the sweep has reached the end. Leaving
// it would make the NEXT run of the same scope skip everything - correct
// only until someone registers a person below the point.
func (c *Contacts) clearResumePoint(ctx context.Context) {
	_, _ = c.Pool.Exec(ctx, `DELETE FROM rekey_progress WHERE id`)
}

// Rekey sweeps all non-erased persons in id order.
func (c *Contacts) Rekey(ctx context.Context, reencryptPII bool, batch int) (RekeyStats, error) {
	var stats RekeyStats
	newestByKind := map[string]string{}
	for _, kind := range []string{crypto.KeyHMACEmail, crypto.KeyHMACPhone, crypto.KeyHMACName} {
		v, err := c.Ring.Newest(ctx, kind)
		if err != nil {
			return stats, err
		}
		newestByKind[kind] = v
	}
	newestKEK, err := c.Ring.Newest(ctx, crypto.KeyPIIKEK)
	if err != nil {
		return stats, err
	}

	scope := rekeyScope(newestByKind, newestKEK, reencryptPII, c.FuzzyName, c.PhoneSuffix)
	resumeFrom, alreadyDone := c.loadResumePoint(ctx, scope)
	stats.Resumed = resumeFrom != rekeyStartID
	stats.PersonsSkipped = alreadyDone

	// Progress, because this sweep is long. The 26.9M-contact backfill ran
	// for SEVEN HOURS without emitting a single line: an operator watching it
	// could not tell a working sweep from a hung one, and the only way to
	// find out was to query the database behind its back. A sweep that takes
	// hours has to say so while it takes them.
	log := c.logger()
	total, _ := c.livePersonCount(ctx)
	started := time.Now()
	if stats.Resumed {
		log.Info("rekey sweep resuming", "from_person", resumeFrom,
			"already_covered", alreadyDone, "live_persons", total)
	} else {
		log.Info("rekey sweep starting", "live_persons", total, "batch", batch)
	}
	lastReport := started

	// Paginate on the uuid ITSELF, never on id::text.
	//
	// `id::text > $1 ORDER BY id::text` is not sargable: the cast makes
	// persons_pkey unusable, so every batch became a parallel sequential scan
	// of the whole table plus a top-N sort. Measured on 26.9M persons:
	// 172,867 shared buffers per batch against 513 for the uncast form - 337x
	// the I/O, 53,842 times over. `pg_stat_user_tables` recorded 6.3 BILLION
	// sequential tuple reads from one sweep, and registrations concurrent
	// with it timed out at 30s while the sweep held its connections.
	//
	// The uuid zero value is the lower bound; uuid ordering differs from text
	// ordering, which does not matter to a sweep that must visit every row.
	lastID := resumeFrom
	tokens := newTokenBatch()
	for {
		rows, err := c.Pool.Query(ctx,
			`SELECT id FROM persons WHERE erased_at IS NULL AND id > $1::uuid ORDER BY id LIMIT $2`,
			lastID, batch)
		if err != nil {
			return stats, err
		}
		var ids []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil { //coverage:defensive rows.Scan failure needs a DB fault injected at this exact statement
				rows.Close()
				return stats, err
			}
			ids = append(ids, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil { //coverage:defensive rows.Err failure needs a DB fault injected at this exact statement
			return stats, err
		}
		if len(ids) == 0 {
			log.Info("rekey sweep finished",
				"persons_this_run", stats.Persons,
				"persons_total", alreadyDone+stats.Persons,
				"tokens_written", stats.TokensInserted,
				"took", time.Since(started).Round(time.Second).String())
			// Reached the end: the resume point has served its purpose, and
			// keeping it would make the next run of the same scope skip a
			// person registered below it.
			c.clearResumePoint(ctx)
			break
		}
		for _, id := range ids {
			if err := c.rekeyPerson(ctx, id, newestByKind, newestKEK, reencryptPII, &stats, tokens); err != nil {
				return stats, fmt.Errorf("person %s: %w", id, err)
			}
			stats.Persons++
		}
		// One statement for the whole batch's tokens.
		if err := c.flushTokens(ctx, tokens, &stats); err != nil {
			return stats, err
		}
		lastID = ids[len(ids)-1]
		// Record the page boundary AFTER its tokens are committed, never
		// before: a resume point ahead of the work it claims would skip
		// persons permanently, and nothing would ever revisit them.
		c.saveResumePoint(ctx, scope, lastID, alreadyDone+stats.Persons)

		// One line every 30s, not one per batch: at batch=500 a large sweep
		// would otherwise produce tens of thousands of lines and bury the
		// warnings that matter.
		if time.Since(lastReport) >= 30*time.Second {
			lastReport = time.Now()
			covered := alreadyDone + stats.Persons
			rate := float64(stats.Persons) / time.Since(started).Seconds()
			attrs := []any{
				"persons_this_run", stats.Persons,
				"persons_total", covered,
				"tokens_written", stats.TokensInserted,
				"persons_per_sec", int64(rate),
			}
			if total > covered && rate > 0 {
				attrs = append(attrs, "eta",
					(time.Duration(float64(total-covered)/rate) * time.Second).Round(time.Minute).String())
			}
			log.Info("rekey sweep progress", attrs...)
		}
	}

	if reencryptPII {
		if err := c.rekeyVaults(ctx, newestKEK, &stats); err != nil {
			return stats, err
		}
	}

	if stats.TokensInserted > 0 || stats.BlobsReenc > 0 || stats.ValueTokensRewrapped > 0 || stats.RecordKeysRewrapped > 0 || stats.VersionsRewrapped > 0 {
		if err := audit.Append(ctx, c.Pool, audit.Entry{
			ClientID: "system", Action: "keys.rekey",
			Detail: map[string]any{
				"persons": stats.Persons, "tokens_inserted": stats.TokensInserted,
				"blobs_reencrypted": stats.BlobsReenc, "blobs_skipped": stats.Skipped,
				"value_tokens_rewrapped": stats.ValueTokensRewrapped,
				"record_keys_rewrapped":  stats.RecordKeysRewrapped,
				"versions_rewrapped":     stats.VersionsRewrapped,
			},
		}); err != nil {
			return stats, err
		}
	}
	return stats, nil
}

// BeforeTokenFlushForTest runs immediately before a token batch is written,
// nil in production. See flushTokens.
var BeforeTokenFlushForTest func()

// tokenBatch accumulates the search tokens produced across every person in
// one sweep batch, so they land in ONE statement instead of one per token.
//
// The sweep used to Exec once per token: 7.2 synchronous round trips per
// person, each waiting for the previous reply. Measured on 26.9M contacts
// that is 193.6 MILLION round trips and ~87 hours, while the same database
// accepts 54,000 rows/s in-server - the bottleneck was never PostgreSQL or
// the decryption, only the latency of asking one row at a time.
type tokenBatch struct {
	personIDs []string
	kinds     []string
	tokens    []string
	versions  []string
	seen      map[string]bool // dedup within the batch, cheaper than a conflict
}

func newTokenBatch() *tokenBatch { return &tokenBatch{seen: map[string]bool{}} }

func (b *tokenBatch) add(personID, kind, token, version string) {
	key := personID + "\x00" + kind + "\x00" + token
	if b.seen[key] {
		return
	}
	b.seen[key] = true
	b.personIDs = append(b.personIDs, personID)
	b.kinds = append(b.kinds, kind)
	b.tokens = append(b.tokens, token)
	b.versions = append(b.versions, version)
}

func (b *tokenBatch) len() int { return len(b.personIDs) }

func (b *tokenBatch) reset() {
	b.personIDs, b.kinds, b.tokens, b.versions = b.personIDs[:0], b.kinds[:0], b.tokens[:0], b.versions[:0]
	clear(b.seen)
}

// flushTokens writes the whole batch in one statement.
//
// The join onto persons is the per-ROW liveness check the single-row form
// had as `WHERE EXISTS (... erased_at IS NULL)`. It is load-bearing, not
// tidiness: the batch snapshot is arbitrarily stale by the time this runs,
// and an erasure landing in that window used to have its deleted search
// tokens RE-CREATED here, under the newest key version, permanently - and
// immediately usable (GDPR-ERASURE-2). Evaluating it per row inside the
// statement keeps that invariant exactly where it was.
func (c *Contacts) flushTokens(ctx context.Context, b *tokenBatch, stats *RekeyStats) error {
	if b.len() == 0 {
		return nil
	}
	if BeforeTokenFlushForTest != nil {
		// A test seam, not a feature. Batching WIDENS the window between
		// reading a person and writing their tokens - the very window
		// GDPR-ERASURE-2 lives in - so a test has to be able to erase
		// someone inside it deterministically rather than by racing.
		BeforeTokenFlushForTest()
	}
	tag, err := c.Pool.Exec(ctx,
		`INSERT INTO person_tokens (person_id, kind, token, key_version)
		 SELECT u.pid, u.kind, u.tok, u.ver
		   FROM unnest($1::uuid[], $2::text[], $3::text[], $4::text[]) AS u(pid, kind, tok, ver)
		   JOIN persons p ON p.id = u.pid AND p.erased_at IS NULL
		 ON CONFLICT (person_id, kind, token) DO NOTHING`,
		b.personIDs, b.kinds, b.tokens, b.versions)
	if err != nil {
		// person_tokens_ident_uq (UNIQUE on (kind, token) for email/phone) is
		// the dedup invariant and is NOT the conflict target above, so a
		// violation of it aborts the statement - and with it the whole batch.
		// That is the same outcome the single-row form had (it returned the
		// error too), but the diagnostic would be worse: "a batch of 500
		// failed" instead of "this person failed". Replay row by row to name
		// the offender, then surface the original error.
		if who := c.findOffendingRow(ctx, b); who != "" {
			return fmt.Errorf("token batch failed at person %s: %w", who, err)
		}
		return err
	}
	stats.TokensInserted += tag.RowsAffected()
	b.reset()
	return nil
}

// findOffendingRow re-runs a failed batch one row at a time and reports the
// first person whose insert fails. Diagnostics only: the caller returns the
// batch's original error either way.
func (c *Contacts) findOffendingRow(ctx context.Context, b *tokenBatch) string {
	for i := range b.personIDs {
		_, err := c.Pool.Exec(ctx,
			`INSERT INTO person_tokens (person_id, kind, token, key_version)
			 SELECT $1,$2,$3,$4
			  WHERE EXISTS (SELECT 1 FROM persons WHERE id=$1 AND erased_at IS NULL)
			 ON CONFLICT (person_id, kind, token) DO NOTHING`,
			b.personIDs[i], b.kinds[i], b.tokens[i], b.versions[i])
		if err != nil {
			return b.personIDs[i]
		}
	}
	return ""
}

func (c *Contacts) rekeyPerson(ctx context.Context, personID string, newest map[string]string, newestKEK string, reencryptPII bool, stats *RekeyStats, batch *tokenBatch) error {
	rows, err := c.Pool.Query(ctx,
		`SELECT cid, COALESCE(pii_encrypted,''::bytea), COALESCE(pii_key_id,'v1'), COALESCE(pii_alg,'aes256gcm'), updated_at
		 FROM cids WHERE person_id=$1`, personID)
	if err != nil {
		return err
	}
	type blobRow struct {
		cid       string
		blob      []byte
		keyID     string
		alg       string
		updatedAt time.Time
	}
	var blobs []blobRow
	for rows.Next() {
		var b blobRow
		if err := rows.Scan(&b.cid, &b.blob, &b.keyID, &b.alg, &b.updatedAt); err != nil { //coverage:defensive rows.Scan failure needs a DB fault injected at this exact statement
			rows.Close()
			return err
		}
		blobs = append(blobs, b)
	}
	rows.Close()
	if err := rows.Err(); err != nil { //coverage:defensive rows.Err failure needs a DB fault injected at this exact statement
		return err
	}

	// Collect identifiers across every scope's blob (values are stored
	// normalized at registration time).
	emails := map[string]bool{}
	phones := map[string]bool{}
	names := map[string]bool{}
	for _, b := range blobs {
		if len(b.blob) == 0 {
			continue
		}
		attrs, err := c.PII.Decrypt(ctx, b.cid, b.blob, b.keyID, b.alg)
		if err != nil {
			stats.Skipped++
			continue
		}
		for k, v := range attrs {
			if m := identAttr.FindStringSubmatch(k); m != nil {
				if m[1] == "email" {
					emails[v] = true
				} else {
					phones[v] = true
				}
			}
			if k == "name" {
				if norm, err := crypto.NormalizeName(v); err == nil {
					names[norm] = true
				}
			}
		}
		// Re-encrypt when the key OR the algorithm is stale: the same sweep
		// that completes a key rotation also migrates the fleet to a newly
		// configured AEAD (docs/RUNBOOK-ALG-MIGRATION.md).
		if reencryptPII && (b.keyID != newestKEK || b.alg != c.PII.Algorithm()) {
			fresh, err := c.PII.Encrypt(ctx, b.cid, newestKEK, attrs)
			if err != nil {
				return err
			}
			// Guarded write: if a register/share re-encrypted the row after
			// our read, skip it - clobbering would resurrect stale
			// attributes. The row was re-keyed on touch
			// anyway.
			//
			// The guard is a compare-and-swap on updated_at, which every
			// concurrent blob writer moves (mergeIntoBlob bumps it) and
			// which the sweep deliberately does not - so it is a real
			// optimistic-concurrency token.
			//
			// (key_id, alg) is NOT one: it is the pair the sweep is trying
			// to change, and it is stable across exactly the racing write
			// the sweep runs alongside - a replica still on the old
			// SUNDER_PII_ALG, or one whose KeyRing cache has not yet seen
			// the rotation, merges an attribute and writes back the SAME
			// pair. The qual then re-evaluated TRUE against the new tuple
			// and clobbered it, losing the merged attribute silently and
			// counting the clobber as a success (TOKENS-LOOKUP-2).
			//
			// The (key_id, alg) predicates stay as a second condition; the
			// persons join and pii_encrypted IS NOT NULL are the erasure and
			// retention-wipe guards, which the tuple alone could not see
			// because both wipe by NULLing pii_key_id and COALESCE turns
			// that back into 'v1' (GDPR-ERASURE-1).
			tag, err := c.Pool.Exec(ctx,
				`UPDATE cids c SET pii_encrypted=$2, pii_key_id=$3, pii_alg=$4
				   FROM persons p
				  WHERE c.cid=$1 AND p.id = c.person_id AND p.erased_at IS NULL
				    AND c.pii_encrypted IS NOT NULL
				    AND c.updated_at = $7
				    AND COALESCE(c.pii_key_id,'v1')=$5 AND COALESCE(c.pii_alg,'aes256gcm')=$6`,
				b.cid, fresh, newestKEK, c.PII.Algorithm(), b.keyID, b.alg, b.updatedAt)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 1 {
				stats.BlobsReenc++
			} else {
				// A concurrent writer won. NOT the same as an undecryptable
				// blob: the row still needs converting, so the operator must
				// know a rerun is required rather than reading it as "N
				// blobs could not be opened".
				stats.Raced++
			}
		}
	}

	// Accumulate rather than Exec. The liveness check that used to ride each
	// INSERT now rides the batch's join onto persons - same invariant, same
	// place in the statement, one statement per batch instead of per token.
	insert := func(rowKind string, values map[string]bool,
		tokFn func(ctx context.Context, version, normalized string) (string, error), version string) error {
		for v := range values {
			tok, err := tokFn(ctx, version, v)
			if err != nil {
				return err
			}
			batch.add(personID, rowKind, tok, version)
		}
		return nil
	}
	if err := insert("email", emails, c.Tok.EmailToken, newest[crypto.KeyHMACEmail]); err != nil {
		return err
	}
	if err := insert("phone", phones, c.Tok.PhoneToken, newest[crypto.KeyHMACPhone]); err != nil {
		return err
	}
	if err := insert("name", names, c.Tok.NameToken, newest[crypto.KeyHMACName]); err != nil {
		return err
	}
	// Derived search tokens (F1/F2): the rekey sweep doubles as the
	// BACKFILL path - enabling either feature on an existing dataset is
	// "flip the config, run `sunder keys rekey`".
	if c.FuzzyName {
		codes := map[string]bool{}
		for n := range names {
			for _, code := range crypto.PhoneticNameCodes(n) {
				codes[code] = true
			}
		}
		if err := insert("name_phonetic", codes, c.Tok.NamePhoneticToken, newest[crypto.KeyHMACName]); err != nil {
			return err
		}
	}
	if c.PhoneSuffix {
		suffixes := map[string]bool{}
		for ph := range phones {
			suffixes[crypto.PhoneSuffix(ph)] = true
		}
		if err := insert("phone_suffix", suffixes, c.Tok.PhoneSuffixToken, newest[crypto.KeyHMACPhone]); err != nil {
			return err
		}
	}
	return nil
}

// rekeyVaults re-wraps the F4 value tokens and F5 per-person record keys
// under the newest pii-kek (M5). Without this, `keys retire` would leave
// every value token and every file (whose DEK hangs off the record key)
// decryptable by a leaked old KEK. AADs are unchanged, so only the wrapping
// key rotates. Both tables are usually small (record keys: one per person
// with files; value tokens: one per mapping), so a single pass suffices.
func (c *Contacts) rekeyVaults(ctx context.Context, newestKEK string, stats *RekeyStats) error {
	eng := c.PII.Engine()

	// Value tokens: re-seal the ciphertext.
	//
	// Rows are selected on a stale KEK **or** a legacy AAD layout: the AAD
	// migration (CRYPTO-4, binding the subject cid into the associated data)
	// converges here, on the sweep that already holds each row's plaintext.
	// Until a row is converted, it keeps opening under the layout it was
	// sealed with.
	newestValueKey, err := c.Ring.Newest(ctx, crypto.KeyHMACValue)
	if err != nil {
		return err
	}
	valueKeyVersion := crypto.KeyHMACValue + "/" + newestValueKey
	trows, err := c.Pool.Query(ctx,
		`SELECT token, scope, ciphertext, key_id, alg, cid, aad_v, token_type, unique_hash IS NOT NULL,
		        COALESCE(unique_key_version,'')
		   FROM value_tokens
		  WHERE key_id <> $1 OR aad_v < $2
		     OR (unique_hash IS NOT NULL AND COALESCE(unique_key_version,'') <> $3)
		     OR alg <> $4`,
		newestKEK, valueAADCurrent, valueKeyVersion, c.PII.Algorithm())
	if err != nil {
		return err
	}
	type vt struct {
		token, scope, keyID, alg string
		tokenType, uniqueVersion string
		cid                      *string
		aadV                     int16
		hasUnique                bool
		ct                       []byte
	}
	var vts []vt
	for trows.Next() {
		var t vt
		if err := trows.Scan(&t.token, &t.scope, &t.ct, &t.keyID, &t.alg, &t.cid, &t.aadV,
			&t.tokenType, &t.hasUnique, &t.uniqueVersion); err != nil { //coverage:defensive rows.Scan failure needs a DB fault injected at this exact statement
			trows.Close()
			return err
		}
		vts = append(vts, t)
	}
	trows.Close()
	if err := trows.Err(); err != nil { //coverage:defensive rows.Err failure needs a DB fault injected at this exact statement
		return err
	}
	for _, t := range vts {
		cid := ""
		if t.cid != nil {
			cid = *t.cid
		}
		// Open under the layout the row was SEALED with, re-seal under the
		// current one.
		plain, err := eng.Open(ctx, crypto.KeyPIIKEK+"/"+t.keyID, t.alg,
			valueAAD(t.aadV, t.scope, t.token, cid), t.ct)
		if err != nil {
			stats.Skipped++
			continue
		}
		// c.PII.Algorithm(), not a literal: RUNBOOK-ALG-MIGRATION exists to
		// move a fleet OFF a deprecated AEAD, and hard-coding aes256gcm here
		// left the F4 value vault and the crypto-shredding pivot for every
		// file on the old algorithm while the runbook's verification query
		// (which reads `cids` only) reported the migration complete
		// (DOCS-6).
		sealed, err := eng.Seal(ctx, crypto.KeyPIIKEK+"/"+newestKEK, c.PII.Algorithm(),
			valueAAD(valueAADCurrent, t.scope, t.token, cid), plain)
		if err != nil {
			return err
		}
		// Re-key the dedup hash on the same pass (CRYPTO-3): the plaintext
		// is in hand exactly here, and it is the only place it ever is - a
		// hash left under a superseded (or leaked, or retired) key version
		// silently breaks `unique:true` and keeps an offline dictionary
		// oracle alive over the value.
		var freshHash []byte
		freshVersion := t.uniqueVersion
		if t.hasUnique && t.uniqueVersion != valueKeyVersion {
			if freshHash, err = eng.MAC(ctx, valueKeyVersion,
				uniqueInput(t.scope, t.tokenType, string(plain))); err != nil {
				return err
			}
			freshVersion = valueKeyVersion
		}
		if _, err := c.Pool.Exec(ctx, `
			UPDATE value_tokens
			   SET ciphertext=$2, key_id=$3, alg=$7, aad_v=$4,
			       unique_hash = COALESCE($5, unique_hash),
			       unique_key_version = NULLIF($6,'')
			 WHERE token=$1`,
			t.token, sealed, newestKEK, valueAADCurrent, freshHash, freshVersion, c.PII.Algorithm()); err != nil {
			return err
		}
		stats.ValueTokensRewrapped++
	}

	// Record keys: re-wrap, AAD "record-key\0"+personID.
	rrows, err := c.Pool.Query(ctx,
		`SELECT person_id, wrapped, key_id, alg FROM person_record_keys
		  WHERE key_id <> $1 OR alg <> $2`, newestKEK, c.PII.Algorithm())
	if err != nil {
		return err
	}
	type rk struct {
		personID, keyID, alg string
		wrapped              []byte
	}
	var rks []rk
	for rrows.Next() {
		var r rk
		if err := rrows.Scan(&r.personID, &r.wrapped, &r.keyID, &r.alg); err != nil { //coverage:defensive rows.Scan failure needs a DB fault injected at this exact statement
			rrows.Close()
			return err
		}
		rks = append(rks, r)
	}
	rrows.Close()
	if err := rrows.Err(); err != nil { //coverage:defensive rows.Err failure needs a DB fault injected at this exact statement
		return err
	}
	for _, r := range rks {
		aad := []byte("record-key\x00" + r.personID)
		plain, err := eng.Open(ctx, crypto.KeyPIIKEK+"/"+r.keyID, r.alg, aad, r.wrapped)
		if err != nil {
			stats.Skipped++
			continue
		}
		// Configured algorithm, not a literal - the record key is the
		// crypto-shredding pivot for every file, so leaving it on a
		// deprecated AEAD is the opposite of what the migration is for
		// (DOCS-6).
		sealed, err := eng.Seal(ctx, crypto.KeyPIIKEK+"/"+newestKEK, c.PII.Algorithm(), aad, plain)
		if err != nil {
			return err
		}
		if _, err := c.Pool.Exec(ctx,
			`UPDATE person_record_keys SET wrapped=$2, key_id=$3, alg=$4 WHERE person_id=$1`,
			r.personID, sealed, newestKEK, c.PII.Algorithm()); err != nil {
			return err
		}
		stats.RecordKeysRewrapped++
	}

	// F6 version history is the same personal data one generation older
	// (migration 0027), so a retired KEK must not keep decrypting it either
	// (S5). Re-encrypt each version blob under the newest KEK. Version blobs
	// are cids-shaped (bound to their cid), so go through PII, not the raw
	// engine AAD path used for the wrapped keys above.
	// Selected on a stale KEK **or** a legacy AAD layout: the generation
	// binding (CRYPTO-5) converges on this sweep, which already decrypts
	// every version blob.
	vrows, err := c.Pool.Query(ctx,
		`SELECT cid, version_no, blob, key_id, alg, aad_v FROM cid_blob_versions
		  WHERE key_id <> $1 OR aad_v < $2`, newestKEK, versionAADCurrent)
	if err != nil {
		return err
	}
	type vv struct {
		cid, keyID, alg string
		versionNo       int64
		aadV            int16
		blob            []byte
	}
	var vvs []vv
	for vrows.Next() {
		var v vv
		if err := vrows.Scan(&v.cid, &v.versionNo, &v.blob, &v.keyID, &v.alg, &v.aadV); err != nil { //coverage:defensive rows.Scan failure needs a DB fault injected at this exact statement
			vrows.Close()
			return err
		}
		vvs = append(vvs, v)
	}
	vrows.Close()
	if err := vrows.Err(); err != nil { //coverage:defensive rows.Err failure needs a DB fault injected at this exact statement
		return err
	}
	for _, v := range vvs {
		// Open under the layout the row was SEALED with, re-seal under the
		// generation-discriminated one.
		attrs, err := c.PII.Decrypt(ctx, versionBoundTo(v.cid, v.versionNo, v.aadV), v.blob, v.keyID, v.alg)
		if err != nil {
			stats.Skipped++
			continue
		}
		fresh, err := c.PII.Encrypt(ctx, versionAAD(v.cid, v.versionNo), newestKEK, attrs)
		if err != nil {
			return err
		}
		if _, err := c.Pool.Exec(ctx,
			`UPDATE cid_blob_versions SET blob=$3, key_id=$4, alg=$5, aad_v=$6 WHERE cid=$1 AND version_no=$2`,
			v.cid, v.versionNo, fresh, newestKEK, c.PII.Algorithm(), versionAADCurrent); err != nil {
			return err
		}
		stats.VersionsRewrapped++
	}

	// portal_outbox.payload is sealed under pii-kek by the same PIIBox
	// (migration 0016, written AFTER this sweep), and nothing re-sealed it:
	// a retired or leaked KEK kept opening the data subject's PLAINTEXT
	// e-mail address plus - for a row still PENDING or SENDING - a live
	// portal login token, for the seven days PrunePortal keeps settled rows
	// (GAP-1). The sweep now covers every pii-kek-sealed store; the
	// information_schema guard test refuses a future table that is not here.
	orows, err := c.Pool.Query(ctx,
		`SELECT id, payload, key_id, alg FROM portal_outbox WHERE key_id <> $1`, newestKEK)
	if err != nil {
		return err
	}
	type ob struct {
		id         int64
		keyID, alg string
		payload    []byte
	}
	var obs []ob
	for orows.Next() {
		var o ob
		if err := orows.Scan(&o.id, &o.payload, &o.keyID, &o.alg); err != nil { //coverage:defensive rows.Scan failure needs a DB fault injected at this exact statement
			orows.Close()
			return err
		}
		obs = append(obs, o)
	}
	orows.Close()
	if err := orows.Err(); err != nil { //coverage:defensive rows.Err failure needs a DB fault injected at this exact statement
		return err
	}
	for _, o := range obs {
		plain, err := c.PII.OpenBytes(ctx, "portal-outbox", o.payload, o.keyID, o.alg)
		if err != nil {
			stats.Skipped++
			continue
		}
		sealed, err := c.PII.SealBytes(ctx, "portal-outbox", newestKEK, plain)
		if err != nil {
			return err
		}
		if _, err := c.Pool.Exec(ctx,
			`UPDATE portal_outbox SET payload=$2, key_id=$3, alg=$4 WHERE id=$1`,
			o.id, sealed, newestKEK, c.PII.Algorithm()); err != nil {
			return err
		}
		stats.OutboxRewrapped++
	}
	return nil
}
