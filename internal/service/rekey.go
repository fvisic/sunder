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
	"fmt"
	"regexp"
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
	// Raced counts blobs a concurrent writer touched between this sweep's
	// read and its write. They were NOT converted and a rerun is required -
	// distinct from Skipped, which means "could not be decrypted at all"
	// (TOKENS-LOOKUP-2).
	Raced int64
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

	lastID := ""
	for {
		rows, err := c.Pool.Query(ctx,
			`SELECT id FROM persons WHERE erased_at IS NULL AND id::text > $1 ORDER BY id::text LIMIT $2`,
			lastID, batch)
		if err != nil {
			return stats, err
		}
		var ids []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return stats, err
			}
			ids = append(ids, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return stats, err
		}
		if len(ids) == 0 {
			break
		}
		for _, id := range ids {
			if err := c.rekeyPerson(ctx, id, newestByKind, newestKEK, reencryptPII, &stats); err != nil {
				return stats, fmt.Errorf("person %s: %w", id, err)
			}
			stats.Persons++
		}
		lastID = ids[len(ids)-1]
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

func (c *Contacts) rekeyPerson(ctx context.Context, personID string, newest map[string]string, newestKEK string, reencryptPII bool, stats *RekeyStats) error {
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
		if err := rows.Scan(&b.cid, &b.blob, &b.keyID, &b.alg, &b.updatedAt); err != nil {
			rows.Close()
			return err
		}
		blobs = append(blobs, b)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
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

	insert := func(rowKind string, values map[string]bool,
		tokFn func(ctx context.Context, version, normalized string) (string, error), version string) error {
		for v := range values {
			tok, err := tokFn(ctx, version, v)
			if err != nil {
				return err
			}
			// The liveness of the batch snapshot (rekey.go's person SELECT)
			// is arbitrarily stale by the time this runs - each person costs
			// several signer round trips. An erasure landing in that window
			// used to see its deleted search tokens RE-CREATED here, under
			// the newest key version, permanently: nothing deletes them
			// again, and they are immediately usable (GDPR-ERASURE-2). The
			// EXISTS makes liveness a per-write invariant.
			tag, err := c.Pool.Exec(ctx,
				`INSERT INTO person_tokens (person_id, kind, token, key_version)
				 SELECT $1,$2,$3,$4
				  WHERE EXISTS (SELECT 1 FROM persons WHERE id=$1 AND erased_at IS NULL)
				 ON CONFLICT (person_id, kind, token) DO NOTHING`,
				personID, rowKind, tok, version)
			if err != nil {
				return err
			}
			stats.TokensInserted += tag.RowsAffected()
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
			&t.tokenType, &t.hasUnique, &t.uniqueVersion); err != nil {
			trows.Close()
			return err
		}
		vts = append(vts, t)
	}
	trows.Close()
	if err := trows.Err(); err != nil {
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
		if err := rrows.Scan(&r.personID, &r.wrapped, &r.keyID, &r.alg); err != nil {
			rrows.Close()
			return err
		}
		rks = append(rks, r)
	}
	rrows.Close()
	if err := rrows.Err(); err != nil {
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
		if err := vrows.Scan(&v.cid, &v.versionNo, &v.blob, &v.keyID, &v.alg, &v.aadV); err != nil {
			vrows.Close()
			return err
		}
		vvs = append(vvs, v)
	}
	vrows.Close()
	if err := vrows.Err(); err != nil {
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
		if err := orows.Scan(&o.id, &o.payload, &o.keyID, &o.alg); err != nil {
			orows.Close()
			return err
		}
		obs = append(obs, o)
	}
	orows.Close()
	if err := orows.Err(); err != nil {
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
