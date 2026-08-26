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

	if stats.TokensInserted > 0 || stats.BlobsReenc > 0 || stats.ValueTokensRewrapped > 0 || stats.RecordKeysRewrapped > 0 {
		if err := audit.Append(ctx, c.Pool, audit.Entry{
			ClientID: "system", Action: "keys.rekey",
			Detail: map[string]any{
				"persons": stats.Persons, "tokens_inserted": stats.TokensInserted,
				"blobs_reencrypted": stats.BlobsReenc, "blobs_skipped": stats.Skipped,
				"value_tokens_rewrapped": stats.ValueTokensRewrapped,
				"record_keys_rewrapped":  stats.RecordKeysRewrapped,
			},
		}); err != nil {
			return stats, err
		}
	}
	return stats, nil
}

func (c *Contacts) rekeyPerson(ctx context.Context, personID string, newest map[string]string, newestKEK string, reencryptPII bool, stats *RekeyStats) error {
	rows, err := c.Pool.Query(ctx,
		`SELECT cid, COALESCE(pii_encrypted,''::bytea), COALESCE(pii_key_id,'v1'), COALESCE(pii_alg,'aes256gcm')
		 FROM cids WHERE person_id=$1`, personID)
	if err != nil {
		return err
	}
	type blobRow struct {
		cid   string
		blob  []byte
		keyID string
		alg   string
	}
	var blobs []blobRow
	for rows.Next() {
		var b blobRow
		if err := rows.Scan(&b.cid, &b.blob, &b.keyID, &b.alg); err != nil {
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
			tag, err := c.Pool.Exec(ctx,
				`UPDATE cids SET pii_encrypted=$2, pii_key_id=$3, pii_alg=$4
				 WHERE cid=$1 AND COALESCE(pii_key_id,'v1')=$5 AND COALESCE(pii_alg,'aes256gcm')=$6`,
				b.cid, fresh, newestKEK, c.PII.Algorithm(), b.keyID, b.alg)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 1 {
				stats.BlobsReenc++
			} else {
				stats.Skipped++
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
			tag, err := c.Pool.Exec(ctx,
				`INSERT INTO person_tokens (person_id, kind, token, key_version)
				 VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
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

	// Value tokens: re-seal the ciphertext, AAD "valtok\0"+scope+"\0"+token.
	trows, err := c.Pool.Query(ctx,
		`SELECT token, scope, ciphertext, key_id, alg FROM value_tokens WHERE key_id <> $1`, newestKEK)
	if err != nil {
		return err
	}
	type vt struct {
		token, scope, keyID, alg string
		ct                       []byte
	}
	var vts []vt
	for trows.Next() {
		var t vt
		if err := trows.Scan(&t.token, &t.scope, &t.ct, &t.keyID, &t.alg); err != nil {
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
		aad := []byte("valtok\x00" + t.scope + "\x00" + t.token)
		plain, err := eng.Open(ctx, crypto.KeyPIIKEK+"/"+t.keyID, t.alg, aad, t.ct)
		if err != nil {
			stats.Skipped++
			continue
		}
		sealed, err := eng.Seal(ctx, crypto.KeyPIIKEK+"/"+newestKEK, "aes256gcm", aad, plain)
		if err != nil {
			return err
		}
		if _, err := c.Pool.Exec(ctx,
			`UPDATE value_tokens SET ciphertext=$2, key_id=$3, alg='aes256gcm' WHERE token=$1`,
			t.token, sealed, newestKEK); err != nil {
			return err
		}
		stats.ValueTokensRewrapped++
	}

	// Record keys: re-wrap, AAD "record-key\0"+personID.
	rrows, err := c.Pool.Query(ctx,
		`SELECT person_id, wrapped, key_id, alg FROM person_record_keys WHERE key_id <> $1`, newestKEK)
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
		sealed, err := eng.Seal(ctx, crypto.KeyPIIKEK+"/"+newestKEK, "aes256gcm", aad, plain)
		if err != nil {
			return err
		}
		if _, err := c.Pool.Exec(ctx,
			`UPDATE person_record_keys SET wrapped=$2, key_id=$3, alg='aes256gcm' WHERE person_id=$1`,
			r.personID, sealed, newestKEK); err != nil {
			return err
		}
		stats.RecordKeysRewrapped++
	}
	return nil
}
