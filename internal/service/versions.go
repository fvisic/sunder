package service

// Attribute blob versioning (Phase 3 / F6). When SUNDER_VERSIONS_KEEP is
// set, mergeIntoBlob appends the PREVIOUS blob to cid_blob_versions before
// overwriting it, so a mistaken update is inspectable and reversible.
// History is the same personal data one generation older: it is erased
// with the person and pruned by retention, and reading a version is a
// purpose-checked, audited read like any attribute disclosure.

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/fvisic/sunder/internal/audit"
	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/crypto"
)

// versionAADCurrent is the AAD layout new snapshots are sealed under.
// aad_v 1 is the legacy layout, where the snapshot was bound to the cid
// alone - i.e. to exactly the same associated data as the live blob.
const versionAADCurrent int16 = 2

// versionAAD is the generation-discriminated binding a snapshot is sealed
// to. Distinct from the live blob's binding (the bare cid) and distinct per
// generation, so no ciphertext can be transplanted between them.
func versionAAD(cid string, versionNo int64) string {
	return cid + "\x00v" + strconv.FormatInt(versionNo, 10)
}

// versionBoundTo returns the AAD subject for a stored snapshot, honouring
// the layout it was actually sealed under.
func versionBoundTo(cid string, versionNo int64, aadV int16) string {
	if aadV < 2 {
		return cid
	}
	return versionAAD(cid, versionNo)
}

// VersionMeta is one history entry (metadata only, never the values).
type VersionMeta struct {
	VersionNo int64     `json:"version_no"`
	WrittenBy string    `json:"written_by"`
	WrittenAt time.Time `json:"written_at"`
}

// appendVersion snapshots the current (about-to-be-overwritten) blob as the
// next version. Runs inside mergeIntoBlob's transaction so the snapshot and
// the overwrite commit together - history can never miss a generation nor
// record one that did not land. No-op when versioning is off or the row
// has no blob yet.
func (c *Contacts) appendVersion(ctx context.Context, tx pgx.Tx, cid, writtenBy string, oldAttrs map[string]string) error {
	if c.VersionsKeep == 0 || len(oldAttrs) == 0 {
		return nil
	}
	var next int64
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(max(version_no),0)+1 FROM cid_blob_versions WHERE cid=$1`, cid).Scan(&next); err != nil {
		return err
	}
	// RE-SEAL, never copy the bytes.
	//
	// A snapshot used to be the outgoing live blob stored verbatim with its
	// own key_id/alg - which made every generation and the live row AEAD
	// INTERCHANGEABLE for a given cid: writing an old cid_blob_versions.blob
	// (plus its key_id/alg) over cids.pii_encrypted decrypted perfectly,
	// silently rolling an Article 16 rectification back with no
	// cryptographic trace (CRYPTO-5). Binding the generation into the AAD
	// makes that transplant fail to open. The plaintext is already in hand
	// here - mergeIntoBlob decrypted it a moment ago - so this costs one
	// extra seal, inside the same transaction.
	keyID, err := c.Ring.Newest(ctx, crypto.KeyPIIKEK)
	if err != nil {
		return err
	}
	blob, err := c.PII.Encrypt(ctx, versionAAD(cid, next), keyID, oldAttrs)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO cid_blob_versions (cid, version_no, blob, key_id, alg, written_by, aad_v)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		cid, next, blob, keyID, c.PII.Algorithm(), writtenBy, versionAADCurrent); err != nil {
		return err
	}
	// Count-based cap: keep only the newest VersionsKeep rows (a positive
	// VersionsKeep is a count; time-based pruning is the retention sweep's
	// job). Delete anything older than the window.
	if c.VersionsKeep > 0 {
		if _, err := tx.Exec(ctx, `
			DELETE FROM cid_blob_versions
			 WHERE cid=$1 AND version_no <= ($2::bigint - $3::bigint)`,
			cid, next, int64(c.VersionsKeep)); err != nil {
			return err
		}
	}
	return nil
}

// ListVersions returns the history metadata for a cid the caller owns.
func (c *Contacts) ListVersions(ctx context.Context, client *auth.Client, cid string) ([]VersionMeta, error) {
	if !client.Can(auth.ActAttributesHistory) {
		return nil, ErrForbidden
	}
	if _, err := c.personForClientCID(ctx, client, cid); err != nil {
		return nil, err
	}
	// A metadata read is still a read: leave a trail, like every other read
	// path (L5).
	if err := audit.ReadEvent(ctx, c.Pool, audit.Entry{
		ClientID: client.ID, Action: "versions.list", CID: cid,
	}); err != nil {
		return nil, fmt.Errorf("audit append: %w", err)
	}
	rows, err := c.Pool.Query(ctx,
		`SELECT version_no, written_by, written_at FROM cid_blob_versions WHERE cid=$1 ORDER BY version_no DESC`, cid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []VersionMeta{}
	for rows.Next() {
		var m VersionMeta
		if err := rows.Scan(&m.VersionNo, &m.WrittenBy, &m.WrittenAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// GetVersionAttribute reads one attribute from one historical version:
// purpose-checked, consent-checked, allowlist-checked and audited exactly
// like a live attribute read - old data is still the person's data.
func (c *Contacts) GetVersionAttribute(ctx context.Context, client *auth.Client, cid string, versionNo int64, name, purpose string) (string, error) {
	if !client.Can(auth.ActAttributesHistory) {
		return "", ErrForbidden
	}
	if purpose == "" {
		return "", fmt.Errorf("%w: purpose required", ErrValidation)
	}
	if !client.CanUse(purpose) {
		return "", ErrPurposeNotAllowed
	}
	if !client.CanReadAttribute(name) {
		return "", ErrForbidden
	}
	if _, err := c.personForClientCID(ctx, client, cid); err != nil {
		return "", err
	}
	if denied, err := consentDenied(ctx, c.Pool, cid, purpose); err != nil {
		return "", err
	} else if denied {
		return "", ErrConsentDenied
	}
	var blob []byte
	var keyID, alg string
	var aadV int16
	err := c.Pool.QueryRow(ctx,
		`SELECT blob, key_id, alg, aad_v FROM cid_blob_versions WHERE cid=$1 AND version_no=$2`,
		cid, versionNo).Scan(&blob, &keyID, &alg, &aadV)
	if err == pgx.ErrNoRows {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	attrs, err := c.PII.Decrypt(ctx, versionBoundTo(cid, versionNo, aadV), blob, keyID, alg)
	if err != nil {
		return "", err
	}
	if err := audit.ReadEvent(ctx, c.Pool, audit.Entry{
		ClientID: client.ID, Action: "attributes.history", CID: cid,
		Detail: map[string]any{"attribute": name, "version": versionNo, "purpose": purpose},
	}); err != nil {
		return "", fmt.Errorf("audit append: %w", err)
	}
	v, ok := attrs[name]
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}

// PruneBlobVersions removes history older than the configured retention.
// Wired into `sunder retention run` when a version TTL is set.
func PruneBlobVersions(ctx context.Context, pool *pgxpool.Pool, olderThan time.Duration) (int64, error) {
	if olderThan <= 0 {
		return 0, nil
	}
	tag, err := pool.Exec(ctx,
		`DELETE FROM cid_blob_versions WHERE written_at < now() - $1::interval`, olderThan.String())
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
