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
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/fvisic/sunder/internal/audit"
	"github.com/fvisic/sunder/internal/auth"
)

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
func (c *Contacts) appendVersion(ctx context.Context, tx pgx.Tx, cid, writtenBy string, oldBlob []byte, oldKeyID, oldAlg string) error {
	if c.VersionsKeep == 0 || len(oldBlob) == 0 {
		return nil
	}
	var next int64
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(max(version_no),0)+1 FROM cid_blob_versions WHERE cid=$1`, cid).Scan(&next); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO cid_blob_versions (cid, version_no, blob, key_id, alg, written_by)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		cid, next, oldBlob, oldKeyID, oldAlg, writtenBy); err != nil {
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
	err := c.Pool.QueryRow(ctx,
		`SELECT blob, key_id, alg FROM cid_blob_versions WHERE cid=$1 AND version_no=$2`,
		cid, versionNo).Scan(&blob, &keyID, &alg)
	if err == pgx.ErrNoRows {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	attrs, err := c.PII.Decrypt(ctx, cid, blob, keyID, alg)
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
