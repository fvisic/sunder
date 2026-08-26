package service

// Shared records (Phase 3 / F8). A share is an expiring, revocable,
// read-only projection of a few named attributes of one person, addressed
// by an unguessable UUID and handed to an external partner. Narrower than a
// scoped pseudonym in every dimension: only the listed fields, only until
// expiry, revocable by the creator or automatically when the person is
// erased or withdraws consent. Every fetch is audited with the partner
// label so a leak is attributable.

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/fvisic/sunder/internal/audit"
	"github.com/fvisic/sunder/internal/auth"
)

// maxShareFields bounds one share; a share is a handful of fields for a
// partner, not a bulk export channel.
const maxShareFields = 32

// Shares creates and reads shared records.
type Shares struct {
	Pool     *pgxpool.Pool
	Contacts *Contacts
}

// ShareInput describes a share to create.
type ShareInput struct {
	CID          string   `json:"cid"`
	Fields       []string `json:"fields"`
	PartnerLabel string   `json:"partner_label"`
	TTLSeconds   int64    `json:"ttl_seconds"`
}

// Create mints a share and returns its UUID. The caller must be able to
// read every listed field (the F3 allowlist applies) - a share cannot leak
// what its creator may not itself see.
func (s *Shares) Create(ctx context.Context, client *auth.Client, in ShareInput) (string, time.Time, error) {
	if !client.Can(auth.ActSharesCreate) {
		return "", time.Time{}, ErrForbidden
	}
	if len(in.Fields) == 0 || len(in.Fields) > maxShareFields {
		return "", time.Time{}, fmt.Errorf("%w: 1-%d fields required", ErrValidation, maxShareFields)
	}
	if in.PartnerLabel == "" || len(in.PartnerLabel) > 128 {
		return "", time.Time{}, fmt.Errorf("%w: partner_label required (max 128 chars)", ErrValidation)
	}
	if in.TTLSeconds <= 0 || in.TTLSeconds > 90*24*3600 {
		return "", time.Time{}, fmt.Errorf("%w: ttl_seconds must be 1..90 days", ErrValidation)
	}
	for _, f := range in.Fields {
		if !client.CanReadAttribute(f) {
			return "", time.Time{}, ErrForbidden
		}
	}
	if _, err := s.Contacts.personForClientCID(ctx, client, in.CID); err != nil {
		return "", time.Time{}, err
	}
	id := newRandomUUID()
	var expiresAt time.Time
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return "", time.Time{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := tx.QueryRow(ctx, `
		INSERT INTO shared_records (uuid, cid, scope, fields, partner_label, expires_at, created_by)
		VALUES ($1,$2,$3,$4,$5, now() + make_interval(secs => $6), $7) RETURNING expires_at`,
		id, in.CID, client.Scope, in.Fields, in.PartnerLabel, in.TTLSeconds, client.ID).Scan(&expiresAt); err != nil {
		return "", time.Time{}, err
	}
	if err := audit.AppendTx(ctx, tx, audit.Entry{
		ClientID: client.ID, Action: "shares.create", CID: in.CID,
		Detail: map[string]any{"share": id, "partner": in.PartnerLabel, "fields": in.Fields},
	}); err != nil {
		return "", time.Time{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", time.Time{}, err
	}
	return id, expiresAt, nil
}

// Fetch returns the shared fields for a live (unexpired, unrevoked) share.
// actor labels the reader in the audit trail - a client id, or "public" for
// a credential-less fetch. Every fetch (hit or miss) is audited with the
// partner label so a leak is attributable.
func (s *Shares) Fetch(ctx context.Context, actor, uuid string) (map[string]string, error) {
	var (
		cid, scope, partner string
		fields              []string
	)
	err := s.Pool.QueryRow(ctx, `
		SELECT cid, scope, fields, partner_label FROM shared_records
		 WHERE uuid=$1 AND revoked_at IS NULL AND expires_at > now()`,
		uuid).Scan(&cid, &scope, &fields, &partner)
	if err == pgx.ErrNoRows {
		// A miss (absent, expired or revoked) is audited and indistinguishable.
		_ = audit.ReadEvent(ctx, s.Pool, audit.Entry{
			ClientID: actor, Action: "shares.fetch",
			Detail: map[string]any{"share": uuid, "matched": false},
		})
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	// Read the person's blob directly (no client - the share IS the
	// authorization) and project only the listed fields.
	attrs, err := s.Contacts.decryptCID(ctx, cid)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, f := range fields {
		if v, ok := attrs[f]; ok {
			out[f] = v
		}
	}
	// Audit BEFORE release, carrying the partner label.
	if err := audit.ReadEvent(ctx, s.Pool, audit.Entry{
		ClientID: actor, Action: "shares.fetch", CID: cid,
		Detail: map[string]any{"share": uuid, "partner": partner, "matched": true},
	}); err != nil {
		return nil, fmt.Errorf("audit append: %w", err)
	}
	return out, nil
}

// Revoke marks a share revoked (its scope's own only).
func (s *Shares) Revoke(ctx context.Context, client *auth.Client, uuid string) error {
	if !client.Can(auth.ActSharesCreate) {
		return ErrForbidden
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx,
		`UPDATE shared_records SET revoked_at = now()
		  WHERE uuid=$1 AND scope=$2 AND revoked_at IS NULL`,
		uuid, client.Scope)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if err := audit.AppendTx(ctx, tx, audit.Entry{
		ClientID: client.ID, Action: "shares.revoke",
		Detail: map[string]any{"share": uuid},
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// revokeSharesForCID revokes every standing share of a person - called when
// the person is erased or withdraws consent, so a share never outlives the
// data it points at. Runs inside the caller's transaction.
func revokeSharesForCID(ctx context.Context, tx pgx.Tx, personID string) error {
	_, err := tx.Exec(ctx, `
		UPDATE shared_records SET revoked_at = now()
		 WHERE revoked_at IS NULL AND cid IN (SELECT cid FROM cids WHERE person_id=$1)`, personID)
	return err
}

// PruneShares removes long-expired shares (operational state; the audit
// chain keeps the create/revoke/fetch record). Wired into retention.
func PruneShares(ctx context.Context, pool *pgxpool.Pool) (int64, error) {
	tag, err := pool.Exec(ctx,
		`DELETE FROM shared_records WHERE expires_at < now() - interval '30 days'`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
