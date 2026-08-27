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
	Purpose      string   `json:"purpose"`
	TTLSeconds   int64    `json:"ttl_seconds"`
}

// Create mints a share and returns its UUID. The caller must be able to
// read every listed field (the F3 allowlist applies) - a share cannot leak
// what its creator may not itself see.
func (s *Shares) Create(ctx context.Context, client *auth.Client, in ShareInput) (string, time.Time, error) {
	// A share discloses attribute values, so minting one is a delegated
	// read: the creator must be able to read (attributes.read) as well as
	// mint shares (shares.create). shares.create alone must not become a
	// way around the read gate.
	if !client.Can(auth.ActSharesCreate) || !client.Can(auth.ActAttributesRead) {
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
	if in.Purpose == "" {
		return "", time.Time{}, fmt.Errorf("%w: purpose required", ErrValidation)
	}
	if !client.CanUse(in.Purpose) {
		return "", time.Time{}, ErrPurposeNotAllowed
	}
	for _, f := range in.Fields {
		if !client.CanReadAttribute(f) {
			return "", time.Time{}, ErrForbidden
		}
	}
	if _, err := s.Contacts.personForClientCID(ctx, client, in.CID); err != nil {
		return "", time.Time{}, err
	}
	// Consent is checked at create (a share for a withdrawn purpose must not
	// be mintable) and again at every fetch below.
	if denied, err := consentDenied(ctx, s.Pool, in.CID, in.Purpose); err != nil {
		return "", time.Time{}, err
	} else if denied {
		return "", time.Time{}, ErrConsentDenied
	}
	id := newRandomUUID()
	var expiresAt time.Time
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return "", time.Time{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Liveness re-checked INSIDE the transaction, under erasePerson's own
	// row locks. personForClientCID above ran on the pool, and between it
	// and this INSERT sit a consent read and a BEGIN - an erasure landing
	// there ran deleteSharesForCID against a row that did not exist yet, so
	// a live, fetchable share carrying the forgotten person's pseudonym,
	// partner label, field names and purpose survived for up to 90 days
	// (GDPR-ERASURE-5). deleteSharesForCID deletes rather than revokes
	// precisely so no such row can linger.
	if _, err := lockPersonRows(ctx, tx, in.CID); err != nil {
		return "", time.Time{}, err
	}
	if err := tx.QueryRow(ctx, `
		INSERT INTO shared_records (uuid, cid, scope, fields, partner_label, expires_at, created_by, purpose)
		VALUES ($1,$2,$3,$4,$5, now() + make_interval(secs => $6), $7, $8) RETURNING expires_at`,
		id, in.CID, client.Scope, in.Fields, in.PartnerLabel, in.TTLSeconds, client.ID, in.Purpose).Scan(&expiresAt); err != nil {
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
		cid, scope, partner, purpose string
		fields                       []string
	)
	// The persons join is defence in depth: a share row that outlived its
	// subject's erasure - by the race above, or by any future path - answers
	// 404 like an absent one instead of 200 with the erased person's data.
	err := s.Pool.QueryRow(ctx, `
		SELECT sr.cid, sr.scope, sr.fields, sr.partner_label, sr.purpose FROM shared_records sr
		  JOIN cids c ON c.cid = sr.cid
		  JOIN persons p ON p.id = c.person_id AND p.erased_at IS NULL
		 WHERE sr.uuid=$1 AND sr.revoked_at IS NULL AND sr.expires_at > now()`,
		uuid).Scan(&cid, &scope, &fields, &partner, &purpose)
	if err == pgx.ErrNoRows {
		// A miss (absent, expired or revoked) is audited and indistinguishable.
		if err := audit.ReadEvent(ctx, s.Pool, audit.Entry{
			ClientID: actor, Action: "shares.fetch",
			Detail: map[string]any{"share": uuid, "matched": false},
		}); err != nil {
			return nil, fmt.Errorf("audit append: %w", err)
		}
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	// Re-check consent at fetch: a withdrawal after the share was minted
	// must block it immediately, not only once the async revoke runs. Audit
	// the miss like the absent/expired case (F2) so a consent-blocked fetch
	// leaves a trace and is timing-symmetric with the other miss paths.
	if denied, err := consentDenied(ctx, s.Pool, cid, purpose); err != nil {
		return nil, err
	} else if denied {
		if err := audit.ReadEvent(ctx, s.Pool, audit.Entry{
			ClientID: actor, Action: "shares.fetch",
			Detail: map[string]any{"share": uuid, "matched": false},
		}); err != nil {
			return nil, fmt.Errorf("audit append: %w", err)
		}
		return nil, ErrNotFound
	}
	// Read the person's blob directly (the share plus its consent check IS
	// the authorization) and project only the listed fields.
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

// revokeShares revokes the standing shares a consent withdrawal governs:
// exactly this cid's shares for exactly this purpose. Broader cleanup
// belongs to erasure (deleteSharesForCID), never to a consent flip.
func revokeShares(ctx context.Context, tx pgx.Tx, cid, purpose string) error {
	_, err := tx.Exec(ctx, `
		UPDATE shared_records SET revoked_at = now()
		 WHERE revoked_at IS NULL AND cid = $1 AND purpose = $2`, cid, purpose)
	return err
}

// deleteSharesForCID removes every share of a person on ERASURE - unlike a
// consent revoke, an erased person's pseudonym must not linger in the row at
// all (a "table survives Article 17" leak).
func deleteSharesForCID(ctx context.Context, tx pgx.Tx, personID string) error {
	_, err := tx.Exec(ctx,
		`DELETE FROM shared_records WHERE cid IN (SELECT cid FROM cids WHERE person_id=$1)`, personID)
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
