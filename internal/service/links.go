package service

// Sub-accounts as person links (Phase 3 / F7). A link is a relationship
// between two persons AS SEEN BY one scope - both endpoints must resolve
// in the caller's scope, so a link can never join persons across a scope
// boundary. It is metadata, not a merge: each person keeps its own blob,
// consents, audit trail and erasure lifecycle. Erasure of a parent lists
// linked children in the report but never cascades on its own; a cascade
// is an explicit per-request opt-in (see gdpr.Erase).

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/fvisic/sunder/internal/audit"
	"github.com/fvisic/sunder/internal/auth"
)

// Links manages person links.
type Links struct {
	Pool     *pgxpool.Pool
	Contacts *Contacts
}

// linkTypes is the closed set of relationship kinds.
var linkTypes = map[string]bool{"guardian": true, "member": true, "owner": true}

// LinkedCID is one endpoint in a link listing.
type LinkedCID struct {
	CID      string `json:"cid"`
	LinkType string `json:"link_type"`
	Role     string `json:"role"` // "child" or "parent" relative to the queried cid
}

// Link relates two cids the caller can resolve. parentCID is the parent
// (guardian/owner/account); childCID is the dependent.
func (l *Links) Link(ctx context.Context, client *auth.Client, parentCID, childCID, linkType string) error {
	if !client.Can(auth.ActLinksManage) {
		return ErrForbidden
	}
	if !linkTypes[linkType] {
		return fmt.Errorf("%w: link_type must be guardian, member or owner", ErrValidation)
	}
	if parentCID == childCID {
		return fmt.Errorf("%w: a person cannot be linked to itself", ErrValidation)
	}
	// Both endpoints must resolve in the caller's scope (no cross-scope
	// link, no oracle for a foreign cid).
	parent, err := l.Contacts.personForClientCID(ctx, client, parentCID)
	if err != nil {
		return err
	}
	child, err := l.Contacts.personForClientCID(ctx, client, childCID)
	if err != nil {
		return err
	}
	tx, err := l.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
		INSERT INTO person_links (parent_person, child_person, scope, link_type, created_by)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (parent_person, child_person, scope) DO UPDATE SET link_type = EXCLUDED.link_type`,
		parent, child, client.Scope, linkType, client.ID); err != nil {
		return err
	}
	if err := audit.AppendTx(ctx, tx, audit.Entry{
		ClientID: client.ID, Action: "links.link", CID: parentCID,
		Detail: map[string]any{"child": childCID, "type": linkType},
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Unlink removes a link (its scope's own only).
func (l *Links) Unlink(ctx context.Context, client *auth.Client, parentCID, childCID string) error {
	if !client.Can(auth.ActLinksManage) {
		return ErrForbidden
	}
	parent, err := l.Contacts.personForClientCID(ctx, client, parentCID)
	if err != nil {
		return err
	}
	child, err := l.Contacts.personForClientCID(ctx, client, childCID)
	if err != nil {
		return err
	}
	tx, err := l.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx,
		`DELETE FROM person_links WHERE parent_person=$1 AND child_person=$2 AND scope=$3`,
		parent, child, client.Scope)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if err := audit.AppendTx(ctx, tx, audit.Entry{
		ClientID: client.ID, Action: "links.unlink", CID: parentCID,
		Detail: map[string]any{"child": childCID},
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// List returns the cids linked to the given cid in the caller's scope,
// both as parent (its children) and as child (its parents).
func (l *Links) List(ctx context.Context, client *auth.Client, cid string) ([]LinkedCID, error) {
	if !client.Can(auth.ActLinksManage) {
		return nil, ErrForbidden
	}
	person, err := l.Contacts.personForClientCID(ctx, client, cid)
	if err != nil {
		return nil, err
	}
	// One query, both directions, resolving the OTHER person back to its
	// cid in this scope.
	rows, err := l.Pool.Query(ctx, `
		SELECT c.cid, pl.link_type, 'child' AS role
		  FROM person_links pl JOIN cids c ON c.person_id = pl.child_person AND c.scope = pl.scope
		 WHERE pl.parent_person = $1 AND pl.scope = $2
		UNION ALL
		SELECT c.cid, pl.link_type, 'parent' AS role
		  FROM person_links pl JOIN cids c ON c.person_id = pl.parent_person AND c.scope = pl.scope
		 WHERE pl.child_person = $1 AND pl.scope = $2
		 ORDER BY 1`, person, client.Scope)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LinkedCID{}
	for rows.Next() {
		var lc LinkedCID
		if err := rows.Scan(&lc.CID, &lc.LinkType, &lc.Role); err != nil {
			return nil, err
		}
		out = append(out, lc)
	}
	return out, rows.Err()
}
