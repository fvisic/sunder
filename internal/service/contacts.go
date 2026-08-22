// Package service implements Sunder's business logic on top of store,
// crypto and audit. Handlers stay thin; policy lives here.
package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/fvisic/sunder/internal/audit"
	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/crypto"
)

// Sentinel errors mapped to HTTP statuses by the API layer.
var (
	ErrNotFound          = errors.New("not found")
	ErrForbidden         = errors.New("forbidden")
	ErrPurposeNotAllowed = errors.New("purpose not allowed")
	ErrValidation        = errors.New("validation")
)

// Contacts covers registration, scoped CID issuance and attribute serving.
type Contacts struct {
	Pool *pgxpool.Pool
	Tok  *crypto.Tokenizer
	PII  *crypto.PIIBox
}

// RegisterInput carries the identifiers and the attributes to protect.
// Email/phone/name feed HMAC search tokens; Attributes go into the encrypted
// blob. Raw identifiers are also stored as attributes so systems can fetch
// them field-by-field later (decision D4).
type RegisterInput struct {
	Email      string            `json:"email"`
	Phone      string            `json:"phone"`
	Name       string            `json:"name"`
	Attributes map[string]string `json:"attributes"`
}

// Register creates (or reuses) a person and returns the caller-scope CID.
// Dedup: an existing person matched by email or phone token is reused, so
// re-registering the same contact from another system yields the same person
// with a different scoped CID.
func (c *Contacts) Register(ctx context.Context, client *auth.Client, in RegisterInput) (cid string, err error) {
	if !client.Can(auth.ActContactsRegister) {
		return "", ErrForbidden
	}
	if in.Email == "" && in.Phone == "" {
		return "", fmt.Errorf("%w: email or phone required", ErrValidation)
	}
	version := crypto.KeyVersions()[0]
	attrs := map[string]string{}
	for k, v := range in.Attributes {
		attrs[k] = v
	}

	var emailTok, phoneTok, nameTok string
	if in.Email != "" {
		norm, err := crypto.NormalizeEmail(in.Email)
		if err != nil {
			return "", fmt.Errorf("%w: %v", ErrValidation, err)
		}
		if emailTok, err = c.Tok.EmailToken(ctx, version, norm); err != nil {
			return "", err
		}
		attrs["email"] = norm
	}
	if in.Phone != "" {
		norm, err := crypto.NormalizePhone(in.Phone)
		if err != nil {
			return "", fmt.Errorf("%w: %v", ErrValidation, err)
		}
		if phoneTok, err = c.Tok.PhoneToken(ctx, version, norm); err != nil {
			return "", err
		}
		attrs["phone"] = norm
	}
	if in.Name != "" {
		norm, err := crypto.NormalizeName(in.Name)
		if err != nil {
			return "", fmt.Errorf("%w: %v", ErrValidation, err)
		}
		if nameTok, err = c.Tok.NameToken(ctx, version, norm); err != nil {
			return "", err
		}
		attrs["name"] = in.Name
	}

	blob, keyID, err := c.PII.Encrypt(ctx, attrs)
	if err != nil {
		return "", err
	}

	tx, err := c.Pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var personID string
	err = tx.QueryRow(ctx,
		`SELECT id FROM persons
		 WHERE (email_token = NULLIF($1,'')) OR (phone_token = NULLIF($2,'')) LIMIT 1`,
		emailTok, phoneTok).Scan(&personID)
	switch {
	case err == pgx.ErrNoRows:
		err = tx.QueryRow(ctx,
			`INSERT INTO persons (email_token, phone_token, name_token, pii_encrypted, pii_key_id)
			 VALUES (NULLIF($1,''), NULLIF($2,''), NULLIF($3,''), $4, $5) RETURNING id`,
			emailTok, phoneTok, nameTok, blob, keyID).Scan(&personID)
		if err != nil {
			return "", err
		}
	case err != nil:
		return "", err
	}

	cid, err = ensureCID(ctx, tx, personID, client.Scope)
	if err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	_ = audit.Append(ctx, c.Pool, audit.Entry{
		ClientID: client.ID, Action: "contacts.register", CID: cid,
		Detail: map[string]any{"scope": client.Scope},
	})
	return cid, nil
}

type execQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// ensureCID returns the person's CID for scope, creating one if absent.
func ensureCID(ctx context.Context, q execQuerier, personID, scope string) (string, error) {
	var cid string
	err := q.QueryRow(ctx,
		`SELECT cid FROM cids WHERE person_id=$1 AND scope=$2`, personID, scope).Scan(&cid)
	if err == nil {
		return cid, nil
	}
	if err != pgx.ErrNoRows {
		return "", err
	}
	fresh, err := crypto.NewCID()
	if err != nil {
		return "", err
	}
	// ON CONFLICT covers a concurrent insert of the same (person, scope).
	err = q.QueryRow(ctx,
		`INSERT INTO cids (cid, person_id, scope) VALUES ($1,$2,$3)
		 ON CONFLICT (person_id, scope) DO UPDATE SET scope=EXCLUDED.scope
		 RETURNING cid`, fresh, personID, scope).Scan(&cid)
	return cid, err
}

// IssueScopedCid gives the same person a pseudonym in another scope. The
// caller must own the source CID (its scope) and hold the scopes.issue action.
func (c *Contacts) IssueScopedCid(ctx context.Context, client *auth.Client, cid, targetScope string) (string, error) {
	if !client.Can(auth.ActScopesIssue) {
		return "", ErrForbidden
	}
	if targetScope == "" {
		return "", fmt.Errorf("%w: scope required", ErrValidation)
	}
	personID, err := c.personForClientCID(ctx, client, cid)
	if err != nil {
		return "", err
	}
	newCID, err := ensureCID(ctx, c.Pool, personID, targetScope)
	if err != nil {
		return "", err
	}
	_ = audit.Append(ctx, c.Pool, audit.Entry{
		ClientID: client.ID, Action: "scopes.issue", CID: cid,
		Detail: map[string]any{"target_scope": targetScope},
	})
	return newCID, nil
}

// personForClientCID resolves cid to its person, enforcing that the CID
// belongs to the caller's scope — a client can never reference another
// scope's pseudonyms (that unlinkability is the whole point).
func (c *Contacts) personForClientCID(ctx context.Context, client *auth.Client, cid string) (string, error) {
	var personID, scope string
	err := c.Pool.QueryRow(ctx,
		`SELECT person_id, scope FROM cids WHERE cid=$1`, cid).Scan(&personID, &scope)
	if err == pgx.ErrNoRows {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if scope != client.Scope {
		// Indistinguishable from absence: do not leak that a foreign CID exists.
		return "", ErrNotFound
	}
	return personID, nil
}

// GetAttribute returns exactly one decrypted field (decision D4): purpose is
// mandatory, checked against the caller's allowed purposes, and every fetch
// is audited. Keys never leave the service.
func (c *Contacts) GetAttribute(ctx context.Context, client *auth.Client, cid, name, purpose string) (string, error) {
	if !client.Can(auth.ActAttributesRead) {
		return "", ErrForbidden
	}
	if purpose == "" {
		return "", fmt.Errorf("%w: purpose required", ErrValidation)
	}
	if !client.CanUse(purpose) {
		return "", ErrPurposeNotAllowed
	}
	personID, err := c.personForClientCID(ctx, client, cid)
	if err != nil {
		return "", err
	}
	var blob []byte
	var keyID string
	err = c.Pool.QueryRow(ctx,
		`SELECT pii_encrypted, COALESCE(pii_key_id,'v1') FROM persons WHERE id=$1`, personID).
		Scan(&blob, &keyID)
	if err != nil {
		return "", err
	}
	_ = audit.Append(ctx, c.Pool, audit.Entry{
		ClientID: client.ID, Action: "attributes.read", CID: cid,
		Detail: map[string]any{"attribute": name, "purpose": purpose},
	})
	if len(blob) == 0 {
		return "", ErrNotFound
	}
	attrs, err := c.PII.Decrypt(ctx, blob, keyID)
	if err != nil {
		return "", err
	}
	val, ok := attrs[name]
	if !ok {
		return "", ErrNotFound
	}
	return val, nil
}
