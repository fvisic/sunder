// Package service implements Sunder's business logic on top of store,
// crypto and audit. Handlers stay thin; policy lives here.
package service

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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
// Email/phone/name feed HMAC search tokens; everything lands in the
// caller-scope encrypted blob. "email"/"phone"/"name" are reserved attribute
// names (the service stores the normalized identifiers under them) and are
// rejected inside Attributes to prevent planting unnormalized fakes.
type RegisterInput struct {
	Email      string            `json:"email"`
	Phone      string            `json:"phone"`
	Name       string            `json:"name"`
	Attributes map[string]string `json:"attributes"`
}

// PII blobs are stored per (person, scope) on the cids row: a scope reads
// exactly the attributes it stored itself. Global blobs would let any client
// with contacts.register dedup onto a person another scope registered and
// then read that scope's attributes — a cross-scope enrichment oracle.

// Register creates (or reuses) a person and returns the caller-scope CID.
// Dedup matches email token first, then phone (deterministic priority).
// On reuse, new attributes merge into the caller-scope blob (new values win)
// and missing identifier tokens are filled in.
func (c *Contacts) Register(ctx context.Context, client *auth.Client, in RegisterInput) (cid string, err error) {
	if !client.Can(auth.ActContactsRegister) {
		return "", ErrForbidden
	}
	if in.Email == "" && in.Phone == "" {
		return "", fmt.Errorf("%w: email or phone required", ErrValidation)
	}
	for _, reserved := range []string{"email", "phone", "name"} {
		if _, ok := in.Attributes[reserved]; ok {
			return "", fmt.Errorf("%w: %q is a reserved attribute name", ErrValidation, reserved)
		}
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

	// Retry once: a concurrent identical registration can win the unique-
	// index race; the second attempt then finds and reuses that person.
	for attempt := 0; ; attempt++ {
		cid, err = c.registerTx(ctx, client, emailTok, phoneTok, nameTok, attrs)
		if err == nil {
			break
		}
		var pgErr *pgconn.PgError
		if attempt == 0 && errors.As(err, &pgErr) && pgErr.Code == "23505" {
			continue
		}
		return "", err
	}
	// Fail closed: an unaudited mutation must not report success.
	if err := audit.Append(ctx, c.Pool, audit.Entry{
		ClientID: client.ID, Action: "contacts.register", CID: cid,
		Detail: map[string]any{"scope": client.Scope},
	}); err != nil {
		return "", fmt.Errorf("audit append: %w", err)
	}
	return cid, nil
}

func (c *Contacts) registerTx(ctx context.Context, client *auth.Client, emailTok, phoneTok, nameTok string, attrs map[string]string) (string, error) {
	tx, err := c.Pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Deterministic dedup: email match takes priority over phone.
	var personID string
	found := false
	if emailTok != "" {
		err = tx.QueryRow(ctx, `SELECT id FROM persons WHERE email_token=$1`, emailTok).Scan(&personID)
		if err != nil && err != pgx.ErrNoRows {
			return "", err
		}
		found = err == nil
	}
	if !found && phoneTok != "" {
		err = tx.QueryRow(ctx, `SELECT id FROM persons WHERE phone_token=$1`, phoneTok).Scan(&personID)
		if err != nil && err != pgx.ErrNoRows {
			return "", err
		}
		found = err == nil
	}

	if !found {
		personID = newUUID()
		if _, err := tx.Exec(ctx,
			`INSERT INTO persons (id, email_token, phone_token, name_token)
			 VALUES ($1, NULLIF($2,''), NULLIF($3,''), NULLIF($4,''))`,
			personID, emailTok, phoneTok, nameTok); err != nil {
			return "", err
		}
	} else {
		// Fill identifier tokens the person did not have yet; never overwrite
		// (an overwrite would silently re-key someone else's identifier).
		if _, err := tx.Exec(ctx,
			`UPDATE persons SET
			   email_token = COALESCE(email_token, NULLIF($2,'')),
			   phone_token = COALESCE(phone_token, NULLIF($3,'')),
			   name_token  = COALESCE(name_token,  NULLIF($4,''))
			 WHERE id=$1`, personID, emailTok, phoneTok, nameTok); err != nil {
			return "", err
		}
	}

	cid, err := ensureCID(ctx, tx, personID, client.Scope)
	if err != nil {
		return "", err
	}

	// Merge into the caller-scope blob: new values win, old ones survive.
	var oldBlob []byte
	var oldKeyID string
	err = tx.QueryRow(ctx,
		`SELECT pii_encrypted, COALESCE(pii_key_id,'v1') FROM cids WHERE cid=$1`, cid).Scan(&oldBlob, &oldKeyID)
	if err != nil {
		return "", err
	}
	if len(oldBlob) > 0 {
		old, err := c.PII.Decrypt(ctx, cid, oldBlob, oldKeyID)
		if err != nil {
			return "", err
		}
		for k, v := range attrs {
			old[k] = v
		}
		attrs = old
	}
	blob, keyID, err := c.PII.Encrypt(ctx, cid, attrs)
	if err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE cids SET pii_encrypted=$2, pii_key_id=$3 WHERE cid=$1`, cid, blob, keyID); err != nil {
		return "", err
	}
	return cid, tx.Commit(ctx)
}

// newUUID returns a random RFC 4122 v4 UUID (stdlib-only).
func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // the kernel CSPRNG failing is not a recoverable state
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
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

// IssueScopedCid gives the same person a pseudonym in another scope.
//
// SECURITY NOTE: this is deliberately a linkage-capable privilege — the
// caller learns the target scope's CID for a person it knows. Grant
// scopes.issue only to trusted integration components; day-to-day
// cross-system handoff should use OTIs instead (PLAN section 6), where the
// verifier learns its own CID and the issuer learns nothing.
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
	if err := audit.Append(ctx, c.Pool, audit.Entry{
		ClientID: client.ID, Action: "scopes.issue", CID: cid,
		Detail: map[string]any{"target_scope": targetScope},
	}); err != nil {
		return "", fmt.Errorf("audit append: %w", err)
	}
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
// mandatory, checked against the caller's allowed purposes, the blob is the
// caller-scope one, and the read is audited BEFORE the value is released —
// an unaudited disclosure must not happen (fail closed).
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
	var blob []byte
	var keyID string
	err := c.Pool.QueryRow(ctx,
		`SELECT pii_encrypted, COALESCE(pii_key_id,'v1') FROM cids WHERE cid=$1 AND scope=$2`,
		cid, client.Scope).Scan(&blob, &keyID)
	if err == pgx.ErrNoRows {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if err := audit.Append(ctx, c.Pool, audit.Entry{
		ClientID: client.ID, Action: "attributes.read", CID: cid,
		Detail: map[string]any{"attribute": name, "purpose": purpose},
	}); err != nil {
		return "", fmt.Errorf("audit append: %w", err)
	}
	if len(blob) == 0 {
		return "", ErrNotFound
	}
	attrs, err := c.PII.Decrypt(ctx, cid, blob, keyID)
	if err != nil {
		return "", err
	}
	val, ok := attrs[name]
	if !ok {
		return "", ErrNotFound
	}
	return val, nil
}
