// Package service implements Sunder's business logic on top of store,
// crypto and audit. Handlers stay thin; policy lives here.
package service

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"regexp"
	"strings"

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
	Ring *KeyRing
}

// tokensAllVersions computes the token under every live version of kind,
// newest first - writes use [0], matches use the whole set (rotation window).
func (c *Contacts) tokensAllVersions(ctx context.Context, kind, normalized string,
	f func(ctx context.Context, version, normalized string) (string, error)) ([]string, error) {
	versions, err := c.Ring.Versions(ctx, kind)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(versions))
	for _, v := range versions {
		tok, err := f(ctx, v, normalized)
		if err != nil {
			return nil, err
		}
		out = append(out, tok)
	}
	return out, nil
}

// RegisterInput carries the identifiers and the attributes to protect.
// A contact can have several searchable emails and phones: the singular
// fields and the plural lists merge (singular first = primary). All feed
// HMAC search tokens; everything lands in the caller-scope encrypted blob.
// "email"/"phone"/"name" and the generated "email_N"/"phone_N" are reserved
// attribute names (the service stores the normalized identifiers under
// them) and are rejected inside Attributes to prevent planting
// unnormalized fakes.
type RegisterInput struct {
	Email      string            `json:"email"`
	Emails     []string          `json:"emails"`
	Phone      string            `json:"phone"`
	Phones     []string          `json:"phones"`
	Name       string            `json:"name"`
	Attributes map[string]string `json:"attributes"`
}

var reservedAttr = regexp.MustCompile(`^(email|phone|name)$|^(email|phone)_[0-9]+$`)

// identSet is one kind's tokenized identifiers, ready for SQL.
type identSet struct {
	matchToks []string // every identifier under every live key version (dedup/lookup)
	writeToks []string // one newest-version token per identifier (rows to insert)
	writeVer  string
}

// buildIdents normalizes and tokenizes values of one kind.
func (c *Contacts) buildIdents(ctx context.Context, kind string, values []string,
	normFn func(string) (string, error),
	tokFn func(ctx context.Context, version, normalized string) (string, error)) (identSet, []string, error) {

	var set identSet
	if len(values) == 0 {
		return set, nil, nil
	}
	versions, err := c.Ring.Versions(ctx, kind)
	if err != nil {
		return set, nil, err
	}
	newest, err := c.Ring.Newest(ctx, kind)
	if err != nil {
		return set, nil, err
	}
	set.writeVer = newest
	var normalized []string
	seen := map[string]bool{}
	for _, v := range values {
		norm, err := normFn(v)
		if err != nil {
			return set, nil, fmt.Errorf("%w: %v", ErrValidation, err)
		}
		if seen[norm] {
			continue
		}
		seen[norm] = true
		normalized = append(normalized, norm)
		for _, ver := range versions {
			tok, err := tokFn(ctx, ver, norm)
			if err != nil {
				return set, nil, err
			}
			set.matchToks = append(set.matchToks, tok)
			if ver == newest {
				set.writeToks = append(set.writeToks, tok)
			}
		}
	}
	return set, normalized, nil
}

// PII blobs are stored per (person, scope) on the cids row: a scope reads
// exactly the attributes it stored itself. Global blobs would let any client
// with contacts.register dedup onto a person another scope registered and
// then read that scope's attributes - a cross-scope enrichment oracle.

// Register creates (or reuses) a person and returns the caller-scope CID.
// Dedup matches email token first, then phone (deterministic priority).
// On reuse, new attributes merge into the caller-scope blob (new values win)
// and missing identifier tokens are filled in.
func (c *Contacts) Register(ctx context.Context, client *auth.Client, in RegisterInput) (cid string, err error) {
	if !client.Can(auth.ActContactsRegister) {
		return "", ErrForbidden
	}
	emails := mergeValues(in.Email, in.Emails)
	phones := mergeValues(in.Phone, in.Phones)
	if len(emails) == 0 && len(phones) == 0 {
		return "", fmt.Errorf("%w: at least one email or phone required", ErrValidation)
	}
	for k := range in.Attributes {
		if reservedAttr.MatchString(k) {
			return "", fmt.Errorf("%w: %q is a reserved attribute name", ErrValidation, k)
		}
		// '@' namespaces external-issuer provenance (claims.external): a
		// self-registered "age_gte_18@gov.wallet" would forge attestation.
		if strings.ContainsRune(k, '@') {
			return "", fmt.Errorf("%w: attribute names must not contain '@' (reserved for external claims)", ErrValidation)
		}
	}
	attrs := map[string]string{}
	for k, v := range in.Attributes {
		attrs[k] = v
	}

	emailSet, emailNorm, err := c.buildIdents(ctx, crypto.KeyHMACEmail, emails, crypto.NormalizeEmail, c.Tok.EmailToken)
	if err != nil {
		return "", err
	}
	phoneSet, phoneNorm, err := c.buildIdents(ctx, crypto.KeyHMACPhone, phones, crypto.NormalizePhone, c.Tok.PhoneToken)
	if err != nil {
		return "", err
	}
	var nameSet identSet
	if in.Name != "" {
		if nameSet, _, err = c.buildIdents(ctx, crypto.KeyHMACName, []string{in.Name}, crypto.NormalizeName, c.Tok.NameToken); err != nil {
			return "", err
		}
		attrs["name"] = in.Name
	}
	storeIndexed(attrs, "email", emailNorm)
	storeIndexed(attrs, "phone", phoneNorm)

	// Retry once: a concurrent identical registration can win the unique-
	// index race; the second attempt then finds and reuses that person.
	for attempt := 0; ; attempt++ {
		cid, err = c.registerTx(ctx, client, emailSet, phoneSet, nameSet, attrs)
		if err == nil {
			break
		}
		var pgErr *pgconn.PgError
		if attempt == 0 && errors.As(err, &pgErr) && pgErr.Code == "23505" {
			continue
		}
		return "", err
	}
	return cid, nil
}

// mergeValues combines the singular (primary, first) and plural forms,
// dropping empties.
func mergeValues(single string, many []string) []string {
	out := make([]string, 0, 1+len(many))
	if single != "" {
		out = append(out, single)
	}
	for _, v := range many {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// storeIndexed writes normalized identifiers as "email", "email_2", ...
func storeIndexed(attrs map[string]string, base string, values []string) {
	for i, v := range values {
		key := base
		if i > 0 {
			key = fmt.Sprintf("%s_%d", base, i+1)
		}
		attrs[key] = v
	}
}

func (c *Contacts) registerTx(ctx context.Context, client *auth.Client, emailSet, phoneSet, nameSet identSet, attrs map[string]string) (string, error) {
	tx, err := c.Pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Deterministic dedup: email match takes priority over phone. Matching
	// spans every identifier under every live key version.
	var personID string
	found := false
	for _, probe := range []struct {
		kind string
		toks []string
	}{{"email", emailSet.matchToks}, {"phone", phoneSet.matchToks}} {
		if found || len(probe.toks) == 0 {
			continue
		}
		err = tx.QueryRow(ctx,
			`SELECT person_id FROM person_tokens WHERE kind=$1 AND token = ANY($2)
			 ORDER BY created_at, person_id LIMIT 1`, probe.kind, probe.toks).Scan(&personID)
		if err != nil && err != pgx.ErrNoRows {
			return "", err
		}
		found = err == nil
	}

	if !found {
		personID = newUUID()
		if _, err := tx.Exec(ctx, `INSERT INTO persons (id) VALUES ($1)`, personID); err != nil {
			return "", err
		}
	}
	// Insert newest-version token rows for every identifier. ON CONFLICT DO
	// NOTHING covers both "row already there" and "identifier owned by
	// another person" - an existing owner is never silently stolen.
	for _, ins := range []struct {
		kind string
		set  identSet
	}{{"email", emailSet}, {"phone", phoneSet}, {"name", nameSet}} {
		for _, tok := range ins.set.writeToks {
			if _, err := tx.Exec(ctx,
				`INSERT INTO person_tokens (person_id, kind, token, key_version)
				 VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
				personID, ins.kind, tok, ins.set.writeVer); err != nil {
				return "", err
			}
		}
	}

	cid, err := ensureCID(ctx, tx, personID, client.Scope)
	if err != nil {
		return "", err
	}

	if err := c.mergeIntoBlob(ctx, tx, cid, attrs); err != nil {
		return "", err
	}
	// Audit inside the same transaction: the registration and its record
	// commit together (fail closed).
	if err := audit.AppendTx(ctx, tx, audit.Entry{
		ClientID: client.ID, Action: "contacts.register", CID: cid,
		Detail: map[string]any{"scope": client.Scope},
	}); err != nil {
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
// SECURITY NOTE: this is deliberately a linkage-capable privilege - the
// caller learns the target scope's CID for a person it knows. Grant
// scopes.issue only to trusted integration components; day-to-day
// cross-system handoff should use OTIs instead (docs/DESIGN.md), where the
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
	tx, err := c.Pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	newCID, err := ensureCID(ctx, tx, personID, targetScope)
	if err != nil {
		return "", err
	}
	if err := audit.AppendTx(ctx, tx, audit.Entry{
		ClientID: client.ID, Action: "scopes.issue", CID: cid,
		Detail: map[string]any{"target_scope": targetScope},
	}); err != nil {
		return "", fmt.Errorf("audit append: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return newCID, nil
}

// personForClientCID resolves cid to its person, enforcing that the CID
// belongs to the caller's scope - a client can never reference another
// scope's pseudonyms (that unlinkability is the whole point).
func (c *Contacts) personForClientCID(ctx context.Context, client *auth.Client, cid string) (string, error) {
	var personID, scope string
	var erased bool
	err := c.Pool.QueryRow(ctx,
		`SELECT c.person_id, c.scope, p.erased_at IS NOT NULL
		 FROM cids c JOIN persons p ON p.id = c.person_id
		 WHERE c.cid=$1`, cid).Scan(&personID, &scope, &erased)
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
	// A tombstoned person is gone for every caller-facing path. Erasure
	// keeps the cids row (the pseudonym must never be reissued), so without
	// this check any path addressing the row by CID - attribute reads, OTI
	// issuance, consent, external claims - could write or serve data for a
	// person who exercised Article 17. Indistinguishable from absence.
	if erased {
		return "", ErrNotFound
	}
	return personID, nil
}

// GetAttribute returns exactly one decrypted field: purpose is
// mandatory, checked against the caller's allowed purposes, the blob is the
// caller-scope one, and the read is audited BEFORE the value is released -
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
	// Scope ownership FIRST: the consent hook must never run on a raw
	// caller-supplied CID, or the 403/404 split becomes an oracle revealing
	// that a foreign CID exists and what its consent state is.
	var blob []byte
	var keyID, alg string
	err := c.Pool.QueryRow(ctx,
		`SELECT pii_encrypted, COALESCE(pii_key_id,'v1'), COALESCE(pii_alg,'aes256gcm') FROM cids WHERE cid=$1 AND scope=$2`,
		cid, client.Scope).Scan(&blob, &keyID, &alg)
	if err == pgx.ErrNoRows {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	// Consent hook (v1.5): an explicit granted=false decision blocks the
	// purpose even though the client is allowed to use it in general.
	// Runs only after the scope check above proved ownership.
	if denied, err := consentDenied(ctx, c.Pool, cid, purpose); err != nil {
		return "", err
	} else if denied {
		return "", ErrConsentDenied
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
	attrs, err := c.PII.Decrypt(ctx, cid, blob, keyID, alg)
	if err != nil {
		return "", err
	}
	val, ok := attrs[name]
	if !ok {
		return "", ErrNotFound
	}
	return val, nil
}

// mergeIntoBlob merges attrs into the cid's scope blob: new values win, old
// ones survive, and the result is always re-encrypted under the newest
// ACTIVE pii-kek and the configured algorithm - rotation and algorithm
// migration complete on touch, old rows stay decryptable via their stored
// pii_key_id/pii_alg.
func (c *Contacts) mergeIntoBlob(ctx context.Context, tx pgx.Tx, cid string, attrs map[string]string) error {
	var oldBlob []byte
	var oldKeyID, oldAlg string
	// FOR UPDATE: two concurrent merges onto the same row (dedup is the
	// whole point of this path) must serialize, or the first writer's
	// attributes are silently lost (review finding F2).
	err := tx.QueryRow(ctx,
		`SELECT pii_encrypted, COALESCE(pii_key_id,'v1'), COALESCE(pii_alg,'aes256gcm') FROM cids WHERE cid=$1 FOR UPDATE`,
		cid).Scan(&oldBlob, &oldKeyID, &oldAlg)
	if err != nil {
		return err
	}
	if len(oldBlob) > 0 {
		old, err := c.PII.Decrypt(ctx, cid, oldBlob, oldKeyID, oldAlg)
		if err != nil {
			return err
		}
		for k, v := range attrs {
			old[k] = v
		}
		attrs = old
	}
	keyID, err := c.Ring.Newest(ctx, crypto.KeyPIIKEK)
	if err != nil {
		return err
	}
	blob, err := c.PII.Encrypt(ctx, cid, keyID, attrs)
	if err != nil {
		return err
	}
	// A blob past this size would eventually exceed the signer IPC frame
	// cap and brick every crypto op on the row - refuse the write instead.
	if len(blob) > maxBlobBytes {
		return fmt.Errorf("%w: attribute blob exceeds %d bytes", ErrValidation, maxBlobBytes)
	}
	_, err = tx.Exec(ctx,
		`UPDATE cids SET pii_encrypted=$2, pii_key_id=$3, pii_alg=$4, updated_at=now() WHERE cid=$1`,
		cid, blob, keyID, c.PII.Algorithm())
	return err
}

// maxBlobBytes caps a scope blob far below the 4 MiB signer frame limit.
const maxBlobBytes = 256 * 1024
