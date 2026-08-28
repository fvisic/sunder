// Package service implements Sunder's business logic on top of store,
// crypto and audit. Handlers stay thin; policy lives here.
package service

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"unicode/utf8"

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
	// Derived search indexes (Phase 3 F1/F2), off by default: each widens
	// the search surface, so enabling is a per-deployment decision
	// (SUNDER_SEARCH_FUZZY_NAME / SUNDER_SEARCH_PHONE_SUFFIX). Turning
	// them on later backfills existing contacts via `sunder keys rekey`.
	FuzzyName   bool
	PhoneSuffix bool
	// VersionsKeep > 0 keeps that many prior blob versions per cid (F6);
	// 0 = off. Set from SUNDER_VERSIONS_KEEP.
	VersionsKeep int
	// WrittenBy labels version rows with the operating client id; set per
	// call is impractical, so mergeIntoBlob passes the client through.

	// Log receives the rekey sweep's progress. Optional: nil falls back to
	// slog.Default(), the same shape GDPR uses.
	Log *slog.Logger
}

func (c *Contacts) logger() *slog.Logger {
	if c.Log != nil {
		return c.Log
	}
	return slog.Default()
}

// mintDerived tokenizes pre-derived values (phonetic codes, suffixes)
// under the newest version of kind - derived kinds are write-and-match by
// exact token, so no per-version match set is needed at registration.
func (c *Contacts) mintDerived(ctx context.Context, kind string, values []string,
	tokFn func(ctx context.Context, version, value string) (string, error)) (identSet, error) {
	var set identSet
	if len(values) == 0 {
		return set, nil
	}
	newest, err := c.Ring.Newest(ctx, kind)
	if err != nil {
		return set, err
	}
	set.writeVer = newest
	seen := map[string]bool{}
	for _, v := range values {
		if seen[v] {
			continue
		}
		seen[v] = true
		tok, err := tokFn(ctx, newest, v)
		if err != nil {
			return set, err
		}
		set.writeToks = append(set.writeToks, tok)
	}
	return set, nil
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
	var nameSet, phoneticSet, suffixSet identSet
	if in.Name != "" {
		var nameNorm []string
		if nameSet, nameNorm, err = c.buildIdents(ctx, crypto.KeyHMACName, []string{in.Name}, crypto.NormalizeName, c.Tok.NameToken); err != nil {
			return "", err
		}
		attrs["name"] = in.Name
		if c.FuzzyName && len(nameNorm) > 0 {
			if phoneticSet, err = c.mintDerived(ctx, crypto.KeyHMACName,
				crypto.PhoneticNameCodes(nameNorm[0]), c.Tok.NamePhoneticToken); err != nil {
				return "", err
			}
		}
	}
	if c.PhoneSuffix && len(phoneNorm) > 0 {
		suffixes := make([]string, 0, len(phoneNorm))
		for _, ph := range phoneNorm {
			suffixes = append(suffixes, crypto.PhoneSuffix(ph))
		}
		if suffixSet, err = c.mintDerived(ctx, crypto.KeyHMACPhone, suffixes, c.Tok.PhoneSuffixToken); err != nil {
			return "", err
		}
	}
	storeIndexed(attrs, "email", emailNorm)
	storeIndexed(attrs, "phone", phoneNorm)

	// A concurrent identical registration can win the unique-index race; the
	// loser's transaction aborts on person_tokens_ident_uq and the next
	// attempt finds and reuses that person. More than two writers can pile
	// up on the same identifier (a fanned-out queue redelivery), so the
	// budget is not one - but it IS finite, and exhausting it is an error
	// rather than a silently duplicated person.
	for attempt := 0; ; attempt++ {
		cid, err = c.registerTx(ctx, client, emailSet, phoneSet, nameSet, phoneticSet, suffixSet, attrs)
		if err == nil {
			return cid, nil
		}
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
			return "", err
		}
		if attempt+1 >= registerDedupRetries {
			return "", fmt.Errorf("register: identifier contended by %d concurrent registrations: %w",
				registerDedupRetries, err)
		}
	}
}

// registerDedupRetries bounds the dedup race retry. Each retry re-runs the
// probe, so a loser converges on the winner in one; the extra budget covers a
// pile-up of concurrent writers on the same identifier.
const registerDedupRetries = 5

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

func (c *Contacts) registerTx(ctx context.Context, client *auth.Client, emailSet, phoneSet, nameSet, phoneticSet, suffixSet identSet, attrs map[string]string) (string, error) {
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
	// Insert newest-version token rows for every identifier.
	//
	// The conflict clause depends on whether the dedup probe found an owner,
	// because an unarbitrated ON CONFLICT DO NOTHING expresses two different
	// intents at once and only one of them is ever right:
	//
	//   found == true - we are merging into an existing person. A secondary
	//     identifier that belongs to somebody ELSE (the documented ambiguous
	//     claim: A's e-mail plus B's phone resolves to A by e-mail priority)
	//     must be left with its owner, not stolen and not fatal. The
	//     unarbitrated clause is exactly right: skip that row, keep going.
	//
	//   found == false - we are minting a NEW person off a dedup probe that
	//     said nobody owns these identifiers. If the insert now conflicts on
	//     person_tokens_ident_uq, that probe has been invalidated by a
	//     concurrent registration and the whole decision is wrong. Absorbing
	//     it committed a second person holding no identifier token at all -
	//     invisible to lookup, to the portal and to erasure, and permanently
	//     unerasable (H2). Naming the PK as the arbiter absorbs only the
	//     idempotent case and lets the ownership conflict surface as 23505,
	//     which aborts the transaction and drives the retry above.
	onConflict := `ON CONFLICT DO NOTHING`
	if !found {
		onConflict = `ON CONFLICT (person_id, kind, token) DO NOTHING`
	}
	for _, ins := range []struct {
		kind string
		set  identSet
	}{{"email", emailSet}, {"phone", phoneSet}, {"name", nameSet},
		{"name_phonetic", phoneticSet}, {"phone_suffix", suffixSet}} {
		for _, tok := range ins.set.writeToks {
			if _, err := tx.Exec(ctx,
				`INSERT INTO person_tokens (person_id, kind, token, key_version)
				 VALUES ($1,$2,$3,$4) `+onConflict,
				personID, ins.kind, tok, ins.set.writeVer); err != nil {
				return "", err
			}
		}
	}

	cid, err := ensureCID(ctx, tx, personID, client.Scope)
	if err != nil {
		return "", err
	}

	if err := c.mergeIntoBlob(ctx, tx, cid, client.ID, attrs); err != nil {
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
	//
	// The EXISTS refuses to mint a pseudonym for a tombstoned person. This
	// path is reached from OTI verification, which both writes PII and
	// CREATES the row that holds it - a row outside the set erasePerson
	// enumerated, locked and queued erasure webhooks for, and which a second
	// erasure cannot reach because the idempotency guard refuses an
	// already-erased person (TOKENS-LOOKUP-5). Every caller treats
	// ErrNotFound here as "this handoff cannot complete".
	err = q.QueryRow(ctx,
		`INSERT INTO cids (cid, person_id, scope)
		 SELECT $1,$2,$3 WHERE EXISTS (SELECT 1 FROM persons WHERE id=$2 AND erased_at IS NULL)
		 ON CONFLICT (person_id, scope) DO UPDATE SET scope=EXCLUDED.scope
		 RETURNING cid`, fresh, personID, scope).Scan(&cid)
	if err == pgx.ErrNoRows {
		return "", ErrNotFound
	}
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
// validCIDShape rejects path values that can never be a CID before they
// reach a query: a NUL byte or invalid UTF-8 makes Postgres error the whole
// statement (a 500 where a 404 belongs), and an oversized value is never a
// miss worth a round trip. Deliberately NOT a strict format check - legacy
// and test pseudonyms vary - just the properties the database itself
// requires of a text parameter.
func validCIDShape(cid string) bool {
	return cid != "" && len(cid) <= 128 && utf8.ValidString(cid) && !strings.ContainsRune(cid, 0)
}

func (c *Contacts) personForClientCID(ctx context.Context, client *auth.Client, cid string) (string, error) {
	if !validCIDShape(cid) {
		return "", ErrNotFound
	}
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

// personForClientCIDAllowingTombstone is personForClientCID for the ONE
// caller that legitimately needs to address an already-erased person: a
// retried cascade erasure, whose outstanding children are otherwise
// unrecoverable (GDPR-ERASURE-4). Scope ownership and the
// indistinguishable-from-absent rule for a foreign cid are unchanged.
func (c *Contacts) personForClientCIDAllowingTombstone(ctx context.Context, client *auth.Client, cid string) (string, bool, error) {
	if !validCIDShape(cid) {
		return "", false, ErrNotFound
	}
	var personID, scope string
	var erased bool
	err := c.Pool.QueryRow(ctx,
		`SELECT c.person_id, c.scope, p.erased_at IS NOT NULL
		 FROM cids c JOIN persons p ON p.id = c.person_id
		 WHERE c.cid=$1`, cid).Scan(&personID, &scope, &erased)
	if err == pgx.ErrNoRows {
		return "", false, ErrNotFound
	}
	if err != nil {
		return "", false, err
	}
	if scope != client.Scope {
		return "", false, ErrNotFound
	}
	return personID, erased, nil
}

// GetAttribute returns exactly one decrypted field: purpose is
// mandatory, checked against the caller's allowed purposes, the blob is the
// caller-scope one, and the read is audited BEFORE the value is released -
// an unaudited disclosure must not happen (fail closed).
func (c *Contacts) GetAttribute(ctx context.Context, client *auth.Client, cid, name, purpose string) (string, error) {
	// The one cid-addressed surface that bypasses personForClientCID (the
	// P0-a refactor folded its tombstone check into the read below) - so it
	// needs the same shape guard, or a NUL byte in the path 500s the hottest
	// read endpoint instead of missing cleanly.
	if !validCIDShape(cid) {
		return "", ErrNotFound
	}
	if !client.Can(auth.ActAttributesRead) {
		return "", ErrForbidden
	}
	if purpose == "" {
		return "", fmt.Errorf("%w: purpose required", ErrValidation)
	}
	if !client.CanUse(purpose) {
		return "", ErrPurposeNotAllowed
	}
	// F3 attribute allowlist: a client narrowed to specific fields must
	// not read anything else, before any per-person work happens - the
	// refusal must not depend on whether the CID exists.
	if !client.CanReadAttribute(name) {
		return "", ErrForbidden
	}
	// Scope ownership FIRST: the consent hook must never run on a raw
	// caller-supplied CID, or the 403/404 split becomes an oracle revealing
	// that a foreign CID exists and what its consent state is.
	// The tombstone predicate is part of THIS read: relying on the blob
	// being NULL after an erasure was an accident, not a guard, and it let
	// an attributes.read audit row be written for an erased person as if a
	// real disclosure had happened.
	var blob []byte
	var keyID, alg string
	err := c.Pool.QueryRow(ctx,
		`SELECT c.pii_encrypted, COALESCE(c.pii_key_id,'v1'), COALESCE(c.pii_alg,'aes256gcm')
		 FROM cids c JOIN persons p ON p.id = c.person_id
		 WHERE c.cid=$1 AND c.scope=$2 AND p.erased_at IS NULL`,
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
	if err := audit.ReadEvent(ctx, c.Pool, audit.Entry{
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
// decryptCID reads and decrypts one cid's attribute blob with no client
// context - used where the authorization is external to a client credential
// (F8 shares carry their own authorization). Returns an empty map for a cid
// with no blob yet.
func (c *Contacts) decryptCID(ctx context.Context, cid string) (map[string]string, error) {
	var blob []byte
	var keyID, alg string
	err := c.Pool.QueryRow(ctx,
		`SELECT COALESCE(pii_encrypted,''::bytea), COALESCE(pii_key_id,'v1'), COALESCE(pii_alg,'aes256gcm') FROM cids WHERE cid=$1`,
		cid).Scan(&blob, &keyID, &alg)
	if err != nil {
		return nil, err
	}
	if len(blob) == 0 {
		return map[string]string{}, nil
	}
	return c.PII.Decrypt(ctx, cid, blob, keyID, alg)
}

func (c *Contacts) mergeIntoBlob(ctx context.Context, tx pgx.Tx, cid, writtenBy string, attrs map[string]string) error {
	var oldBlob []byte
	var oldKeyID, oldAlg string
	// FOR UPDATE: two concurrent merges onto the same row (dedup is the
	// whole point of this path) must serialize, or the first writer's
	// attributes are silently lost.
	//
	// The tombstone predicate is in the SAME locking read: a
	// check done earlier on the pool could be overtaken by an erasure that
	// commits before this transaction writes, landing a fresh live blob on
	// a forgotten person. The lock must name BOTH relations: under READ
	// COMMITTED, EvalPlanQual re-fetches only the tuples of FOR UPDATE
	// targets, so "FOR UPDATE OF c" alone re-evaluates p.erased_at against
	// a STALE persons tuple when this read blocks on the erasure's own cids
	// update - exactly the race this predicate exists to close. The c lock
	// is ALSO needed here (unlike tokens/files) to serialize concurrent
	// merges on the same blob; the c -> p acquisition order matches
	// erasePerson's, so the pair cannot ABBA-deadlock.
	err := tx.QueryRow(ctx,
		`SELECT c.pii_encrypted, COALESCE(c.pii_key_id,'v1'), COALESCE(c.pii_alg,'aes256gcm')
		 FROM cids c JOIN persons p ON p.id = c.person_id
		 WHERE c.cid=$1 AND p.erased_at IS NULL
		 FOR UPDATE OF c, p`,
		cid).Scan(&oldBlob, &oldKeyID, &oldAlg)
	if err == pgx.ErrNoRows {
		// Erased (or vanished) between the caller's check and this write.
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	var previous map[string]string
	if len(oldBlob) > 0 {
		old, err := c.PII.Decrypt(ctx, cid, oldBlob, oldKeyID, oldAlg)
		if err != nil {
			return err
		}
		// Keep the pre-merge generation for the version snapshot, which
		// re-seals it under its own AAD rather than copying ciphertext.
		previous = make(map[string]string, len(old))
		for k, v := range old {
			previous[k] = v
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
	// F6: snapshot the outgoing blob as a version BEFORE overwriting, in
	// this same transaction, so history and the overwrite are atomic.
	if err := c.appendVersion(ctx, tx, cid, writtenBy, previous); err != nil {
		return err
	}
	_, err = tx.Exec(ctx,
		`UPDATE cids SET pii_encrypted=$2, pii_key_id=$3, pii_alg=$4, updated_at=now() WHERE cid=$1`,
		cid, blob, keyID, c.PII.Algorithm())
	return err
}

// maxBlobBytes caps a scope blob far below the 4 MiB signer frame limit.
const maxBlobBytes = 256 * 1024

// MergeIntoBlobForTest exposes mergeIntoBlob to the external test package so
// the erasure race can be exercised at the write itself,
// not only through a caller that pre-checks.
func (c *Contacts) MergeIntoBlobForTest(ctx context.Context, tx pgx.Tx, cid string, attrs map[string]string) error {
	return c.mergeIntoBlob(ctx, tx, cid, "test", attrs)
}

// deadlockRetries bounds the retry on SQLSTATE 40P01. The lock ordering
// above makes a cycle with erasePerson impossible, but PostgreSQL can still
// detect one between paths this convention does not cover (an index or FK
// interaction, a future writer), and surfacing that as a 500 on a legitimate
// Article 17 erasure or a cross-scope handoff is the worst possible outcome
// of a condition the database already resolved for us (DB-TXN-3).
const deadlockRetries = 3

// isDeadlock reports SQLSTATE 40P01.
func isDeadlock(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "40P01"
}

// retryOnDeadlock runs fn, retrying a deadlock victim. fn must be
// idempotent under abort, which every transactional writer here is: a
// deadlocked transaction is rolled back in full before fn returns.
func retryOnDeadlock(fn func() error) error {
	var err error
	for attempt := 0; attempt < deadlockRetries; attempt++ {
		if err = fn(); !isDeadlock(err) {
			return err
		}
	}
	return err
}

// lockPersonRows takes exactly the lock prefix erasePerson takes - every one
// of the person's cids rows in cid order, then the persons row - and returns
// the person id, or ErrNotFound if the cid is unknown or the person is a
// tombstone.
//
// It exists because the c -> p convention alone is not enough for a writer
// that needs MORE THAN ONE of a person's cids (OTI verification needs the
// issuer's and the verifier's): erasePerson locks them all in one statement,
// so a writer locking a subset in a different order closes an ABBA cycle
// with it (DB-TXN-3). Taking the same set in the same order makes a cycle
// impossible by construction, and folds in the in-transaction tombstone
// check that check-then-act on the pool cannot provide (GDPR-ERASURE-5/6):
// under READ COMMITTED, a liveness answer read outside the transaction is
// already stale by the time the write lands.
//
// Writers that touch exactly one cid may keep the cheaper `FOR UPDATE OF
// c, p` shape (mergeIntoBlob, Files.Upload, tokenizeInTx) - one row cannot
// be taken out of order.
func lockPersonRows(ctx context.Context, tx pgx.Tx, cid string) (string, error) {
	var personID string
	switch err := tx.QueryRow(ctx,
		`SELECT person_id FROM cids WHERE cid=$1`, cid).Scan(&personID); {
	case err == pgx.ErrNoRows:
		return "", ErrNotFound
	case err != nil:
		return "", err
	}
	if _, err := tx.Exec(ctx,
		`SELECT 1 FROM cids WHERE person_id=$1 ORDER BY cid FOR UPDATE`, personID); err != nil {
		return "", err
	}
	var erased bool
	switch err := tx.QueryRow(ctx,
		`SELECT erased_at IS NOT NULL FROM persons WHERE id=$1 FOR UPDATE`, personID).Scan(&erased); {
	case err == pgx.ErrNoRows:
		return "", ErrNotFound
	case err != nil:
		return "", err
	case erased:
		return "", ErrNotFound
	}
	return personID, nil
}
