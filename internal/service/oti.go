package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/fvisic/sunder/internal/audit"
	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/crypto"
)

// OTI sentinel errors (SDK taxonomy: TokenInvalid/TokenExpired/TokenUsed/
// AudienceMismatch).
var (
	ErrTokenInvalid     = errors.New("token invalid")
	ErrTokenExpired     = errors.New("token expired")
	ErrTokenUsed        = errors.New("token used")
	ErrAudienceMismatch = errors.New("audience mismatch")
)

// OTITTL is the default one-time-identifier lifetime (docs/DESIGN.md).
// Configurable per deployment via SUNDER_OTI_TTL: shorter for same-network
// handoffs, longer where the receiving system polls slowly - but a token is
// a bearer credential, so longer TTLs widen the interception window.
const OTITTL = 5 * time.Minute

// OTI issues and verifies one-time identifiers - the only identity currency
// systems exchange (docs/DESIGN.md). Tokens are PASETO v4.public, bound to
// one purpose and one audience, single-use enforced by an atomic DB
// transition (not just the signature).
type OTI struct {
	Pool     *pgxpool.Pool
	Eng      crypto.Engine
	Ring     *KeyRing
	Contacts *Contacts
	// TTL overrides the token lifetime; zero means OTITTL.
	TTL time.Duration
}

func (o *OTI) ttl() time.Duration {
	if o.TTL <= 0 {
		return OTITTL
	}
	return o.TTL
}

type otiClaims struct {
	JTI      string `json:"jti"`
	CID      string `json:"cid"`
	Purpose  string `json:"purpose"`
	Audience string `json:"aud"`
	IssuedAt string `json:"iat"`
	Expires  string `json:"exp"`
	KeyID    string `json:"kid"`
}

// Issue mints a token for a CID of the caller's own scope, addressed to one
// audience (target scope) and one purpose.
//
// shareAttrs lists attributes from the ISSUER's scope blob that the
// verifier's scope receives at verification (copied into its own blob) -
// the mechanism behind delayed flows like escalation e-mails: the verifier
// stores no PII itself and fetches just-in-time, yet a handoff shares
// nothing unless the issuer explicitly says so.
// IssueInput carries the optional sharing directives for a handoff.
type IssueInput struct {
	CID             string      `json:"cid"`
	Purpose         string      `json:"purpose"`
	Audience        string      `json:"audience"`
	ShareAttributes []string    `json:"share_attributes"`
	SharePredicates []Predicate `json:"share_predicates"`
}

// Issue keeps the pre-P2.3 signature; predicate-bearing handoffs use IssueFull.
func (o *OTI) Issue(ctx context.Context, client *auth.Client, cid, purpose, audience string, shareAttrs []string) (string, time.Time, error) {
	return o.IssueFull(ctx, client, IssueInput{CID: cid, Purpose: purpose, Audience: audience, ShareAttributes: shareAttrs})
}

func (o *OTI) IssueFull(ctx context.Context, client *auth.Client, in IssueInput) (token string, expiresAt time.Time, err error) {
	cid, purpose, audience, shareAttrs := in.CID, in.Purpose, in.Audience, in.ShareAttributes
	if err := validatePredicates(in.SharePredicates); err != nil {
		return "", time.Time{}, err
	}
	if len(shareAttrs) > 32 {
		return "", time.Time{}, fmt.Errorf("%w: at most 32 shared attributes per token", ErrValidation)
	}
	for _, a := range shareAttrs {
		if a == "" || len(a) > 64 {
			return "", time.Time{}, fmt.Errorf("%w: shared attribute names must be 1-64 chars", ErrValidation)
		}
	}
	if !client.Can(auth.ActOTIIssue) {
		return "", time.Time{}, ErrForbidden
	}
	if purpose == "" || audience == "" {
		return "", time.Time{}, fmt.Errorf("%w: purpose and audience required", ErrValidation)
	}
	if !client.CanUse(purpose) {
		return "", time.Time{}, ErrPurposeNotAllowed
	}
	// Scope ownership FIRST (see GetAttribute: the consent hook on a raw
	// caller CID would leak foreign-CID existence via the 403/404 split).
	if _, err := o.Contacts.personForClientCID(ctx, client, cid); err != nil {
		return "", time.Time{}, err
	}
	// Consent hook (v1.5): withdrawn consent blocks handoffs for the purpose.
	if denied, err := consentDenied(ctx, o.Pool, cid, purpose); err != nil {
		return "", time.Time{}, err
	} else if denied {
		return "", time.Time{}, ErrConsentDenied
	}

	version, err := o.Ring.Newest(ctx, crypto.SigningKeyName)
	if err != nil {
		return "", time.Time{}, err
	}
	now := time.Now().UTC()
	expiresAt = now.Add(o.ttl())
	claims := otiClaims{
		JTI: newUUID(), CID: cid, Purpose: purpose, Audience: audience,
		IssuedAt: now.Format(time.RFC3339), Expires: expiresAt.Format(time.RFC3339), KeyID: version,
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", time.Time{}, err
	}
	token, err = o.Eng.Sign(ctx, crypto.SigningKeyName+"/"+version, payload)
	if err != nil {
		return "", time.Time{}, err
	}

	// Row + audit in one transaction: an issued token always has both.
	tx, err := o.Pool.Begin(ctx)
	if err != nil {
		return "", time.Time{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if shareAttrs == nil {
		shareAttrs = []string{}
	}
	preds := in.SharePredicates
	if preds == nil {
		preds = []Predicate{}
	}
	predsJSON, err := json.Marshal(preds)
	if err != nil {
		return "", time.Time{}, err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO oti (jti, cid, purpose, audience, expires_at, share_attrs, share_predicates) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		claims.JTI, cid, purpose, audience, expiresAt, shareAttrs, predsJSON); err != nil {
		return "", time.Time{}, err
	}
	if err := audit.AppendTx(ctx, tx, audit.Entry{
		ClientID: client.ID, Action: "oti.issue", CID: cid,
		Detail: map[string]any{"jti": claims.JTI, "purpose": purpose, "audience": audience, "share_attrs": shareAttrs, "share_predicates": preds},
	}); err != nil {
		return "", time.Time{}, fmt.Errorf("audit append: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return "", time.Time{}, err
	}
	return token, expiresAt, nil
}

// Verify checks signature, purpose, audience and expiry, atomically marks
// the token USED, and returns the VERIFIER'S OWN scoped CID for the person -
// the issuer's pseudonym never crosses the scope boundary (docs/DESIGN.md).
// VerifyOutcome is the verifier's full view of a consumed handoff.
type VerifyOutcome struct {
	CID        string            `json:"cid"`
	Shared     []string          `json:"shared,omitempty"`
	Predicates []PredicateResult `json:"predicates,omitempty"`
}

// Verify keeps the pre-P2.3 signature; predicate consumers use VerifyFull.
func (o *OTI) Verify(ctx context.Context, client *auth.Client, token, purpose, audience string) (string, error) {
	out, err := o.VerifyFull(ctx, client, token, purpose, audience)
	if err != nil {
		return "", err
	}
	return out.CID, nil
}

func (o *OTI) VerifyFull(ctx context.Context, client *auth.Client, token, purpose, audience string) (*VerifyOutcome, error) {
	if !client.Can(auth.ActOTIVerify) {
		return nil, ErrForbidden
	}
	// The purpose cap applies to the verifier too: revoking a purpose from a
	// client must also stop it consuming tokens for that purpose.
	if !client.CanUse(purpose) {
		return nil, ErrPurposeNotAllowed
	}
	// You can only verify tokens addressed to you.
	if audience != client.Scope {
		return nil, ErrAudienceMismatch
	}

	payload, err := crypto.PasetoPayload(token)
	if err != nil {
		return nil, ErrTokenInvalid
	}
	var claims otiClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, ErrTokenInvalid
	}
	// kid is read pre-verification (necessarily), but only key versions the
	// ring lists as live are ever tried - an attacker cannot point at
	// arbitrary key names.
	live, err := o.Ring.Versions(ctx, crypto.SigningKeyName)
	if err != nil {
		return nil, err
	}
	isLive := func() bool {
		for _, v := range live {
			if v == claims.KeyID {
				return true
			}
		}
		return false
	}
	if !isLive() {
		// A freshly rotated key may not be in this replica's 30s cache yet;
		// refresh once before rejecting (only on the unknown-kid path, so
		// forged kids cannot turn this into a cache-busting vector at scale).
		o.Ring.InvalidateThrottled()
		if live, err = o.Ring.Versions(ctx, crypto.SigningKeyName); err != nil {
			return nil, err
		}
		if !isLive() {
			return nil, ErrTokenInvalid
		}
	}
	if _, err := o.Eng.VerifyToken(ctx, crypto.SigningKeyName+"/"+claims.KeyID, token); err != nil {
		if errors.Is(err, crypto.ErrVerifyFailed) {
			return nil, ErrTokenInvalid
		}
		return nil, err // environment (keystore/signer down): surface as 5xx, not "invalid"
	}
	if claims.Audience != audience {
		return nil, ErrAudienceMismatch
	}
	if claims.Purpose != purpose {
		return nil, ErrTokenInvalid
	}
	exp, err := time.Parse(time.RFC3339, claims.Expires)
	if err != nil {
		return nil, ErrTokenInvalid
	}
	if time.Now().After(exp) {
		return nil, ErrTokenExpired
	}
	// Consent is checked at ISSUE and re-checked here: a withdrawal within
	// the token's 5-minute life must stop the handoff.
	if denied, err := consentDenied(ctx, o.Pool, claims.CID, purpose); err != nil {
		return nil, err
	} else if denied {
		return nil, ErrConsentDenied
	}

	// One transaction end to end: a failure anywhere rolls the row back to
	// VALID (no burned-but-undelivered handoffs) and the audit record commits
	// with the consumption or not at all.
	tx, err := o.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Atomic single-use transition - the replay guard (no TOCTOU). The row's
	// cid/purpose/audience are matched against the SIGNED claims as defense
	// in depth: even with a compromised signing key, a crafted token cannot
	// consume a jti bound to different parameters.
	var issuerCID string
	var shareAttrs []string
	var predsJSON []byte
	err = tx.QueryRow(ctx,
		`UPDATE oti SET status='USED', used_at=now(), used_by=$2
		 WHERE jti=$1 AND cid=$3 AND purpose=$4 AND audience=$5
		   AND status='VALID' AND expires_at > now()
		 RETURNING cid, share_attrs, share_predicates`, claims.JTI, client.ID, claims.CID, purpose, audience).Scan(&issuerCID, &shareAttrs, &predsJSON)
	if err == pgx.ErrNoRows {
		var status string
		var expiresAt time.Time
		serr := tx.QueryRow(ctx,
			`SELECT status, expires_at FROM oti WHERE jti=$1 AND cid=$2 AND purpose=$3 AND audience=$4`,
			claims.JTI, claims.CID, purpose, audience).Scan(&status, &expiresAt)
		switch {
		case serr == pgx.ErrNoRows:
			return nil, ErrTokenInvalid // signed but never persisted (or claims differ from the row): treat as forged
		case serr != nil:
			return nil, serr
		case status == "USED":
			return nil, ErrTokenUsed
		case status == "REVOKED":
			// Erasure revokes outstanding tokens; indistinguishable from a
			// forged token on purpose (no oracle for "this person was erased").
			return nil, ErrTokenInvalid
		default:
			return nil, ErrTokenExpired
		}
	}
	if err != nil {
		return nil, err
	}

	// Map to the verifier's scope: same person, the verifier's own pseudonym.
	var personID string
	if err := tx.QueryRow(ctx,
		`SELECT person_id FROM cids WHERE cid=$1`, issuerCID).Scan(&personID); err != nil {
		return nil, err
	}
	verifierCID, err := ensureCID(ctx, tx, personID, client.Scope)
	if err != nil {
		return nil, err
	}
	// Copy issuer-authorized attributes into the verifier-scope blob so
	// delayed, just-in-time reads work without the verifier storing PII.
	shared, err := o.shareIntoScope(ctx, tx, issuerCID, verifierCID, shareAttrs)
	if err != nil {
		return nil, err
	}
	// Predicate claims: evaluated against the ISSUER blob, results only -
	// values never cross the scope boundary (P2.3 selective disclosure).
	var preds []Predicate
	if err := json.Unmarshal(predsJSON, &preds); err != nil {
		return nil, err
	}
	predResults, err := o.evalPredicates(ctx, tx, issuerCID, preds)
	if err != nil {
		return nil, err
	}
	// The chain records WHAT WAS ASKED, never what the data said: attribute
	// reads log the attribute name and not its value, and a predicate
	// result is that value, one bit wide. Logging it would put a derived
	// personal-data assertion ("this person is over 18") into a log that is
	// never pruned and survives erasure as a tombstone-keyed row. The
	// disclosure event is fully accounted for by the request itself.
	askedPredicates := make([]string, 0, len(predResults))
	for _, r := range predResults {
		if r.Op == PredAgeGTE {
			askedPredicates = append(askedPredicates, fmt.Sprintf("%s %s %d", r.Attr, r.Op, r.Threshold()))
			continue
		}
		askedPredicates = append(askedPredicates, r.Attr+" "+r.Op)
	}
	if err := audit.AppendTx(ctx, tx, audit.Entry{
		ClientID: client.ID, Action: "oti.verify", CID: verifierCID,
		Detail: map[string]any{"jti": claims.JTI, "purpose": purpose, "audience": audience,
			"shared": shared, "predicates_asked": askedPredicates},
	}); err != nil {
		return nil, fmt.Errorf("audit append: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &VerifyOutcome{CID: verifierCID, Shared: shared, Predicates: predResults}, nil
}

// shareIntoScope copies the listed attributes from the issuer's blob into
// the verifier's blob (issuer values win on conflict; missing attributes are
// silently absent). Returns the names actually copied, for the audit record.
func (o *OTI) shareIntoScope(ctx context.Context, tx pgx.Tx, issuerCID, verifierCID string, attrs []string) ([]string, error) {
	shared := []string{}
	if len(attrs) == 0 || issuerCID == verifierCID {
		return shared, nil
	}
	var srcBlob []byte
	var srcKey, srcAlg string
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(pii_encrypted,''::bytea), COALESCE(pii_key_id,'v1'), COALESCE(pii_alg,'aes256gcm') FROM cids WHERE cid=$1`,
		issuerCID).Scan(&srcBlob, &srcKey, &srcAlg); err != nil {
		return nil, err
	}
	if len(srcBlob) == 0 {
		return shared, nil
	}
	src, err := o.Contacts.PII.Decrypt(ctx, issuerCID, srcBlob, srcKey, srcAlg)
	if err != nil {
		return nil, err
	}
	var dstBlob []byte
	var dstKey, dstAlg string
	// FOR UPDATE: the merge into the verifier blob must not race a
	// concurrent register/verify on the same cid.
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(pii_encrypted,''::bytea), COALESCE(pii_key_id,'v1'), COALESCE(pii_alg,'aes256gcm') FROM cids WHERE cid=$1 FOR UPDATE`,
		verifierCID).Scan(&dstBlob, &dstKey, &dstAlg); err != nil {
		return nil, err
	}
	dst := map[string]string{}
	if len(dstBlob) > 0 {
		if dst, err = o.Contacts.PII.Decrypt(ctx, verifierCID, dstBlob, dstKey, dstAlg); err != nil {
			return nil, err
		}
	}
	for _, name := range attrs {
		if v, ok := src[name]; ok {
			dst[name] = v
			shared = append(shared, name)
		}
	}
	if len(shared) == 0 {
		return shared, nil
	}
	newKey, err := o.Ring.Newest(ctx, crypto.KeyPIIKEK)
	if err != nil {
		return nil, err
	}
	fresh, err := o.Contacts.PII.Encrypt(ctx, verifierCID, newKey, dst)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE cids SET pii_encrypted=$2, pii_key_id=$3, pii_alg=$4, updated_at=now() WHERE cid=$1`,
		verifierCID, fresh, newKey, o.Contacts.PII.Algorithm()); err != nil {
		return nil, err
	}
	return shared, nil
}
