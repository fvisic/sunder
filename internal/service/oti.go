package service

import (
	"context"
	"crypto/ed25519"
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

// OTITTL is the maximum one-time-identifier lifetime (PLAN section 3).
const OTITTL = 5 * time.Minute

// OTI issues and verifies one-time identifiers — the only identity currency
// systems exchange (PLAN section 6). Tokens are PASETO v4.public, bound to
// one purpose and one audience, single-use enforced by an atomic DB
// transition (not just the signature).
type OTI struct {
	Pool     *pgxpool.Pool
	KS       crypto.Keystore
	Ring     *KeyRing
	Contacts *Contacts
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

func (o *OTI) signingKey(ctx context.Context, version string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	seed, err := o.KS.Key(ctx, crypto.SigningKeyName+"/"+version)
	if err != nil {
		return nil, nil, err
	}
	return crypto.Ed25519FromSeed(seed)
}

// Issue mints a token for a CID of the caller's own scope, addressed to one
// audience (target scope) and one purpose.
func (o *OTI) Issue(ctx context.Context, client *auth.Client, cid, purpose, audience string) (token string, expiresAt time.Time, err error) {
	if !client.Can(auth.ActOTIIssue) {
		return "", time.Time{}, ErrForbidden
	}
	if purpose == "" || audience == "" {
		return "", time.Time{}, fmt.Errorf("%w: purpose and audience required", ErrValidation)
	}
	if !client.CanUse(purpose) {
		return "", time.Time{}, ErrPurposeNotAllowed
	}
	if _, err := o.Contacts.personForClientCID(ctx, client, cid); err != nil {
		return "", time.Time{}, err
	}

	version, err := o.Ring.Newest(ctx, crypto.SigningKeyName)
	if err != nil {
		return "", time.Time{}, err
	}
	sk, _, err := o.signingKey(ctx, version)
	if err != nil {
		return "", time.Time{}, err
	}

	now := time.Now().UTC()
	expiresAt = now.Add(OTITTL)
	claims := otiClaims{
		JTI: newUUID(), CID: cid, Purpose: purpose, Audience: audience,
		IssuedAt: now.Format(time.RFC3339), Expires: expiresAt.Format(time.RFC3339), KeyID: version,
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", time.Time{}, err
	}
	token = crypto.PasetoSign(sk, payload)

	if _, err := o.Pool.Exec(ctx,
		`INSERT INTO oti (jti, cid, purpose, audience, expires_at) VALUES ($1,$2,$3,$4,$5)`,
		claims.JTI, cid, purpose, audience, expiresAt); err != nil {
		return "", time.Time{}, err
	}
	if err := audit.Append(ctx, o.Pool, audit.Entry{
		ClientID: client.ID, Action: "oti.issue", CID: cid,
		Detail: map[string]any{"jti": claims.JTI, "purpose": purpose, "audience": audience},
	}); err != nil {
		return "", time.Time{}, fmt.Errorf("audit append: %w", err)
	}
	return token, expiresAt, nil
}

// Verify checks signature, purpose, audience and expiry, atomically marks
// the token USED, and returns the VERIFIER'S OWN scoped CID for the person —
// the issuer's pseudonym never crosses the scope boundary (PLAN section 6).
func (o *OTI) Verify(ctx context.Context, client *auth.Client, token, purpose, audience string) (string, error) {
	if !client.Can(auth.ActOTIVerify) {
		return "", ErrForbidden
	}
	// You can only verify tokens addressed to you.
	if audience != client.Scope {
		return "", ErrAudienceMismatch
	}

	payload, err := crypto.PasetoPayload(token)
	if err != nil {
		return "", ErrTokenInvalid
	}
	var claims otiClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", ErrTokenInvalid
	}
	// kid is read pre-verification (necessarily), but only key versions the
	// ring lists as live are ever tried — an attacker cannot point at
	// arbitrary key names.
	live, err := o.Ring.Versions(ctx, crypto.SigningKeyName)
	if err != nil {
		return "", err
	}
	known := false
	for _, v := range live {
		known = known || v == claims.KeyID
	}
	if !known {
		return "", ErrTokenInvalid
	}
	_, pk, err := o.signingKey(ctx, claims.KeyID)
	if err != nil {
		return "", err
	}
	if _, err := crypto.PasetoVerify(pk, token); err != nil {
		return "", ErrTokenInvalid
	}
	if claims.Audience != audience {
		return "", ErrAudienceMismatch
	}
	if claims.Purpose != purpose {
		return "", ErrTokenInvalid
	}
	exp, err := time.Parse(time.RFC3339, claims.Expires)
	if err != nil {
		return "", ErrTokenInvalid
	}
	if time.Now().After(exp) {
		return "", ErrTokenExpired
	}

	// Atomic single-use transition — the replay guard (no TOCTOU).
	var issuerCID string
	err = o.Pool.QueryRow(ctx,
		`UPDATE oti SET status='USED', used_at=now(), used_by=$2
		 WHERE jti=$1 AND status='VALID' AND expires_at > now()
		 RETURNING cid`, claims.JTI, client.ID).Scan(&issuerCID)
	if err == pgx.ErrNoRows {
		var status string
		var expiresAt time.Time
		serr := o.Pool.QueryRow(ctx,
			`SELECT status, expires_at FROM oti WHERE jti=$1`, claims.JTI).Scan(&status, &expiresAt)
		switch {
		case serr == pgx.ErrNoRows:
			return "", ErrTokenInvalid // signed but never persisted: treat as forged
		case serr != nil:
			return "", serr
		case status == "USED":
			return "", ErrTokenUsed
		default:
			return "", ErrTokenExpired
		}
	}
	if err != nil {
		return "", err
	}

	// Map to the verifier's scope: same person, the verifier's own pseudonym.
	var personID string
	if err := o.Pool.QueryRow(ctx,
		`SELECT person_id FROM cids WHERE cid=$1`, issuerCID).Scan(&personID); err != nil {
		return "", err
	}
	verifierCID, err := ensureCID(ctx, o.Pool, personID, client.Scope)
	if err != nil {
		return "", err
	}
	if err := audit.Append(ctx, o.Pool, audit.Entry{
		ClientID: client.ID, Action: "oti.verify", CID: verifierCID,
		Detail: map[string]any{"jti": claims.JTI, "purpose": purpose, "audience": audience},
	}); err != nil {
		return "", fmt.Errorf("audit append: %w", err)
	}
	return verifierCID, nil
}
