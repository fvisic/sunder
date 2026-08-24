package service

// P2.4 external-issuer federation: a registered issuer (a wallet gateway, a
// national attribute provider) signs a claim envelope; this instance
// verifies it against the trust registry and stores the claims into the
// caller-scope blob with provenance ("<claim>@<issuer>"). This is the
// pragmatic pre-EUDI integration surface - full OpenID4VP stays a design
// doc until the wallet ecosystem stabilizes (docs/DESIGN-EUDI-GATEWAY.md).

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/fvisic/sunder/internal/audit"
	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/crypto"
)

// externalEnvelope is the signed payload a trusted issuer produces:
// a PASETO v4.public token whose JSON body carries the claims.
type externalEnvelope struct {
	Issuer string `json:"iss"`
	// JTI is the envelope's unique id: consumed exactly once (anti-replay).
	JTI string `json:"jti"`
	// CID binds the envelope to ONE pseudonym: the issuer/gateway asserts
	// claims for a specific person, and the envelope cannot be re-attached
	// to anyone else.
	CID     string            `json:"cid"`
	Claims  map[string]string `json:"claims"`
	IssuedA string            `json:"iat"`
	Expires string            `json:"exp"`
}

const (
	maxExternalClaims    = 16
	maxExternalClaimSize = 4096
	// maxEnvelopeLifetime bounds how far ahead an issuer may pre-stage
	// envelopes; without it the replay table can never be pruned.
	// maxEnvelopeLifetime is the ONLY definition of this window: the
	// migration's column default exists solely for pre-existing rows, and
	// every insert writes an explicit expires_at from here.
	maxEnvelopeLifetime = 24 * time.Hour
)

// issuerIDPattern mirrors the registry CHECK constraint. Applied to the
// unverified payload before any lookup, audit write or error message.
var issuerIDPattern = regexp.MustCompile(`^[a-z0-9._-]{1,64}$`)

// claimNamePattern keeps stored claim names addressable through the
// attribute endpoint and free of the '@' provenance separator.
var claimNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,64}$`)

// ExternalClaims verifies an issuer-signed envelope and merges its claims
// into the caller-scope blob for cid, namespaced with the issuer id.
// Returns the stored attribute names.
func (c *Contacts) ExternalClaims(ctx context.Context, client *auth.Client, cid, envelope string) ([]string, error) {
	if !client.Can(auth.ActClaimsExternal) {
		return nil, ErrForbidden
	}
	// Scope ownership AND tombstone check first: external claims must not
	// become a probe for foreign CIDs, nor a way to write fresh PII into a
	// person who has been erased (personForClientCID enforces both).
	if _, err := c.personForClientCID(ctx, client, cid); err != nil {
		return nil, err
	}

	// Parse the UNVERIFIED payload only to learn which issuer to look up;
	// nothing is trusted until the signature checks out below.
	payload, err := crypto.PasetoPayload(envelope)
	if err != nil {
		return nil, fmt.Errorf("%w: not a valid envelope", ErrValidation)
	}
	var env externalEnvelope
	if err := json.Unmarshal(payload, &env); err != nil || env.Issuer == "" {
		return nil, fmt.Errorf("%w: envelope missing issuer", ErrValidation)
	}
	// Validate the issuer id BEFORE it is used as a query parameter or
	// written to the audit chain: it comes from the UNVERIFIED payload, and
	// every audit append takes a global advisory lock. Unbounded
	// attacker-chosen bytes there mean both audit inflation and
	// service-wide serialisation behind that lock.
	if !issuerIDPattern.MatchString(env.Issuer) {
		return nil, fmt.Errorf("%w: malformed issuer id", ErrValidation)
	}

	var pubKey []byte
	var allowed []string
	err = c.Pool.QueryRow(ctx,
		`SELECT public_key, allowed_claims FROM trusted_issuers
		 WHERE issuer_id=$1 AND revoked_at IS NULL`,
		env.Issuer).Scan(&pubKey, &allowed)
	if err == pgx.ErrNoRows {
		_ = audit.Append(ctx, c.Pool, audit.Entry{
			ClientID: client.ID, Action: "claims.external.rejected",
			Detail: map[string]any{"issuer": env.Issuer, "reason": "untrusted_issuer"},
		})
		return nil, fmt.Errorf("%w: issuer %q is not trusted", ErrForbidden, env.Issuer)
	}
	if err != nil {
		return nil, err
	}
	// Unusable key material must never reach ed25519.Verify: a wrong length
	// panics, and ANY small-order point (not just the all-zero one) makes
	// every signature verify.
	if err := crypto.ValidEd25519PublicKey(pubKey); err != nil {
		return nil, fmt.Errorf("%w: issuer %q has unusable key material: %v", ErrForbidden, env.Issuer, err)
	}
	if _, err := crypto.PasetoVerify(ed25519.PublicKey(pubKey), envelope); err != nil {
		// Audit forgery attempts: a signature that fails against a REGISTERED
		// issuer's key is a monitoring signal, not noise.
		_ = audit.Append(ctx, c.Pool, audit.Entry{
			ClientID: client.ID, Action: "claims.external.rejected",
			Detail: map[string]any{"issuer": env.Issuer, "reason": "bad_signature"},
		})
		return nil, fmt.Errorf("%w: envelope signature invalid", ErrValidation)
	}
	// Subject binding: the SIGNED cid must match the target - an envelope
	// issued for one person cannot be attached to another.
	if env.CID != cid {
		return nil, fmt.Errorf("%w: envelope is bound to a different subject", ErrForbidden)
	}
	if env.JTI == "" {
		return nil, fmt.Errorf("%w: envelope missing jti", ErrValidation)
	}
	exp, err := time.Parse(time.RFC3339, env.Expires)
	if err != nil || time.Now().After(exp) {
		return nil, fmt.Errorf("%w: envelope expired or missing exp", ErrValidation)
	}
	// A bounded lifetime keeps pre-staged envelopes from living for years
	// and makes the replay table prunable.
	if time.Until(exp) > maxEnvelopeLifetime {
		return nil, fmt.Errorf("%w: envelope exp is more than %s ahead", ErrValidation, maxEnvelopeLifetime)
	}
	// iat was parsed and never read: an envelope dated in the future is
	// either a clock problem or a pre-staged token, and both deserve a
	// refusal rather than silent acceptance.
	if env.IssuedA != "" {
		iat, err := time.Parse(time.RFC3339, env.IssuedA)
		if err != nil {
			return nil, fmt.Errorf("%w: envelope iat is not an RFC 3339 timestamp", ErrValidation)
		}
		if iat.After(time.Now().Add(5 * time.Minute)) {
			return nil, fmt.Errorf("%w: envelope iat is in the future", ErrValidation)
		}
	}
	if len(env.Claims) == 0 || len(env.Claims) > maxExternalClaims {
		return nil, fmt.Errorf("%w: 1-%d claims per envelope", ErrValidation, maxExternalClaims)
	}
	wildcard := slices.Contains(allowed, "*")
	for name, value := range env.Claims {
		if name == "" || len(name) > 64 {
			return nil, fmt.Errorf("%w: claim names must be 1-64 chars", ErrValidation)
		}
		// The name must be addressable through
		// GET /v1/contacts/{cid}/attributes/{name} and must not carry the
		// '@' provenance separator (which could impersonate another issuer
		// after suffixing). Anything else would store an attribute the API
		// cannot serve.
		if !claimNamePattern.MatchString(name) {
			return nil, fmt.Errorf("%w: claim names must match %s", ErrValidation, claimNamePattern)
		}
		if len(value) > maxExternalClaimSize {
			return nil, fmt.Errorf("%w: claim values are capped at %d bytes", ErrValidation, maxExternalClaimSize)
		}
		// Deny-by-default: an issuer registered without -claims may assert
		// NOTHING; "*" grants everything explicitly.
		if !wildcard && !slices.Contains(allowed, name) {
			return nil, fmt.Errorf("%w: issuer %q may not assert %q", ErrForbidden, env.Issuer, name)
		}
	}

	// Store with provenance: the attribute name records who asserted it.
	attrs := make(map[string]string, len(env.Claims))
	stored := make([]string, 0, len(env.Claims))
	for name, value := range env.Claims {
		key := name + "@" + env.Issuer
		attrs[key] = value
		stored = append(stored, key)
	}
	slices.Sort(stored)

	tx, err := c.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Anti-replay: the jti is consumed in the SAME transaction as the merge.
	if _, err := tx.Exec(ctx,
		`INSERT INTO external_envelopes (jti, issuer_id, expires_at, cid) VALUES ($1,$2,$3,$4)`,
		env.JTI, env.Issuer, exp, cid); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, fmt.Errorf("%w: envelope already used", ErrValidation)
		}
		if errors.As(err, &pgErr) && pgErr.Code == "23514" {
			return nil, fmt.Errorf("%w: jti must be 8-128 characters", ErrValidation)
		}
		return nil, err
	}
	if err := c.mergeIntoBlob(ctx, tx, cid, attrs); err != nil {
		return nil, err
	}
	if err := audit.AppendTx(ctx, tx, audit.Entry{
		ClientID: client.ID, Action: "claims.external", CID: cid,
		Detail: map[string]any{"issuer": env.Issuer, "claims": stored},
	}); err != nil {
		return nil, fmt.Errorf("audit append: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return stored, nil
}
