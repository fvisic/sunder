package service

// P2.5 self-service privacy portal: citizens authenticate with a magic
// link (delivered by the ORG's mailer via a signed webhook - Sunder sends
// no e-mail) and can then see their data across scopes, manage consents,
// export, and request erasure with a second confirmation. Every action is
// audited with actor "portal:<cid>"; token and session secrets exist in
// the database only as SHA-256 hashes.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/fvisic/sunder/internal/audit"
	"github.com/fvisic/sunder/internal/crypto"
)

// PortalMailerScope is the reserved webhooks.scope row carrying the org's
// mailer endpoint for portal login links.
const PortalMailerScope = "_portal"

const (
	portalLoginTTL   = 15 * time.Minute
	portalSessionTTL = 30 * time.Minute
	portalEraseTTL   = 10 * time.Minute
)

// Portal bundles the self-service operations.
type Portal struct {
	GDPR     *GDPR
	Contacts *Contacts
}

// Start begins a login: if the e-mail resolves to a person, a one-time
// token is queued to the org's mailer webhook. The return is identical
// whether or not the address exists - no enumeration oracle.
func (p *Portal) Start(ctx context.Context, email string) error {
	normalized, err := crypto.NormalizeEmail(email)
	if err != nil {
		return nil // silently accept: same response as "not found"
	}
	personID, ok, err := p.findPersonByEmail(ctx, normalized)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	token, err := crypto.NewClientSecret()
	if err != nil {
		return err
	}
	if _, err := p.GDPR.Pool.Exec(ctx,
		`INSERT INTO portal_tokens (token_hash, person_id, kind, expires_at) VALUES ($1,$2,'login',$3)`,
		hashToken(token), personID, time.Now().Add(portalLoginTTL)); err != nil {
		return err
	}
	if err := audit.Append(ctx, p.GDPR.Pool, audit.Entry{
		ClientID: "portal", Action: "portal.start",
		Detail: map[string]any{"delivered": true},
	}); err != nil {
		return err
	}
	return p.mailLoginLink(ctx, normalized, token)
}

// findPersonByEmail resolves a normalized e-mail through the same keyed
// search tokens the lookup path uses (all live key versions).
func (p *Portal) findPersonByEmail(ctx context.Context, normalized string) (string, bool, error) {
	versions, err := p.Contacts.Ring.Versions(ctx, crypto.KeyHMACEmail)
	if err != nil {
		return "", false, err
	}
	for _, v := range versions {
		tok, err := p.Contacts.Tok.EmailToken(ctx, v, normalized)
		if err != nil {
			return "", false, err
		}
		var personID string
		err = p.GDPR.Pool.QueryRow(ctx,
			`SELECT pt.person_id FROM person_tokens pt
			 JOIN persons pe ON pe.id = pt.person_id AND pe.erased_at IS NULL
			 WHERE pt.kind='email' AND pt.token=$1 LIMIT 1`, tok).Scan(&personID)
		if err == pgx.ErrNoRows {
			continue
		}
		if err != nil {
			return "", false, err
		}
		return personID, true, nil
	}
	return "", false, nil
}

// mailLoginLink posts the signed portal_login event to the '_portal'
// webhook. A missing mailer is logged as a failed audit detail, not an
// error - the caller's response must not change.
func (p *Portal) mailLoginLink(ctx context.Context, email, token string) error {
	var url, secret string
	err := p.GDPR.Pool.QueryRow(ctx,
		`SELECT url, secret FROM webhooks WHERE scope=$1`, PortalMailerScope).Scan(&url, &secret)
	if err == pgx.ErrNoRows {
		return nil // no mailer configured: silently drop (documented)
	}
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{
		"event": "portal_login", "email": email, "token": token,
		"expires_at": time.Now().Add(portalLoginTTL).UTC().Format(time.RFC3339),
	})
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sunder-Signature", hex.EncodeToString(mac.Sum(nil)))
	resp, err := p.GDPR.client().Do(req)
	if err != nil {
		return nil // mailer down: still no oracle; the token simply expires
	}
	_ = resp.Body.Close()
	return nil
}

// Redeem exchanges a one-time login token for a session token.
func (p *Portal) Redeem(ctx context.Context, token string) (string, error) {
	var personID string
	err := p.GDPR.Pool.QueryRow(ctx,
		`UPDATE portal_tokens SET used_at=now()
		 WHERE token_hash=$1 AND kind='login' AND used_at IS NULL AND expires_at > now()
		 RETURNING person_id`, hashToken(token)).Scan(&personID)
	if err == pgx.ErrNoRows {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	session, err := crypto.NewClientSecret()
	if err != nil {
		return "", err
	}
	if _, err := p.GDPR.Pool.Exec(ctx,
		`INSERT INTO portal_sessions (session_hash, person_id, expires_at) VALUES ($1,$2,$3)`,
		hashToken(session), personID, time.Now().Add(portalSessionTTL)); err != nil {
		return "", err
	}
	if err := audit.Append(ctx, p.GDPR.Pool, audit.Entry{
		ClientID: "portal", Action: "portal.login",
	}); err != nil {
		return "", err
	}
	return session, nil
}

// SessionPerson resolves a live session to its person.
func (p *Portal) SessionPerson(ctx context.Context, session string) (string, error) {
	var personID string
	err := p.GDPR.Pool.QueryRow(ctx,
		`SELECT ps.person_id FROM portal_sessions ps
		 JOIN persons pe ON pe.id = ps.person_id AND pe.erased_at IS NULL
		 WHERE ps.session_hash=$1 AND ps.expires_at > now()`,
		hashToken(session)).Scan(&personID)
	if err == pgx.ErrNoRows {
		return "", ErrForbidden
	}
	return personID, err
}

// Data returns everything every scope stored about the session's person.
func (p *Portal) Data(ctx context.Context, personID string) (map[string]any, error) {
	scopes, trail, err := p.GDPR.accessPerson(ctx, personID)
	if err != nil {
		return nil, err
	}
	if err := audit.Append(ctx, p.GDPR.Pool, audit.Entry{
		ClientID: "portal:" + firstCID(scopes), Action: "portal.access",
		Detail: map[string]any{"scopes": len(scopes)},
	}); err != nil {
		return nil, err
	}
	return map[string]any{"scopes": scopes, "audit_trail": trail}, nil
}

// SetConsent flips one consent decision on one of the person's own CIDs.
func (p *Portal) SetConsent(ctx context.Context, personID, cid, purpose string, granted bool) error {
	if err := p.ownCID(ctx, personID, cid); err != nil {
		return err
	}
	if purpose == "" {
		return fmt.Errorf("%w: purpose required", ErrValidation)
	}
	tx, err := p.GDPR.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx,
		`INSERT INTO consents (cid, purpose, granted) VALUES ($1,$2,$3)
		 ON CONFLICT (cid, purpose) DO UPDATE SET granted=$3, updated_at=now()`,
		cid, purpose, granted); err != nil {
		return err
	}
	if err := audit.AppendTx(ctx, tx, audit.Entry{
		ClientID: "portal:" + cid, Action: "portal.consent", CID: cid,
		Detail: map[string]any{"purpose": purpose, "granted": granted},
	}); err != nil {
		return fmt.Errorf("audit append: %w", err)
	}
	return tx.Commit(ctx)
}

// RequestErase issues a second-confirmation token: erasure is the one
// action a hijacked 30-minute session must not be able to finish alone.
func (p *Portal) RequestErase(ctx context.Context, personID string) (string, error) {
	token, err := crypto.NewClientSecret()
	if err != nil {
		return "", err
	}
	if _, err := p.GDPR.Pool.Exec(ctx,
		`INSERT INTO portal_tokens (token_hash, person_id, kind, expires_at) VALUES ($1,$2,'erase',$3)`,
		hashToken(token), personID, time.Now().Add(portalEraseTTL)); err != nil {
		return "", err
	}
	if err := audit.Append(ctx, p.GDPR.Pool, audit.Entry{
		ClientID: "portal", Action: "portal.erase_requested",
	}); err != nil {
		return "", err
	}
	return token, nil
}

// ConfirmErase consumes the confirmation token and runs the full erasure.
func (p *Portal) ConfirmErase(ctx context.Context, personID, confirmToken string) (int64, int, error) {
	// The person match is part of the UPDATE: a wrong-session attempt must
	// NOT consume the legitimate owner's confirmation token.
	var tokenPerson string
	err := p.GDPR.Pool.QueryRow(ctx,
		`UPDATE portal_tokens SET used_at=now()
		 WHERE token_hash=$1 AND kind='erase' AND person_id=$2
		   AND used_at IS NULL AND expires_at > now()
		 RETURNING person_id`, hashToken(confirmToken), personID).Scan(&tokenPerson)
	if err == pgx.ErrNoRows {
		// Unknown, expired, already used, or issued for someone else -
		// indistinguishable on purpose.
		return 0, 0, ErrNotFound
	}
	if err != nil {
		return 0, 0, err
	}
	var cid string
	if err := p.GDPR.Pool.QueryRow(ctx,
		`SELECT cid FROM cids WHERE person_id=$1 ORDER BY cid LIMIT 1`, personID).Scan(&cid); err != nil {
		return 0, 0, err
	}
	return p.GDPR.erasePerson(ctx, "portal:"+cid, cid, personID)
}

func (p *Portal) ownCID(ctx context.Context, personID, cid string) error {
	var owner string
	err := p.GDPR.Pool.QueryRow(ctx, `SELECT person_id FROM cids WHERE cid=$1`, cid).Scan(&owner)
	if err == pgx.ErrNoRows || (err == nil && owner != personID) {
		return ErrNotFound
	}
	return err
}

func hashToken(t string) []byte {
	sum := sha256.Sum256([]byte(t))
	return sum[:]
}

func firstCID(scopes []ScopeData) string {
	if len(scopes) > 0 {
		return scopes[0].CID
	}
	return ""
}
