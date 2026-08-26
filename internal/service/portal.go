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
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/fvisic/sunder/internal/audit"
	"github.com/fvisic/sunder/internal/crypto"
)

// PortalMailerScope is the reserved webhooks.scope row carrying the org's
// mailer endpoint for portal login links.
const PortalMailerScope = "_portal"

// PortalSessionTTL is exported so the session cookie's MaxAge and the
// stored row's expiry cannot drift apart.
const PortalSessionTTL = 30 * time.Minute

const (
	// portalSendsPerWindow caps login mails per ADDRESS per window (N9).
	portalSendsPerWindow = 3
	portalSendWindow     = 15 * time.Minute

	// portalStartFloor is the minimum wall-clock duration of a login-start
	// request, whatever the outcome.
	portalStartFloor = 40 * time.Millisecond

	portalLoginTTL   = 15 * time.Minute
	portalSessionTTL = PortalSessionTTL
	portalEraseTTL   = 10 * time.Minute
)

// Portal bundles the self-service operations.
type Portal struct {
	GDPR     *GDPR
	Contacts *Contacts
	// BaseURL, when set, turns the mailed token into an actual clickable
	// link (SUNDER_PORTAL_BASE_URL). The token rides the FRAGMENT, which
	// browsers never send to the server and never put in a Referer.
	BaseURL string
}

// Start begins a login: if the e-mail resolves to a person, a one-time
// token is queued to the org's mailer webhook. The return is identical
// whether or not the address exists - no enumeration oracle.
func (p *Portal) Start(ctx context.Context, email string) error {
	startedAt := time.Now()
	// A CONSTANT-TIME FLOOR, not "equal work": removing the inline mail
	// send closed the network-round-trip gap, but the hit path still does
	// measurably more database work (throttle upsert, token insert, sealed
	// outbox insert) - about 2 ms, which separates perfectly under
	// measurement. Every call therefore returns no earlier than
	// portalStartFloor, which dominates that variance. Combined with the
	// 5/min per-IP limit and the per-address cap, enumeration is
	// impractical rather than merely inconvenient.
	defer func() {
		if remaining := portalStartFloor - time.Since(startedAt); remaining > 0 {
			select {
			case <-time.After(remaining):
			case <-ctx.Done():
			}
		}
	}()

	// The work itself is still kept as symmetric as practical:
	// - the address is resolved over ALL live key versions (no early
	// return on a hit, which would be observably faster);
	// - a hit ENQUEUES the mail into portal_outbox and returns; the
	// delivery (a network round-trip that used to run inline and made
	// the two branches trivially separable) happens in the background
	// worker.
	// This is not cryptographic constant time - the hit path does one more
	// INSERT - but the observable difference is no longer a network
	// round-trip, which is what made enumeration practical.
	normalized, nerr := crypto.NormalizeEmail(email)
	var personID string
	var found bool
	if nerr == nil {
		var err error
		personID, found, err = p.findPersonByEmail(ctx, normalized)
		if err != nil {
			return err
		}
	}
	// NO audit row in this request path, deliberately, for two reasons:
	//
	// - every audit append takes the global advisory lock that serialises
	// all audit writes, and this endpoint is UNAUTHENTICATED: writing
	// here lets anyone serialise the product's whole write path
	// ;
	// - a row whose presence or content depends on whether the address
	// exists is an enumeration oracle for anyone who can read the
	// chain and time their own probe.
	//
	// Accountability is not lost: the outbox worker records
	// portal.mail.delivered / .failed / .no_mailer for every queued mail,
	// and portal.login for every redeemed token. What is not recorded is
	// the failed guess - which is exactly the part that must not be.
	if !found {
		return nil
	}
	token, err := crypto.NewClientSecret()
	if err != nil {
		return err
	}
	expires := time.Now().Add(portalLoginTTL)
	tx, err := p.GDPR.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// The per-address throttle is counted INSIDE the transaction that mints
	// the token: counted outside, a rolled-back transaction still burned a
	// send, and three of those locked a citizen out for 15 minutes with an
	// empty inbox.
	allowed, err := p.allowEmailSend(ctx, tx, normalized)
	if err != nil {
		return err
	}
	if !allowed {
		return nil
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO portal_tokens (token_hash, person_id, kind, expires_at) VALUES ($1,$2,'login',$3)`,
		hashToken(token), personID, expires); err != nil {
		return err
	}
	if err := p.enqueueMail(ctx, tx, personID, "login", normalized, token, expires); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// allowEmailSend permits at most portalSendsPerWindow login mails per
// address per window (N9: there was no per-address limit at all).
func (p *Portal) allowEmailSend(ctx context.Context, tx pgx.Tx, normalized string) (bool, error) {
	// A KEYED token, like every other identifier index in this system: a
	// bare sha256 of an address is dictionary-attackable, which would turn
	// this throttle table into a list of registered addresses (probe C).
	version, err := p.Contacts.Ring.Newest(ctx, crypto.KeyHMACEmail)
	if err != nil {
		return false, err
	}
	tok, err := p.Contacts.Tok.EmailToken(ctx, version, normalized)
	if err != nil {
		return false, err
	}
	key := []byte(tok)
	var sends int
	err = tx.QueryRow(ctx,
		`INSERT INTO portal_email_throttle (email_token, window_start, sends)
		 VALUES ($1, now(), 1)
		 ON CONFLICT (email_token) DO UPDATE SET
		   window_start = CASE WHEN portal_email_throttle.window_start < now() - $2::interval
		                       THEN now() ELSE portal_email_throttle.window_start END,
		   sends = CASE WHEN portal_email_throttle.window_start < now() - $2::interval
		                THEN 1 ELSE portal_email_throttle.sends + 1 END
		 RETURNING sends`, key, portalSendWindow.String()).Scan(&sends)
	if err != nil {
		return false, err
	}
	return sends <= portalSendsPerWindow, nil
}

// mailPayload is what the outbox holds - SEALED, never in the clear: the
// token is a live credential and the address is PII.
type mailPayload struct {
	Email string `json:"email"`
	Token string `json:"token"`
}

// maxMailAttempts bounds retries before a queued mail is abandoned. A
// single transient mailer blip must not permanently lose a login link
// .
const maxMailAttempts = 5

func (p *Portal) enqueueMail(ctx context.Context, tx pgx.Tx, personID, kind, email, token string, expires time.Time) error {
	plain, err := json.Marshal(mailPayload{Email: email, Token: token})
	if err != nil {
		return err
	}
	keyID, err := p.Contacts.Ring.Newest(ctx, crypto.KeyPIIKEK)
	if err != nil {
		return err
	}
	sealed, err := p.Contacts.PII.SealBytes(ctx, "portal-outbox", keyID, plain)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO portal_outbox (kind, payload, key_id, alg, expires_at, person_id) VALUES ($1,$2,$3,$4,$5,$6)`,
		kind, sealed, keyID, p.Contacts.PII.Algorithm(), expires, personID)
	return err
}

// DeliverPendingMail is the background worker: it drains portal_outbox to
// the org's mailer webhook and records the REAL outcome. Transient
// failures stay PENDING and are retried up to maxMailAttempts; only then
// (or once the token has expired) is the row abandoned. Runs on the same
// ticker as the erasure webhook worker.
func (p *Portal) DeliverPendingMail(ctx context.Context) (int, error) {
	// CLAIM the rows: the worker runs in every replica (the chart defaults
	// to two), so a plain SELECT ... WHERE status='PENDING' had every
	// replica mail every link. SKIP LOCKED lets replicas work
	// disjoint batches; the transaction holds the claim until the outcome
	// is recorded.
	claim, err := p.GDPR.Pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = claim.Rollback(ctx) }()
	rows, err := claim.Query(ctx,
		`SELECT id, kind, payload, key_id, alg, expires_at, attempts FROM portal_outbox
		 WHERE status='PENDING' ORDER BY id LIMIT 100 FOR UPDATE SKIP LOCKED`)
	if err != nil {
		return 0, err
	}
	type item struct {
		id       int64
		kind     string
		payload  []byte
		keyID    string
		alg      string
		expires  time.Time
		attempts int
	}
	var items []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.id, &it.kind, &it.payload, &it.keyID, &it.alg, &it.expires, &it.attempts); err != nil {
			rows.Close()
			return 0, err
		}
		items = append(items, it)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	// Mark the batch CLAIMED inside the same transaction, so releasing the
	// row locks does not hand the same rows to another replica.
	if len(items) > 0 {
		ids := make([]int64, 0, len(items))
		for _, it := range items {
			ids = append(ids, it.id)
		}
		if _, err := claim.Exec(ctx,
			`UPDATE portal_outbox SET status='SENDING' WHERE id = ANY($1)`, ids); err != nil {
			return 0, err
		}
	}
	if err := claim.Commit(ctx); err != nil {
		return 0, err
	}

	delivered := 0
	for _, it := range items {
		plain, err := p.Contacts.PII.OpenBytes(ctx, "portal-outbox", it.payload, it.keyID, it.alg)
		if err != nil {
			// Unopenable payload (retired key): abandon, never retry.
			p.settleMail(ctx, it.id, it.kind, "FAILED")
			continue
		}
		var mp mailPayload
		if err := json.Unmarshal(plain, &mp); err != nil {
			p.settleMail(ctx, it.id, it.kind, "FAILED")
			continue
		}
		switch err := p.mail(ctx, it.kind, mp.Email, mp.Token, it.expires); {
		case err == errNoMailer:
			p.settleMail(ctx, it.id, it.kind, "NO_MAILER")
		case err == nil:
			p.settleMail(ctx, it.id, it.kind, "DELIVERED")
			delivered++
		default:
			// Transient: keep it PENDING for the next sweep unless the
			// attempt cap is reached or the token has already expired.
			attempts := it.attempts + 1
			if attempts >= maxMailAttempts || time.Now().After(it.expires) {
				p.settleMail(ctx, it.id, it.kind, "FAILED")
				continue
			}
			if _, err := p.GDPR.Pool.Exec(ctx,
				`UPDATE portal_outbox SET attempts=$2, status='PENDING' WHERE id=$1`,
				it.id, attempts); err != nil {
				continue
			}
		}
	}
	return delivered, nil
}

// settleMail records a terminal outcome for one queued mail, with the audit
// row reflecting what actually happened.
func (p *Portal) settleMail(ctx context.Context, id int64, kind, status string) {
	tx, err := p.GDPR.Pool.Begin(ctx)
	if err != nil {
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx,
		`UPDATE portal_outbox SET status=$2, attempts=attempts+1 WHERE id=$1`, id, status); err != nil {
		return
	}
	if err := audit.AppendTx(ctx, tx, audit.Entry{
		ClientID: "portal", Action: "portal.mail." + strings.ToLower(status),
		Detail: map[string]any{"kind": kind, "outbox_id": id},
	}); err != nil {
		return
	}
	_ = tx.Commit(ctx)
}

var errNoMailer = errors.New("portal: no mailer webhook configured")

// findPersonByEmail resolves a normalized e-mail through the same keyed
// search tokens the lookup path uses (all live key versions).
func (p *Portal) findPersonByEmail(ctx context.Context, normalized string) (string, bool, error) {
	versions, err := p.Contacts.Ring.Versions(ctx, crypto.KeyHMACEmail)
	if err != nil {
		return "", false, err
	}
	// Every live version is queried on BOTH outcomes: returning on the
	// first hit made a hit observably cheaper than a miss.
	var hit string
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
		if hit == "" {
			hit = personID
		}
	}
	return hit, hit != "", nil
}

// mail posts a signed portal event to the '_portal' webhook and returns
// the REAL outcome: errNoMailer when none is configured, an error when the
// transport or the receiver failed. The caller (the outbox worker) records
// it; no request path blocks on this.
func (p *Portal) mail(ctx context.Context, kind, email, token string, expires time.Time) error {
	var url, secret string
	err := p.GDPR.Pool.QueryRow(ctx,
		`SELECT url, secret FROM webhooks WHERE scope=$1`, PortalMailerScope).Scan(&url, &secret)
	if err == pgx.ErrNoRows {
		return errNoMailer
	}
	if err != nil {
		return err
	}
	payload := map[string]string{
		"event": "portal_" + kind, "email": email, "token": token,
		"expires_at": expires.UTC().Format(time.RFC3339),
	}
	if p.BaseURL != "" {
		payload["link"] = strings.TrimSuffix(p.BaseURL, "/") + "/portal/#token=" + token
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
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
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("portal mailer returned %d", resp.StatusCode)
	}
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

// RequestErase starts an erasure: the confirmation token is mailed
// OUT OF BAND (same mailer path as login), never returned to the caller.
// Returning it to the session that asked for it was security theatre -
// whoever holds the cookie just makes two calls. Erasure is
// irreversible and cross-scope, so the second factor must leave the
// session: possession of the mailbox is what confirms it.
//
// Outstanding confirmations for the person are invalidated first, so a
// requester cannot accumulate live erase tokens.
func (p *Portal) RequestErase(ctx context.Context, personID string) error {
	// Already erased: nothing to confirm, and no oracle either.
	var erased bool
	if err := p.GDPR.Pool.QueryRow(ctx,
		`SELECT erased_at IS NOT NULL FROM persons WHERE id=$1`, personID).Scan(&erased); err != nil {
		return err
	}
	if erased {
		return ErrNotFound
	}
	email, err := p.primaryEmail(ctx, personID)
	if err != nil {
		return err
	}
	token, err := crypto.NewClientSecret()
	if err != nil {
		return err
	}
	expires := time.Now().Add(portalEraseTTL)
	tx, err := p.GDPR.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx,
		`UPDATE portal_tokens SET used_at=now()
		 WHERE person_id=$1 AND kind='erase' AND used_at IS NULL`, personID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO portal_tokens (token_hash, person_id, kind, expires_at) VALUES ($1,$2,'erase',$3)`,
		hashToken(token), personID, expires); err != nil {
		return err
	}
	if err := p.enqueueMail(ctx, tx, personID, "erase_confirm", email, token, expires); err != nil {
		return err
	}
	if err := audit.AppendTx(ctx, tx, audit.Entry{
		ClientID: "portal", Action: "portal.erase_requested",
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// primaryEmail returns one stored e-mail for the person - the address the
// confirmation is mailed to. Read from the person's own scope blobs, so it
// is the address the org already holds, never caller-supplied.
func (p *Portal) primaryEmail(ctx context.Context, personID string) (string, error) {
	rows, err := p.GDPR.Pool.Query(ctx,
		`SELECT cid, COALESCE(pii_encrypted,''::bytea), COALESCE(pii_key_id,'v1'), COALESCE(pii_alg,'aes256gcm')
		 FROM cids WHERE person_id=$1 ORDER BY cid`, personID)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	for rows.Next() {
		var cid, keyID, alg string
		var blob []byte
		if err := rows.Scan(&cid, &blob, &keyID, &alg); err != nil {
			return "", err
		}
		if len(blob) == 0 {
			continue
		}
		attrs, err := p.Contacts.PII.Decrypt(ctx, cid, blob, keyID, alg)
		if err != nil {
			continue
		}
		for k, v := range attrs {
			if k == "email" || strings.HasPrefix(k, "email_") {
				return v, nil
			}
		}
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("%w: no e-mail on file to confirm against", ErrValidation)
}

// ConfirmErase consumes the confirmation token and runs the full erasure.
func (p *Portal) ConfirmErase(ctx context.Context, personID, confirmToken string) (int64, int, error) {
	// Resolve the audit CID BEFORE consuming the token: doing it after
	// meant a person with no CID row burned their confirmation on a 500.
	var auditCID string
	if err := p.GDPR.Pool.QueryRow(ctx,
		`SELECT cid FROM cids WHERE person_id=$1 ORDER BY cid LIMIT 1`, personID).Scan(&auditCID); err != nil {
		if err == pgx.ErrNoRows {
			return 0, 0, ErrNotFound
		}
		return 0, 0, err
	}
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
	return p.GDPR.erasePerson(ctx, "portal:"+auditCID, auditCID, personID)
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

// Logout revokes the current session immediately. A citizen surface with no
// way to end a session is a gap, not a simplification.
func (p *Portal) Logout(ctx context.Context, session string) error {
	_, err := p.GDPR.Pool.Exec(ctx,
		`DELETE FROM portal_sessions WHERE session_hash=$1`, hashToken(session))
	return err
}

// PrunePortal deletes expired sessions, spent or expired one-time tokens,
// and settled outbox rows, and drops everything belonging to an erased
// person. Runs from `sunder retention run` - none of these tables were
// cleaned up before.
func PrunePortal(ctx context.Context, pool *pgxpool.Pool) (int64, error) {
	var total int64
	for _, q := range []string{
		`DELETE FROM portal_sessions WHERE expires_at < now()`,
		`DELETE FROM portal_sessions ps USING persons p
		   WHERE p.id = ps.person_id AND p.erased_at IS NOT NULL`,
		`DELETE FROM portal_tokens WHERE expires_at < now() OR used_at IS NOT NULL`,
		`DELETE FROM portal_tokens pt USING persons p
		   WHERE p.id = pt.person_id AND p.erased_at IS NOT NULL`,
		`DELETE FROM portal_outbox WHERE status NOT IN ('PENDING','SENDING') AND created_at < now() - interval '7 days'`,
		// A PENDING row whose token has expired can never be useful: an
		// unreachable mailer would otherwise grow this table without bound
		//.
		`DELETE FROM portal_outbox WHERE status='PENDING' AND expires_at < now()`,
		// A claim left behind by a crashed worker returns to the queue.
		`UPDATE portal_outbox SET status='PENDING'
		   WHERE status='SENDING' AND created_at < now() - interval '10 minutes'`,
		`DELETE FROM portal_email_throttle WHERE window_start < now() - interval '1 day'`,
	} {
		tag, err := pool.Exec(ctx, q)
		if err != nil {
			return total, err
		}
		total += tag.RowsAffected()
	}
	return total, nil
}
