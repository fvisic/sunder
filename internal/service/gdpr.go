package service

// GDPR / data-subject rights layer (docs/DESIGN.md, GDPR layer): consent
// management, right of access, right to erasure (orchestrated org-wide via
// signed webhooks - the provider is the only component that knows which
// scopes hold a person), data portability, and per-scope retention.

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
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/fvisic/sunder/internal/audit"
	"github.com/fvisic/sunder/internal/auth"
)

// ErrConsentDenied maps to 403 consent_denied: the person explicitly
// withdrew consent for this purpose.
var ErrConsentDenied = errors.New("consent denied")

// GDPR bundles the data-subject-rights operations.
type GDPR struct {
	Pool     *pgxpool.Pool
	Contacts *Contacts
	HTTP     *http.Client // webhook delivery; nil -> hardened default with HTTPTimeout
	// HTTPTimeout bounds each webhook POST; zero means DefaultWebhookTimeout.
	HTTPTimeout time.Duration
	// MaxAttempts is the failed-delivery cap before FAILED; zero means
	// DefaultWebhookMaxAttempts.
	MaxAttempts int
}

func (g *GDPR) client() *http.Client {
	if g.HTTP != nil {
		return g.HTTP
	}
	t := g.HTTPTimeout
	if t <= 0 {
		t = DefaultWebhookTimeout
	}
	return &http.Client{
		Timeout: t,
		// Never follow redirects: a hostile/compromised webhook receiver
		// must not be able to steer the signed POST at internal addresses.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// --- consent -----------------------------------------------------------------

// Consent is one (purpose, granted) decision for a CID.
type Consent struct {
	Purpose   string    `json:"purpose"`
	Granted   bool      `json:"granted"`
	UpdatedAt time.Time `json:"updated_at"`
}

// SetConsent records a consent decision for a caller-scope CID.
func (g *GDPR) SetConsent(ctx context.Context, client *auth.Client, cid, purpose string, granted bool) error {
	if !client.Can(auth.ActConsentManage) {
		return ErrForbidden
	}
	if purpose == "" {
		return fmt.Errorf("%w: purpose required", ErrValidation)
	}
	if _, err := g.Contacts.personForClientCID(ctx, client, cid); err != nil {
		return err
	}
	tx, err := g.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx,
		`INSERT INTO consents (cid, purpose, granted) VALUES ($1,$2,$3)
		 ON CONFLICT (cid, purpose) DO UPDATE SET granted=EXCLUDED.granted, updated_at=now()`,
		cid, purpose, granted); err != nil {
		return err
	}
	if err := audit.AppendTx(ctx, tx, audit.Entry{
		ClientID: client.ID, Action: "consent.set", CID: cid,
		Detail: map[string]any{"purpose": purpose, "granted": granted},
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ListConsents returns the decisions recorded for a caller-scope CID.
func (g *GDPR) ListConsents(ctx context.Context, client *auth.Client, cid string) ([]Consent, error) {
	if !client.Can(auth.ActConsentManage) {
		return nil, ErrForbidden
	}
	if _, err := g.Contacts.personForClientCID(ctx, client, cid); err != nil {
		return nil, err
	}
	return consentsFor(ctx, g.Pool, cid)
}

func consentsFor(ctx context.Context, pool *pgxpool.Pool, cid string) ([]Consent, error) {
	rows, err := pool.Query(ctx,
		`SELECT purpose, granted, updated_at FROM consents WHERE cid=$1 ORDER BY purpose`, cid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Consent{}
	for rows.Next() {
		var c Consent
		if err := rows.Scan(&c.Purpose, &c.Granted, &c.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// consentDenied is the enforcement hook used by attribute reads and OTI
// issuance: only an explicit granted=false row blocks (absence = the
// purpose is not consent-governed).
func consentDenied(ctx context.Context, pool *pgxpool.Pool, cid, purpose string) (bool, error) {
	var granted bool
	err := pool.QueryRow(ctx,
		`SELECT granted FROM consents WHERE cid=$1 AND purpose=$2`, cid, purpose).Scan(&granted)
	if err == pgx.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return !granted, nil
}

// --- right of access / portability --------------------------------------------

// ScopeData is one scope's view of a person, decrypted for the DSR response.
type ScopeData struct {
	Scope      string            `json:"scope"`
	CID        string            `json:"cid"`
	Attributes map[string]string `json:"attributes"`
	Consents   []Consent         `json:"consents"`
}

// AuditTrailEntry is one access-log line included in a right-of-access
// response (who touched this person, when, doing what).
type AuditTrailEntry struct {
	Seq      int64     `json:"seq"`
	TS       time.Time `json:"ts"`
	ClientID string    `json:"client_id"`
	Action   string    `json:"action"`
	CID      string    `json:"cid"`
}

const accessTrailLimit = 10000

// Access implements the GDPR right of access, org-wide: everything every
// scope stored about the person plus the audit trail of who touched them.
// dsr.access is a high-privilege, linkage-capable action for the privacy
// officer's client only.
func (g *GDPR) Access(ctx context.Context, client *auth.Client, cid string) (map[string]any, error) {
	if !client.Can(auth.ActDSRAccess) {
		return nil, ErrForbidden
	}
	personID, err := g.Contacts.personForClientCID(ctx, client, cid)
	if err != nil {
		return nil, err
	}
	scopes, trail, err := g.accessPerson(ctx, personID)
	if err != nil {
		return nil, err
	}
	if err := audit.Append(ctx, g.Pool, audit.Entry{
		ClientID: client.ID, Action: "dsr.access", CID: cid,
		Detail: map[string]any{"scopes": len(scopes)},
	}); err != nil {
		return nil, fmt.Errorf("audit append: %w", err)
	}
	return map[string]any{"scopes": scopes, "audit_trail": trail}, nil
}

// accessPerson gathers everything every scope stored about a person plus
// the audit trail - shared by the privacy officer's Access and the
// self-service portal (which authenticates the person directly).
func (g *GDPR) accessPerson(ctx context.Context, personID string) ([]ScopeData, []AuditTrailEntry, error) {
	rows, err := g.Pool.Query(ctx,
		`SELECT cid, scope, pii_encrypted, COALESCE(pii_key_id,'v1'), COALESCE(pii_alg,'aes256gcm') FROM cids WHERE person_id=$1 ORDER BY scope`, personID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var scopes []ScopeData
	var cidList []string
	for rows.Next() {
		var sd ScopeData
		var blob []byte
		var keyID, alg string
		if err := rows.Scan(&sd.CID, &sd.Scope, &blob, &keyID, &alg); err != nil {
			return nil, nil, err
		}
		sd.Attributes = map[string]string{}
		if len(blob) > 0 {
			if sd.Attributes, err = g.Contacts.PII.Decrypt(ctx, sd.CID, blob, keyID, alg); err != nil {
				return nil, nil, err
			}
		}
		if sd.Consents, err = consentsFor(ctx, g.Pool, sd.CID); err != nil {
			return nil, nil, err
		}
		scopes = append(scopes, sd)
		cidList = append(cidList, sd.CID)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	trailRows, err := g.Pool.Query(ctx,
		`SELECT seq, ts, COALESCE(client_id,''), action, COALESCE(cid,'')
		 FROM audit WHERE cid = ANY($1) ORDER BY seq LIMIT $2`, cidList, accessTrailLimit)
	if err != nil {
		return nil, nil, err
	}
	defer trailRows.Close()
	trail := []AuditTrailEntry{}
	for trailRows.Next() {
		var e AuditTrailEntry
		if err := trailRows.Scan(&e.Seq, &e.TS, &e.ClientID, &e.Action, &e.CID); err != nil {
			return nil, nil, err
		}
		trail = append(trail, e)
	}
	if err := trailRows.Err(); err != nil {
		return nil, nil, err
	}
	return scopes, trail, nil
}

// Export implements data portability for the CALLER'S scope only: a
// machine-readable dump of what this scope holds.
func (g *GDPR) Export(ctx context.Context, client *auth.Client, cid string) (*ScopeData, error) {
	if !client.Can(auth.ActDSRExport) {
		return nil, ErrForbidden
	}
	if _, err := g.Contacts.personForClientCID(ctx, client, cid); err != nil {
		return nil, err
	}
	sd := &ScopeData{Scope: client.Scope, CID: cid, Attributes: map[string]string{}}
	var blob []byte
	var keyID, alg string
	err := g.Pool.QueryRow(ctx,
		`SELECT pii_encrypted, COALESCE(pii_key_id,'v1'), COALESCE(pii_alg,'aes256gcm') FROM cids WHERE cid=$1`, cid).Scan(&blob, &keyID, &alg)
	if err != nil {
		return nil, err
	}
	if len(blob) > 0 {
		if sd.Attributes, err = g.Contacts.PII.Decrypt(ctx, cid, blob, keyID, alg); err != nil {
			return nil, err
		}
	}
	if sd.Consents, err = consentsFor(ctx, g.Pool, cid); err != nil {
		return nil, err
	}
	if err := audit.Append(ctx, g.Pool, audit.Entry{
		ClientID: client.ID, Action: "dsr.export", CID: cid, Detail: map[string]any{},
	}); err != nil {
		return nil, err
	}
	return sd, nil
}

// --- right to erasure ---------------------------------------------------------

// Erase implements the right to be forgotten, org-wide and fail-closed:
// every scope's blob is wiped, every search token deleted, the person
// becomes a tombstone (client-side CID references never break), and one
// erasure event per scope is queued for signed webhook delivery. A later
// registration of the same identifiers creates a brand-new person.
func (g *GDPR) Erase(ctx context.Context, client *auth.Client, cid string) (erasureID int64, scopes int, err error) {
	if !client.Can(auth.ActDSRErase) {
		return 0, 0, ErrForbidden
	}
	personID, err := g.Contacts.personForClientCID(ctx, client, cid)
	if err != nil {
		return 0, 0, err
	}
	return g.erasePerson(ctx, client.ID, cid, personID)
}

// erasePerson runs the full erasure for a person - shared by the privacy
// officer's Erase and the self-service portal. actor lands in the audit
// record and the erasure row; auditCID is the pseudonym the request came in
// under (portal erasures use the person's first CID).
func (g *GDPR) erasePerson(ctx context.Context, actor, auditCID, personID string) (erasureID int64, scopes int, err error) {
	tx, err := g.Pool.Begin(ctx)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Idempotency guard: a tombstone cannot be erased again (a second call
	// would re-queue webhook deliveries for an already-forgotten person).
	var alreadyErased bool
	if err := tx.QueryRow(ctx,
		`SELECT erased_at IS NOT NULL FROM persons WHERE id=$1 FOR UPDATE`, personID).Scan(&alreadyErased); err != nil {
		return 0, 0, err
	}
	if alreadyErased {
		return 0, 0, fmt.Errorf("%w: person already erased", ErrValidation)
	}

	if err := tx.QueryRow(ctx,
		`INSERT INTO erasures (person_id, requested_by) VALUES ($1,$2) RETURNING id`,
		personID, actor).Scan(&erasureID); err != nil {
		return 0, 0, err
	}
	rows, err := tx.Query(ctx, `SELECT cid, scope FROM cids WHERE person_id=$1`, personID)
	if err != nil {
		return 0, 0, err
	}
	type sc struct{ cid, scope string }
	var all []sc
	for rows.Next() {
		var s sc
		if err := rows.Scan(&s.cid, &s.scope); err != nil {
			rows.Close()
			return 0, 0, err
		}
		all = append(all, s)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, 0, err
	}
	for _, s := range all {
		if _, err := tx.Exec(ctx,
			`INSERT INTO erasure_events (erasure_id, scope, cid) VALUES ($1,$2,$3)`,
			erasureID, s.scope, s.cid); err != nil {
			return 0, 0, err
		}
	}
	if _, err := tx.Exec(ctx,
		`UPDATE cids SET pii_encrypted=NULL, pii_key_id=NULL, pii_alg='aes256gcm' WHERE person_id=$1`, personID); err != nil {
		return 0, 0, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM person_tokens WHERE person_id=$1`, personID); err != nil {
		return 0, 0, err
	}
	// Outstanding one-time tokens die with the person: a pre-erasure OTI
	// must not stay verifiable (it would mint a fresh live CID for the
	// forgotten person in the verifier's scope).
	if _, err := tx.Exec(ctx,
		`UPDATE oti SET status='REVOKED' WHERE status='VALID'
		   AND cid IN (SELECT cid FROM cids WHERE person_id=$1)`, personID); err != nil {
		return 0, 0, err
	}
	if _, err := tx.Exec(ctx, `UPDATE persons SET erased_at=now() WHERE id=$1`, personID); err != nil {
		return 0, 0, err
	}
	if err := audit.AppendTx(ctx, tx, audit.Entry{
		ClientID: actor, Action: "dsr.erase", CID: auditCID,
		Detail: map[string]any{"erasure_id": erasureID, "scopes": len(all)},
	}); err != nil {
		return 0, 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, 0, err
	}
	// Best-effort immediate delivery; the periodic worker retries the rest.
	_, _ = g.DeliverPending(ctx)
	return erasureID, len(all), nil
}

// --- webhook delivery ----------------------------------------------------------

// erasePayload is what a scope's system receives when one of its CIDs must
// be forgotten. The body is signed: X-Sunder-Signature =
// hex(HMAC-SHA256(webhook secret, body)).
type erasePayload struct {
	Event     string `json:"event"` // "erase"
	Scope     string `json:"scope"`
	CID       string `json:"cid"`
	ErasureID int64  `json:"erasure_id"`
	TS        string `json:"ts"`
}

// Delivery defaults; overridable via SUNDER_WEBHOOK_TIMEOUT and
// SUNDER_WEBHOOK_MAX_ATTEMPTS (the attempts cap keeps one dead endpoint from
// starving the queue; every terminal transition is audited).
const (
	DefaultWebhookTimeout     = 5 * time.Second
	DefaultWebhookMaxAttempts = 10
)

func (g *GDPR) maxAttempts() int {
	if g.MaxAttempts <= 0 {
		return DefaultWebhookMaxAttempts
	}
	return g.MaxAttempts
}

// DeliverPending pushes queued erasure events to their scopes' webhooks.
// Events for scopes without a webhook are marked NO_WEBHOOK; failures stay
// PENDING until the attempts cap, then FAILED. Every terminal transition is
// written to the audit chain - delivery confirmations are accountability
// records, not operational noise.
func (g *GDPR) DeliverPending(ctx context.Context) (delivered int, err error) {
	rows, err := g.Pool.Query(ctx,
		`SELECT e.id, e.erasure_id, e.scope, e.cid, w.url, w.secret
		 FROM erasure_events e LEFT JOIN webhooks w ON w.scope = e.scope
		 WHERE e.status='PENDING' ORDER BY e.attempts, e.id LIMIT 100`)
	if err != nil {
		return 0, err
	}
	type ev struct {
		id, erasureID int64
		scope, cid    string
		url, secret   *string
	}
	var evs []ev
	for rows.Next() {
		var e ev
		if err := rows.Scan(&e.id, &e.erasureID, &e.scope, &e.cid, &e.url, &e.secret); err != nil {
			rows.Close()
			return 0, err
		}
		evs = append(evs, e)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	terminal := func(e ev, status, action string) {
		tx, err := g.Pool.Begin(ctx)
		if err != nil {
			return
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx,
			`UPDATE erasure_events SET status=$2, delivered_at=CASE WHEN $2='DELIVERED' THEN now() END,
			        attempts=attempts+1 WHERE id=$1`, e.id, status); err != nil {
			return
		}
		if err := audit.AppendTx(ctx, tx, audit.Entry{
			ClientID: "system", Action: action, CID: e.cid,
			Detail: map[string]any{"erasure_id": e.erasureID, "scope": e.scope, "event_id": e.id},
		}); err != nil {
			return
		}
		_ = tx.Commit(ctx)
	}

	for _, e := range evs {
		if e.url == nil {
			terminal(e, "NO_WEBHOOK", "dsr.erase.no_webhook")
			continue
		}
		body, _ := json.Marshal(erasePayload{
			Event: "erase", Scope: e.scope, CID: e.cid, ErasureID: e.erasureID,
			TS: time.Now().UTC().Format(time.RFC3339),
		})
		mac := hmac.New(sha256.New, []byte(*e.secret))
		mac.Write(body)
		req, err := http.NewRequestWithContext(ctx, "POST", *e.url, bytes.NewReader(body))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Sunder-Signature", hex.EncodeToString(mac.Sum(nil)))
		resp, err := g.client().Do(req)
		ok := err == nil && resp.StatusCode >= 200 && resp.StatusCode < 300
		if resp != nil {
			_ = resp.Body.Close()
		}
		if ok {
			terminal(e, "DELIVERED", "dsr.erase.delivered")
			delivered++
			continue
		}
		var attempts int
		if err := g.Pool.QueryRow(ctx,
			`UPDATE erasure_events SET attempts=attempts+1 WHERE id=$1 RETURNING attempts`, e.id).Scan(&attempts); err != nil {
			continue
		}
		if attempts >= g.maxAttempts() {
			// terminal() adds one more attempt in its UPDATE; compensate by
			// marking FAILED directly here with an audited record.
			tx, err := g.Pool.Begin(ctx)
			if err != nil {
				continue
			}
			if _, err := tx.Exec(ctx,
				`UPDATE erasure_events SET status='FAILED' WHERE id=$1`, e.id); err == nil {
				if audit.AppendTx(ctx, tx, audit.Entry{
					ClientID: "system", Action: "dsr.erase.failed", CID: e.cid,
					Detail: map[string]any{"erasure_id": e.erasureID, "scope": e.scope, "event_id": e.id, "attempts": attempts},
				}) == nil {
					_ = tx.Commit(ctx)
				}
			}
			_ = tx.Rollback(ctx)
		}
	}
	return delivered, nil
}

// --- retention ------------------------------------------------------------------

// RunRetention applies per-scope contact TTLs (blob wipe, audited) and
// prunes long-expired OTI rows. Audit rows are NEVER pruned: the hash chain
// plus external anchors are the tamper evidence.
func RunRetention(ctx context.Context, pool *pgxpool.Pool) (wiped int64, otiPruned int64, err error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// TTL keys off updated_at (bumped on every blob write): an actively
	// maintained contact is never "old" just because it was first seen long
	// ago. RETURNING captures WHICH pseudonyms lost data - a PII-destroying
	// mutation needs a per-CID accountability trail, not just a count.
	rows, err := tx.Query(ctx,
		`UPDATE cids c SET pii_encrypted=NULL, pii_key_id=NULL
		 FROM retention_policies rp
		 WHERE rp.scope = c.scope
		   AND c.pii_encrypted IS NOT NULL
		   AND c.updated_at < now() - make_interval(days => rp.contacts_ttl_days)
		 RETURNING c.cid`)
	if err != nil {
		return 0, 0, err
	}
	var wipedCIDs []string
	for rows.Next() {
		var cid string
		if err := rows.Scan(&cid); err != nil {
			rows.Close()
			return 0, 0, err
		}
		wipedCIDs = append(wipedCIDs, cid)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, 0, err
	}
	wiped = int64(len(wipedCIDs))

	tag, err := tx.Exec(ctx, `DELETE FROM oti WHERE expires_at < now() - interval '30 days'`)
	if err != nil {
		return 0, 0, err
	}
	otiPruned = tag.RowsAffected()
	if wiped > 0 || otiPruned > 0 {
		detail := map[string]any{"blobs_wiped": wiped, "oti_pruned": otiPruned}
		const listCap = 500
		if len(wipedCIDs) > listCap {
			detail["cids"] = wipedCIDs[:listCap]
			detail["cids_truncated"] = true
		} else {
			detail["cids"] = wipedCIDs
		}
		if err := audit.AppendTx(ctx, tx, audit.Entry{
			ClientID: "system", Action: "retention.run", Detail: detail,
		}); err != nil {
			return 0, 0, err
		}
	}
	return wiped, otiPruned, tx.Commit(ctx)
}
