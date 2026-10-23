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
	"log/slog"
	"net/http"
	"sync"
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
	// ClaimTTL is how long a claimed (SENDING) event may go unsettled
	// before the reaper returns it to the queue; zero means
	// DefaultWorkerClaimTTL. Wired from SUNDER_WORKER_CLAIM_TTL.
	ClaimTTL time.Duration
	// Log receives the settle failures that used to be swallowed. Nil means
	// slog.Default().
	Log *slog.Logger
	// MaxCascadeChildren bounds one cascading erasure; zero means
	// DefaultMaxCascadeChildren. Wired from SUNDER_MAX_CASCADE_CHILDREN.
	MaxCascadeChildren int

	// wg holds the detached deliveries dispatched by erasePerson so a
	// graceful shutdown can wait for them (Drain).
	wg sync.WaitGroup
}

// DefaultMaxCascadeChildren bounds a cascading erasure when nothing else
// says otherwise. One thousand people is already a large deliberate act;
// beyond it the operator should be choosing batches, not discovering the
// size from a timeout.
const DefaultMaxCascadeChildren = 1000

// ErrCascadeTooLarge is returned BEFORE anything is erased. The parent and
// every child are untouched: a request that would destroy more data than
// the deployment allows must not half-run.
var ErrCascadeTooLarge = errors.New("cascade too large")

func (g *GDPR) maxCascadeChildren() int {
	if g.MaxCascadeChildren <= 0 {
		return DefaultMaxCascadeChildren
	}
	return g.MaxCascadeChildren
}

func (g *GDPR) logger() *slog.Logger {
	if g.Log != nil {
		return g.Log
	}
	return slog.Default()
}

// Drain waits for deliveries dispatched off the request goroutine. Called
// from the server's shutdown path so a stop does not abandon an in-flight
// webhook and leave its claim to the reaper.
func (g *GDPR) Drain() { g.wg.Wait() }

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
	// The purpose must be one the CLIENT may operate under, like every other
	// purposed call (GetAttribute, shares.Create): without this, a client
	// could manage consent - and through the revoke below, kill standing
	// shares - for purposes entirely outside its own remit. Checked AFTER
	// cid resolution so an unknown/foreign cid stays a plain 404, never a
	// purpose-dependent 403 oracle.
	if !client.CanUse(purpose) {
		return ErrForbidden
	}
	tx, err := g.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Liveness is re-checked INSIDE the transaction, under the same row
	// locks erasePerson takes. The resolution above ran on the pool, and
	// under READ COMMITTED that answer is stale by the time this row lands:
	// an erasure committing in between deleted rows that did not exist yet,
	// so the write survived the sweep the erasure code promises empties this
	// table (GDPR-ERASURE-5).
	if _, err := lockPersonRows(ctx, tx, cid); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO consents (cid, purpose, granted) VALUES ($1,$2,$3)
		 ON CONFLICT (cid, purpose) DO UPDATE SET granted=EXCLUDED.granted, updated_at=now()`,
		cid, purpose, granted); err != nil {
		return err
	}
	// F8: withdrawing consent revokes the standing shares this withdrawal
	// actually governs - THIS cid, THIS purpose. Shares carry a purpose
	// (S1) and their fetch re-checks consent per (cid, purpose), so a
	// person-wide revoke was both redundant and a cross-scope hammer: a
	// client in scope A with only consent.manage could kill every scope's
	// shares for every purpose.
	if !granted {
		if err := revokeShares(ctx, tx, cid, purpose); err != nil {
			return err
		}
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
		if err := rows.Scan(&c.Purpose, &c.Granted, &c.UpdatedAt); err != nil { //coverage:defensive rows.Scan failure needs a DB fault injected at this exact statement
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
	// The holdings a subject cannot see in Attributes, because they do not
	// live in the blob. Article 15(1) is "what do you hold about me", and
	// 15(1)(c) is "who did you disclose it to" - a value token holding the
	// person's IBAN, a file, a standing share with a named partner and a
	// link to another person are all answers to those questions, and none
	// of them appeared in any subject-facing response (TOKENS-LOOKUP-7,
	// GAP-2). Metadata only: the values reach the subject through the
	// controller's own channel, and a share's partner label is the
	// recipient, not their data.
	ValueTokens []ValueTokenRef `json:"value_tokens"`
	Files       []FileRef       `json:"files"`
	Shares      []ShareRef      `json:"shares"`
	Links       []LinkRef       `json:"links"`
}

// ValueTokenRef is one tokenized value held for this person. Never the
// value itself.
type ValueTokenRef struct {
	Token     string     `json:"token"`
	Type      string     `json:"type"`
	Scope     string     `json:"scope"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	LastUsed  *time.Time `json:"last_used,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// FileRef is one stored file. Never its content.
type FileRef struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	ContentType string     `json:"content_type"`
	SizeBytes   int64      `json:"size_bytes"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// ShareRef is one disclosure to a named recipient - the Article 15(1)(c)
// answer.
type ShareRef struct {
	UUID      string    `json:"uuid"`
	Partner   string    `json:"partner_label"`
	Fields    []string  `json:"fields"`
	Purpose   string    `json:"purpose"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"revoked"`
}

// LinkRef is one relationship to another person in the same scope.
type LinkRef struct {
	CID      string `json:"cid"`
	LinkType string `json:"link_type"`
	Role     string `json:"role"`
}

// holdingsFor fills the non-blob holdings for one cid. Read-only and
// metadata-only; every query is scoped to the cid the caller already
// resolved.
func (g *GDPR) holdingsFor(ctx context.Context, sd *ScopeData) error {
	sd.ValueTokens, sd.Files, sd.Shares, sd.Links = []ValueTokenRef{}, []FileRef{}, []ShareRef{}, []LinkRef{}

	vt, err := g.Pool.Query(ctx, `
		SELECT token, token_type, scope, COALESCE(created_by,''), created_at, last_used, expires_final
		  FROM value_tokens WHERE cid=$1 ORDER BY created_at`, sd.CID)
	if err != nil {
		return err
	}
	for vt.Next() {
		var r ValueTokenRef
		if err := vt.Scan(&r.Token, &r.Type, &r.Scope, &r.CreatedBy, &r.CreatedAt, &r.LastUsed, &r.ExpiresAt); err != nil { //coverage:defensive rows.Scan failure needs a DB fault injected at this exact statement
			vt.Close()
			return err
		}
		sd.ValueTokens = append(sd.ValueTokens, r)
	}
	vt.Close()
	if err := vt.Err(); err != nil {
		return err
	}

	// Files not yet garbage-collected. A gc-marked row has had its name and
	// checksum redacted already, so it is no longer a holding.
	fr, err := g.Pool.Query(ctx, `
		SELECT id::text, name, content_type, size_bytes, created_at, expires_at
		  FROM files WHERE cid=$1 AND gc_at IS NULL ORDER BY created_at`, sd.CID)
	if err != nil {
		return err
	}
	for fr.Next() {
		var r FileRef
		if err := fr.Scan(&r.ID, &r.Name, &r.ContentType, &r.SizeBytes, &r.CreatedAt, &r.ExpiresAt); err != nil { //coverage:defensive rows.Scan failure needs a DB fault injected at this exact statement
			fr.Close()
			return err
		}
		sd.Files = append(sd.Files, r)
	}
	fr.Close()
	if err := fr.Err(); err != nil {
		return err
	}

	// Disclosures, INCLUDING revoked and expired ones: Article 15(1)(c) is
	// about recipients the data HAS been disclosed to, not only current
	// ones.
	sr, err := g.Pool.Query(ctx, `
		SELECT uuid::text, partner_label, fields, purpose, created_by, created_at, expires_at,
		       revoked_at IS NOT NULL
		  FROM shared_records WHERE cid=$1 ORDER BY created_at`, sd.CID)
	if err != nil {
		return err
	}
	for sr.Next() {
		var r ShareRef
		if err := sr.Scan(&r.UUID, &r.Partner, &r.Fields, &r.Purpose, &r.CreatedBy,
			&r.CreatedAt, &r.ExpiresAt, &r.Revoked); err != nil { //coverage:defensive rows.Scan failure needs a DB fault injected at this exact statement
			sr.Close()
			return err
		}
		sd.Shares = append(sd.Shares, r)
	}
	sr.Close()
	if err := sr.Err(); err != nil {
		return err
	}

	lr, err := g.Pool.Query(ctx, `
		SELECT other.cid, pl.link_type, 'child' AS role
		  FROM person_links pl
		  JOIN cids self ON self.person_id = pl.parent_person AND self.scope = pl.scope
		  JOIN cids other ON other.person_id = pl.child_person AND other.scope = pl.scope
		 WHERE self.cid = $1
		UNION ALL
		SELECT other.cid, pl.link_type, 'parent' AS role
		  FROM person_links pl
		  JOIN cids self ON self.person_id = pl.child_person AND self.scope = pl.scope
		  JOIN cids other ON other.person_id = pl.parent_person AND other.scope = pl.scope
		 WHERE self.cid = $1
		 ORDER BY 1`, sd.CID)
	if err != nil {
		return err
	}
	defer lr.Close()
	for lr.Next() {
		var r LinkRef
		if err := lr.Scan(&r.CID, &r.LinkType, &r.Role); err != nil { //coverage:defensive rows.Scan failure needs a DB fault injected at this exact statement
			return err
		}
		sd.Links = append(sd.Links, r)
	}
	return lr.Err()
}

// AuditTrailEntry is one access-log line included in a right-of-access
// response (who touched this person, when, doing what).
type AuditTrailEntry struct {
	Seq      int64     `json:"seq"`
	TS       time.Time `json:"ts"`
	ClientID string    `json:"client_id"`
	Action   string    `json:"action"`
	CID      string    `json:"cid"`
	// UserID is the operator inside the client system, when the client
	// asserted one (P4.2). Empty otherwise.
	UserID string `json:"user_id,omitempty"`
	// Bucketed read events (P4.2 default) arrive aggregated: Count > 1
	// with TS = first access in the hour and LastTS = the last. Count 0
	// means a plain per-event chained row.
	Count  int64      `json:"count,omitempty"`
	LastTS *time.Time `json:"last_ts,omitempty"`
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
	// F3: the allowlist applies to the org-wide view too - a narrowed
	// officer credential sees the scopes and the trail, but only the
	// attribute fields it is allowed to read.
	for i := range scopes {
		filterAllowedAttributes(client, scopes[i].Attributes)
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
		if err := rows.Scan(&sd.CID, &sd.Scope, &blob, &keyID, &alg); err != nil { //coverage:defensive rows.Scan failure needs a DB fault injected at this exact statement
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
		if err := g.holdingsFor(ctx, &sd); err != nil {
			return nil, nil, err
		}
		scopes = append(scopes, sd)
		cidList = append(cidList, sd.CID)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	trailRows, err := g.Pool.Query(ctx,
		`SELECT seq, ts, COALESCE(client_id,''), action, COALESCE(cid,''), COALESCE(user_id,'')
		 FROM audit WHERE cid = ANY($1) ORDER BY seq LIMIT $2`, cidList, accessTrailLimit)
	if err != nil {
		return nil, nil, err
	}
	defer trailRows.Close()
	trail := []AuditTrailEntry{}
	for trailRows.Next() {
		var e AuditTrailEntry
		if err := trailRows.Scan(&e.Seq, &e.TS, &e.ClientID, &e.Action, &e.CID, &e.UserID); err != nil { //coverage:defensive rows.Scan failure needs a DB fault injected at this exact statement
			return nil, nil, err
		}
		trail = append(trail, e)
	}
	if err := trailRows.Err(); err != nil {
		return nil, nil, err
	}

	// Bucketed read events (P4.2): the Article 15 answer must include them
	// or "who accessed my data" silently loses every lookup and read made
	// under the default mode. Reported as aggregates: who, how many times,
	// first and last time in the hour.
	bRows, err := g.Pool.Query(ctx,
		`SELECT client_id, user_id, cid, action, count, first_seen, last_seen
		 FROM audit_read_buckets WHERE cid = ANY($1) ORDER BY first_seen LIMIT $2`,
		cidList, accessTrailLimit)
	if err != nil {
		return nil, nil, err
	}
	defer bRows.Close()
	for bRows.Next() {
		var e AuditTrailEntry
		var last time.Time
		if err := bRows.Scan(&e.ClientID, &e.UserID, &e.CID, &e.Action, &e.Count, &e.TS, &last); err != nil { //coverage:defensive rows.Scan failure needs a DB fault injected at this exact statement
			return nil, nil, err
		}
		e.LastTS = &last
		trail = append(trail, e)
	}
	if err := bRows.Err(); err != nil {
		return nil, nil, err
	}
	return scopes, trail, nil
}

// filterAllowedAttributes removes fields outside the client's F3
// allowlist, in place. nil allowlist = untouched (pre-F3 behaviour).
func filterAllowedAttributes(client *auth.Client, attrs map[string]string) {
	if len(client.AllowedAttributes) == 0 || attrs == nil {
		return
	}
	for k := range attrs {
		if !client.CanReadAttribute(k) {
			delete(attrs, k)
		}
	}
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
		// F3: an export through a field-narrowed client carries only the
		// fields that client may read - the allowlist is about the CLIENT
		// CREDENTIAL's blast radius, and a portability dump through it is
		// the biggest single read it can make.
		filterAllowedAttributes(client, sd.Attributes)
	}
	if sd.Consents, err = consentsFor(ctx, g.Pool, cid); err != nil {
		return nil, err
	}
	// Portability (Art. 20) must carry the same holdings the access answer
	// does, or the export silently omits the most sensitive category the
	// product stores (TOKENS-LOOKUP-7).
	if err := g.holdingsFor(ctx, sd); err != nil {
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
	id, scopes, _, err := g.EraseWithCascade(ctx, client, cid, nil)
	return id, scopes, err
}

// LinkedErasure reports one person linked to an erased parent (F7): whether
// this request cascaded the erasure to it, so a report can prove a child's
// data was left intact unless the caller explicitly asked otherwise.
type LinkedErasure struct {
	CID      string `json:"cid"`
	LinkType string `json:"link_type"`
	Cascaded bool   `json:"cascaded"`
}

// EraseWithCascade erases the person behind cid and, for each link_type in
// cascadeTypes (F7), the person's linked children too. Children are ALWAYS
// listed in the returned report; they are erased only when their link_type
// was named - a silent cascade is how a child's data gets deleted by
// accident, so it must be asked for explicitly.
func (g *GDPR) EraseWithCascade(ctx context.Context, client *auth.Client, cid string, cascadeTypes []string) (erasureID int64, scopes int, linked []LinkedErasure, err error) {
	if !client.Can(auth.ActDSRErase) {
		return 0, 0, nil, ErrForbidden
	}
	// personForClientCID refuses a tombstone, which used to make a RETRY of
	// an interrupted cascade a flat 404 - the one thing an operator would
	// naturally do to recover. Resolve the person tolerating the tombstone,
	// so a re-issued request can resume the outstanding children
	// (GDPR-ERASURE-4).
	personID, erased, err := g.Contacts.personForClientCIDAllowingTombstone(ctx, client, cid)
	if err != nil {
		return 0, 0, nil, err
	}
	if erased {
		// The parent is already done; resume whatever its cascade left.
		return g.resumeCascade(ctx, client, personID)
	}
	// List the children (all link types) BEFORE erasing, resolving each to
	// a cid in the caller's scope for the report.
	rows, err := g.Pool.Query(ctx, `
		SELECT c.cid, pl.link_type, pl.child_person::text
		  FROM person_links pl JOIN cids c ON c.person_id = pl.child_person AND c.scope = pl.scope
		 WHERE pl.parent_person = $1 AND pl.scope = $2`, personID, client.Scope)
	if err != nil {
		return 0, 0, nil, err
	}
	type childRow struct{ cid, linkType, person string }
	var children []childRow
	for rows.Next() {
		var cr childRow
		if err := rows.Scan(&cr.cid, &cr.linkType, &cr.person); err != nil { //coverage:defensive rows.Scan failure needs a DB fault injected at this exact statement
			rows.Close()
			return 0, 0, nil, err
		}
		children = append(children, cr)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, 0, nil, err
	}
	cascade := map[string]bool{}
	for _, t := range cascadeTypes {
		cascade[t] = true
	}
	plan := make([]cascadeTarget, 0, len(children))
	for _, cr := range children {
		if cascade[cr.linkType] {
			plan = append(plan, cascadeTarget{cid: cr.cid, person: cr.person, linkType: cr.linkType})
		}
	}

	// Refuse BEFORE touching anything. The check has to sit here - after the
	// plan is known, before the parent's erasure transaction opens -
	// because the parent's own transaction is what deletes person_links,
	// i.e. the map to the children. Refusing later would mean refusing
	// after the only description of the work had been destroyed.
	if limit := g.maxCascadeChildren(); len(plan) > limit {
		return 0, 0, nil, fmt.Errorf("%w: %d linked children exceed the limit of %d; "+
			"erase them in smaller batches, or raise SUNDER_MAX_CASCADE_CHILDREN "+
			"after deciding that destroying this many people's data in one request is intended",
			ErrCascadeTooLarge, len(plan), limit)
	}

	// The parent is erased LAST. Its transaction is what deletes
	// person_links, i.e. the map to the children - doing that first meant a
	// partial cascade could not even be described afterwards. The durable
	// plan (written inside the parent's own erasure transaction) is the
	// belt to that braces: it survives the link deletion AND the crash.
	erasureID, scopes, err = g.erasePersonWithPlan(ctx, client.ID, cid, personID, plan)
	if err != nil {
		return 0, 0, nil, err
	}
	done, err := g.runCascade(ctx, client.ID, erasureID)
	if err != nil {
		return 0, 0, nil, err
	}
	for _, cr := range children {
		linked = append(linked, LinkedErasure{
			CID: cr.cid, LinkType: cr.linkType, Cascaded: cascade[cr.linkType] && done[cr.person]})
	}
	return erasureID, scopes, linked, nil
}

// EraseWithCascadePlanOnlyForTest erases the parent and records the cascade
// plan WITHOUT running it - the state an interrupted request leaves behind.
// Test-only seam: the alternative is killing a goroutine mid-loop, which
// cannot be done deterministically.
func (g *GDPR) EraseWithCascadePlanOnlyForTest(ctx context.Context, client *auth.Client, cid string, cascadeTypes []string) (int64, int, error) {
	personID, err := g.Contacts.personForClientCID(ctx, client, cid)
	if err != nil {
		return 0, 0, err
	}
	rows, err := g.Pool.Query(ctx, `
		SELECT c.cid, pl.link_type, pl.child_person::text
		  FROM person_links pl JOIN cids c ON c.person_id = pl.child_person AND c.scope = pl.scope
		 WHERE pl.parent_person = $1 AND pl.scope = $2`, personID, client.Scope)
	if err != nil {
		return 0, 0, err
	}
	want := map[string]bool{}
	for _, t := range cascadeTypes {
		want[t] = true
	}
	var plan []cascadeTarget
	for rows.Next() {
		var c, lt, p string
		if err := rows.Scan(&c, &lt, &p); err != nil { //coverage:defensive rows.Scan failure needs a DB fault injected at this exact statement
			rows.Close()
			return 0, 0, err
		}
		if want[lt] {
			plan = append(plan, cascadeTarget{cid: c, person: p, linkType: lt})
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil { //coverage:defensive rows.Err failure needs a DB fault injected at this exact statement
		return 0, 0, err
	}
	return g.erasePersonWithPlan(ctx, client.ID, cid, personID, plan)
}

// cascadeTarget is one planned child erasure.
type cascadeTarget struct{ cid, person, linkType string }

// runCascade erases every PENDING child of an erasure and marks each done as
// it commits, so an interruption leaves an accurate, resumable record.
func (g *GDPR) runCascade(ctx context.Context, actor string, erasureID int64) (map[string]bool, error) {
	done := map[string]bool{}
	rows, err := g.Pool.Query(ctx,
		`SELECT child_person::text, child_cid FROM erasure_cascade
		  WHERE erasure_id=$1 AND status='PENDING' ORDER BY child_person`, erasureID)
	if err != nil {
		return nil, err
	}
	type target struct{ person, cid string }
	var targets []target
	for rows.Next() {
		var t target
		if err := rows.Scan(&t.person, &t.cid); err != nil { //coverage:defensive rows.Scan failure needs a DB fault injected at this exact statement
			rows.Close()
			return nil, err
		}
		targets = append(targets, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil { //coverage:defensive rows.Err failure needs a DB fault injected at this exact statement
		return nil, err
	}
	for _, t := range targets {
		// An already-erased child is fine - report it as cascaded.
		if _, _, cerr := g.erasePerson(ctx, actor, t.cid, t.person); cerr != nil && !errorsIsValidation(cerr) {
			return done, fmt.Errorf("cascade erase of %s: %w", t.cid, cerr)
		}
		if _, err := g.Pool.Exec(ctx,
			`UPDATE erasure_cascade SET status='DONE', done_at=now()
			  WHERE erasure_id=$1 AND child_person=$2`, erasureID, t.person); err != nil {
			return done, err
		}
		done[t.person] = true
	}
	// A cascade that reaches zero outstanding children is FINISHED, and that
	// is an accountability fact: it is the moment the organisation can say
	// "every person named by this erasure is gone". Without a terminal
	// record, the only evidence is the absence of PENDING rows - which is
	// indistinguishable from a plan that was never written.
	if len(targets) > 0 {
		var left int
		if err := g.Pool.QueryRow(ctx,
			`SELECT count(*) FROM erasure_cascade WHERE erasure_id=$1 AND status='PENDING'`,
			erasureID).Scan(&left); err == nil && left == 0 {
			var total int
			_ = g.Pool.QueryRow(ctx,
				`SELECT count(*) FROM erasure_cascade WHERE erasure_id=$1`, erasureID).Scan(&total)
			if aerr := audit.Append(ctx, g.Pool, audit.Entry{
				ClientID: actor, Action: "dsr.cascade_completed",
				Detail: map[string]any{"erasure_id": erasureID, "children": total},
			}); aerr != nil {
				// Not fatal: the children ARE erased, and failing here would
				// make a completed cascade look like a failed one on retry.
				g.logger().Error("cascade completed but its audit record failed",
					"erasure_id", erasureID, "err", aerr.Error())
			}
		}
	}
	return done, nil
}

// PendingCascades reports outstanding cascade work: how many children are
// still PENDING and how old the oldest one is.
//
// Both numbers are needed. A count alone cannot distinguish "a large cascade
// is progressing" from "a cascade stopped an hour ago", and the second is an
// Article 17 problem: people the organisation has committed to erasing, and
// has not.
func PendingCascades(ctx context.Context, pool *pgxpool.Pool) (pending int64, oldestSeconds float64, err error) {
	err = pool.QueryRow(ctx, `
		SELECT count(*),
		       COALESCE(EXTRACT(EPOCH FROM (now() - min(created_at))), 0)
		  FROM erasure_cascade WHERE status='PENDING'`).Scan(&pending, &oldestSeconds)
	return pending, oldestSeconds, err
}

// RunPendingCascades finishes cascades left outstanding by an interrupted
// request, without waiting for someone to re-issue it.
//
// The durable plan made an interrupted cascade RECOVERABLE; it did not make
// it recover. Until now the only thing that resumed one was an operator
// re-issuing the identical erase call - which assumes they know it stopped,
// and the report that would have told them is exactly what the interruption
// swallowed. Runs from the same sweep as webhook delivery.
func (g *GDPR) RunPendingCascades(ctx context.Context) (finished int, err error) {
	rows, err := g.Pool.Query(ctx, `
		SELECT DISTINCT erasure_id FROM erasure_cascade
		 WHERE status='PENDING' ORDER BY erasure_id LIMIT 20`)
	if err != nil {
		return 0, err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil { //coverage:defensive rows.Scan failure needs a DB fault injected at this exact statement
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil { //coverage:defensive rows.Err failure needs a DB fault injected at this exact statement
		return 0, err
	}
	for _, id := range ids {
		// "system" rather than a client id: nobody asked for THIS run. The
		// original request is on the chain under its own actor; this is the
		// deployment finishing what that request started.
		if _, cerr := g.runCascade(ctx, "system", id); cerr != nil {
			// One stuck erasure must not stop the others - and it must be
			// visible, because a child that cannot be erased is a person the
			// organisation said it would forget and has not.
			g.logger().Error("pending cascade did not finish",
				"erasure_id", id, "err", cerr.Error())
			continue
		}
		finished++
	}
	return finished, nil
}

// resumeCascade finishes an interrupted cascade for an already-tombstoned
// parent. Idempotent: with nothing outstanding it is a no-op that reports
// the original erasure, so a retry is never an error.
func (g *GDPR) resumeCascade(ctx context.Context, client *auth.Client, personID string) (int64, int, []LinkedErasure, error) {
	var erasureID int64
	err := g.Pool.QueryRow(ctx,
		`SELECT id FROM erasures WHERE person_id=$1 ORDER BY id DESC LIMIT 1`, personID).Scan(&erasureID)
	if err == pgx.ErrNoRows {
		return 0, 0, nil, ErrNotFound
	}
	if err != nil {
		return 0, 0, nil, err
	}
	// Nothing outstanding: the person really is fully erased, so keep the
	// established answer - ErrNotFound, indistinguishable from a cid that
	// never existed. A distinct "already erased" code would confirm that
	// this pseudonym existed and was erased, and re-running a COMPLETED
	// erasure would re-queue a whole round of webhook deliveries for an
	// already-forgotten person.
	//
	// Resuming is therefore scoped to the case that actually needs it: a
	// cascade with children still PENDING, which is exactly the state an
	// interrupted request leaves and which no other call can recover
	// (GDPR-ERASURE-4).
	var pending int
	if err := g.Pool.QueryRow(ctx,
		`SELECT count(*) FROM erasure_cascade WHERE erasure_id=$1 AND status='PENDING'`,
		erasureID).Scan(&pending); err != nil {
		return 0, 0, nil, err
	}
	if pending == 0 {
		return 0, 0, nil, ErrNotFound
	}
	if _, err := g.runCascade(ctx, client.ID, erasureID); err != nil {
		return 0, 0, nil, err
	}
	rows, err := g.Pool.Query(ctx,
		`SELECT child_cid, link_type, status='DONE' FROM erasure_cascade WHERE erasure_id=$1 ORDER BY child_person`,
		erasureID)
	if err != nil {
		return 0, 0, nil, err
	}
	defer rows.Close()
	var linked []LinkedErasure
	for rows.Next() {
		var le LinkedErasure
		if err := rows.Scan(&le.CID, &le.LinkType, &le.Cascaded); err != nil { //coverage:defensive rows.Scan failure needs a DB fault injected at this exact statement
			return 0, 0, nil, err
		}
		linked = append(linked, le)
	}
	var scopes int
	if err := g.Pool.QueryRow(ctx,
		`SELECT count(*) FROM erasure_events WHERE erasure_id=$1`, erasureID).Scan(&scopes); err != nil {
		return 0, 0, nil, err
	}
	return erasureID, scopes, linked, rows.Err()
}

// errorsIsValidation reports the "already erased" sentinel so a cascade
// tolerates a child that was erased in a prior request.
func errorsIsValidation(err error) bool { return errors.Is(err, ErrValidation) }

// erasePerson runs the full erasure for a person - shared by the privacy
// officer's Erase and the self-service portal. actor lands in the audit
// record and the erasure row; auditCID is the pseudonym the request came in
// under (portal erasures use the person's first CID).
func (g *GDPR) erasePerson(ctx context.Context, actor, auditCID, personID string) (erasureID int64, scopes int, err error) {
	return g.erasePersonWithPlan(ctx, actor, auditCID, personID, nil)
}

// erasePersonWithPlan erases one person and, in the SAME transaction, records
// the children this erasure is responsible for cascading to. Writing the plan
// atomically with the erasure is what makes an interrupted cascade
// describable and resumable: the parent's own transaction deletes
// person_links, which was the only other record that those children existed
// (GDPR-ERASURE-4).
func (g *GDPR) erasePersonWithPlan(ctx context.Context, actor, auditCID, personID string, plan []cascadeTarget) (erasureID int64, scopes int, err error) {
	// An erasure that loses a deadlock is not retried by anything - the
	// subject's request just returns 500 and the person stays un-erased.
	err = retryOnDeadlock(func() error {
		var rerr error
		erasureID, scopes, rerr = g.erasePersonOnce(ctx, actor, auditCID, personID, plan)
		return rerr
	})
	return erasureID, scopes, err
}

func (g *GDPR) erasePersonOnce(ctx context.Context, actor, auditCID, personID string, plan []cascadeTarget) (erasureID int64, scopes int, err error) {
	tx, err := g.Pool.Begin(ctx)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Lock ORDER matters: every tombstone-guarded writer locks cids before
	// persons (mergeIntoBlob's FOR UPDATE OF c, p) or persons only (tokens,
	// files). Erasure must take the same c -> p order, or a writer holding a
	// cids row while erasure holds the persons row is an ABBA deadlock -
	// fail-safe (the writer is always the victim), but a legitimate request
	// then stalls deadlock_timeout and dies with a 500.
	// ORDER BY cid is load-bearing, not cosmetic: this statement locks
	// SEVERAL rows, and a writer that also needs two of them (OTI verify
	// needs the issuer's and the verifier's) can only be deadlock-free if
	// both sides walk the set in the same order. lockPersonRows takes the
	// identical statement.
	if _, err := tx.Exec(ctx,
		`SELECT 1 FROM cids WHERE person_id=$1 ORDER BY cid FOR UPDATE`, personID); err != nil {
		return 0, 0, err
	}
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

	// F5 crypto-shredding: destroying the record key makes every file of
	// this person unrecoverable the instant this transaction commits; the
	// dead ciphertext is garbage-collected by the retention sweep.
	if err := ShredRecordKey(ctx, tx, personID); err != nil {
		return 0, 0, err
	}
	if err := tx.QueryRow(ctx,
		`INSERT INTO erasures (person_id, requested_by) VALUES ($1,$2) RETURNING id`,
		personID, actor).Scan(&erasureID); err != nil {
		return 0, 0, err
	}
	// The cascade plan, in the same transaction as the erasure it belongs to
	// and BEFORE the person_links delete below wipes the map to these
	// children (GDPR-ERASURE-4).
	for _, t := range plan {
		if _, err := tx.Exec(ctx,
			`INSERT INTO erasure_cascade (erasure_id, child_person, child_cid, link_type)
			 VALUES ($1,$2,$3,$4) ON CONFLICT (erasure_id, child_person) DO NOTHING`,
			erasureID, t.person, t.cid, t.linkType); err != nil {
			return 0, 0, err
		}
	}
	rows, err := tx.Query(ctx, `SELECT cid, scope FROM cids WHERE person_id=$1`, personID)
	if err != nil {
		return 0, 0, err
	}
	type sc struct{ cid, scope string }
	var all []sc
	for rows.Next() {
		var s sc
		if err := rows.Scan(&s.cid, &s.scope); err != nil { //coverage:defensive rows.Scan failure needs a DB fault injected at this exact statement
			rows.Close()
			return 0, 0, err
		}
		all = append(all, s)
	}
	rows.Close()
	if err := rows.Err(); err != nil { //coverage:defensive rows.Err failure needs a DB fault injected at this exact statement
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
	// F6: blob history is the same personal data, one generation older -
	// it dies with the person.
	if _, err := tx.Exec(ctx,
		`DELETE FROM cid_blob_versions WHERE cid IN (SELECT cid FROM cids WHERE person_id=$1)`, personID); err != nil {
		return 0, 0, err
	}
	// F4: value tokens bound to one of this person's CIDs (S4). An
	// unattributed token (cid NULL) belongs to no single subject and is left
	// to its own expiry.
	if _, err := tx.Exec(ctx,
		`DELETE FROM value_tokens WHERE cid IN (SELECT cid FROM cids WHERE person_id=$1)`, personID); err != nil {
		return 0, 0, err
	}
	// Consent STATE dies with the person: there is nothing left to gate, and
	// the accountability record ("what was granted when") is the immutable
	// consent.set trail in the audit chain, not this mutable table. Keeping
	// the rows would only tie purposes to the tombstoned pseudonym.
	if _, err := tx.Exec(ctx,
		`DELETE FROM consents WHERE cid IN (SELECT cid FROM cids WHERE person_id=$1)`, personID); err != nil {
		return 0, 0, err
	}
	// F8: DELETE the person's shares on erasure - not merely revoke - so the
	// erased pseudonym does not linger in a revoked row (consent withdrawal
	// keeps the row; erasure must not).
	if err := deleteSharesForCID(ctx, tx, personID); err != nil {
		return 0, 0, err
	}
	// Portal state dies with the person: a queued login or erase-confirm
	// mail must not still be delivered, and a live session must not
	// outlive the data.
	for _, q := range []string{
		`DELETE FROM portal_sessions WHERE person_id=$1`,
		`DELETE FROM portal_tokens WHERE person_id=$1`,
		`DELETE FROM portal_outbox WHERE person_id=$1`,
		// F7: a link referencing the erased person (as parent or child)
		// would otherwise keep leaking their pseudonym through the surviving
		// side's link listing, and could not be removed via the API.
		`DELETE FROM person_links WHERE parent_person=$1 OR child_person=$1`,
	} {
		if _, err := tx.Exec(ctx, q, personID); err != nil {
			return 0, 0, err
		}
	}
	// Consumed-envelope records for this person's pseudonyms: the jti is
	// issuer-chosen and may reference the subject.
	if _, err := tx.Exec(ctx,
		`DELETE FROM external_envelopes WHERE cid IN (SELECT cid FROM cids WHERE person_id=$1)`,
		personID); err != nil {
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
	// Best-effort immediate delivery, DETACHED and scoped to this erasure.
	// Running it inline on the request goroutine meant an ordinary client
	// timeout cancelled the settle statements of a queue-wide batch of 100,
	// stranding other subjects' notifications (H1, path B). The periodic
	// worker retries whatever this misses.
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), detachedDeliverTimeout)
		defer cancel()
		if _, err := g.deliverPending(dctx, erasureID); err != nil {
			g.logger().Error("inline erasure delivery", "erasure_id", erasureID, "err", err.Error())
		}
	}()
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
	// DefaultWorkerClaimTTL matches portal_outbox's reaper grace period.
	DefaultWorkerClaimTTL = 10 * time.Minute
	// settleTimeout bounds the acknowledgement statements, which run on a
	// context deliberately detached from the caller's.
	settleTimeout = 10 * time.Second
	// detachedDeliverTimeout bounds the immediate post-erasure delivery.
	detachedDeliverTimeout = 30 * time.Second
)

func (g *GDPR) claimTTL() time.Duration {
	if g.ClaimTTL <= 0 {
		return DefaultWorkerClaimTTL
	}
	return g.ClaimTTL
}

// ReapStrandedErasureEvents returns claims older than ttl to the queue. A
// worker that dies (or is cancelled) between committing its claim and
// settling the row leaves it SENDING, and the claim SELECT only matches
// PENDING - without this, SENDING is an absorbing state and the Article 19
// notification is lost silently and permanently (H1).
//
// claimed_at IS NULL backfills rows stranded before migration 0035, which
// added the column.
func ReapStrandedErasureEvents(ctx context.Context, pool *pgxpool.Pool, ttl time.Duration) (int64, error) {
	if ttl <= 0 {
		ttl = DefaultWorkerClaimTTL
	}
	tag, err := pool.Exec(ctx,
		`UPDATE erasure_events SET status='PENDING', claimed_at=NULL
		 WHERE status='SENDING'
		   AND (claimed_at IS NULL OR claimed_at < now() - make_interval(secs => $1))`,
		ttl.Seconds())
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// ErasureQueueDepth counts claimed-but-unsettled (SENDING) and abandoned
// (FAILED) events, for the sunder_erasure_events_* gauges. A sending count
// that does not return to zero is the alarm for a stalled or crash-looping
// delivery worker; any failed count at all means a downstream scope was
// never told to erase.
func ErasureQueueDepth(ctx context.Context, pool *pgxpool.Pool) (sending, failed int64, err error) {
	err = pool.QueryRow(ctx,
		`SELECT count(*) FILTER (WHERE status='SENDING'), count(*) FILTER (WHERE status='FAILED')
		 FROM erasure_events`).Scan(&sending, &failed)
	return sending, failed, err
}

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
	return g.deliverPending(ctx, 0)
}

// deliverPending drains the erasure queue. onlyErasure > 0 restricts the
// batch to one erasure's own events, which is what the post-erasure inline
// delivery uses: a queue-wide batch let one subject's request claim - and,
// on cancellation, strand - notifications belonging to other subjects.
func (g *GDPR) deliverPending(ctx context.Context, onlyErasure int64) (delivered int, err error) {
	// The acknowledgement statements must NOT share fate with the delivery.
	// Every settle path used to run on the same context that performed the
	// POST, so a cancelled request or a SIGTERM killed the statement that
	// releases the claim - and the claim has no other release (H1).
	settleCtx, cancelSettle := context.WithTimeout(context.WithoutCancel(ctx), settleTimeout)
	defer cancelSettle()

	// Recover claims abandoned by an earlier worker before taking new ones,
	// so recovery does not depend on an operator having wired up the cron.
	if n, rerr := ReapStrandedErasureEvents(settleCtx, g.Pool, g.claimTTL()); rerr != nil {
		g.logger().Error("erasure event reap", "err", rerr.Error())
	} else if n > 0 {
		g.logger().Warn("requeued stranded erasure events", "count", n, "claim_ttl", g.claimTTL().String())
	}

	// Claim the batch: without SKIP LOCKED every replica delivered every
	// event.
	claim, err := g.Pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = claim.Rollback(ctx) }()
	rows, err := claim.Query(ctx,
		`SELECT e.id, e.erasure_id, e.scope, e.cid, w.url, w.secret
		 FROM erasure_events e JOIN webhooks w ON w.scope = e.scope
		 WHERE e.status='PENDING' AND ($1 = 0 OR e.erasure_id = $1)
		 ORDER BY e.attempts, e.id LIMIT 100
		 FOR UPDATE OF e SKIP LOCKED`, onlyErasure)
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
		if err := rows.Scan(&e.id, &e.erasureID, &e.scope, &e.cid, &e.url, &e.secret); err != nil { //coverage:defensive rows.Scan failure needs a DB fault injected at this exact statement
			rows.Close()
			return 0, err
		}
		evs = append(evs, e)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if len(evs) > 0 {
		ids := make([]int64, 0, len(evs))
		for _, e := range evs {
			ids = append(ids, e.id)
		}
		if _, err := claim.Exec(ctx,
			`UPDATE erasure_events SET status='SENDING', claimed_at=now() WHERE id = ANY($1)`, ids); err != nil {
			return 0, err
		}
	}
	if err := claim.Commit(ctx); err != nil {
		return 0, err
	}
	// release returns unattempted claims immediately rather than leaving
	// them to the reaper's grace period.
	release := func(rest []ev) {
		if len(rest) == 0 {
			return
		}
		ids := make([]int64, 0, len(rest))
		for _, e := range rest {
			ids = append(ids, e.id)
		}
		if _, rerr := g.Pool.Exec(settleCtx,
			`UPDATE erasure_events SET status='PENDING', claimed_at=NULL
			 WHERE id = ANY($1) AND status='SENDING'`, ids); rerr != nil {
			g.logger().Error("release erasure claims", "count", len(ids), "err", rerr.Error())
		}
	}
	terminal := func(e ev, status, action string) error {
		tx, err := g.Pool.Begin(settleCtx)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(settleCtx) }()
		if _, err := tx.Exec(settleCtx,
			`UPDATE erasure_events SET status=$2, delivered_at=CASE WHEN $2='DELIVERED' THEN now() END,
			        attempts=attempts+1, claimed_at=NULL WHERE id=$1`, e.id, status); err != nil {
			return err
		}
		if err := audit.AppendTx(settleCtx, tx, audit.Entry{
			ClientID: "system", Action: action, CID: e.cid,
			Detail: map[string]any{"erasure_id": e.erasureID, "scope": e.scope, "event_id": e.id},
		}); err != nil {
			return err
		}
		return tx.Commit(settleCtx)
	}

	// Events whose scope has no webhook are BLOCKED, not failed. The claim
	// is an inner join now, so they never enter a batch (they used to sort
	// first, attempts=0, and could crowd out deliverable ones) and they are
	// never settled NO_WEBHOOK - a terminal status no claim SELECT and no
	// reaper ever revisits, which wrote off Article 19 propagation for every
	// scope onboarded before its endpoint was registered (QUEUE-WORKER-6).
	// They stay PENDING and deliver on the sweep after `sunder webhook set`.
	// Reported once per sweep, per scope, rather than once per event.
	g.warnBlockedScopes(settleCtx)

	for i, e := range evs {
		// A dead caller context means every remaining POST would fail
		// instantly; hand the rest back to the queue instead of burning
		// their attempt counters.
		if ctx.Err() != nil {
			release(evs[i:])
			return delivered, nil
		}
		body, _ := json.Marshal(erasePayload{
			Event: "erase", Scope: e.scope, CID: e.cid, ErasureID: e.erasureID,
			TS: time.Now().UTC().Format(time.RFC3339),
		})
		mac := hmac.New(sha256.New, []byte(*e.secret))
		mac.Write(body)
		req, err := http.NewRequestWithContext(ctx, "POST", *e.url, bytes.NewReader(body))
		if err != nil {
			release(evs[i : i+1])
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
			if serr := terminal(e, "DELIVERED", "dsr.erase.delivered"); serr != nil {
				// The downstream system HAS deleted the record; only our
				// bookkeeping failed. The reaper will requeue the claim and
				// the next sweep re-delivers (at-least-once, as documented).
				g.logger().Error("settle erasure event after successful POST",
					"event_id", e.id, "err", serr.Error())
				continue
			}
			delivered++
			continue
		}
		// The POST failed. If it failed because OUR context died rather
		// than because the endpoint is unhealthy, do not charge an attempt.
		if ctx.Err() != nil {
			release(evs[i:])
			return delivered, nil
		}
		var attempts int
		if uerr := g.Pool.QueryRow(settleCtx,
			`UPDATE erasure_events SET attempts=attempts+1, status='PENDING', claimed_at=NULL
			 WHERE id=$1 RETURNING attempts`, e.id).Scan(&attempts); uerr != nil {
			g.logger().Error("requeue erasure event", "event_id", e.id, "err", uerr.Error())
			continue
		}
		if attempts >= g.maxAttempts() {
			// terminal() adds one more attempt in its UPDATE; compensate by
			// marking FAILED directly here with an audited record.
			if ferr := g.failEvent(settleCtx, e.id, e.erasureID, e.scope, e.cid, attempts); ferr != nil {
				g.logger().Error("mark erasure event FAILED", "event_id", e.id, "err", ferr.Error())
			}
		}
	}
	return delivered, nil
}

// warnBlockedScopes logs the scopes holding undeliverable erasure events.
func (g *GDPR) warnBlockedScopes(ctx context.Context) {
	rows, err := g.Pool.Query(ctx, `
		SELECT e.scope, count(*) FROM erasure_events e
		 WHERE e.status='PENDING'
		   AND NOT EXISTS (SELECT 1 FROM webhooks w WHERE w.scope = e.scope)
		 GROUP BY e.scope`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var scope string
		var n int64
		if rows.Scan(&scope, &n) != nil { //coverage:defensive rows.Scan failure needs a DB fault injected at this exact statement
			return
		}
		g.logger().Warn("erasure events are waiting for a scope webhook that does not exist - the downstream system has NOT been told to erase; register it with `sunder webhook set` and they deliver on the next sweep",
			"scope", scope, "events", n)
	}
}

func (g *GDPR) failEvent(ctx context.Context, id, erasureID int64, scope, cid string, attempts int) error {
	tx, err := g.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx,
		`UPDATE erasure_events SET status='FAILED', claimed_at=NULL WHERE id=$1`, id); err != nil {
		return err
	}
	if err := audit.AppendTx(ctx, tx, audit.Entry{
		ClientID: "system", Action: "dsr.erase.failed", CID: cid,
		Detail: map[string]any{"erasure_id": erasureID, "scope": scope, "event_id": id, "attempts": attempts},
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// --- retention ------------------------------------------------------------------

// RunRetention applies per-scope contact TTLs (blob wipe, audited) and
// prunes long-expired OTI rows. Audit rows are NEVER pruned: the hash chain
// plus external anchors are the tamper evidence.
// PruneEnvelopes deletes consumed external envelopes whose replay window
// has closed (this is envelope hygiene; RunRetention below handles contact
// TTLs and is a different sweep). Safe because envelopes carry a bounded lifetime: past
// expires_at no envelope with that jti can still be accepted, so the row
// no longer has anti-replay value - and issuer-chosen jtis may reference a
// subject, so keeping them past an Article 17 erasure is not acceptable
// .
func PruneEnvelopes(ctx context.Context, pool *pgxpool.Pool) (int64, error) {
	// The safety margin covers clock skew between the application (which
	// decides acceptance) and the database (which decides pruning): without
	// it, a database clock running ahead deletes rows for envelopes the
	// application would still accept, reopening a replay window
	//.
	tag, err := pool.Exec(ctx,
		`DELETE FROM external_envelopes WHERE expires_at < now() - interval '1 hour'`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

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
		if err := rows.Scan(&cid); err != nil { //coverage:defensive rows.Scan failure needs a DB fault injected at this exact statement
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
	if wiped > 0 {
		// The retention sweep NULLs the blob but the contact was left fully
		// resolvable: blob history (F6) still returned old values. Prune it
		// here, inside the same tx as the wipe.
		if _, err := tx.Exec(ctx,
			`DELETE FROM cid_blob_versions WHERE cid = ANY($1)`, wipedCIDs); err != nil {
			return 0, 0, err
		}
		// Value tokens bound to a wiped CID are that scope's data about the
		// person and age out with the contact (P3); unattributed tokens keep
		// their own expiry.
		if _, err := tx.Exec(ctx,
			`DELETE FROM value_tokens WHERE cid = ANY($1)`, wipedCIDs); err != nil {
			return 0, 0, err
		}
	}

	// Search-token cleanup runs on EVERY sweep and is not scoped to the CIDs
	// this sweep happened to wipe (GDPR-ERASURE-7). It used to be: a CID can
	// be wiped only once (the UPDATE requires pii_encrypted IS NOT NULL), so
	// a person whose token deletion was blocked at that single instant by a
	// then-live share, file, link or value token kept their searchable
	// identifiers FOREVER - long after the blocker expired. The condition
	// being enforced is level-triggered ("this person has no live data
	// anywhere"), so the pass that enforces it must be too.
	tokensPruned, err := pruneOrphanSearchTokens(ctx, tx)
	if err != nil {
		return 0, 0, err
	}

	tag, err := tx.Exec(ctx, `DELETE FROM oti WHERE expires_at < now() - interval '30 days'`)
	if err != nil {
		return 0, 0, err
	}
	otiPruned = tag.RowsAffected()
	if wiped > 0 || otiPruned > 0 || tokensPruned > 0 {
		detail := map[string]any{"blobs_wiped": wiped, "oti_pruned": otiPruned,
			"search_tokens_pruned": tokensPruned}
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

// retentionTokenBatch bounds one pass of the search-token sweep. Persons whose
// tokens are deleted stop being candidates, so the loop converges.
const retentionTokenBatch = 5000

// pruneOrphanSearchTokens deletes the keyed identifier tokens of persons who
// have nothing live left. Two candidate sets:
//
//   - tombstoned persons. Erasure already deleted their tokens, so anything
//     present is a resurrection - the rekey sweep used to re-create them
//     under the newest key version (GDPR-ERASURE-2), and nothing else ever
//     removed them again. No guards apply: an erased person must not be
//     resolvable by an identifier under any circumstance.
//   - persons under a scope with a retention policy who have no attribute
//     blob, no un-GC'd file, no standing share, no link and no live value
//     token anywhere. A blob-less CID minted by an OTI handoff can carry
//     files and shares, and a scope retaining those must keep resolving the
//     person (F6); only when the person's last datum is gone does the
//     searchable identifier itself become the last datum, and then it goes
//     too.
func pruneOrphanSearchTokens(ctx context.Context, tx pgx.Tx) (int64, error) {
	var total int64
	tag, err := tx.Exec(ctx,
		`DELETE FROM person_tokens pt USING persons p
		  WHERE p.id = pt.person_id AND p.erased_at IS NOT NULL`)
	if err != nil {
		return 0, err
	}
	total += tag.RowsAffected()

	for {
		tag, err := tx.Exec(ctx, `
			WITH candidates AS (
				SELECT DISTINCT pt.person_id FROM person_tokens pt
				 WHERE EXISTS (
					SELECT 1 FROM cids c JOIN retention_policies rp ON rp.scope = c.scope
					 WHERE c.person_id = pt.person_id)
				   AND NOT EXISTS (
					SELECT 1 FROM cids c2
					 WHERE c2.person_id = pt.person_id AND c2.pii_encrypted IS NOT NULL)
				   AND NOT EXISTS (
					SELECT 1 FROM files f JOIN cids c3 ON c3.cid = f.cid
					 WHERE c3.person_id = pt.person_id AND f.gc_at IS NULL
					   AND (f.expires_at IS NULL OR f.expires_at > now()))
				   AND NOT EXISTS (
					SELECT 1 FROM shared_records sr JOIN cids c4 ON c4.cid = sr.cid
					 WHERE c4.person_id = pt.person_id AND sr.revoked_at IS NULL
					   AND sr.expires_at > now())
				   AND NOT EXISTS (
					SELECT 1 FROM person_links pl
					 WHERE pl.parent_person = pt.person_id OR pl.child_person = pt.person_id)
				   AND NOT EXISTS (
					SELECT 1 FROM value_tokens vt JOIN cids c5 ON c5.cid = vt.cid
					 WHERE c5.person_id = pt.person_id
					   AND (vt.expires_final IS NULL OR vt.expires_final > now())
					   AND (vt.sliding_seconds IS NULL OR vt.last_used + make_interval(secs => vt.sliding_seconds) > now()))
				 LIMIT $1)
			DELETE FROM person_tokens pt USING candidates c WHERE pt.person_id = c.person_id`,
			retentionTokenBatch)
		if err != nil {
			return total, err
		}
		total += tag.RowsAffected()
		if tag.RowsAffected() == 0 {
			return total, nil
		}
	}
}
