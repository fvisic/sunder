// The routes beyond the core handoff surface: consent, the data-subject
// rights endpoints, value tokenization, the file vault, cross-org shares,
// person links, attribute version history, external claims and the admin
// unlock token.
//
// Everything here goes through the same transport, error mapping and retry
// policy as sunder.go. The rule for retries is unchanged and load-bearing:
// only reads and idempotent creates retry; anything that consumes a
// single-use credential or destroys data never does.
package sunder

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// -- consent ----------------------------------------------------------------

// Consent is one purpose's current state for a person.
type Consent struct {
	Purpose   string `json:"purpose"`
	Granted   bool   `json:"granted"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// SetConsent records the person's decision for one purpose. Consent is
// per (client, cid, purpose) and gates attribute reads for that purpose:
// revoking it makes GetAttribute answer ErrConsentDenied even though the
// client's own grant is unchanged.
//
// Every call is appended to the audit chain, and that trail SURVIVES
// erasure - it is the accountability record proving what was consented to
// and when.
func (c *Client) SetConsent(ctx context.Context, cid, purpose string, granted bool) (Consent, error) {
	var out Consent
	body := map[string]any{"cid": cid, "purpose": purpose, "granted": granted}
	if err := c.do(ctx, http.MethodPost, "/v1/consent", body, &out, false); err != nil {
		return Consent{}, err
	}
	return out, nil
}

// GetConsent lists every purpose the caller's scope has recorded for this
// person. A purpose that was never set is absent, not false: "no decision"
// and "refused" are different facts.
func (c *Client) GetConsent(ctx context.Context, cid string) ([]Consent, error) {
	var out struct {
		Consents []Consent `json:"consents"`
	}
	path := "/v1/consent/" + url.PathEscape(cid)
	if err := c.do(ctx, http.MethodGet, path, nil, &out, true); err != nil {
		return nil, err
	}
	return out.Consents, nil
}

// -- data subject rights ----------------------------------------------------

// ValueTokenRef is one tokenized value held for a person - never the value.
type ValueTokenRef struct {
	Token     string `json:"token"`
	Type      string `json:"type,omitempty"`
	Scope     string `json:"scope,omitempty"`
	CreatedBy string `json:"created_by,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
	LastUsed  string `json:"last_used,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// ShareRef is one cross-org share, from the discloser's side: who received
// what. Article 15 asks who the data was disclosed TO.
type ShareRef struct {
	UUID         string   `json:"uuid"`
	PartnerLabel string   `json:"partner_label,omitempty"`
	Purpose      string   `json:"purpose,omitempty"`
	Fields       []string `json:"fields,omitempty"`
	CreatedAt    string   `json:"created_at,omitempty"`
	ExpiresAt    string   `json:"expires_at,omitempty"`
	Revoked      bool     `json:"revoked,omitempty"`
}

// LinkRef is one person link as seen from this cid.
type LinkRef struct {
	CID      string `json:"cid"`
	LinkType string `json:"link_type"`
	Role     string `json:"role,omitempty"`
}

// ScopeData is one scope's complete holdings for a person: the attribute
// blob plus everything that does NOT live in it.
type ScopeData struct {
	Scope       string            `json:"scope"`
	CID         string            `json:"cid"`
	Attributes  map[string]string `json:"attributes,omitempty"`
	Consents    []Consent         `json:"consents,omitempty"`
	ValueTokens []ValueTokenRef   `json:"value_tokens,omitempty"`
	Files       []FileMeta        `json:"files,omitempty"`
	Shares      []ShareRef        `json:"shares,omitempty"`
	Links       []LinkRef         `json:"links,omitempty"`
}

// AuditEntry is one row of the Article 15 access trail. Under bucketed read
// auditing a read entry carries Count and LastTS for its hour instead of
// one row per event.
type AuditEntry struct {
	Seq      int64  `json:"seq,omitempty"`
	TS       string `json:"ts"`
	ClientID string `json:"client_id"`
	UserID   string `json:"user_id,omitempty"`
	Action   string `json:"action"`
	CID      string `json:"cid,omitempty"`
	Count    int64  `json:"count,omitempty"`
	LastTS   string `json:"last_ts,omitempty"`
}

// AccessResult answers Article 15: every scope's holdings plus who accessed
// the person's records.
type AccessResult struct {
	Scopes     []ScopeData  `json:"scopes"`
	AuditTrail []AuditEntry `json:"audit_trail,omitempty"`
}

// DSRAccess is the Article 15 answer, ORG-WIDE: it crosses scope boundaries
// on the data subject's behalf, so it needs its own grant and is itself
// audited. Never route it through an ordinary integration credential.
func (c *Client) DSRAccess(ctx context.Context, cid string) (AccessResult, error) {
	var out AccessResult
	path := "/v1/dsr/access?cid=" + url.QueryEscape(cid)
	if err := c.do(ctx, http.MethodGet, path, nil, &out, true); err != nil {
		return AccessResult{}, err
	}
	return out, nil
}

// DSRExport is the Article 20 answer for the CALLER's scope only: the same
// holdings sections in machine-readable form, for portability.
func (c *Client) DSRExport(ctx context.Context, cid string) (ScopeData, error) {
	var out ScopeData
	path := "/v1/dsr/export?cid=" + url.QueryEscape(cid)
	if err := c.do(ctx, http.MethodGet, path, nil, &out, true); err != nil {
		return ScopeData{}, err
	}
	return out, nil
}

// LinkedErasure reports one linked child and whether the erasure reached it.
type LinkedErasure struct {
	CID      string `json:"cid"`
	LinkType string `json:"link_type"`
	Cascaded bool   `json:"cascaded"`
}

// EraseResult is the outcome of an Article 17 erasure.
type EraseResult struct {
	ErasureID int64           `json:"erasure_id"`
	Scopes    int             `json:"scopes"`
	Linked    []LinkedErasure `json:"linked,omitempty"`
}

// DSRErase erases the person ORG-WIDE and queues one Article 19
// notification per scope that held them.
//
// cascadeLinkTypes names the link types ("guardian", "member", "owner")
// whose linked children are erased along with this person. Empty means the
// children are LISTED in the result and left untouched: an accidental
// cascade would delete a third party's data, so it is opt-in per link type.
//
// A cascade is one transaction PER PERSON, not one overall, and the plan is
// recorded before any child is touched - so re-issuing the identical call
// after an interruption RESUMES the outstanding children. Once everything
// is done the call answers ErrNotFound, deliberately indistinguishable from
// a cid that never existed.
//
// Never retried: erasure is destructive and the resume path is an explicit
// decision, not something an SDK should take on the caller's behalf.
func (c *Client) DSRErase(ctx context.Context, cid string, cascadeLinkTypes ...string) (EraseResult, error) {
	body := map[string]any{"cid": cid}
	if len(cascadeLinkTypes) > 0 {
		body["cascade"] = cascadeLinkTypes
	}
	var out EraseResult
	if err := c.do(ctx, http.MethodPost, "/v1/dsr/erase", body, &out, false); err != nil {
		return EraseResult{}, err
	}
	return out, nil
}

// -- value tokenization -----------------------------------------------------

// TokenizeInput describes one value to vault. The value is encrypted at
// rest; the token is an opaque reference safe to store in systems that must
// not hold the value itself.
type TokenizeInput struct {
	// Value is the plaintext to vault (max 8192 bytes).
	Value string `json:"value"`
	// Type is "string" (default) or "card", which additionally validates
	// the Luhn checksum and preserves the last four digits for display.
	Type string `json:"type,omitempty"`
	// CID binds the token to a person in the caller's scope, so erasure and
	// the retention sweep destroy it with the rest of their data. Omit ONLY
	// for a scope-wide value that belongs to no single subject: an
	// unattributed token survives that person's erasure.
	CID string `json:"cid,omitempty"`
	// Unique dedups per (scope, cid): the same value returns the same token.
	Unique bool `json:"unique,omitempty"`
	// ExpiresFinal is a hard deadline, decided by the DATABASE clock.
	ExpiresFinal string `json:"expires_final,omitempty"`
	// SlidingSeconds extends the life on every read; 0 means no extension.
	SlidingSeconds int64 `json:"sliding_seconds,omitempty"`
}

// Tokenize vaults one value and returns its token.
func (c *Client) Tokenize(ctx context.Context, in TokenizeInput) (string, error) {
	var out struct {
		Token string `json:"token"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/tokens", in, &out, false); err != nil {
		return "", err
	}
	if out.Token == "" {
		return "", &Error{Code: ErrBadResponse.code, Status: http.StatusCreated,
			Detail: "tokenize response carried no token"}
	}
	return out.Token, nil
}

// Detokenize resolves a token back to its value. Audited per read and, for
// a cid-bound token, attributed to that person's CID - so "who read my
// tokenized IBAN" is answerable from the access trail.
func (c *Client) Detokenize(ctx context.Context, token string) (string, error) {
	var out struct {
		Value string `json:"value"`
	}
	path := "/v1/tokens/" + url.PathEscape(token)
	if err := c.do(ctx, http.MethodGet, path, nil, &out, true); err != nil {
		return "", err
	}
	return out.Value, nil
}

// DeleteToken destroys a token and its value. Not retried: it is
// destructive, and a second attempt would report ErrNotFound for a delete
// that had already succeeded.
func (c *Client) DeleteToken(ctx context.Context, token string) error {
	path := "/v1/tokens/" + url.PathEscape(token)
	return c.do(ctx, http.MethodDelete, path, nil, nil, false)
}

// TokenizeBulk vaults many values in one call and returns the tokens in
// input order.
//
// Bulk surfaces ALWAYS require a single-use unlock token, regardless of
// SUNDER_SEARCH_UNLOCK: one call that touches many people is exactly the
// shape a rate limit does not constrain. Get one from Unlock. The whole
// batch is validated before the token is spent, so a rejected item does not
// burn the unlock.
func (c *Client) TokenizeBulk(ctx context.Context, unlockToken string, items []TokenizeInput) ([]string, error) {
	var out struct {
		Tokens []string `json:"tokens"`
	}
	body := map[string]any{"items": items}
	err := c.doWithHeaders(ctx, http.MethodPost, "/v1/tokens/bulk", body, &out,
		map[string]string{"X-Sunder-Unlock": unlockToken})
	if err != nil {
		return nil, err
	}
	return out.Tokens, nil
}

// DetokenizeBulk resolves many tokens in one call, values in input order.
// Requires an unlock token for the same reason TokenizeBulk does.
func (c *Client) DetokenizeBulk(ctx context.Context, unlockToken string, tokens []string) ([]string, error) {
	var out struct {
		Values []string `json:"values"`
	}
	body := map[string]any{"tokens": tokens}
	err := c.doWithHeaders(ctx, http.MethodPost, "/v1/tokens/bulk/read", body, &out,
		map[string]string{"X-Sunder-Unlock": unlockToken})
	if err != nil {
		return nil, err
	}
	return out.Values, nil
}

// -- file vault -------------------------------------------------------------

// FileMeta describes one stored file. SHA256 is the digest of the
// PLAINTEXT, for a client-side integrity check after download.
type FileMeta struct {
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	SizeBytes   int64  `json:"size_bytes,omitempty"`
	SHA256      string `json:"sha256,omitempty"`
	CreatedAt   string `json:"created_at,omitempty"`
	ExpiresAt   string `json:"expires_at,omitempty"`
}

// UploadFile stores a file for a person. Each file gets its own data key,
// wrapped by the person's record key - so erasing the person shreds the
// file even if the object store still holds the ciphertext.
//
// expiry, when non-zero, sets a hard deadline after which the file is
// unreadable and collected by the retention sweep.
//
// Never retried: a retried upload after an ambiguous failure stores the
// file twice.
func (c *Client) UploadFile(ctx context.Context, cid, name, contentType string, content io.Reader, expiry time.Time) (FileMeta, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="file"; filename=%q`, name))
	if contentType != "" {
		h.Set("Content-Type", contentType)
	}
	part, err := mw.CreatePart(h)
	if err != nil {
		return FileMeta{}, &Error{Code: ErrValidation.code, Detail: err.Error()}
	}
	if _, err := io.Copy(part, content); err != nil {
		return FileMeta{}, &Error{Code: ErrValidation.code, Detail: "reading file content: " + err.Error()}
	}
	if err := mw.Close(); err != nil {
		return FileMeta{}, &Error{Code: ErrValidation.code, Detail: err.Error()}
	}
	headers := map[string]string{"Content-Type": mw.FormDataContentType()}
	if !expiry.IsZero() {
		headers["X-Sunder-File-Expiry"] = expiry.UTC().Format(time.RFC3339)
	}
	var out FileMeta
	path := "/v1/contacts/" + url.PathEscape(cid) + "/files"
	if err := c.raw(ctx, http.MethodPost, path, buf.Bytes(), headers, &out, nil); err != nil {
		return FileMeta{}, err
	}
	return out, nil
}

// ListFiles lists a person's files (metadata only). Purpose-gated and
// consent-gated like any other read, and expired files are hidden.
func (c *Client) ListFiles(ctx context.Context, cid, purpose string) ([]FileMeta, error) {
	var out struct {
		Files []FileMeta `json:"files"`
	}
	path := "/v1/contacts/" + url.PathEscape(cid) + "/files?purpose=" + url.QueryEscape(purpose)
	if err := c.do(ctx, http.MethodGet, path, nil, &out, true); err != nil {
		return nil, err
	}
	return out.Files, nil
}

// DownloadFile streams one file's plaintext. The caller owns the returned
// ReadCloser and must close it.
//
// A download that fails mid-stream ABORTS the connection rather than
// completing a 200 with a short body, so a truncated read surfaces as a
// transport error - always verify the length, or the SHA256 from ListFiles,
// before treating the bytes as complete.
func (c *Client) DownloadFile(ctx context.Context, id, purpose string) (io.ReadCloser, error) {
	path := "/v1/files/" + url.PathEscape(id) + "?purpose=" + url.QueryEscape(purpose)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, &Error{Code: ErrValidation.code, Detail: err.Error()}
	}
	c.setHeaders(req, nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, &Error{Code: ErrServiceUnavailable.code,
			Detail: "network failure calling GET " + path + ": " + err.Error()}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		code, detail := parseErrorBody(raw)
		return nil, mapError(resp.StatusCode, code, detail)
	}
	return resp.Body, nil
}

// DeleteFile removes a file. Its name and digest are redacted immediately;
// the ciphertext is collected by the retention sweep. Not retried.
func (c *Client) DeleteFile(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/v1/files/"+url.PathEscape(id), nil, nil, false)
}

// -- cross-org shares -------------------------------------------------------

// ShareInput describes a share to create.
type ShareInput struct {
	CID string `json:"cid"`
	// Fields names the attributes disclosed. A share is a SNAPSHOT: the
	// values are captured now, so a later attribute change does not
	// propagate to a share already handed out.
	Fields []string `json:"fields"`
	// PartnerLabel identifies the recipient in the audit trail and in the
	// Article 15 answer. It is what makes "who was my data disclosed to"
	// answerable, so label the actual partner, not the integration.
	PartnerLabel string `json:"partner_label,omitempty"`
	// Purpose is checked against the client's grants and the person's
	// consent, exactly like an attribute read.
	Purpose string `json:"purpose,omitempty"`
	// TTLSeconds bounds the share's life. A share with no expiry is a
	// standing disclosure; prefer the shortest window the partner can use.
	TTLSeconds int64 `json:"ttl_seconds,omitempty"`
}

// Share is a freshly created share. The UUID is unguessable and, when the
// server runs with SUNDER_SHARES_PUBLIC, it is the ONLY credential needed
// to fetch it - treat it as a bearer secret and hand it over a channel that
// protects it.
type Share struct {
	UUID      string `json:"uuid"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// CreateShare discloses a snapshot of named fields to a partner.
func (c *Client) CreateShare(ctx context.Context, in ShareInput) (Share, error) {
	var out Share
	if err := c.do(ctx, http.MethodPost, "/v1/shares", in, &out, false); err != nil {
		return Share{}, err
	}
	if out.UUID == "" {
		return Share{}, &Error{Code: ErrBadResponse.code, Status: http.StatusCreated,
			Detail: "share response carried no uuid"}
	}
	return out, nil
}

// FetchShare reads a share's fields. Whether this needs a credential is the
// server's SUNDER_SHARES_PUBLIC decision; the SDK sends one either way.
// An expired, revoked or erased share is ErrNotFound.
func (c *Client) FetchShare(ctx context.Context, uuid string) (map[string]string, error) {
	var out struct {
		Fields map[string]string `json:"fields"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/shares/"+url.PathEscape(uuid), nil, &out, true); err != nil {
		return nil, err
	}
	return out.Fields, nil
}

// RevokeShare withdraws a share. Precise to (cid, purpose) on the consent
// path, so revoking one share never silently withdraws another. Not retried.
func (c *Client) RevokeShare(ctx context.Context, uuid string) error {
	return c.do(ctx, http.MethodDelete, "/v1/shares/"+url.PathEscape(uuid), nil, nil, false)
}

// -- person links -----------------------------------------------------------

// Link relates two people in the caller's scope - a guardian and a child, a
// member and an organisation, an owner and an asset. Erasing the parent
// LISTS the children; it never erases them unless DSRErase names the type.
func (c *Client) Link(ctx context.Context, parentCID, childCID, linkType string) error {
	body := map[string]string{"parent_cid": parentCID, "child_cid": childCID, "link_type": linkType}
	return c.do(ctx, http.MethodPost, "/v1/links", body, nil, false)
}

// Unlink removes the relation. Not retried.
func (c *Client) Unlink(ctx context.Context, parentCID, childCID string) error {
	body := map[string]string{"parent_cid": parentCID, "child_cid": childCID}
	return c.do(ctx, http.MethodDelete, "/v1/links", body, nil, false)
}

// ListLinks reports this person's links, each with the role ("parent" or
// "child") this cid plays in it.
func (c *Client) ListLinks(ctx context.Context, cid string) ([]LinkRef, error) {
	var out struct {
		Links []LinkRef `json:"links"`
	}
	path := "/v1/contacts/" + url.PathEscape(cid) + "/links"
	if err := c.do(ctx, http.MethodGet, path, nil, &out, true); err != nil {
		return nil, err
	}
	return out.Links, nil
}

// -- attribute version history ----------------------------------------------

// BlobVersion is one historical revision of a person's attribute blob.
type BlobVersion struct {
	VersionNo int64  `json:"version_no"`
	WrittenBy string `json:"written_by,omitempty"`
	WrittenAt string `json:"written_at,omitempty"`
}

// ListVersions reports the retained revisions of a person's attributes,
// newest first. How many are kept is the server's SUNDER_VERSIONS_KEEP and
// SUNDER_VERSIONS_TTL decision; history is personal data and is destroyed
// by erasure like everything else.
func (c *Client) ListVersions(ctx context.Context, cid string) ([]BlobVersion, error) {
	var out struct {
		Versions []BlobVersion `json:"versions"`
	}
	path := "/v1/contacts/" + url.PathEscape(cid) + "/versions"
	if err := c.do(ctx, http.MethodGet, path, nil, &out, true); err != nil {
		return nil, err
	}
	return out.Versions, nil
}

// GetVersionAttribute reads one attribute as it was at a past revision.
// Purpose-gated, consent-gated and audited exactly like a current read: an
// old value is not a lesser secret.
func (c *Client) GetVersionAttribute(ctx context.Context, cid string, versionNo int64, name, purpose string) (string, error) {
	var out struct {
		Value string `json:"value"`
	}
	path := "/v1/contacts/" + url.PathEscape(cid) + "/versions/" +
		strconv.FormatInt(versionNo, 10) + "/attributes/" + url.PathEscape(name) +
		"?purpose=" + url.QueryEscape(purpose)
	if err := c.do(ctx, http.MethodGet, path, nil, &out, true); err != nil {
		return "", err
	}
	return out.Value, nil
}

// -- external claims --------------------------------------------------------

// StoreExternalClaim ingests a signed envelope from a trusted issuer. The
// stored attribute names carry the issuer's provenance after an '@'
// separator, which is why '@' is refused in a caller-supplied attribute
// name: an attribute an external issuer vouched for must never be
// impersonable by an ordinary write.
//
// Returns the names actually stored.
func (c *Client) StoreExternalClaim(ctx context.Context, cid, envelope string) ([]string, error) {
	var out struct {
		Stored []string `json:"stored"`
	}
	body := map[string]string{"cid": cid, "envelope": envelope}
	if err := c.do(ctx, http.MethodPost, "/v1/claims/external", body, &out, false); err != nil {
		return nil, err
	}
	return out.Stored, nil
}

// -- admin ------------------------------------------------------------------

// Unlock is a short-lived single-use token authorizing one privileged call.
type Unlock struct {
	Token     string `json:"unlock_token"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// Unlock mints a single-use token for one purpose ("search" for fuzzy and
// partial lookups when SUNDER_SEARCH_UNLOCK is on, "tokens" for the bulk
// vault routes). It lives about a minute and is spent by ONE call.
//
// Requires the admin.unlock action, and the server refuses to grant that to
// a credential with no expiry: a standing key to every gated surface is not
// something an audit can reconstruct after the fact.
func (c *Client) Unlock(ctx context.Context, purpose string) (Unlock, error) {
	var out Unlock
	body := map[string]string{"purpose": purpose}
	if err := c.do(ctx, http.MethodPost, "/v1/admin/unlock", body, &out, false); err != nil {
		return Unlock{}, err
	}
	if out.Token == "" {
		return Unlock{}, &Error{Code: ErrBadResponse.code, Status: http.StatusCreated,
			Detail: "unlock response carried no token"}
	}
	return out, nil
}

// Ready is the readiness probe: unlike Health it reports whether the
// backing store and keystore are actually usable, so it is the one to gate
// traffic on.
func (c *Client) Ready(ctx context.Context) (string, error) {
	return c.probe(ctx, "/readyz")
}

func (c *Client) probe(ctx context.Context, path string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return "", &Error{Code: ErrValidation.code, Detail: err.Error()}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", &Error{Code: ErrServiceUnavailable.code,
			Detail: "network failure calling GET " + path + ": " + err.Error()}
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		code, detail := parseErrorBody(raw)
		return "", mapError(resp.StatusCode, code, detail)
	}
	status := strings.TrimSpace(string(raw))
	if status == "" {
		status = "ok"
	}
	return status, nil
}
