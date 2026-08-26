// Package auth authenticates client applications and enforces per-client
// allowed actions (bearer keys by default, mTLS as a deployment option).
package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/fvisic/sunder/internal/crypto"
)

// Actions a client may be granted. Purpose checks are separate and apply on
// top of these (an action says WHAT, a purpose says WHY).
const (
	ActContactsRegister = "contacts.register"
	ActScopesIssue      = "scopes.issue"
	ActLookup           = "lookup"
	ActAttributesRead   = "attributes.read"
	ActOTIIssue         = "oti.issue"
	ActOTIVerify        = "oti.verify"
	ActConsentManage    = "consent.manage"
	ActClaimsExternal   = "claims.external"
	// DSR actions (docs/DESIGN.md, GDPR layer). dsr.access and dsr.erase are org-wide,
	// linkage-capable privileges for the privacy-officer client only;
	// dsr.export is scope-local portability.
	ActAdminUnlock       = "admin.unlock"
	ActTokensCreate      = "tokens.create"
	ActTokensRead        = "tokens.read"
	ActTokensDelete      = "tokens.delete"
	ActFilesWrite        = "files.write"
	ActFilesRead         = "files.read"
	ActAttributesHistory = "attributes.history"
	ActLinksManage       = "links.manage"
	ActDSRAccess         = "dsr.access"
	ActDSRErase          = "dsr.erase"
	ActDSRExport         = "dsr.export"
)

// Client is an authenticated caller (one row in the clients table).
type Client struct {
	ID              string
	Name            string
	Scope           string
	AllowedActions  []string
	AllowedPurposes []string
	// AllowedAttributes narrows WHICH attributes this client may read
	// (F3): nil means all its purposes allow; a list makes GetAttribute
	// refuse anything else and filters Export/Access output.
	AllowedAttributes []string
	// Role is an introspection label plus creation-time preset (F12).
	// Enforcement is ALWAYS AllowedActions - one source of truth.
	Role      string
	RateLimit int
	// CredentialExpiresAt makes the bearer credential short-lived; nil
	// keeps it non-expiring (the pre-P2.2 behaviour).
	CredentialExpiresAt *time.Time
}

// Roles a client can be created with. Presets expand to action sets at
// creation; "custom" is explicit -actions (and every pre-F12 client).
const (
	RoleReadonly       = "readonly"
	RoleService        = "service"
	RoleAdmin          = "admin"
	RolePrivacyOfficer = "privacy-officer"
	RoleCustom         = "custom"
)

// RoleActions returns the preset action set, or nil for custom/unknown.
func RoleActions(role string) []string {
	switch role {
	case RoleReadonly:
		return []string{ActLookup, ActAttributesRead}
	case RoleService:
		return []string{ActLookup, ActAttributesRead, ActContactsRegister,
			ActOTIIssue, ActOTIVerify, ActConsentManage,
			ActTokensCreate, ActTokensRead, ActTokensDelete, ActFilesWrite, ActFilesRead}
	case RoleAdmin:
		// Operational admin: the full integration set plus unlock, value
		// tokens and files - but NOT the org-wide, cross-scope DSR
		// privileges (review F5: those stay deliberately opt-in and go to
		// the privacy-officer preset or explicit -actions).
		return []string{ActLookup, ActAttributesRead, ActContactsRegister,
			ActScopesIssue, ActOTIIssue, ActOTIVerify, ActConsentManage,
			ActClaimsExternal, ActAdminUnlock, ActTokensCreate, ActTokensRead, ActTokensDelete,
			ActFilesWrite, ActFilesRead, ActAttributesHistory, ActLinksManage}
	case RolePrivacyOfficer:
		return []string{ActDSRAccess, ActDSRErase, ActDSRExport, ActConsentManage}
	}
	return nil
}

func (c *Client) Can(action string) bool { return slices.Contains(c.AllowedActions, action) }

// CanReadAttribute applies the F3 allowlist: nil = every attribute its
// purposes allow (pre-F3 behaviour), a list = exactly those names.
func (c *Client) CanReadAttribute(name string) bool {
	// nil OR empty = unrestricted: an empty non-nil list is what a stray
	// "-attributes ," produces, and silently denying every read is a worse
	// failure than ignoring an empty filter (review F7). A real narrowing
	// always has at least one name.
	if len(c.AllowedAttributes) == 0 {
		return true
	}
	return slices.Contains(c.AllowedAttributes, name)
}
func (c *Client) CanUse(purpose string) bool {
	return slices.Contains(c.AllowedPurposes, purpose)
}

type ctxKey struct{}

// FromContext returns the authenticated client, or nil.
func FromContext(ctx context.Context) *Client {
	c, _ := ctx.Value(ctxKey{}).(*Client)
	return c
}

// FailureLimiter throttles authentication FAILURES per source IP - brute
// force and credential-confirmation probing must not run at line rate.
type FailureLimiter interface {
	Allow(key string, limit int) bool
}

// Authenticator loads and verifies clients.
type Authenticator struct {
	Pool *pgxpool.Pool
	// Limiter, when set, throttles failed attempts per source IP.
	Limiter FailureLimiter
}

// ErrCredentialExpired distinguishes an expired (but otherwise valid)
// credential from a wrong one: the caller should rotate, not retry.
var ErrCredentialExpired = errors.New("credential expired")

// Authenticate resolves "Bearer <client_id>.<secret>". The stored hash is
// compared in constant time; the decoy compare below narrows (but cannot
// fully close - the DB roundtrip differs) the timing gap between unknown
// ids and bad secrets. Client ids are not secrets; the secret is.
//
// The error return is nil for plain rejection and ErrCredentialExpired when
// a correct secret has passed its expiry - the expiry check runs AFTER the
// constant-time compare so expiry never becomes a secret-validity oracle.
func (a *Authenticator) Authenticate(ctx context.Context, authorization string) (*Client, bool, error) {
	raw, ok := strings.CutPrefix(authorization, "Bearer ")
	if !ok {
		return nil, false, nil
	}
	id, secret, ok := strings.Cut(raw, ".")
	if !ok || id == "" || secret == "" {
		return nil, false, nil
	}
	var c Client
	var keyHash []byte
	var expiresAt *time.Time
	err := a.Pool.QueryRow(ctx,
		`SELECT client_id, name, scope, allowed_actions, allowed_purposes, allowed_attributes,
		        COALESCE(role,'custom'), rate_limit, key_hash, credential_expires_at
		 FROM clients WHERE client_id=$1`, id).
		Scan(&c.ID, &c.Name, &c.Scope, &c.AllowedActions, &c.AllowedPurposes, &c.AllowedAttributes,
			&c.Role, &c.RateLimit, &keyHash, &expiresAt)
	if err == pgx.ErrNoRows {
		// Equalize timing with the found-client path.
		subtle.ConstantTimeCompare(crypto.HashSecret(secret), crypto.HashSecret("decoy"))
		return nil, false, nil
	}
	if err != nil {
		// Environment failure, not a credential verdict: the middleware
		// answers 503 so an outage is never read as "bad credentials".
		return nil, false, fmt.Errorf("auth backend: %w", err)
	}
	if subtle.ConstantTimeCompare(crypto.HashSecret(secret), keyHash) != 1 {
		return nil, false, nil
	}
	if expiresAt != nil && time.Now().After(*expiresAt) {
		return nil, false, ErrCredentialExpired
	}
	return &c, true, nil
}

// Middleware rejects unauthenticated requests and puts the client in context.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok, err := a.Authenticate(r.Context(), r.Header.Get("Authorization"))
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			if err != nil && !errors.Is(err, ErrCredentialExpired) {
				// Backend outage: 503, never a credential verdict.
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"error":"service_unavailable"}`))
				return
			}
			// Throttle FAILURES per source IP: 60/min covers fat-fingered
			// configs; brute force and expired-credential probing do not
			// get to run at line rate.
			if a.Limiter != nil {
				ip, _, splitErr := net.SplitHostPort(r.RemoteAddr)
				if splitErr != nil {
					ip = r.RemoteAddr
				}
				if !a.Limiter.Allow("authfail:"+ip, 60) {
					w.WriteHeader(http.StatusTooManyRequests)
					_, _ = w.Write([]byte(`{"error":"rate_limited"}`))
					return
				}
			}
			w.Header().Set("WWW-Authenticate", "Bearer")
			w.WriteHeader(http.StatusUnauthorized)
			if errors.Is(err, ErrCredentialExpired) {
				_, _ = w.Write([]byte(`{"error":"credential_expired"}`))
				return
			}
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, c)))
	})
}

// clientIDPattern keeps ids unambiguous inside the "<id>.<secret>"
// credential: a '.' in the id would make Authenticate's split parse the
// credential as a different client's.
var clientIDPattern = regexp.MustCompile(`^[a-z0-9_-]{1,64}$`)

// Create registers a client and returns the full bearer credential
// ("<id>.<secret>") exactly once; only the hash is stored.
// CreateTx is Create inside a caller-supplied transaction: bootstrap needs
// the client row and the persisted credential to commit or roll back
// together, or a failed write leaves an admin whose secret nobody holds
// .
func CreateTx(ctx context.Context, tx pgx.Tx, c Client) (string, error) {
	if !clientIDPattern.MatchString(c.ID) {
		return "", fmt.Errorf("client id must match %s", clientIDPattern)
	}
	secret, err := crypto.NewClientSecret()
	if err != nil {
		return "", err
	}
	applyRole(&c)
	if _, err := tx.Exec(ctx,
		`INSERT INTO clients (client_id, name, key_hash, scope, allowed_actions, allowed_purposes, allowed_attributes, role, rate_limit, credential_expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		c.ID, c.Name, crypto.HashSecret(secret), c.Scope, c.AllowedActions, c.AllowedPurposes,
		c.AllowedAttributes, c.Role, c.RateLimit, c.CredentialExpiresAt); err != nil {
		return "", err
	}
	return c.ID + "." + secret, nil
}

func Create(ctx context.Context, pool *pgxpool.Pool, c Client) (credential string, err error) {
	if !clientIDPattern.MatchString(c.ID) {
		return "", fmt.Errorf("client id must match %s", clientIDPattern)
	}
	secret, err := crypto.NewClientSecret()
	if err != nil {
		return "", err
	}
	applyRole(&c)
	_, err = pool.Exec(ctx,
		`INSERT INTO clients (client_id, name, key_hash, scope, allowed_actions, allowed_purposes, allowed_attributes, role, rate_limit, credential_expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		c.ID, c.Name, crypto.HashSecret(secret), c.Scope, c.AllowedActions, c.AllowedPurposes,
		c.AllowedAttributes, c.Role, c.RateLimit, c.CredentialExpiresAt)
	if err != nil {
		return "", err
	}
	return c.ID + "." + secret, nil
}

// applyRole expands a preset role into its action set at creation time. A
// preset REPLACES actions (mixing "readonly" with extra actions would make
// the label a lie); explicit actions mean the role is custom.
func applyRole(c *Client) {
	if c.Role == "" {
		c.Role = RoleCustom
	}
	if preset := RoleActions(c.Role); preset != nil {
		c.AllowedActions = preset
	}
}

// RotateSecret replaces a client's secret and returns the new credential
// exactly once. The old secret stops working immediately - schedule
// rotations, don't race them. setExpiry=false preserves the stored expiry
// policy (the safe default); setExpiry=true writes expiresAt (nil clears).
func RotateSecret(ctx context.Context, pool *pgxpool.Pool, clientID string, expiresAt *time.Time, setExpiry bool) (string, error) {
	secret, err := crypto.NewClientSecret()
	if err != nil {
		return "", err
	}
	var tag pgconn.CommandTag
	if setExpiry {
		tag, err = pool.Exec(ctx,
			`UPDATE clients SET key_hash=$2, credential_expires_at=$3 WHERE client_id=$1`,
			clientID, crypto.HashSecret(secret), expiresAt)
	} else {
		tag, err = pool.Exec(ctx,
			`UPDATE clients SET key_hash=$2 WHERE client_id=$1`,
			clientID, crypto.HashSecret(secret))
	}
	if err != nil {
		return "", err
	}
	if tag.RowsAffected() == 0 {
		return "", fmt.Errorf("client %q not found", clientID)
	}
	return clientID + "." + secret, nil
}
