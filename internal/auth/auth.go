// Package auth authenticates client applications and enforces per-client
// allowed actions (bearer keys by default, mTLS as a deployment option).
package auth

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
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
	// DSR actions (docs/DESIGN.md, GDPR layer). dsr.access and dsr.erase are org-wide,
	// linkage-capable privileges for the privacy-officer client only;
	// dsr.export is scope-local portability.
	ActDSRAccess = "dsr.access"
	ActDSRErase  = "dsr.erase"
	ActDSRExport = "dsr.export"
)

// Client is an authenticated caller (one row in the clients table).
type Client struct {
	ID              string
	Name            string
	Scope           string
	AllowedActions  []string
	AllowedPurposes []string
	RateLimit       int
}

func (c *Client) Can(action string) bool { return slices.Contains(c.AllowedActions, action) }
func (c *Client) CanUse(purpose string) bool {
	return slices.Contains(c.AllowedPurposes, purpose)
}

type ctxKey struct{}

// FromContext returns the authenticated client, or nil.
func FromContext(ctx context.Context) *Client {
	c, _ := ctx.Value(ctxKey{}).(*Client)
	return c
}

// Authenticator loads and verifies clients.
type Authenticator struct {
	Pool *pgxpool.Pool
}

// Authenticate resolves "Bearer <client_id>.<secret>". The stored hash is
// compared in constant time; the decoy compare below narrows (but cannot
// fully close — the DB roundtrip differs) the timing gap between unknown
// ids and bad secrets. Client ids are not secrets; the secret is.
func (a *Authenticator) Authenticate(ctx context.Context, authorization string) (*Client, bool) {
	raw, ok := strings.CutPrefix(authorization, "Bearer ")
	if !ok {
		return nil, false
	}
	id, secret, ok := strings.Cut(raw, ".")
	if !ok || id == "" || secret == "" {
		return nil, false
	}
	var c Client
	var keyHash []byte
	err := a.Pool.QueryRow(ctx,
		`SELECT client_id, name, scope, allowed_actions, allowed_purposes, rate_limit, key_hash
		 FROM clients WHERE client_id=$1`, id).
		Scan(&c.ID, &c.Name, &c.Scope, &c.AllowedActions, &c.AllowedPurposes, &c.RateLimit, &keyHash)
	if err == pgx.ErrNoRows {
		// Equalize timing with the found-client path.
		subtle.ConstantTimeCompare(crypto.HashSecret(secret), crypto.HashSecret("decoy"))
		return nil, false
	}
	if err != nil {
		return nil, false
	}
	if subtle.ConstantTimeCompare(crypto.HashSecret(secret), keyHash) != 1 {
		return nil, false
	}
	return &c, true
}

// Middleware rejects unauthenticated requests and puts the client in context.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := a.Authenticate(r.Context(), r.Header.Get("Authorization"))
		if !ok {
			w.Header().Set("WWW-Authenticate", "Bearer")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
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
func Create(ctx context.Context, pool *pgxpool.Pool, c Client) (credential string, err error) {
	if !clientIDPattern.MatchString(c.ID) {
		return "", fmt.Errorf("client id must match %s", clientIDPattern)
	}
	secret, err := crypto.NewClientSecret()
	if err != nil {
		return "", err
	}
	_, err = pool.Exec(ctx,
		`INSERT INTO clients (client_id, name, key_hash, scope, allowed_actions, allowed_purposes, rate_limit)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		c.ID, c.Name, crypto.HashSecret(secret), c.Scope, c.AllowedActions, c.AllowedPurposes, c.RateLimit)
	if err != nil {
		return "", err
	}
	return c.ID + "." + secret, nil
}
