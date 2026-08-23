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
	// CredentialExpiresAt makes the bearer credential short-lived; nil
	// keeps it non-expiring (the pre-P2.2 behaviour).
	CredentialExpiresAt *time.Time
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
		`SELECT client_id, name, scope, allowed_actions, allowed_purposes, rate_limit, key_hash, credential_expires_at
		 FROM clients WHERE client_id=$1`, id).
		Scan(&c.ID, &c.Name, &c.Scope, &c.AllowedActions, &c.AllowedPurposes, &c.RateLimit, &keyHash, &expiresAt)
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
func Create(ctx context.Context, pool *pgxpool.Pool, c Client) (credential string, err error) {
	if !clientIDPattern.MatchString(c.ID) {
		return "", fmt.Errorf("client id must match %s", clientIDPattern)
	}
	secret, err := crypto.NewClientSecret()
	if err != nil {
		return "", err
	}
	_, err = pool.Exec(ctx,
		`INSERT INTO clients (client_id, name, key_hash, scope, allowed_actions, allowed_purposes, rate_limit, credential_expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		c.ID, c.Name, crypto.HashSecret(secret), c.Scope, c.AllowedActions, c.AllowedPurposes, c.RateLimit, c.CredentialExpiresAt)
	if err != nil {
		return "", err
	}
	return c.ID + "." + secret, nil
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
