package service_test

// P2.4 external-issuer federation: only registered issuers, only allowed
// claims, only unexpired envelopes; stored attributes carry provenance.

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/crypto"
	"github.com/fvisic/sunder/internal/service"
)

// mintEnvelope signs a claim envelope the way a wallet gateway would.
func mintEnvelope(t *testing.T, sk ed25519.PrivateKey, issuer string, claims map[string]string, exp time.Time) string {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"iss": issuer, "claims": claims,
		"iat": time.Now().UTC().Format(time.RFC3339),
		"exp": exp.UTC().Format(time.RFC3339),
	})
	if err != nil {
		t.Fatal(err)
	}
	return crypto.PasetoSign(sk, payload)
}

func registerIssuer(t *testing.T, e *faultEnv, id string, pk ed25519.PublicKey, allowed []string) {
	t.Helper()
	if _, err := e.admin.Pool.Exec(context.Background(),
		`INSERT INTO trusted_issuers (issuer_id, public_key, allowed_claims, added_by) VALUES ($1,$2,$3,'test')`,
		id, []byte(pk), allowed); err != nil {
		t.Fatal(err)
	}
}

func TestExternalClaimsHappyPath(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cid := e.register(t)
	e.crm.AllowedActions = append(e.crm.AllowedActions, auth.ActClaimsExternal)

	seed := make([]byte, 32)
	seed[0] = 7
	sk := ed25519.NewKeyFromSeed(seed)
	registerIssuer(t, e, "gov.wallet", sk.Public().(ed25519.PublicKey), []string{"age_gte_18"})

	env := mintEnvelope(t, sk, "gov.wallet", map[string]string{"age_gte_18": "true"},
		time.Now().Add(time.Hour))
	stored, err := e.svc.ExternalClaims(ctx, e.crm, cid, env)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 || stored[0] != "age_gte_18@gov.wallet" {
		t.Fatalf("stored: %v", stored)
	}
	// The claim is a normal purpose-checked attribute now, with provenance.
	if v, err := e.svc.GetAttribute(ctx, e.crm, cid, "age_gte_18@gov.wallet", "support"); err != nil || v != "true" {
		t.Fatalf("read back: %q %v", v, err)
	}
}

func TestExternalClaimsRejections(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cid := e.register(t)
	e.crm.AllowedActions = append(e.crm.AllowedActions, auth.ActClaimsExternal)

	seed := make([]byte, 32)
	seed[0] = 9
	sk := ed25519.NewKeyFromSeed(seed)
	registerIssuer(t, e, "partner.one", sk.Public().(ed25519.PublicKey), []string{"kyc_level"})

	good := func() string {
		return mintEnvelope(t, sk, "partner.one", map[string]string{"kyc_level": "2"},
			time.Now().Add(time.Hour))
	}

	// Unknown issuer.
	env := mintEnvelope(t, sk, "partner.unknown", map[string]string{"kyc_level": "2"}, time.Now().Add(time.Hour))
	if _, err := e.svc.ExternalClaims(ctx, e.crm, cid, env); err == nil {
		t.Fatal("unknown issuer must be rejected")
	}
	// Wrong key (signature does not match the registered one).
	otherSeed := make([]byte, 32)
	otherSeed[0] = 11
	other := ed25519.NewKeyFromSeed(otherSeed)
	env = mintEnvelope(t, other, "partner.one", map[string]string{"kyc_level": "2"}, time.Now().Add(time.Hour))
	if _, err := e.svc.ExternalClaims(ctx, e.crm, cid, env); err == nil {
		t.Fatal("envelope signed with the wrong key must be rejected")
	}
	// Expired.
	env = mintEnvelope(t, sk, "partner.one", map[string]string{"kyc_level": "2"}, time.Now().Add(-time.Minute))
	if _, err := e.svc.ExternalClaims(ctx, e.crm, cid, env); err == nil {
		t.Fatal("expired envelope must be rejected")
	}
	// Claim outside the allowlist.
	env = mintEnvelope(t, sk, "partner.one", map[string]string{"credit_score": "800"}, time.Now().Add(time.Hour))
	if _, err := e.svc.ExternalClaims(ctx, e.crm, cid, env); err == nil {
		t.Fatal("disallowed claim must be rejected")
	}
	// Foreign CID: indistinguishable from absent.
	foreign := *e.crm
	foreign.Scope = "other"
	if _, err := e.svc.ExternalClaims(ctx, &foreign, cid, good()); err != service.ErrNotFound {
		t.Fatalf("foreign cid: %v", err)
	}
	// Missing action.
	noAct := &auth.Client{ID: "n", Scope: "crm"}
	if _, err := e.svc.ExternalClaims(ctx, noAct, cid, good()); err != service.ErrForbidden {
		t.Fatalf("missing action: %v", err)
	}
	// Garbage envelope.
	if _, err := e.svc.ExternalClaims(ctx, e.crm, cid, "not-a-token"); err == nil {
		t.Fatal("garbage envelope must be rejected")
	}
	// Sanity: the good one still works after all rejections.
	if _, err := e.svc.ExternalClaims(ctx, e.crm, cid, good()); err != nil {
		t.Fatal(err)
	}
}
