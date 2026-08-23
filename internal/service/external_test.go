package service_test

// P2.4 external-issuer federation: only registered issuers, only allowed
// claims, only unexpired envelopes; stored attributes carry provenance.

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/crypto"
	"github.com/fvisic/sunder/internal/service"
)

var envSeq int

// mintEnvelope signs a claim envelope the way a wallet gateway would:
// subject-bound to one CID, replay-protected by a unique jti.
func mintEnvelope(t *testing.T, sk ed25519.PrivateKey, issuer, cid string, claims map[string]string, exp time.Time) string {
	t.Helper()
	envSeq++
	payload, err := json.Marshal(map[string]any{
		"iss": issuer, "jti": fmt.Sprintf("env-%d-%d", os.Getpid(), envSeq), "cid": cid,
		"claims": claims,
		"iat":    time.Now().UTC().Format(time.RFC3339),
		"exp":    exp.UTC().Format(time.RFC3339),
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

	env := mintEnvelope(t, sk, "gov.wallet", cid, map[string]string{"age_gte_18": "true"},
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
		return mintEnvelope(t, sk, "partner.one", cid, map[string]string{"kyc_level": "2"},
			time.Now().Add(time.Hour))
	}

	// Unknown issuer.
	env := mintEnvelope(t, sk, "partner.unknown", cid, map[string]string{"kyc_level": "2"}, time.Now().Add(time.Hour))
	if _, err := e.svc.ExternalClaims(ctx, e.crm, cid, env); err == nil {
		t.Fatal("unknown issuer must be rejected")
	}
	// Wrong key (signature does not match the registered one).
	otherSeed := make([]byte, 32)
	otherSeed[0] = 11
	other := ed25519.NewKeyFromSeed(otherSeed)
	env = mintEnvelope(t, other, "partner.one", cid, map[string]string{"kyc_level": "2"}, time.Now().Add(time.Hour))
	if _, err := e.svc.ExternalClaims(ctx, e.crm, cid, env); err == nil {
		t.Fatal("envelope signed with the wrong key must be rejected")
	}
	// Expired.
	env = mintEnvelope(t, sk, "partner.one", cid, map[string]string{"kyc_level": "2"}, time.Now().Add(-time.Minute))
	if _, err := e.svc.ExternalClaims(ctx, e.crm, cid, env); err == nil {
		t.Fatal("expired envelope must be rejected")
	}
	// Claim outside the allowlist.
	env = mintEnvelope(t, sk, "partner.one", cid, map[string]string{"credit_score": "800"}, time.Now().Add(time.Hour))
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

// Review findings 18-21: replay, cross-CID reuse, forged provenance,
// deny-by-default allowlists.
func TestExternalClaimsReviewFindings(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cidA := e.register(t)
	e.crm.AllowedActions = append(e.crm.AllowedActions, auth.ActClaimsExternal)
	cidB, err := e.svc.Register(ctx, e.crm, service.RegisterInput{Email: "second@example.com"})
	if err != nil {
		t.Fatal(err)
	}

	seed := make([]byte, 32)
	seed[0] = 21
	sk := ed25519.NewKeyFromSeed(seed)
	registerIssuer(t, e, "gw", sk.Public().(ed25519.PublicKey), []string{"*"})

	// Replay: the same envelope is consumed exactly once.
	env := mintEnvelope(t, sk, "gw", cidA, map[string]string{"kyc": "2"}, time.Now().Add(time.Hour))
	if _, err := e.svc.ExternalClaims(ctx, e.crm, cidA, env); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.ExternalClaims(ctx, e.crm, cidA, env); err == nil {
		t.Fatal("replaying the same envelope must fail")
	}
	// Subject binding: an envelope for A cannot be attached to B.
	envA := mintEnvelope(t, sk, "gw", cidA, map[string]string{"kyc": "3"}, time.Now().Add(time.Hour))
	if _, err := e.svc.ExternalClaims(ctx, e.crm, cidB, envA); err == nil {
		t.Fatal("an envelope bound to A must not attach to B")
	}
	// Missing jti is rejected.
	payload, _ := json.Marshal(map[string]any{
		"iss": "gw", "cid": cidA, "claims": map[string]string{"kyc": "2"},
		"exp": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	})
	if _, err := e.svc.ExternalClaims(ctx, e.crm, cidA, crypto.PasetoSign(sk, payload)); err == nil {
		t.Fatal("an envelope without a jti must be rejected")
	}
	// Claim name with '@' (issuer impersonation via suffixing) is rejected.
	env = mintEnvelope(t, sk, "gw", cidA, map[string]string{"age_gte_18@gov.wallet": "true"}, time.Now().Add(time.Hour))
	if _, err := e.svc.ExternalClaims(ctx, e.crm, cidA, env); err == nil {
		t.Fatal("claim names containing '@' must be rejected")
	}
	// Oversized claim value is rejected.
	env = mintEnvelope(t, sk, "gw", cidA, map[string]string{"blob": strings.Repeat("x", 5000)}, time.Now().Add(time.Hour))
	if _, err := e.svc.ExternalClaims(ctx, e.crm, cidA, env); err == nil {
		t.Fatal("oversized claim values must be rejected")
	}

	// Deny-by-default: an issuer registered with NO allowed claims may
	// assert nothing.
	seed2 := make([]byte, 32)
	seed2[0] = 22
	sk2 := ed25519.NewKeyFromSeed(seed2)
	registerIssuer(t, e, "restricted", sk2.Public().(ed25519.PublicKey), []string{})
	env = mintEnvelope(t, sk2, "restricted", cidA, map[string]string{"anything": "x"}, time.Now().Add(time.Hour))
	if _, err := e.svc.ExternalClaims(ctx, e.crm, cidA, env); err == nil {
		t.Fatal("empty allowlist must mean NOTHING, not everything")
	}
}

// Review finding 19: forged provenance via self-registration.
func TestRegisterRejectsProvenanceForgery(t *testing.T) {
	e := newFaultEnv(t)
	if _, err := e.svc.Register(context.Background(), e.crm, service.RegisterInput{
		Email:      "forge@example.com",
		Attributes: map[string]string{"age_gte_18@gov.wallet": "true"},
	}); err == nil {
		t.Fatal("self-registered '@' attribute names must be rejected")
	}
}
