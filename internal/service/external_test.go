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

// N1 (verified exploit in review): an erased person must not be
// resurrectable through ANY path that addresses the row by CID.
func TestErasedPersonIsUnreachableEverywhere(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cid := e.register(t)
	e.crm.AllowedActions = append(e.crm.AllowedActions, auth.ActClaimsExternal)

	seed := make([]byte, 32)
	seed[0] = 77
	sk := ed25519.NewKeyFromSeed(seed)
	registerIssuer(t, e, "gov", sk.Public().(ed25519.PublicKey), []string{"*"})

	if _, _, err := e.gdpr.Erase(ctx, e.crm, cid); err != nil {
		t.Fatal(err)
	}

	// External claims must not write into the tombstone.
	env := mintEnvelope(t, sk, "gov", cid, map[string]string{"age_gte_18": "true"}, time.Now().Add(time.Hour))
	if _, err := e.svc.ExternalClaims(ctx, e.crm, cid, env); err != service.ErrNotFound {
		t.Fatalf("external claims on an erased person: %v", err)
	}
	// And nothing reads back.
	if _, err := e.svc.GetAttribute(ctx, e.crm, cid, "age_gte_18@gov", "support"); err != service.ErrNotFound {
		t.Fatalf("attribute read on an erased person: %v", err)
	}
	// Every other CID-addressed path is equally closed.
	if _, _, err := e.oti.Issue(ctx, e.crm, cid, "support", "billing", nil); err != service.ErrNotFound {
		t.Fatalf("oti issue on an erased person: %v", err)
	}
	if err := e.gdpr.SetConsent(ctx, e.crm, cid, "support", true); err != service.ErrNotFound {
		t.Fatalf("consent on an erased person: %v", err)
	}
	if _, err := e.gdpr.Access(ctx, e.crm, cid); err != service.ErrNotFound {
		t.Fatalf("access on an erased person: %v", err)
	}
	if _, err := e.gdpr.Export(ctx, e.crm, cid); err != service.ErrNotFound {
		t.Fatalf("export on an erased person: %v", err)
	}
	if _, err := e.svc.IssueScopedCid(ctx, e.crm, cid, "billing"); err != service.ErrNotFound {
		t.Fatalf("scope issuance on an erased person: %v", err)
	}
	// A fresh registration of the same identifiers is a NEW person, not a
	// revival: the tombstoned CID must not come back.
	fresh, err := e.svc.Register(ctx, e.crm, service.RegisterInput{Email: "fault@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if fresh == cid {
		t.Fatal("re-registration must mint a new pseudonym, not reuse the tombstoned one")
	}
}

// Unusable registered key material must be refused, not fed to
// ed25519.Verify (which panics on a wrong length and accepts low-order
// points).
func TestExternalClaimsRejectsDegenerateIssuerKey(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cid := e.register(t)
	e.crm.AllowedActions = append(e.crm.AllowedActions, auth.ActClaimsExternal)

	// An all-zero key passes the 32-byte CHECK but is degenerate.
	registerIssuer(t, e, "degenerate", make([]byte, 32), []string{"*"})
	seed := make([]byte, 32)
	seed[0] = 55
	sk := ed25519.NewKeyFromSeed(seed)
	env := mintEnvelope(t, sk, "degenerate", cid, map[string]string{"x": "1"}, time.Now().Add(time.Hour))
	if _, err := e.svc.ExternalClaims(ctx, e.crm, cid, env); err == nil {
		t.Fatal("a degenerate issuer key must be refused")
	}

	// A malformed issuer id never reaches the registry lookup or the audit
	// chain (it is attacker-controlled and unbounded).
	payload, _ := json.Marshal(map[string]any{
		"iss": strings.Repeat("A", 5000), "jti": "envelope-0001", "cid": cid,
		"claims": map[string]string{"x": "1"},
		"exp":    time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	})
	if _, err := e.svc.ExternalClaims(ctx, e.crm, cid, crypto.PasetoSign(sk, payload)); err == nil {
		t.Fatal("a malformed issuer id must be rejected before any lookup")
	}
	var n int
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM audit WHERE length(detail) > 1000`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("attacker-controlled bulk data reached the audit chain (%d rows)", n)
	}

	// An envelope valid for a year is refused: unbounded lifetimes make the
	// replay table unprunable.
	long := mintEnvelope(t, sk, "degenerate", cid, map[string]string{"x": "1"}, time.Now().Add(365*24*time.Hour))
	if _, err := e.svc.ExternalClaims(ctx, e.crm, cid, long); err == nil {
		t.Fatal("an over-long envelope lifetime must be rejected")
	}
}
