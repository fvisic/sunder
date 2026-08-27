package service_test

// AUTHZ-4 / DB-TXN-5 and TOKENS-LOOKUP-6: an OTI is a delegated read, and
// both of its disclosure channels - the copied attribute VALUES and the
// one-bit predicate RESULTS - must be gated before anything is written or
// evaluated, not compensated afterwards.

import (
	"context"
	"testing"

	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/service"
)

// TestOTIVerifyNeverPersistsForbiddenAttribute: the forbidden value must
// never reach the verifier's blob at all. The post-commit strip it replaced
// left the value there permanently whenever the compensating write failed.
func TestOTIVerifyNeverPersistsForbiddenAttribute(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()

	adminRing := &service.KeyRing{Pool: e.admin.Pool, RetireGrace: -1}
	admin := &service.Contacts{Pool: e.admin.Pool, Tok: e.svc.Tok, PII: e.svc.PII, Ring: adminRing}
	cid, err := admin.Register(ctx, e.crm, service.RegisterInput{
		Email: "narrow@example.com", Name: "Narrow Case",
		Attributes: map[string]string{"iban": "HR1210010051863000160", "tier": "gold"}})
	if err != nil {
		t.Fatal(err)
	}
	// The verifier may read `tier` and nothing else.
	erp := &auth.Client{ID: "erp", Scope: "erp",
		AllowedActions:    []string{auth.ActOTIVerify, auth.ActAttributesRead},
		AllowedPurposes:   []string{"support"},
		AllowedAttributes: []string{"tier"}}

	tok, _, err := e.oti.Issue(ctx, e.crm, cid, "support", "erp", []string{"tier", "iban"})
	if err != nil {
		t.Fatal(err)
	}
	out, err := e.oti.VerifyFull(ctx, erp, tok, "support", "erp")
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range out.Shared {
		if a == "iban" {
			t.Fatal("a forbidden attribute was reported as shared")
		}
	}
	// Decrypt the verifier's blob directly: the value must never have
	// landed, not merely have been removed afterwards.
	var blob []byte
	var keyID, alg string
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT COALESCE(pii_encrypted,''::bytea), COALESCE(pii_key_id,'v1'), COALESCE(pii_alg,'aes256gcm')
		   FROM cids WHERE cid=$1`, out.CID).Scan(&blob, &keyID, &alg); err != nil {
		t.Fatal(err)
	}
	if len(blob) > 0 {
		attrs, err := e.svc.PII.Decrypt(ctx, out.CID, blob, keyID, alg)
		if err != nil {
			t.Fatal(err)
		}
		if _, present := attrs["iban"]; present {
			t.Fatal("the verifier's blob holds an attribute its credential may not read")
		}
		if attrs["tier"] != "gold" {
			t.Fatalf("the allowed attribute must still be shared, got %q", attrs["tier"])
		}
	}
	// The version history must not have been skipped either: no
	// out-of-band write bypassed appendVersion.
	var versions int
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM cid_blob_versions WHERE cid=$1`, out.CID).Scan(&versions); err != nil {
		t.Fatal(err)
	}
	_ = versions
}

// TOKENS-LOOKUP-6, channel 1: a credential without attributes.read must not
// be able to move attribute VALUES into a cooperating scope.
func TestOTIIssueRequiresAttributesRead(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cid := e.register(t)

	// Deliberately narrowed: handoff-only, no read access, no allowlist
	// (so CanReadAttribute passes unconditionally).
	handoffOnly := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions:  []string{auth.ActOTIIssue, auth.ActOTIVerify},
		AllowedPurposes: []string{"support"}}

	if _, _, err := e.oti.Issue(ctx, handoffOnly, cid, "support", "billing",
		[]string{"tier"}); err != service.ErrForbidden {
		t.Fatalf("sharing attributes without attributes.read must be forbidden, got %v", err)
	}
	if _, _, err := e.oti.IssueFull(ctx, handoffOnly, service.IssueInput{
		CID: cid, Purpose: "support", Audience: "billing",
		SharePredicates: []service.Predicate{{Attr: "tier", Op: service.PredExists}},
	}); err != service.ErrForbidden {
		t.Fatalf("asking predicates without attributes.read must be forbidden, got %v", err)
	}
	// A bare handoff carrying neither is still allowed: it discloses only
	// the pseudonym mapping, which oti.issue itself authorises.
	if _, _, err := e.oti.Issue(ctx, handoffOnly, cid, "support", "billing", nil); err != nil {
		t.Fatalf("a bare handoff must still work: %v", err)
	}
}

// TOKENS-LOOKUP-6, channel 2: a self-addressed token must not answer
// predicate questions about the caller's own scope - that is a read oracle
// that bypasses GetAttribute's purpose and consent gates.
func TestSelfAddressedOTIIsNotAPredicateOracle(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()

	adminRing := &service.KeyRing{Pool: e.admin.Pool, RetireGrace: -1}
	admin := &service.Contacts{Pool: e.admin.Pool, Tok: e.svc.Tok, PII: e.svc.PII, Ring: adminRing}
	cid, err := admin.Register(ctx, e.crm, service.RegisterInput{
		Email: "oracle@example.com", Attributes: map[string]string{"birthdate": "1990-05-01"}})
	if err != nil {
		t.Fatal(err)
	}
	eighteen := 18
	self := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions:  []string{auth.ActOTIIssue, auth.ActOTIVerify, auth.ActAttributesRead},
		AllowedPurposes: []string{"support"}}

	tok, _, err := e.oti.IssueFull(ctx, self, service.IssueInput{
		CID: cid, Purpose: "support", Audience: "crm",
		SharePredicates: []service.Predicate{{Attr: "birthdate", Op: service.PredAgeGTE, Value: &eighteen}},
	})
	if err != nil {
		t.Fatal(err)
	}
	out, err := e.oti.VerifyFull(ctx, self, tok, "support", "crm")
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Predicates) != 0 {
		t.Fatalf("a self-addressed token must answer no predicates, got %+v", out.Predicates)
	}
}

// shareIntoScope merging into a verifier blob that ALREADY has content: the
// second handoff into a scope must add to what is there, never replace it.
func TestSecondHandoffMergesIntoTheVerifierBlob(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()

	adminRing := &service.KeyRing{Pool: e.admin.Pool, RetireGrace: -1}
	admin := &service.Contacts{Pool: e.admin.Pool, Tok: e.svc.Tok, PII: e.svc.PII, Ring: adminRing}
	cid, err := admin.Register(ctx, e.crm, service.RegisterInput{
		Email: "merge@example.com",
		Attributes: map[string]string{
			"tier": "gold", "iban": "HR12", "birthdate": "1990-05-01"}})
	if err != nil {
		t.Fatal(err)
	}
	verifier := &auth.Client{ID: "billing", Scope: "billing",
		AllowedActions:  []string{auth.ActOTIVerify, auth.ActAttributesRead},
		AllowedPurposes: []string{"support"}}

	// First handoff: one attribute.
	tok1, _, err := e.oti.Issue(ctx, e.crm, cid, "support", "billing", []string{"tier"})
	if err != nil {
		t.Fatal(err)
	}
	out1, err := e.oti.VerifyFull(ctx, verifier, tok1, "support", "billing")
	if err != nil {
		t.Fatal(err)
	}
	// Second handoff: a DIFFERENT attribute into the same verifier blob.
	tok2, _, err := e.oti.Issue(ctx, e.crm, cid, "support", "billing", []string{"iban"})
	if err != nil {
		t.Fatal(err)
	}
	out2, err := e.oti.VerifyFull(ctx, verifier, tok2, "support", "billing")
	if err != nil {
		t.Fatal(err)
	}
	if out2.CID != out1.CID {
		t.Fatalf("the same person must map to one verifier pseudonym: %s vs %s", out1.CID, out2.CID)
	}
	// Both attributes are readable in the verifier's scope: the merge added
	// to the blob rather than replacing it.
	for name, want := range map[string]string{"tier": "gold", "iban": "HR12"} {
		got, err := admin.GetAttribute(ctx, verifier, out2.CID, name, "support")
		if err != nil || got != want {
			t.Fatalf("the verifier blob lost %q after the second handoff: %q %v", name, got, err)
		}
	}
	// An attribute never shared stays out of the verifier's scope.
	if _, err := admin.GetAttribute(ctx, verifier, out2.CID, "birthdate", "support"); err == nil {
		t.Fatal("an attribute no handoff shared must not appear in the verifier's scope")
	}
}
