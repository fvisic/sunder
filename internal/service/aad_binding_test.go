package service_test

// CRYPTO-4 / CRYPTO-5: the associated data must name what the ciphertext is
// FOR, so a database-write attacker cannot re-point it. Both are the same
// adversary the file-DEK AAD (files.go) and the PII blob AAD already assume.

import (
	"context"
	"testing"

	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/service"
)

// A value token repointed at another person (or unbound) must stop opening,
// instead of surviving the subject's erasure and still disclosing.
func TestValueTokenAADBindsTheSubject(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cid := e.register(t)

	vt := &service.ValueTokens{Pool: e.svc.Pool, Eng: e.oti.Eng, Ring: e.svc.Ring, Tok: e.svc.Tok}
	client := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions:  []string{auth.ActTokensCreate, auth.ActTokensRead},
		AllowedPurposes: []string{"support"}}

	token, err := vt.Tokenize(ctx, client, service.TokenizeInput{
		Type: "string", Value: "HR1210010051863000160", CID: cid})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := vt.Detokenize(ctx, client, token); err != nil || got != "HR1210010051863000160" {
		t.Fatalf("precondition: %q %v", got, err)
	}

	// The edit that used to hide the row from the erasure sweep while
	// leaving the ciphertext readable.
	if _, err := e.admin.Pool.Exec(ctx,
		`UPDATE value_tokens SET cid=NULL WHERE token=$1`, token); err != nil {
		t.Fatal(err)
	}
	if got, err := vt.Detokenize(ctx, client, token); err == nil {
		t.Fatalf("a value token unbound from its subject must not open, got %q", got)
	}

	// The same for a repoint at another person in the same scope.
	other, err := e.svc.Register(ctx, e.crm, service.RegisterInput{Email: "other-aad@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.admin.Pool.Exec(ctx,
		`UPDATE value_tokens SET cid=$2 WHERE token=$1`, token, other); err != nil {
		t.Fatal(err)
	}
	if got, err := vt.Detokenize(ctx, client, token); err == nil {
		t.Fatalf("a value token repointed at another person must not open, got %q", got)
	}
}

// A historical generation must not be transplantable over the live blob.
func TestVersionBlobIsNotInterchangeableWithLive(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()

	adminRing := &service.KeyRing{Pool: e.admin.Pool, RetireGrace: -1}
	admin := &service.Contacts{Pool: e.admin.Pool, Tok: e.svc.Tok, PII: e.svc.PII,
		Ring: adminRing, VersionsKeep: 3}
	crm := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions: []string{auth.ActContactsRegister, auth.ActAttributesRead,
			auth.ActAttributesHistory},
		AllowedPurposes: []string{"support"}}

	cid, err := admin.Register(ctx, crm, service.RegisterInput{
		Email: "rollback@example.com", Attributes: map[string]string{"address": "old"}})
	if err != nil {
		t.Fatal(err)
	}
	// A rectification: the old generation is snapshotted as version 1.
	if _, err := admin.Register(ctx, crm, service.RegisterInput{
		Email: "rollback@example.com", Attributes: map[string]string{"address": "new"}}); err != nil {
		t.Fatal(err)
	}
	if got, err := admin.GetAttribute(ctx, crm, cid, "address", "support"); err != nil || got != "new" {
		t.Fatalf("precondition: %q %v", got, err)
	}
	// History still reads correctly through its own path.
	if got, err := admin.GetVersionAttribute(ctx, crm, cid, 1, "address", "support"); err != nil || got != "old" {
		t.Fatalf("version read must still work: %q %v", got, err)
	}

	// The attack: transplant the snapshot over the live row, key id and alg
	// included, to roll the rectification back.
	if _, err := e.admin.Pool.Exec(ctx, `
		UPDATE cids c SET pii_encrypted = v.blob, pii_key_id = v.key_id, pii_alg = v.alg
		  FROM cid_blob_versions v
		 WHERE v.cid = c.cid AND v.version_no = 1 AND c.cid = $1`, cid); err != nil {
		t.Fatal(err)
	}
	got, err := admin.GetAttribute(ctx, crm, cid, "address", "support")
	if err == nil {
		t.Fatalf("a transplanted version blob must fail to open, got %q", got)
	}
}
