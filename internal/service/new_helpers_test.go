package service_test

// Direct coverage for the helpers the review's fixes introduced. Several are
// only reachable from a background worker or an operator command, so without
// these they were shipping untested - which is the exact failure mode
// several of the findings were about.

import (
	"context"
	"testing"
	"time"

	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/crypto"
	"github.com/fvisic/sunder/internal/service"
)

// ErasureQueueDepth feeds the two gauges the erasure alerts fire on, so a
// wrong number there is a silent alarm.
func TestErasureQueueDepthCountsBothStates(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	seedEvents(t, e, "http://127.0.0.1:1/never", 3)

	sending, failed, err := service.ErasureQueueDepth(ctx, e.admin.Pool)
	if err != nil {
		t.Fatal(err)
	}
	if sending != 0 || failed != 0 {
		t.Fatalf("a fresh queue is neither sending nor failed: %d/%d", sending, failed)
	}
	if _, err := e.admin.Pool.Exec(ctx,
		`UPDATE erasure_events SET status='SENDING', claimed_at=now() WHERE id=(SELECT min(id) FROM erasure_events)`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.admin.Pool.Exec(ctx,
		`UPDATE erasure_events SET status='FAILED' WHERE id=(SELECT max(id) FROM erasure_events)`); err != nil {
		t.Fatal(err)
	}
	sending, failed, err = service.ErasureQueueDepth(ctx, e.admin.Pool)
	if err != nil {
		t.Fatal(err)
	}
	if sending != 1 || failed != 1 {
		t.Fatalf("expected 1 sending + 1 failed, got %d/%d", sending, failed)
	}
}

// The FAILED transition: an endpoint that never answers must stop being
// retried, with an audited terminal record naming the scope.
func TestDeliveryGivesUpWithAnAuditedRecord(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	e.gdpr.MaxAttempts = 2
	seedEvents(t, e, "http://127.0.0.1:1/never", 1)

	for i := 0; i < 3; i++ {
		if _, err := e.gdpr.DeliverPending(ctx); err != nil {
			t.Fatal(err)
		}
	}
	var status string
	var attempts int
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT status, attempts FROM erasure_events`).Scan(&status, &attempts); err != nil {
		t.Fatal(err)
	}
	if status != "FAILED" {
		t.Fatalf("an unreachable endpoint must reach the attempts cap, got %s after %d attempts", status, attempts)
	}
	var audited int
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM audit WHERE action='dsr.erase.failed'`).Scan(&audited); err != nil {
		t.Fatal(err)
	}
	if audited != 1 {
		t.Fatalf("the terminal transition must be audited exactly once, got %d", audited)
	}
	// A FAILED row is terminal: no reaper and no sweep touches it again.
	if n, err := service.ReapStrandedErasureEvents(ctx, e.admin.Pool, time.Nanosecond); err != nil || n != 0 {
		t.Fatalf("the reaper must not resurrect a FAILED row: %d %v", n, err)
	}
}

// The retire reference check across every pii-kek-sealed store, and the
// hmac-value branch of referencesFor.
func TestReferencedKEKStoresNamesEveryHolder(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	e.register(t) // a cids blob under pii-kek/v1

	refs, err := service.ReferencedKEKStores(ctx, e.admin.Pool, "v1")
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) == 0 {
		t.Fatal("a live blob must make v1 referenced")
	}
	found := false
	for _, r := range refs {
		if r == "cids" {
			found = true
		}
	}
	if !found {
		t.Fatalf("cids must be named as a holder, got %v", refs)
	}
	// A version nothing was ever written under is free.
	refs, err = service.ReferencedKEKStores(ctx, e.admin.Pool, "v99")
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 0 {
		t.Fatalf("an unused version must be unreferenced, got %v", refs)
	}
}

// The legacy AAD layout must keep opening pre-migration rows, and the two
// layouts must never collide.
func TestLegacyValueTokenAADStillOpens(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cid := e.register(t)

	vt := &service.ValueTokens{Pool: e.admin.Pool, Eng: e.oti.Eng, Ring: e.svc.Ring, Tok: e.svc.Tok}
	client := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions:  []string{auth.ActTokensCreate, auth.ActTokensRead},
		AllowedPurposes: []string{"support"}}
	token, err := vt.Tokenize(ctx, client, service.TokenizeInput{
		Type: "string", Value: "legacy-value", CID: cid})
	if err != nil {
		t.Fatal(err)
	}
	// Rewrite the row the way it looked before migration 0038: sealed under
	// the legacy AAD, aad_v = 1.
	legacy, err := e.oti.Eng.Seal(ctx, crypto.KeyPIIKEK+"/v1", crypto.AlgAES256GCM,
		[]byte("valtok\x00crm\x00"+token), []byte("legacy-value"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.admin.Pool.Exec(ctx,
		`UPDATE value_tokens SET ciphertext=$2, key_id='v1', alg='aes256gcm', aad_v=1 WHERE token=$1`,
		token, legacy); err != nil {
		t.Fatal(err)
	}
	got, err := vt.Detokenize(ctx, client, token)
	if err != nil || got != "legacy-value" {
		t.Fatalf("a pre-migration row must keep opening under its own layout: %q %v", got, err)
	}
	// ...and the rekey sweep converges it onto the subject-bound layout.
	adminRing := &service.KeyRing{Pool: e.admin.Pool, RetireGrace: -1}
	admin := &service.Contacts{Pool: e.admin.Pool, Tok: e.svc.Tok, PII: e.svc.PII, Ring: adminRing}
	if _, err := admin.Rekey(ctx, true, 100); err != nil {
		t.Fatal(err)
	}
	var aadV int16
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT aad_v FROM value_tokens WHERE token=$1`, token).Scan(&aadV); err != nil {
		t.Fatal(err)
	}
	if aadV != 2 {
		t.Fatalf("the sweep must converge the AAD layout, got v%d", aadV)
	}
	if got, err := vt.Detokenize(ctx, client, token); err != nil || got != "legacy-value" {
		t.Fatalf("the converted row must still open: %q %v", got, err)
	}
}

// lockPersonRows is the lock prefix every person-scoped writer now takes.
// Its refusal branches are what make an unknown cid, a foreign-scope cid and
// a tombstone one indistinguishable answer.
func TestLockPersonRowsRefusalBranches(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cid := e.register(t)

	// A cid that does not exist: the consent writer (which takes the lock
	// first) must answer like any other cid-addressed path.
	if err := e.gdpr.SetConsent(ctx, e.crm, "CID-DOESNOTEXIST0000000000", "support", true); err == nil {
		t.Error("an unknown cid must be refused")
	}
	// A malformed one, same answer, no 500.
	if err := e.gdpr.SetConsent(ctx, e.crm, "not-a-cid", "support", true); err == nil {
		t.Error("a malformed cid must be refused")
	}
	// A live one works, so the guard is not simply refusing everything.
	if err := e.gdpr.SetConsent(ctx, e.crm, cid, "support", true); err != nil {
		t.Fatalf("a live person must still be writable: %v", err)
	}
	// And a database failure surfaces rather than being read as a
	// tombstone: "we could not check" must never answer like "erased".
	denied := newFaultEnv(t, "persons")
	deniedCID := denied.register(t)
	if err := denied.gdpr.SetConsent(ctx, denied.crm, deniedCID, "support", true); err == nil {
		t.Error("a database failure must surface, not read as 'not found'")
	}
}
