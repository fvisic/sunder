package service_test

// Direct service-level tests for branches the HTTP layer never reaches:
// scoped-CID issuance guard rails, attribute-share edge cases, verify
// negatives, retention wipes and idempotent migrations.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/service"
)

func TestIssueScopedCidGuardsAndSuccess(t *testing.T) {
	e := newFaultEnv(t) // no denials: fully privileged role
	ctx := context.Background()
	cid := e.register(t)

	noPerm := &auth.Client{ID: "np", Scope: "crm"}
	if _, err := e.svc.IssueScopedCid(ctx, noPerm, cid, "billing"); err != service.ErrForbidden {
		t.Fatalf("missing action must be forbidden: %v", err)
	}
	if _, err := e.svc.IssueScopedCid(ctx, e.crm, cid, ""); err == nil {
		t.Fatal("empty target scope must be rejected")
	}
	if _, err := e.svc.IssueScopedCid(ctx, e.crm, "CID-NOPE", "billing"); err != service.ErrNotFound {
		t.Fatalf("unknown cid: %v", err)
	}
	foreign := *e.crm
	foreign.Scope = "other"
	if _, err := e.svc.IssueScopedCid(ctx, &foreign, cid, "billing"); err != service.ErrNotFound {
		t.Fatalf("foreign-scope cid must be indistinguishable from absent: %v", err)
	}
	got, err := e.svc.IssueScopedCid(ctx, e.crm, cid, "billing")
	if err != nil || got == "" || got == cid {
		t.Fatalf("scoped issue: %q %v", got, err)
	}
	again, err := e.svc.IssueScopedCid(ctx, e.crm, cid, "billing")
	if err != nil || again != got {
		t.Fatalf("scoped issue must be idempotent: %q vs %q, %v", again, got, err)
	}
}

func TestShareIntoScopeEdgeCases(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cid := e.register(t)

	// Requested attribute absent from the issuer blob: nothing shared, no error.
	tok, _, err := e.oti.Issue(ctx, e.crm, cid, "support", "billing", []string{"does-not-exist"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.oti.Verify(ctx, e.verifier(), tok, "support", "billing"); err != nil {
		t.Fatalf("verify with unshareable attribute must still succeed: %v", err)
	}

	// Same-scope verify: issuer and verifier CID coincide, sharing is a no-op.
	sameScope := &auth.Client{ID: "crm2", Scope: "crm",
		AllowedActions:  []string{auth.ActOTIVerify},
		AllowedPurposes: []string{"support"}}
	tok2, _, err := e.oti.Issue(ctx, e.crm, cid, "support", "crm", []string{"tier"})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := e.oti.Verify(ctx, sameScope, tok2, "support", "crm"); err != nil || got != cid {
		t.Fatalf("same-scope verify: %q %v", got, err)
	}

	// Issuer without any PII blob: sharing finds nothing to copy.
	var personID string
	if err := e.admin.Pool.QueryRow(ctx,
		`INSERT INTO persons (id) VALUES (gen_random_uuid()) RETURNING id`).Scan(&personID); err != nil {
		t.Fatal(err)
	}
	blobless := "CID-BLOBLESS0000000000000000AA"
	if _, err := e.admin.Pool.Exec(ctx,
		`INSERT INTO cids (cid, person_id, scope) VALUES ($1,$2,'crm')`, blobless, personID); err != nil {
		t.Fatal(err)
	}
	tok3, _, err := e.oti.Issue(ctx, e.crm, blobless, "support", "billing", []string{"tier"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.oti.Verify(ctx, e.verifier(), tok3, "support", "billing"); err != nil {
		t.Fatalf("verify of blobless issuer must succeed: %v", err)
	}
}

func TestVerifyNegatives(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cid := e.register(t)

	issue := func() string {
		tok, _, err := e.oti.Issue(ctx, e.crm, cid, "support", "billing", nil)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	v := e.verifier()

	if _, err := e.oti.Verify(ctx, v, issue(), "support", "other-audience"); err == nil {
		t.Fatal("audience mismatch must fail")
	}
	if _, err := e.oti.Verify(ctx, v, issue(), "marketing", "billing"); err == nil {
		t.Fatal("purpose mismatch must fail")
	}
	noPurpose := &auth.Client{ID: "b2", Scope: "billing", AllowedActions: []string{auth.ActOTIVerify}}
	if _, err := e.oti.Verify(ctx, noPurpose, issue(), "support", "billing"); err == nil {
		t.Fatal("verifier without the purpose must fail")
	}
	tok := issue()
	if _, err := e.oti.Verify(ctx, v, tok, "support", "billing"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.oti.Verify(ctx, v, tok, "support", "billing"); err == nil {
		t.Fatal("second use must fail (single-use)")
	}
	rev := issue()
	if _, err := e.admin.Pool.Exec(ctx, `UPDATE oti SET status='REVOKED'`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.oti.Verify(ctx, v, rev, "support", "billing"); err == nil {
		t.Fatal("revoked token must fail")
	}
	if _, err := e.oti.Verify(ctx, v, "v4.public.garbage", "support", "billing"); err == nil {
		t.Fatal("malformed token must fail")
	}
}

func TestRunRetentionWipes(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	e.register(t)

	if _, err := e.admin.Pool.Exec(ctx,
		`INSERT INTO retention_policies (scope, contacts_ttl_days) VALUES ('crm', 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.admin.Pool.Exec(ctx,
		`UPDATE cids SET updated_at = now() - interval '10 days'`); err != nil {
		t.Fatal(err)
	}
	wiped, _, err := service.RunRetention(ctx, e.admin.Pool)
	if err != nil || wiped == 0 {
		t.Fatalf("expected wipes: %d %v", wiped, err)
	}
	// Second run: nothing left to wipe.
	wiped, _, err = service.RunRetention(ctx, e.admin.Pool)
	if err != nil || wiped != 0 {
		t.Fatalf("second run must be a no-op: %d %v", wiped, err)
	}
}

func TestDeliverPendingDefaultHTTPClient(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cid := e.register(t)

	// First attempt (the erase-time immediate delivery) fails with 500, the
	// retry from DeliverPending succeeds - covering the stay-PENDING branch
	// and the default (nil-HTTP) hardened client construction.
	var calls int
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(200)
	}))
	defer hook.Close()
	if _, err := e.admin.Pool.Exec(ctx,
		`INSERT INTO webhooks (scope, url, secret) VALUES ('crm', $1, 'sec')`, hook.URL); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.gdpr.Erase(ctx, e.crm, cid); err != nil {
		t.Fatal(err)
	}
	if n, err := e.gdpr.DeliverPending(ctx); err != nil || n != 1 {
		t.Fatalf("retry with default client: %d %v", n, err)
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	e := newFaultEnv(t)
	if err := e.admin.Migrate(context.Background()); err != nil {
		t.Fatalf("re-running migrations must be a no-op: %v", err)
	}
}

func TestIssueGuardsAndEraseTwice(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cid := e.register(t)

	noAct := &auth.Client{ID: "n", Scope: "crm", AllowedPurposes: []string{"support"}}
	if _, _, err := e.oti.Issue(ctx, noAct, cid, "support", "billing", nil); err != service.ErrForbidden {
		t.Fatalf("issue without action: %v", err)
	}
	if _, _, err := e.oti.Issue(ctx, e.crm, cid, "", "billing", nil); err == nil {
		t.Fatal("empty purpose must be rejected")
	}
	if _, _, err := e.oti.Issue(ctx, e.crm, cid, "marketing", "billing", nil); err != service.ErrPurposeNotAllowed {
		t.Fatalf("issue with disallowed purpose: %v", err)
	}
	if _, _, err := e.oti.Issue(ctx, e.crm, "CID-NOPE", "support", "billing", nil); err != service.ErrNotFound {
		t.Fatalf("issue for unknown cid: %v", err)
	}
	// Withdrawn consent blocks issuance.
	if err := e.gdpr.SetConsent(ctx, e.crm, cid, "support", false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.oti.Issue(ctx, e.crm, cid, "support", "billing", nil); err != service.ErrConsentDenied {
		t.Fatalf("withdrawn consent must block issue: %v", err)
	}
	if err := e.gdpr.SetConsent(ctx, e.crm, cid, "support", true); err != nil {
		t.Fatal(err)
	}
	// Verify without the verify action.
	tok, _, err := e.oti.Issue(ctx, e.crm, cid, "support", "billing", nil)
	if err != nil {
		t.Fatal(err)
	}
	noVerify := &auth.Client{ID: "v", Scope: "billing", AllowedPurposes: []string{"support"}}
	if _, err := e.oti.Verify(ctx, noVerify, tok, "support", "billing"); err != service.ErrForbidden {
		t.Fatalf("verify without action: %v", err)
	}

	// Erase, then erase again: the tombstone is not re-erasable.
	if _, _, err := e.gdpr.Erase(ctx, e.crm, cid); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.gdpr.Erase(ctx, e.crm, cid); err == nil {
		t.Fatal("second erase must hit the idempotency guard")
	}
	// GDPR calls without their actions.
	if _, err := e.gdpr.Access(ctx, noAct, cid); err != service.ErrForbidden {
		t.Fatalf("access without action: %v", err)
	}
	if _, err := e.gdpr.Export(ctx, noAct, cid); err != service.ErrForbidden {
		t.Fatalf("export without action: %v", err)
	}
	if _, _, err := e.gdpr.Erase(ctx, noAct, cid); err != service.ErrForbidden {
		t.Fatalf("erase without action: %v", err)
	}
	if err := e.gdpr.SetConsent(ctx, noAct, cid, "support", true); err != service.ErrForbidden {
		t.Fatalf("consent without action: %v", err)
	}
	if _, err := e.gdpr.ListConsents(ctx, noAct, cid); err != service.ErrForbidden {
		t.Fatalf("list consents without action: %v", err)
	}
}

func TestRegisterPluralValidationAndRekeyTokensOnly(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()

	if _, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
		Emails: []string{"ok@example.com", "not-an-email"},
	}); err == nil {
		t.Fatal("invalid plural email must be rejected")
	}
	if _, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
		Phones: []string{"+385911234567", "banana"},
	}); err == nil {
		t.Fatal("invalid plural phone must be rejected")
	}
	if _, err := e.svc.Register(ctx, e.crm, service.RegisterInput{}); err == nil {
		t.Fatal("register with no identifiers must be rejected")
	}

	e.register(t)
	// Token-only rekey (reencryptPII=false) with a tiny batch: multiple sweeps.
	stats, err := e.svc.Rekey(ctx, false, 1)
	if err != nil {
		t.Fatalf("token-only rekey: %+v %v", stats, err)
	}
}

func TestWebhookRedirectIsNotFollowed(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cid := e.register(t)

	// A hostile receiver answering 302 must not steer the signed POST; the
	// delivery counts as failed and the event stays queued.
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer hook.Close()
	if _, err := e.admin.Pool.Exec(ctx,
		`INSERT INTO webhooks (scope, url, secret) VALUES ('crm', $1, 'sec')`, hook.URL); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.gdpr.Erase(ctx, e.crm, cid); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT status FROM erasure_events LIMIT 1`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "PENDING" {
		t.Fatalf("redirected delivery must not count as delivered: %s", status)
	}
}

func TestMigrateOnDeadPool(t *testing.T) {
	e := newFaultEnv(t)
	e.admin.Close()
	if err := e.admin.Migrate(context.Background()); err == nil {
		t.Fatal("migrate on dead pool must error")
	}
}

func TestVerifyAfterSigningKeyRotation(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cid := e.register(t)

	// Warm the verifier-side ring cache on the CURRENT signing key.
	tok, _, err := e.oti.Issue(ctx, e.crm, cid, "support", "billing", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.oti.Verify(ctx, e.verifier(), tok, "support", "billing"); err != nil {
		t.Fatal(err)
	}
	// Rotate the OTI signing key out from under the cached ring.
	adminRing := &service.KeyRing{Pool: e.admin.Pool}
	if _, err := adminRing.Rotate(ctx, e.oti.Eng, "oti-sign"); err != nil {
		t.Fatal(err)
	}
	fresh := e.adminOTI()
	tok2, _, err := fresh.Issue(ctx, e.crm, cid, "support", "billing", nil)
	if err != nil {
		t.Fatal(err)
	}
	// The stale-cached service must refresh on the unknown kid and verify.
	if _, err := e.oti.Verify(ctx, e.verifier(), tok2, "support", "billing"); err != nil {
		t.Fatalf("verify after rotation must refresh the kid cache: %v", err)
	}
}

func TestNewestWithoutActiveVersion(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	if _, err := e.admin.Pool.Exec(ctx, `DELETE FROM keys WHERE kind='hmac-name'`); err != nil {
		t.Fatal(err)
	}
	ring := &service.KeyRing{Pool: e.admin.Pool}
	if _, err := ring.Newest(ctx, "hmac-name"); err == nil {
		t.Fatal("kind without an ACTIVE version must error")
	}
}

// erasePerson branches: a person whose scopes hold no blob still erases
// cleanly, and the erasure is recorded once per scope.
func TestErasePersonWithoutBlobs(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	var personID string
	if err := e.admin.Pool.QueryRow(ctx,
		`INSERT INTO persons (id) VALUES (gen_random_uuid()) RETURNING id`).Scan(&personID); err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{"crm", "billing"} {
		if _, err := e.admin.Pool.Exec(ctx,
			`INSERT INTO cids (cid, person_id, scope) VALUES ($1,$2,$3)`,
			"CID-EMPTY"+scope+"000000000000000", personID, scope); err != nil {
			t.Fatal(err)
		}
	}
	id, scopes, err := e.gdpr.Erase(ctx, e.crm, "CID-EMPTYcrm000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	if id == 0 || scopes != 2 {
		t.Fatalf("erasure must cover every scope: id=%d scopes=%d", id, scopes)
	}
	var events int
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM erasure_events WHERE erasure_id=$1`, id).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 2 {
		t.Fatalf("one event per scope expected, got %d", events)
	}
}

// TestNameNarrowingUsesItsOwnIndex covers the access path that migration
// 0020 moved. Names are deliberately excluded from person_tokens_ident_uq
// (a name is shared by many people and only ever narrows), so when the
// redundant catch-all index went away the name path had to keep an index
// of its own. Without one it degrades to scanning every name row with the
// token as a filter, which stays correct and therefore stays invisible to
// every other test in this suite.
func TestNameNarrowingUsesItsOwnIndex(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cid := e.register(t) // fault@example.com / "Fault Case"

	// Name plus the matching e-mail resolves to the same person.
	got, err := e.svc.Lookup(ctx, e.crm, service.LookupInput{
		Email: "fault@example.com", Name: "Fault Case"})
	if err != nil {
		t.Fatalf("name narrowing must resolve: %v", err)
	}
	if got != cid {
		t.Fatalf("name narrowing returned %q, want %q", got, cid)
	}

	// A name that does not belong to that person must NOT resolve: the
	// narrowing has to actually narrow, not be silently ignored.
	if _, err := e.svc.Lookup(ctx, e.crm, service.LookupInput{
		Email: "fault@example.com", Name: "Someone Else"}); err != service.ErrNotFound {
		t.Fatalf("non-matching name must narrow to nothing, got %v", err)
	}

	// And the query the new partial index serves must be planned through
	// an index, not a filter over every name row.
	var plan string
	rows, err := e.admin.Pool.Query(ctx,
		`EXPLAIN SELECT person_id FROM person_tokens WHERE kind='name' AND token = ANY($1)`,
		[]string{"probe"})
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		plan += line + "\n"
	}
	if !strings.Contains(plan, "person_tokens_search_idx") {
		t.Fatalf("name lookup no longer uses its index:\n%s", plan)
	}
}

// TestShareIntoScopeShortCircuits pins the two cheap-exit branches of the
// attribute-share merge: sharing with yourself is a no-op (same CID on
// both sides), and sharing FROM a scope whose blob is empty (a cid minted
// by scopes.issue carries no attributes) shares nothing rather than
// failing the verify.
func TestShareIntoScopeShortCircuits(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cid := e.register(t)

	// Same scope on both ends: issuer CID == verifier CID.
	tok, _, err := e.oti.Issue(ctx, e.crm, cid, "support", "crm", []string{"tier"})
	if err != nil {
		t.Fatal(err)
	}
	out, err := e.oti.VerifyFull(ctx, e.crm, tok, "support", "crm")
	if err != nil {
		t.Fatalf("self-audience verify: %v", err)
	}
	if len(out.Shared) != 0 {
		t.Fatalf("sharing with yourself must be a no-op, shared %v", out.Shared)
	}

	// Issue FROM the billing scope, whose CID was minted by scopes.issue
	// and holds no blob: nothing to share, verify still succeeds.
	billingCID, err := e.svc.IssueScopedCid(ctx, e.crm, cid, "billing")
	if err != nil {
		t.Fatal(err)
	}
	billing := &auth.Client{ID: "billing", Scope: "billing",
		AllowedActions:  []string{auth.ActOTIIssue, auth.ActOTIVerify},
		AllowedPurposes: []string{"support"}}
	tok2, _, err := e.oti.Issue(ctx, billing, billingCID, "support", "crm", []string{"tier"})
	if err != nil {
		t.Fatal(err)
	}
	out2, err := e.oti.VerifyFull(ctx, e.crm, tok2, "support", "crm")
	if err != nil {
		t.Fatalf("verify with empty issuer blob: %v", err)
	}
	if len(out2.Shared) != 0 {
		t.Fatalf("an empty issuer blob must share nothing, shared %v", out2.Shared)
	}
}
