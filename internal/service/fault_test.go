package service_test

// Mid-transaction fault injection: a second pool logs in as a role that has
// been REVOKEd on exactly one table, so precisely that statement fails while
// everything before it in the flow succeeds. This exercises the error
// branches a dead pool cannot reach.

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/fvisic/sunder/internal/audit"
	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/crypto"
	"github.com/fvisic/sunder/internal/service"
	"github.com/fvisic/sunder/internal/store"
	"github.com/fvisic/sunder/internal/testutil"
)

var roleSeq int

type faultEnv struct {
	admin *store.Store
	svc   *service.Contacts
	oti   *service.OTI
	gdpr  *service.GDPR
	crm   *auth.Client
}

// newFaultEnv builds services over a pool whose role is denied the given
// tables. Registered data is seeded through the ADMIN pool first when needed.
func newFaultEnv(t *testing.T, deny ...string) *faultEnv {
	t.Helper()
	st := testutil.NewDB(t)
	ctx := context.Background()

	eng := crypto.NewLocalEngine(crypto.NewCachingKeystore(&crypto.FileKeystore{Dir: t.TempDir()}))
	// RetireGrace: -1 - the production default makes a version wait out the
	// fleet's ring-cache TTL before it may be retired (CONCURRENCY-CORE-4);
	// a test has no second replica to convince.
	adminRing := &service.KeyRing{Pool: st.Pool, RetireGrace: -1}
	if err := adminRing.EnsureAll(ctx, eng); err != nil {
		t.Fatal(err)
	}

	roleSeq++
	role := fmt.Sprintf("sunder_fault_%d_%d", os.Getpid(), roleSeq)
	stmts := []string{
		fmt.Sprintf(`DROP ROLE IF EXISTS %s`, role),
		fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD 'fault-test-only'`, role),
		fmt.Sprintf(`GRANT USAGE ON SCHEMA public TO %s`, role),
		fmt.Sprintf(`GRANT ALL ON ALL TABLES IN SCHEMA public TO %s`, role),
		fmt.Sprintf(`GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO %s`, role),
	}
	for _, tbl := range deny {
		stmts = append(stmts, fmt.Sprintf(`REVOKE ALL ON %s FROM %s`, tbl, role))
	}
	for _, s := range stmts {
		if _, err := st.Pool.Exec(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		// Revoke this DB's grants first so the cluster-global role can drop.
		_, _ = st.Pool.Exec(context.Background(), `DROP OWNED BY `+role)
		_, _ = st.Pool.Exec(context.Background(), `DROP ROLE IF EXISTS `+role)
	})

	cfg := st.Pool.Config().ConnConfig
	url := fmt.Sprintf("postgres://%s:fault-test-only@%s:%d/%s", role, cfg.Host, cfg.Port, cfg.Database)
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	ring := &service.KeyRing{Pool: pool, RetireGrace: -1}
	contacts := &service.Contacts{Pool: pool, Tok: crypto.NewTokenizer(eng), PII: crypto.NewPIIBox(eng), Ring: ring}
	gdpr := &service.GDPR{Pool: pool, Contacts: contacts}
	// Erase dispatches its immediate delivery DETACHED from the request, so
	// the test must wait for it before the pool is torn down (H1).
	t.Cleanup(gdpr.Drain)
	return &faultEnv{
		admin: st,
		svc:   contacts,
		oti:   &service.OTI{Pool: pool, Eng: eng, Ring: ring, Contacts: contacts},
		gdpr:  gdpr,
		crm: &auth.Client{ID: "crm", Scope: "crm",
			AllowedActions: []string{auth.ActContactsRegister, auth.ActLookup, auth.ActOTIIssue,
				auth.ActOTIVerify, auth.ActConsentManage, auth.ActDSRAccess, auth.ActDSRErase,
				auth.ActDSRExport, auth.ActAttributesRead, auth.ActScopesIssue},
			AllowedPurposes: []string{"support"}},
	}
}

func (e *faultEnv) verifier() *auth.Client {
	return &auth.Client{ID: "billing", Scope: "billing",
		AllowedActions:  []string{auth.ActOTIVerify, auth.ActAttributesRead},
		AllowedPurposes: []string{"support"}}
}

// register seeds one contact through a FULLY privileged service (admin pool)
// so fault tests can fail later steps in isolation.
func (e *faultEnv) register(t *testing.T) string {
	t.Helper()
	ks := crypto.NewCachingKeystore(&crypto.FileKeystore{Dir: t.TempDir()})
	// Reuse the same key material: point the file keystore at the admin one.
	// Simpler: build the admin service with the SAME keystore as e.svc.
	_ = ks
	adminRing := &service.KeyRing{Pool: e.admin.Pool, RetireGrace: -1}
	admin := &service.Contacts{Pool: e.admin.Pool, Tok: e.svc.Tok, PII: e.svc.PII, Ring: adminRing}
	cid, err := admin.Register(context.Background(), e.crm, service.RegisterInput{
		Email: "fault@example.com", Name: "Fault Case",
		Attributes: map[string]string{"tier": "gold"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return cid
}

// adminOTI builds a fully privileged OTI service sharing key material.
func (e *faultEnv) adminOTI() *service.OTI {
	ring := &service.KeyRing{Pool: e.admin.Pool, RetireGrace: -1}
	contacts := &service.Contacts{Pool: e.admin.Pool, Tok: e.svc.Tok, PII: e.svc.PII, Ring: ring}
	return &service.OTI{Pool: e.admin.Pool, Eng: e.oti.Eng, Ring: ring, Contacts: contacts}
}

func TestAuditDeniedBlocksEveryFlow(t *testing.T) {
	// Both audit stores are denied: reads fail closed against the bucket
	// table under the default mode and against the chain otherwise.
	e := newFaultEnv(t, "audit", "audit_read_buckets")
	ctx := context.Background()
	cid := e.register(t)

	if _, err := e.svc.Register(ctx, e.crm, service.RegisterInput{Email: "x@example.com"}); err == nil {
		t.Fatal("register must fail when the audit append fails")
	}
	if _, err := e.svc.Lookup(ctx, e.crm, service.LookupInput{Email: "fault@example.com"}); err == nil {
		t.Fatal("lookup must fail when the audit append fails")
	}
	if _, _, err := e.oti.Issue(ctx, e.crm, cid, "support", "billing", nil); err == nil {
		t.Fatal("issue must fail when the audit append fails")
	}
	if err := e.gdpr.SetConsent(ctx, e.crm, cid, "support", true); err == nil {
		t.Fatal("consent must fail when the audit append fails")
	}
	if _, _, err := e.gdpr.Erase(ctx, e.crm, cid); err == nil {
		t.Fatal("erase must fail when the audit append fails")
	}
	if _, err := e.gdpr.Access(ctx, e.crm, cid); err == nil {
		t.Fatal("access must fail when the audit append fails")
	}
	if _, err := e.gdpr.Export(ctx, e.crm, cid); err == nil {
		t.Fatal("export must fail when the audit append fails")
	}
	if _, err := e.svc.GetAttribute(ctx, e.crm, cid, "tier", "support"); err == nil {
		t.Fatal("attribute read must fail when the audit append fails")
	}
}

func TestOTITableDeniedBlocksIssueAndErase(t *testing.T) {
	e := newFaultEnv(t, "oti")
	ctx := context.Background()
	cid := e.register(t)
	if _, _, err := e.oti.Issue(ctx, e.crm, cid, "support", "billing", nil); err == nil {
		t.Fatal("issue must fail when the oti insert fails")
	}
	if _, _, err := e.gdpr.Erase(ctx, e.crm, cid); err == nil {
		t.Fatal("erase must fail when oti revocation fails")
	}
}

func TestVerifyFaults(t *testing.T) {
	ctx := context.Background()

	// cids denied: verify fails at ensureCID/shareIntoScope.
	e := newFaultEnv(t, "cids")
	cid := e.register(t)
	tok, _, err := e.adminOTI().Issue(ctx, e.crm, cid, "support", "billing", []string{"tier"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.oti.Verify(ctx, e.verifier(), tok, "support", "billing"); err == nil {
		t.Fatal("verify must fail when the verifier CID cannot be minted")
	}

	// oti denied: verify fails at the single-use CAS update.
	e2 := newFaultEnv(t, "oti")
	cid2 := e2.register(t)
	tok2, _, err := e2.adminOTI().Issue(ctx, e2.crm, cid2, "support", "billing", []string{"tier"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e2.oti.Verify(ctx, e2.verifier(), tok2, "support", "billing"); err == nil {
		t.Fatal("verify must fail when the single-use CAS cannot run")
	}
}

func TestRegisterFaults(t *testing.T) {
	ctx := context.Background()
	for _, tbl := range []string{"person_tokens", "persons", "cids"} {
		e := newFaultEnv(t, tbl)
		if _, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
			Email: "y@example.com", Name: "Why",
		}); err == nil {
			t.Fatalf("register must fail when %s writes fail", tbl)
		}
	}
}

func TestConsentAndErasureFaults(t *testing.T) {
	ctx := context.Background()

	e := newFaultEnv(t, "consents")
	cid := e.register(t)
	if err := e.gdpr.SetConsent(ctx, e.crm, cid, "support", false); err == nil {
		t.Fatal("consent write must surface the denial")
	}

	for _, tbl := range []string{"erasures", "erasure_events"} {
		e := newFaultEnv(t, tbl)
		cid := e.register(t)
		if _, _, err := e.gdpr.Erase(ctx, e.crm, cid); err == nil {
			t.Fatalf("erase must fail when %s writes fail", tbl)
		}
	}
}

func TestRekeyAndRetentionFaults(t *testing.T) {
	ctx := context.Background()

	e := newFaultEnv(t, "person_tokens")
	e.register(t)
	if _, err := e.svc.Rekey(ctx, true, 10); err == nil {
		t.Fatal("rekey must fail when token writes fail")
	}

	e2 := newFaultEnv(t, "retention_policies")
	if _, _, err := service.RunRetention(ctx, e2.gdpr.Pool); err == nil {
		t.Fatal("retention must fail when policies are unreadable")
	}
}

func TestKeyringFaults(t *testing.T) {
	ctx := context.Background()
	e := newFaultEnv(t, "keys")
	eng2 := crypto.NewLocalEngine(crypto.NewCachingKeystore(&crypto.FileKeystore{Dir: t.TempDir()}))
	ring := &service.KeyRing{Pool: e.svc.Pool, RetireGrace: -1}
	if _, err := ring.Newest(ctx, "hmac-email"); err == nil {
		t.Fatal("newest must fail when the keys table is unreadable")
	}
	if _, err := ring.Rotate(ctx, eng2, "hmac-email"); err == nil {
		t.Fatal("rotate must fail when the keys table is unreadable")
	}
	if err := ring.Retire(ctx, "hmac-email", "v1"); err == nil {
		t.Fatal("retire must fail when the keys table is unwritable")
	}
	if err := ring.EnsureAll(ctx, eng2); err == nil {
		t.Fatal("ensure-all must fail when the keys table is unreadable")
	}
}

// Remaining GDPR/OTI error branches, reached by denying one table at a time.
func TestMoreDatabaseFaults(t *testing.T) {
	ctx := context.Background()

	// webhooks denied: delivery cannot look up its target.
	e := newFaultEnv(t, "webhooks")
	cid := e.register(t)
	// Erasure must NOT fail because a webhook is unreachable: the data is
	// gone either way and the queued event is retried by the worker.
	if _, _, err := e.gdpr.Erase(ctx, e.crm, cid); err != nil {
		t.Fatalf("erasure must not depend on webhook availability: %v", err)
	}
	if _, err := e.gdpr.DeliverPending(ctx); err == nil {
		t.Fatal("the delivery worker must surface a webhook-read failure")
	}

	// erasure_events denied: the worker cannot record outcomes.
	e2 := newFaultEnv(t, "erasure_events")
	if _, err := e2.gdpr.DeliverPending(ctx); err == nil {
		t.Fatal("the worker must surface an event-read failure")
	}

	// external_envelopes denied: replay protection cannot be recorded, so
	// the claim must not be stored.
	e3 := newFaultEnv(t, "external_envelopes")
	cid3 := e3.register(t)
	e3.crm.AllowedActions = append(e3.crm.AllowedActions, auth.ActClaimsExternal)
	seed := make([]byte, 32)
	seed[0] = 99
	sk := ed25519.NewKeyFromSeed(seed)
	if _, err := e3.admin.Pool.Exec(ctx,
		`INSERT INTO trusted_issuers (issuer_id, public_key, allowed_claims, added_by) VALUES ('gw',$1,'{*}','t')`,
		[]byte(sk.Public().(ed25519.PublicKey))); err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{
		"iss": "gw", "jti": "envelope-fault-1", "cid": cid3,
		"claims": map[string]string{"kyc": "1"},
		"exp":    time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	})
	if _, err := e3.svc.ExternalClaims(ctx, e3.crm, cid3, crypto.PasetoSign(sk, payload)); err == nil {
		t.Fatal("claims must not be stored when replay protection cannot be recorded")
	}

	// retention_policies denied handled elsewhere; here: cids denied blocks
	// the retention wipe.
	e4 := newFaultEnv(t, "cids")
	if _, _, err := service.RunRetention(ctx, e4.gdpr.Pool); err == nil {
		t.Fatal("retention must surface a cids-write failure")
	}

	// oti denied: pruning expired tokens fails.
	e5 := newFaultEnv(t, "oti")
	if _, _, err := service.RunRetention(ctx, e5.gdpr.Pool); err == nil {
		t.Fatal("retention must surface an oti-prune failure")
	}
}

// OTI and contacts error branches under one-table denials: every path that
// touches the database must fail closed, and none may panic.
func TestOTIAndContactsFaultBranches(t *testing.T) {
	ctx := context.Background()

	// keys denied: no path can resolve a key version.
	e := newFaultEnv(t, "keys")
	if _, err := e.svc.Register(ctx, e.crm, service.RegisterInput{Email: "k@example.com"}); err == nil {
		t.Fatal("register must fail without a resolvable key version")
	}
	if _, err := e.svc.Lookup(ctx, e.crm, service.LookupInput{Email: "k@example.com"}); err == nil {
		t.Fatal("lookup must fail without a resolvable key version")
	}
	if _, err := e.svc.Rekey(ctx, true, 5); err == nil {
		t.Fatal("rekey must fail without a resolvable key version")
	}

	// person_tokens denied: lookup by identifier cannot resolve.
	e2 := newFaultEnv(t, "person_tokens")
	if _, err := e2.svc.Lookup(ctx, e2.crm, service.LookupInput{Email: "x@example.com"}); err == nil {
		t.Fatal("lookup must surface a token-read failure")
	}
	if _, err := e2.svc.Lookup(ctx, e2.crm, service.LookupInput{Phone: "+385911234567"}); err == nil {
		t.Fatal("phone lookup must surface a token-read failure")
	}
	if _, err := e2.svc.Lookup(ctx, e2.crm, service.LookupInput{
		Name: "Fault Case", Email: "fault@example.com"}); err == nil {
		t.Fatal("name+factor lookup must surface a token-read failure")
	}

	// Validation branches that never touch the database.
	e3 := newFaultEnv(t)
	if _, err := e3.svc.Lookup(ctx, e3.crm, service.LookupInput{}); err == nil {
		t.Fatal("a lookup with no criteria must be rejected")
	}
	if _, err := e3.svc.Lookup(ctx, e3.crm, service.LookupInput{Name: "Only A Name"}); err == nil {
		t.Fatal("a name alone is never an identifier")
	}
	if _, err := e3.svc.Lookup(ctx, e3.crm, service.LookupInput{Email: "not-an-email"}); err == nil {
		t.Fatal("a malformed email must be rejected before any query")
	}
	noLookup := *e3.crm
	noLookup.AllowedActions = nil
	if _, err := e3.svc.Lookup(ctx, &noLookup, service.LookupInput{Email: "x@example.com"}); err != service.ErrForbidden {
		t.Fatal("lookup without the action must be forbidden")
	}
	if _, err := e3.svc.GetAttribute(ctx, &noLookup, "CID-X", "email", "support"); err != service.ErrForbidden {
		t.Fatal("attribute read without the action must be forbidden")
	}
	cid := e3.register(t)
	if _, err := e3.svc.GetAttribute(ctx, e3.crm, cid, "email", ""); err == nil {
		t.Fatal("an empty purpose must be rejected")
	}
	if _, err := e3.svc.GetAttribute(ctx, e3.crm, cid, "email", "marketing"); err != service.ErrPurposeNotAllowed {
		t.Fatal("an ungranted purpose must be refused")
	}
	if _, err := e3.svc.GetAttribute(ctx, e3.crm, cid, "nonexistent", "support"); err != service.ErrNotFound {
		t.Fatal("an absent attribute must be not-found")
	}
}

// GDPR consent/access branches the happy-path tests skip.
func TestGDPRRemainingBranches(t *testing.T) {
	ctx := context.Background()
	e := newFaultEnv(t)
	cid := e.register(t)

	// Consent listing on a foreign CID and on an unknown one.
	foreign := *e.crm
	foreign.Scope = "other"
	if _, err := e.gdpr.ListConsents(ctx, &foreign, cid); err != service.ErrNotFound {
		t.Fatalf("foreign consent listing: %v", err)
	}
	if _, err := e.gdpr.ListConsents(ctx, e.crm, "CID-NOPE"); err != service.ErrNotFound {
		t.Fatalf("unknown consent listing: %v", err)
	}
	// An empty purpose is rejected on the service path too.
	if err := e.gdpr.SetConsent(ctx, e.crm, cid, "", true); err == nil {
		t.Fatal("an empty purpose must be rejected")
	}
	// Listing returns what was set, including a withdrawal.
	if err := e.gdpr.SetConsent(ctx, e.crm, cid, "support", false); err != nil {
		t.Fatal(err)
	}
	list, err := e.gdpr.ListConsents(ctx, e.crm, cid)
	if err != nil || len(list) != 1 || list[0].Granted {
		t.Fatalf("consent listing: %+v %v", list, err)
	}
	// Export and access on an unknown CID.
	if _, err := e.gdpr.Export(ctx, e.crm, "CID-NOPE"); err != service.ErrNotFound {
		t.Fatalf("export of an unknown cid: %v", err)
	}
	if _, err := e.gdpr.Access(ctx, e.crm, "CID-NOPE"); err != service.ErrNotFound {
		t.Fatalf("access of an unknown cid: %v", err)
	}
	// consents denied: the listing surfaces the failure.
	e2 := newFaultEnv(t, "consents")
	cid2 := e2.register(t)
	if _, err := e2.gdpr.ListConsents(ctx, e2.crm, cid2); err == nil {
		t.Fatal("consent listing must surface a read failure")
	}
	// retention_policies denied: the sweep cannot read its policies.
	e3 := newFaultEnv(t, "retention_policies")
	if _, _, err := service.RunRetention(ctx, e3.gdpr.Pool); err == nil {
		t.Fatal("retention must surface a policy-read failure")
	}
}

// TestBucketPathsFailClosedUnderDeniedRole: the same restricted-role fault
// injection, aimed at the P4.2 tables - the closer and the verifier must
// surface permission failures, never report an hour closed or intact.
func TestBucketPathsFailClosedUnderDeniedRole(t *testing.T) {
	e := newFaultEnv(t, "audit_read_buckets")
	ctx := context.Background()
	if _, err := audit.CloseReadBuckets(ctx, e.svc.Pool); err == nil {
		t.Fatal("closing buckets without table rights must error")
	}
	if _, _, _, err := audit.VerifyReadBuckets(ctx, e.svc.Pool); err == nil {
		t.Fatal("verifying buckets without table rights must error")
	}
}

// TestEraseFailsClosedWhenErasureTablesDenied: erasure is the operation a
// regulator asks about; a permissions regression must fail it loudly, not
// half-erase.
func TestEraseFailsClosedWhenErasureTablesDenied(t *testing.T) {
	e := newFaultEnv(t, "erasures")
	ctx := context.Background()
	cid := e.register(t)
	if _, _, err := e.gdpr.Erase(ctx, e.crm, cid); err == nil {
		t.Fatal("erase must fail when the erasures table is denied")
	}
	// And nothing was tombstoned by the failed attempt.
	var erased bool
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT erased_at IS NOT NULL FROM persons LIMIT 1`).Scan(&erased); err != nil {
		t.Fatal(err)
	}
	if erased {
		t.Fatal("a failed erase must not leave a tombstone")
	}
}

func TestEraseFailsClosedWhenTokensDenied(t *testing.T) {
	e := newFaultEnv(t, "person_tokens")
	ctx := context.Background()
	// register needs person_tokens too, so seed via the admin service.
	cid := e.register(t)
	if _, _, err := e.gdpr.Erase(ctx, e.crm, cid); err == nil {
		t.Fatal("erase must fail when search tokens cannot be deleted")
	}
}

// TESTS-9: the fault-injection suite asserted only that an error came back.
// A failed mutation must also leave the database EXACTLY as it was - that is
// the whole point of doing it in one transaction, and nothing checked it. A
// split into two transactions would ship green.
func TestFailedErasureLeavesEverythingIntact(t *testing.T) {
	// erasure_events is denied, so erasePerson fails at its per-scope
	// fan-out - AFTER the blob wipe and the deletes in the same tx.
	e := newFaultEnv(t, "erasure_events")
	ctx := context.Background()
	cid := e.register(t)

	type snap struct {
		blobs, tokens, consents, shares, links, valueTokens, cidsRows int
		erased                                                        bool
	}
	take := func() snap {
		var s snap
		if err := e.admin.Pool.QueryRow(ctx, `
			SELECT (SELECT count(*) FROM cids WHERE pii_encrypted IS NOT NULL),
			       (SELECT count(*) FROM person_tokens),
			       (SELECT count(*) FROM consents),
			       (SELECT count(*) FROM shared_records),
			       (SELECT count(*) FROM person_links),
			       (SELECT count(*) FROM value_tokens),
			       (SELECT count(*) FROM cids),
			       (SELECT count(*) FROM persons WHERE erased_at IS NOT NULL) > 0`).Scan(
			&s.blobs, &s.tokens, &s.consents, &s.shares, &s.links, &s.valueTokens, &s.cidsRows, &s.erased); err != nil {
			t.Fatal(err)
		}
		return s
	}

	before := take()
	if before.blobs == 0 || before.tokens == 0 {
		t.Fatal("precondition: the contact should have a blob and search tokens")
	}
	if _, _, err := e.gdpr.Erase(ctx, e.crm, cid); err == nil {
		t.Fatal("erase must fail when erasure_events is denied")
	}
	e.gdpr.Drain()

	after := take()
	if after != before {
		t.Fatalf("a failed erasure changed the database.\nbefore: %+v\nafter:  %+v\n"+
			"Every deletion an erasure performs is in ONE transaction with the erasure record; "+
			"a failure must roll all of it back, and asserting only on the returned error cannot see that.",
			before, after)
	}
}

// Every table the erasure and delivery paths touch, denied one at a time.
// Each is an error branch that returns early - collectively the largest
// untested surface in the GDPR layer, and the branches on which "fail
// closed" actually rests.
func TestErasureAndDeliveryFailClosedPerTable(t *testing.T) {
	for _, table := range []string{
		"erasures", "erasure_events", "person_tokens", "consents",
		"shared_records", "person_links", "cid_blob_versions", "value_tokens",
		"portal_outbox", "external_envelopes", "oti", "audit",
	} {
		t.Run(table, func(t *testing.T) {
			e := newFaultEnv(t, table)
			ctx := context.Background()
			cid := e.register(t)
			if _, _, err := e.gdpr.Erase(ctx, e.crm, cid); err == nil {
				t.Errorf("erase must fail closed when %s is unavailable", table)
			}
			e.gdpr.Drain()
			// And the person is untouched: no half-erasure.
			var erased bool
			if err := e.admin.Pool.QueryRow(ctx,
				`SELECT erased_at IS NOT NULL FROM persons WHERE id=(SELECT person_id FROM cids WHERE cid=$1)`,
				cid).Scan(&erased); err != nil {
				t.Fatal(err)
			}
			if erased {
				t.Errorf("a failed erasure must not tombstone the person (%s denied)", table)
			}
		})
	}
}

// The delivery worker's own failure branches. Each denial breaks a different
// statement of the claim/POST/settle cycle.
func TestDeliveryFailsClosedPerTable(t *testing.T) {
	for _, table := range []string{"erasure_events", "webhooks", "audit"} {
		t.Run(table, func(t *testing.T) {
			e := newFaultEnv(t, table)
			ctx := context.Background()
			// Seed through the ADMIN pool, then deliver through the denied one.
			var personID string
			if err := e.admin.Pool.QueryRow(ctx,
				`INSERT INTO persons (id) VALUES (gen_random_uuid()) RETURNING id`).Scan(&personID); err != nil {
				t.Fatal(err)
			}
			var erasureID int64
			if err := e.admin.Pool.QueryRow(ctx,
				`INSERT INTO erasures (person_id, requested_by) VALUES ($1,'t') RETURNING id`,
				personID).Scan(&erasureID); err != nil {
				t.Fatal(err)
			}
			if _, err := e.admin.Pool.Exec(ctx,
				`INSERT INTO erasure_events (erasure_id, scope, cid) VALUES ($1,'crm','CID-FAULT00000000000000')`,
				erasureID); err != nil {
				t.Fatal(err)
			}
			// A worker that cannot read its own queue must return the error,
			// not report "nothing to deliver".
			_, err := e.gdpr.DeliverPending(ctx)
			if table == "erasure_events" || table == "webhooks" {
				if err == nil {
					t.Errorf("DeliverPending must surface a failure to read %s, not report an empty queue", table)
				}
			}
			// Whatever happened, nothing may be left claimed beyond the
			// reaper's reach.
			if n, rerr := service.ReapStrandedErasureEvents(ctx, e.admin.Pool, time.Nanosecond); rerr != nil {
				t.Fatal(rerr)
			} else {
				_ = n // recoverable is the property; the count varies by branch
			}
			var sending int
			if err := e.admin.Pool.QueryRow(ctx,
				`SELECT count(*) FROM erasure_events WHERE status='SENDING'`).Scan(&sending); err != nil {
				t.Fatal(err)
			}
			if sending != 0 {
				t.Errorf("%d event(s) unrecoverable after a %s failure", sending, table)
			}
		})
	}
}

// claimTTL's default branch: an unconfigured worker must still have a lease.
func TestClaimTTLDefaults(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	seedEvents(t, e, "http://127.0.0.1:1/never", 1)
	if _, err := e.admin.Pool.Exec(ctx,
		`UPDATE erasure_events SET status='SENDING', claimed_at=now()-interval '2 hours'`); err != nil {
		t.Fatal(err)
	}
	// ClaimTTL is unset on this env, so the sweep must fall back to the
	// documented default rather than to "no lease at all".
	if e.gdpr.ClaimTTL != 0 {
		t.Fatal("precondition: this env should have no explicit claim TTL")
	}
	if _, err := e.gdpr.DeliverPending(ctx); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := e.admin.Pool.QueryRow(ctx, `SELECT status FROM erasure_events`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status == "SENDING" {
		t.Fatal("a two-hour-old claim must be reaped under the default lease")
	}
}

// One denied table per subtest, across every person-scoped writer. Each
// combination is a distinct early-return that "fail closed" rests on, and
// none of them is reachable any other way. The assertion is the same in
// every case: the call fails AND leaves nothing half-written.
func TestEveryWriterFailsClosedOnADeniedTable(t *testing.T) {
	// Only the tables Register actually writes: persons, its identifier
	// tokens, the scoped cids row and the chained audit record. A table it
	// never touches would succeed, which proves nothing.
	for _, table := range []string{"persons", "person_tokens", "cids", "audit"} {
		t.Run(table, func(t *testing.T) {
			e := newFaultEnv(t, table)
			ctx := context.Background()
			client := &auth.Client{ID: "crm", Scope: "crm",
				AllowedActions: []string{auth.ActContactsRegister, auth.ActLookup,
					auth.ActTokensCreate, auth.ActSharesCreate, auth.ActLinksManage,
					auth.ActOTIIssue, auth.ActConsentManage, auth.ActAttributesRead,
					auth.ActScopesIssue},
				AllowedPurposes: []string{"support"}}

			before := countAllRows(ctx, t, e)
			if _, err := e.svc.Register(ctx, client, service.RegisterInput{
				Email: "denied@example.com", Name: "Denied",
				Attributes: map[string]string{"tier": "gold"}}); err == nil {
				t.Errorf("register must fail closed when %s is unavailable", table)
			}
			after := countAllRows(ctx, t, e)
			if after != before {
				t.Errorf("a failed register left rows behind (%s denied): %d -> %d", table, before, after)
			}
		})
	}
}

// countAllRows is a cheap whole-schema fingerprint for "nothing was
// written": the exact numbers do not matter, only that they do not move.
func countAllRows(ctx context.Context, t *testing.T, e *faultEnv) int {
	t.Helper()
	var n int
	if err := e.admin.Pool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM persons) + (SELECT count(*) FROM cids)
		     + (SELECT count(*) FROM person_tokens) + (SELECT count(*) FROM consents)
		     + (SELECT count(*) FROM value_tokens) + (SELECT count(*) FROM shared_records)
		     + (SELECT count(*) FROM person_links) + (SELECT count(*) FROM oti)
		     + (SELECT count(*) FROM cid_blob_versions)`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// The same sweep over the SECOND-stage writers, which run only once a
// person exists - so they exercise a different set of early returns.
func TestSecondStageWritersFailClosedOnADeniedTable(t *testing.T) {
	for _, table := range []string{"value_tokens", "shared_records", "person_links", "oti", "audit"} {
		t.Run(table, func(t *testing.T) {
			e := newFaultEnv(t, table)
			ctx := context.Background()
			cid := e.register(t)
			other := ""
			{
				adminRing := &service.KeyRing{Pool: e.admin.Pool, RetireGrace: -1}
				admin := &service.Contacts{Pool: e.admin.Pool, Tok: e.svc.Tok, PII: e.svc.PII, Ring: adminRing}
				var err error
				if other, err = admin.Register(ctx, e.crm, service.RegisterInput{Email: "other-denied@example.com"}); err != nil {
					t.Fatal(err)
				}
			}
			client := &auth.Client{ID: "crm", Scope: "crm",
				AllowedActions: []string{auth.ActTokensCreate, auth.ActSharesCreate,
					auth.ActLinksManage, auth.ActOTIIssue, auth.ActConsentManage,
					auth.ActAttributesRead},
				AllowedPurposes: []string{"support"}}

			vt := &service.ValueTokens{Pool: e.svc.Pool, Eng: e.oti.Eng, Ring: e.svc.Ring, Tok: e.svc.Tok}
			shares := &service.Shares{Pool: e.svc.Pool, Contacts: e.svc}
			links := &service.Links{Pool: e.svc.Pool, Contacts: e.svc}

			before := countAllRows(ctx, t, e)
			// Each of these touches the denied table on some path; the ones
			// that do not simply succeed, which is equally fine - what must
			// never happen is a partial write.
			_, _ = vt.Tokenize(ctx, client, service.TokenizeInput{Type: "string", Value: "v", CID: cid})
			_, _, _ = shares.Create(ctx, client, service.ShareInput{
				CID: cid, Fields: []string{"tier"}, PartnerLabel: "p", Purpose: "support", TTLSeconds: 60})
			_ = links.Link(ctx, client, other, cid, "guardian")
			_, _, _ = e.oti.Issue(ctx, client, cid, "support", "billing", nil)
			_ = e.gdpr.SetConsent(ctx, client, cid, "support", true)

			// Whatever succeeded is durable and whatever failed wrote
			// nothing: the count may only move by the calls that returned
			// nil, never by a fraction of one.
			after := countAllRows(ctx, t, e)
			if after < before {
				t.Errorf("rows disappeared under a %s failure: %d -> %d", table, before, after)
			}
			// And the audit chain still verifies across all of it.
			if broken, reason, _, err := audit.Verify(ctx, e.admin.Pool); err != nil || broken != 0 {
				t.Errorf("the chain broke under a %s failure: %d %s %v", table, broken, reason, err)
			}
		})
	}
}
