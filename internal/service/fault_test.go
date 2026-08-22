package service_test

// Mid-transaction fault injection: a second pool logs in as a role that has
// been REVOKEd on exactly one table, so precisely that statement fails while
// everything before it in the flow succeeds. This exercises the error
// branches a dead pool cannot reach.

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

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
	adminRing := &service.KeyRing{Pool: st.Pool}
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

	ring := &service.KeyRing{Pool: pool}
	contacts := &service.Contacts{Pool: pool, Tok: crypto.NewTokenizer(eng), PII: crypto.NewPIIBox(eng), Ring: ring}
	return &faultEnv{
		admin: st,
		svc:   contacts,
		oti:   &service.OTI{Pool: pool, Eng: eng, Ring: ring, Contacts: contacts},
		gdpr:  &service.GDPR{Pool: pool, Contacts: contacts},
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
	adminRing := &service.KeyRing{Pool: e.admin.Pool}
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
	ring := &service.KeyRing{Pool: e.admin.Pool}
	contacts := &service.Contacts{Pool: e.admin.Pool, Tok: e.svc.Tok, PII: e.svc.PII, Ring: ring}
	return &service.OTI{Pool: e.admin.Pool, Eng: e.oti.Eng, Ring: ring, Contacts: contacts}
}

func TestAuditDeniedBlocksEveryFlow(t *testing.T) {
	e := newFaultEnv(t, "audit")
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
	ring := &service.KeyRing{Pool: e.svc.Pool}
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
