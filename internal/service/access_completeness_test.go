package service_test

// TOKENS-LOOKUP-7 and GAP-2: the Article 15 answer covered the attribute
// blob, consents and the audit trail - and nothing else. A tokenized IBAN or
// national id, an uploaded file, a standing disclosure to a named partner
// and a link to another person are all things the controller holds about the
// subject (Art. 15(1)) or people it disclosed to (Art. 15(1)(c)), and none of
// them appeared in any subject-facing response. Worse, every tokens.read
// aggregated into a bucket with cid='' under the default posture, so the
// trail could not even say WHO was read.

import (
	"context"
	"testing"

	"github.com/fvisic/sunder/internal/audit"
	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/service"
)

func TestAccessReportsEveryHolding(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()

	officer := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions: []string{auth.ActContactsRegister, auth.ActDSRAccess, auth.ActDSRExport,
			auth.ActTokensCreate, auth.ActTokensRead, auth.ActSharesCreate,
			auth.ActLinksManage, auth.ActAttributesRead},
		AllowedPurposes: []string{"support"}}

	cid, err := e.svc.Register(ctx, officer, service.RegisterInput{
		Email: "subject@example.com", Attributes: map[string]string{"tier": "gold"}})
	if err != nil {
		t.Fatal(err)
	}
	counterparty, err := e.svc.Register(ctx, officer, service.RegisterInput{Email: "counter2@example.com"})
	if err != nil {
		t.Fatal(err)
	}

	vt := &service.ValueTokens{Pool: e.admin.Pool, Eng: e.oti.Eng, Ring: e.svc.Ring, Tok: e.svc.Tok}
	token, err := vt.Tokenize(ctx, officer, service.TokenizeInput{
		Type: "string", Value: "HR1210010051863000160", CID: cid})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := vt.Detokenize(ctx, officer, token); err != nil {
			t.Fatal(err)
		}
	}

	shares := &service.Shares{Pool: e.admin.Pool, Contacts: e.svc}
	shareID, _, err := shares.Create(ctx, officer, service.ShareInput{
		CID: cid, Fields: []string{"tier"}, PartnerLabel: "acme-partner",
		Purpose: "support", TTLSeconds: 3600})
	if err != nil {
		t.Fatal(err)
	}
	links := &service.Links{Pool: e.admin.Pool, Contacts: e.svc}
	if err := links.Link(ctx, officer, counterparty, cid, "guardian"); err != nil {
		t.Fatal(err)
	}

	out, err := e.gdpr.Access(ctx, officer, cid)
	if err != nil {
		t.Fatal(err)
	}
	scopes, _ := out["scopes"].([]service.ScopeData)
	trail, _ := out["audit_trail"].([]service.AuditTrailEntry)
	var mine *service.ScopeData
	for i := range scopes {
		if scopes[i].CID == cid {
			mine = &scopes[i]
		}
	}
	if mine == nil {
		t.Fatal("the subject's own scope is missing from the access answer")
	}

	if len(mine.ValueTokens) != 1 || mine.ValueTokens[0].Token != token {
		t.Fatalf("Art. 15(1): the tokenized value must be reported as held, got %+v", mine.ValueTokens)
	}
	if mine.ValueTokens[0].CreatedBy != "crm" {
		t.Errorf("the token's minter must be reported, got %q", mine.ValueTokens[0].CreatedBy)
	}
	if len(mine.Shares) != 1 || mine.Shares[0].UUID != shareID {
		t.Fatalf("Art. 15(1)(c): the disclosure must be reported, got %+v", mine.Shares)
	}
	if mine.Shares[0].Partner != "acme-partner" {
		t.Errorf("the RECIPIENT must be named, got %q", mine.Shares[0].Partner)
	}
	if len(mine.Links) != 1 || mine.Links[0].CID != counterparty {
		t.Fatalf("the relationship to another person must be reported, got %+v", mine.Links)
	}

	// The reads must be attributable to THIS subject, not to an anonymous
	// per-client bucket.
	var reads int
	if audit.ReadsMode() == audit.ReadsBucketed {
		if err := e.admin.Pool.QueryRow(ctx,
			`SELECT COALESCE(sum(count),0) FROM audit_read_buckets WHERE action='tokens.read' AND cid=$1`,
			cid).Scan(&reads); err != nil {
			t.Fatal(err)
		}
	} else {
		if err := e.admin.Pool.QueryRow(ctx,
			`SELECT count(*) FROM audit WHERE action='tokens.read' AND cid=$1`, cid).Scan(&reads); err != nil {
			t.Fatal(err)
		}
	}
	if reads != 3 {
		t.Fatalf("the three detokenizations must be attributed to the subject, got %d", reads)
	}
	// ...and therefore visible in the trail the subject receives.
	sawRead := false
	for _, tr := range trail {
		if tr.Action == "tokens.read" && tr.CID == cid {
			sawRead = true
		}
	}
	if !sawRead {
		t.Fatal("the access trail does not tell the subject their tokenized value was read")
	}

	// Portability carries the same holdings.
	exp, err := e.gdpr.Export(ctx, officer, cid)
	if err != nil {
		t.Fatal(err)
	}
	if len(exp.ValueTokens) != 1 || len(exp.Shares) != 1 {
		t.Fatalf("Art. 20: the export omits holdings: tokens=%d shares=%d", len(exp.ValueTokens), len(exp.Shares))
	}
	// The VALUE never crosses: metadata only.
	if exp.ValueTokens[0].Token == "HR1210010051863000160" {
		t.Fatal("the export must carry the token, never the tokenized value")
	}
}

// The holdings sections on a person with nothing but a blob: every list is
// present and empty, never null - a subject-facing answer that omits the
// key entirely reads as "we do not track that", which is a different claim.
func TestAccessReportsEmptyHoldingsExplicitly(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	officer := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions:  []string{auth.ActContactsRegister, auth.ActDSRAccess, auth.ActDSRExport, auth.ActAttributesRead},
		AllowedPurposes: []string{"support"}}
	cid, err := e.svc.Register(ctx, officer, service.RegisterInput{
		Email: "bare@example.com", Attributes: map[string]string{"tier": "gold"}})
	if err != nil {
		t.Fatal(err)
	}
	out, err := e.gdpr.Access(ctx, officer, cid)
	if err != nil {
		t.Fatal(err)
	}
	scopes, _ := out["scopes"].([]service.ScopeData)
	if len(scopes) != 1 {
		t.Fatalf("expected one scope, got %d", len(scopes))
	}
	sd := scopes[0]
	if sd.ValueTokens == nil || sd.Files == nil || sd.Shares == nil || sd.Links == nil {
		t.Fatalf("every holdings section must be an empty list, never null: %+v", sd)
	}
	if len(sd.ValueTokens)+len(sd.Files)+len(sd.Shares)+len(sd.Links) != 0 {
		t.Fatalf("this person holds nothing beyond the blob: %+v", sd)
	}
	exp, err := e.gdpr.Export(ctx, officer, cid)
	if err != nil {
		t.Fatal(err)
	}
	if exp.ValueTokens == nil || exp.Files == nil || exp.Shares == nil || exp.Links == nil {
		t.Fatalf("the export must carry the same sections: %+v", exp)
	}
}

// A subject-access answer must FAIL rather than silently omit a holdings
// section: "we hold nothing else about you" and "one query errored" are
// different statements, and only one of them is safe to send a data subject.
func TestAccessFailsClosedWhenAHoldingsQueryCannotRun(t *testing.T) {
	for _, table := range []string{"value_tokens", "files", "shared_records", "person_links"} {
		t.Run(table, func(t *testing.T) {
			e := newFaultEnv(t, table)
			ctx := context.Background()
			officer := &auth.Client{ID: "crm", Scope: "crm",
				AllowedActions:  []string{auth.ActDSRAccess, auth.ActDSRExport, auth.ActAttributesRead},
				AllowedPurposes: []string{"support"}}
			cid := e.register(t)

			if _, err := e.gdpr.Access(ctx, officer, cid); err == nil {
				t.Errorf("Access must fail closed when %s cannot be read - a partial answer reads as 'nothing held'", table)
			}
			if _, err := e.gdpr.Export(ctx, officer, cid); err == nil {
				t.Errorf("Export must fail closed when %s cannot be read", table)
			}
		})
	}
}
