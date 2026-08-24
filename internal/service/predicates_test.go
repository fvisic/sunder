package service_test

// P2.3 selective disclosure: the verifier learns booleans, never values;
// absence is "unknown", not "failed"; malformed requests die at issue time.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/fvisic/sunder/internal/service"
)

// ptr is the age_gte threshold helper: the field is a pointer so an
// omitted threshold fails loudly instead of meaning 0.
func ptr(v int) *int { return &v }

func issueWithPreds(t *testing.T, e *faultEnv, cid string, preds []service.Predicate) string {
	t.Helper()
	tok, _, err := e.oti.IssueFull(context.Background(), e.crm, service.IssueInput{
		CID: cid, Purpose: "support", Audience: "billing", SharePredicates: preds,
	})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestPredicateAgeGate(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()

	adult := time.Now().UTC().AddDate(-30, 0, 0).Format("2006-01-02")
	minor := time.Now().UTC().AddDate(-15, 0, 0).Format("2006-01-02")

	cidAdult, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
		Email: "adult@example.com", Attributes: map[string]string{"birthdate": adult},
	})
	if err != nil {
		t.Fatal(err)
	}
	cidMinor, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
		Email: "minor@example.com", Attributes: map[string]string{"birthdate": minor},
	})
	if err != nil {
		t.Fatal(err)
	}

	check := func(cid string, wantResult, wantKnown bool) {
		t.Helper()
		tok := issueWithPreds(t, e, cid, []service.Predicate{{Attr: "birthdate", Op: "age_gte", Value: ptr(18)}})
		out, err := e.oti.VerifyFull(ctx, e.verifier(), tok, "support", "billing")
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Predicates) != 1 {
			t.Fatalf("want 1 predicate result, got %+v", out.Predicates)
		}
		p := out.Predicates[0]
		if p.Result != wantResult || p.Known != wantKnown {
			t.Fatalf("age_gte 18: result=%v known=%v, want %v/%v", p.Result, p.Known, wantResult, wantKnown)
		}
	}
	check(cidAdult, true, true)
	check(cidMinor, false, true)

	// No birthdate at all: unknown, NOT "failed" - absence must be
	// distinguishable from a genuine under-18 result.
	cidNone, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
		Email: "nobd@example.com", Attributes: map[string]string{"tier": "gold"},
	})
	if err != nil {
		t.Fatal(err)
	}
	check(cidNone, false, false)

	// Garbage birthdate: unknown too.
	cidBad, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
		Email: "badbd@example.com", Attributes: map[string]string{"birthdate": "sometime in spring"},
	})
	if err != nil {
		t.Fatal(err)
	}
	check(cidBad, false, false)
}

func TestPredicateExistsAndNoValueLeak(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cid := e.register(t) // has "tier":"gold"

	tok := issueWithPreds(t, e, cid, []service.Predicate{
		{Attr: "tier", Op: "exists"},
		{Attr: "iban", Op: "exists"},
	})
	out, err := e.oti.VerifyFull(ctx, e.verifier(), tok, "support", "billing")
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Predicates) != 2 || !out.Predicates[0].Result || out.Predicates[1].Result {
		t.Fatalf("exists results wrong: %+v", out.Predicates)
	}
	// Nothing was copied into the verifier blob - predicates share no values.
	var blob []byte
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT COALESCE(pii_encrypted,''::bytea) FROM cids WHERE cid=$1`, out.CID).Scan(&blob); err != nil {
		t.Fatal(err)
	}
	if len(blob) != 0 {
		t.Fatal("predicate-only handoff must not write a verifier blob")
	}
}

func TestPredicateValidationAtIssue(t *testing.T) {
	e := newFaultEnv(t)
	cid := e.register(t)
	ctx := context.Background()

	bad := [][]service.Predicate{
		{{Attr: "birthdate", Op: "age_lte", Value: ptr(18)}},  // unknown op
		{{Attr: "", Op: "exists"}},                            // empty attr
		{{Attr: "birthdate", Op: "age_gte", Value: ptr(-1)}},  // negative
		{{Attr: "birthdate", Op: "age_gte"}},                  // threshold omitted: must NOT mean 0
		{{Attr: "birthdate", Op: "age_gte", Value: ptr(200)}}, // absurd
		{{Attr: "tier", Op: "exists", Value: ptr(5)}},         // exists with value
		{{Attr: strings.Repeat("a", 65), Op: "exists"}},       // overlong attr
		make([]service.Predicate, 9),                          // too many
	}
	for i, preds := range bad {
		if _, _, err := e.oti.IssueFull(ctx, e.crm, service.IssueInput{
			CID: cid, Purpose: "support", Audience: "billing", SharePredicates: preds,
		}); err == nil {
			t.Fatalf("case %d must be rejected at issue time", i)
		}
	}
}

func TestPredicatesCombineWithAttributeSharing(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	adult := time.Now().UTC().AddDate(-40, 0, 0).Format("2006-01-02")
	cid, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
		Email: "both@example.com", Attributes: map[string]string{"birthdate": adult, "tier": "gold"},
	})
	if err != nil {
		t.Fatal(err)
	}
	tok, _, err := e.oti.IssueFull(ctx, e.crm, service.IssueInput{
		CID: cid, Purpose: "support", Audience: "billing",
		ShareAttributes: []string{"tier"},
		SharePredicates: []service.Predicate{{Attr: "birthdate", Op: "age_gte", Value: ptr(18)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	out, err := e.oti.VerifyFull(ctx, e.verifier(), tok, "support", "billing")
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Shared) != 1 || out.Shared[0] != "tier" {
		t.Fatalf("shared: %+v", out.Shared)
	}
	if len(out.Predicates) != 1 || !out.Predicates[0].Result {
		t.Fatalf("predicates: %+v", out.Predicates)
	}
	// tier was copied; birthdate was NOT.
	billing := e.verifier()
	billing.AllowedActions = append(billing.AllowedActions, "attributes.read")
	if v, err := e.svc.GetAttribute(ctx, billing, out.CID, "tier", "support"); err != nil || v != "gold" {
		t.Fatalf("tier must be shared: %q %v", v, err)
	}
	if _, err := e.svc.GetAttribute(ctx, billing, out.CID, "birthdate", "support"); err == nil {
		t.Fatal("birthdate must NOT cross the boundary via a predicate")
	}
}

// Review finding: the exact-birthday boundary. Someone born exactly N years
// ago today IS N years old from 00:00 UTC.
func TestPredicateBirthdayBoundary(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	today18 := time.Now().UTC().AddDate(-18, 0, 0).Format("2006-01-02")
	tomorrow18 := time.Now().UTC().AddDate(-18, 0, 1).Format("2006-01-02")

	for _, tc := range []struct {
		birthdate string
		want      bool
	}{
		{today18, true},     // 18th birthday is today: already 18
		{tomorrow18, false}, // 18th birthday is tomorrow: still 17
	} {
		cid, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
			Email:      tc.birthdate + "@example.com",
			Attributes: map[string]string{"birthdate": tc.birthdate},
		})
		if err != nil {
			t.Fatal(err)
		}
		tok := issueWithPreds(t, e, cid, []service.Predicate{{Attr: "birthdate", Op: "age_gte", Value: ptr(18)}})
		out, err := e.oti.VerifyFull(ctx, e.verifier(), tok, "support", "billing")
		if err != nil {
			t.Fatal(err)
		}
		if out.Predicates[0].Result != tc.want || !out.Predicates[0].Known {
			t.Fatalf("birthdate %s: result=%v known=%v, want %v/true",
				tc.birthdate, out.Predicates[0].Result, out.Predicates[0].Known, tc.want)
		}
	}
}

// The chain must record the predicate that was ASKED,
// never its boolean outcome - the outcome is a one-bit value about a
// person, and audit rows outlive erasure.
func TestPredicateResultsAreNotAudited(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	adult := time.Now().UTC().AddDate(-30, 0, 0).Format("2006-01-02")
	cid, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
		Email: "audited@example.com", Attributes: map[string]string{"birthdate": adult},
	})
	if err != nil {
		t.Fatal(err)
	}
	tok := issueWithPreds(t, e, cid, []service.Predicate{{Attr: "birthdate", Op: "age_gte", Value: ptr(18)}})
	out, err := e.oti.VerifyFull(ctx, e.verifier(), tok, "support", "billing")
	if err != nil {
		t.Fatal(err)
	}
	// The verifier DOES learn the boolean.
	if !out.Predicates[0].Result {
		t.Fatal("verifier must receive the result")
	}
	var detail string
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT detail FROM audit WHERE action='oti.verify' ORDER BY seq DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(detail, "predicates_asked") || !strings.Contains(detail, "birthdate age_gte 18") {
		t.Fatalf("the chain must record what was asked: %s", detail)
	}
	// No outcome in any form.
	for _, leak := range []string{`"result"`, `"known"`, "true,", ":true"} {
		if strings.Contains(detail, leak) {
			t.Fatalf("predicate outcome leaked into the audit chain (%q): %s", leak, detail)
		}
	}
}
