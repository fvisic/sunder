package service_test

import (
	"context"
	"errors"
	"testing"

	"github.com/fvisic/sunder/internal/service"
)

// searchEnv is a faultEnv whose service has the F1/F2 switches ON - the
// features are off by default, so every other test in this package keeps
// exercising the default posture.
func searchEnv(t *testing.T) *faultEnv {
	t.Helper()
	e := newFaultEnv(t) // no denials: fully privileged role
	e.svc.FuzzyName = true
	e.svc.PhoneSuffix = true
	return e
}

func TestFuzzyNameNarrowing(t *testing.T) {
	e := searchEnv(t)
	ctx := context.Background()

	cid, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
		Email: "ana@example.com", Name: "Ana Anić"})
	if err != nil {
		t.Fatal(err)
	}

	// The client's actual case: the operator types the name WITHOUT
	// diacritics. Exact narrowing would miss; phonetic narrowing hits.
	got, err := e.svc.Lookup(ctx, e.crm, service.LookupInput{
		Email: "ana@example.com", Name: "Ana Anic"})
	if err != nil || got != cid {
		t.Fatalf("diacritic-stripped name must narrow to the person: %q %v", got, err)
	}
	// Surname alone narrows too (phonetic codes are per word).
	if got, err = e.svc.Lookup(ctx, e.crm, service.LookupInput{
		Email: "ana@example.com", Name: "ANIC"}); err != nil || got != cid {
		t.Fatalf("surname-only fuzzy narrowing: %q %v", got, err)
	}
	// A genuinely different name still narrows to nothing - fuzzy must
	// not mean "ignores the name".
	if _, err := e.svc.Lookup(ctx, e.crm, service.LookupInput{
		Email: "ana@example.com", Name: "Babić"}); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("non-matching name must still narrow out: %v", err)
	}
}

func TestFuzzyNameOffKeepsExactSemantics(t *testing.T) {
	e := newFaultEnv(t) // default posture: fuzzy OFF
	ctx := context.Background()
	if _, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
		Email: "off@example.com", Name: "Ana Anić"}); err != nil {
		t.Fatal(err)
	}
	// Without the feature there are no phonetic tokens and no fuzzy path:
	// the stripped spelling misses, exactly as before this change.
	if _, err := e.svc.Lookup(ctx, e.crm, service.LookupInput{
		Email: "off@example.com", Name: "Ana Anic"}); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("fuzzy off must keep exact narrowing: %v", err)
	}
	var n int64
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM person_tokens WHERE kind IN ('name_phonetic','phone_suffix')`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("derived tokens must not be minted while the features are off, found %d", n)
	}
}

func TestPhoneSuffixLookupSingleHit(t *testing.T) {
	e := searchEnv(t)
	ctx := context.Background()

	cid, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
		Phone: "+385911234567", Name: "Ana Anić"})
	if err != nil {
		t.Fatal(err)
	}

	// The caller-ID case: national spelling, no country code.
	got, err := e.svc.Lookup(ctx, e.crm, service.LookupInput{PhoneSuffix: "0911234567"})
	if err != nil || got != cid {
		t.Fatalf("suffix lookup by national spelling: %q %v", got, err)
	}
	// Formatting characters are the operator's problem, not the API's.
	if got, err = e.svc.Lookup(ctx, e.crm, service.LookupInput{PhoneSuffix: "091/123-4567"}); err != nil || got != cid {
		t.Fatalf("suffix lookup with formatting: %q %v", got, err)
	}

	// Guards: length, combination, and the feature switch.
	if _, err := e.svc.Lookup(ctx, e.crm, service.LookupInput{PhoneSuffix: "1234567"}); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("short suffix must be a validation error: %v", err)
	}
	if _, err := e.svc.Lookup(ctx, e.crm, service.LookupInput{
		PhoneSuffix: "0911234567", Phone: "+385911234567"}); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("suffix combined with a full identifier must be rejected: %v", err)
	}
	e.svc.PhoneSuffix = false
	if _, err := e.svc.Lookup(ctx, e.crm, service.LookupInput{PhoneSuffix: "0911234567"}); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("disabled feature must reject, not miss: %v", err)
	}
}

func TestPhoneSuffixAmbiguousIsAMiss(t *testing.T) {
	e := searchEnv(t)
	ctx := context.Background()

	// Two persons whose numbers share the last eight digits.
	if _, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
		Phone: "+385911234567", Name: "Ana Anić"}); err != nil {
		t.Fatal(err)
	}
	cidB, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
		Phone: "+38111234567", Name: "Marko Babić"})
	if err != nil {
		t.Fatal(err)
	}

	// Ambiguous: a miss, never a list, never a count (bulk-deny).
	if _, err := e.svc.Lookup(ctx, e.crm, service.LookupInput{PhoneSuffix: "11234567"}); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("two matches must read as a miss: %v", err)
	}
	// A name disambiguates: suffix + fuzzy name narrows to one person.
	got, err := e.svc.Lookup(ctx, e.crm, service.LookupInput{PhoneSuffix: "11234567", Name: "Babic"})
	if err != nil || got != cidB {
		t.Fatalf("suffix+name must disambiguate: %q %v", got, err)
	}
}

// TestDerivedTokensErasedWithPerson: the erasure path must not leave
// derived search tokens behind - they are search keys like any other.
func TestDerivedTokensErasedWithPerson(t *testing.T) {
	e := searchEnv(t)
	ctx := context.Background()
	cid, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
		Phone: "+385911234567", Name: "Ana Anić"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.gdpr.Erase(ctx, e.crm, cid); err != nil {
		t.Fatal(err)
	}
	var n int64
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM person_tokens`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("erasure must delete every token kind, %d left", n)
	}
}

func TestFuzzyNameWithNoPhoneticSignal(t *testing.T) {
	e := searchEnv(t)
	ctx := context.Background()
	// A "name" of pure symbols normalizes but reduces to no phonetic
	// codes: registration must still succeed and mint nothing derived.
	if _, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
		Email: "sym@example.com", Name: "---"}); err != nil {
		t.Fatal(err)
	}
	var n int64
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM person_tokens WHERE kind='name_phonetic'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("symbol-only name must mint no phonetic tokens, got %d", n)
	}
}
