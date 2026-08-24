package service

// P2.3 selective disclosure: predicate claims are attached to an OTI at
// issue time and evaluated against the ISSUER-scope blob at verification.
// The verifier receives booleans only - the underlying value (a birthdate,
// a field's presence) never crosses the scope boundary and nothing is
// copied into the verifier's blob.

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Predicate ops supported in v2. `age_gte` reads the attribute as an ISO
// date (YYYY-MM-DD, or an RFC 3339 timestamp) and compares full years.
const (
	PredAgeGTE = "age_gte"
	PredExists = "exists"
)

// Predicate is one issuer-authorized claim request.
type Predicate struct {
	Attr string `json:"attr"`
	Op   string `json:"op"`
	// Value is required for age_gte (a pointer so an omitted threshold is
	// a loud validation failure rather than a silently-always-true 0).
	Value *int `json:"value,omitempty"`
}

// Threshold returns the age_gte threshold, or 0 when unset.
func (p Predicate) Threshold() int {
	if p.Value == nil {
		return 0
	}
	return *p.Value
}

// PredicateResult is one evaluated claim.
//
// Known is op-specific, on purpose:
// - age_gte: false when the attribute is absent or unparseable, so "we do
// not know the birthdate" never reads as "under 18";
// - exists: always true - the question IS whether the attribute is there,
// so its absence is an answer, not an unknown.
type PredicateResult struct {
	Predicate
	Result bool `json:"result"`
	Known  bool `json:"known"`
}

const maxPredicates = 8

// validatePredicates rejects malformed predicate requests at ISSUE time -
// a typo'd op must fail loudly for the issuer, not silently at verification.
func validatePredicates(preds []Predicate) error {
	if len(preds) > maxPredicates {
		return fmt.Errorf("%w: at most %d predicates per token", ErrValidation, maxPredicates)
	}
	for _, p := range preds {
		if p.Attr == "" || len(p.Attr) > 64 {
			return fmt.Errorf("%w: predicate attr must be 1-64 chars", ErrValidation)
		}
		switch p.Op {
		case PredAgeGTE:
			// An omitted threshold used to mean 0, which is true for every
			// parseable past date - a silent always-pass.
			if p.Value == nil {
				return fmt.Errorf("%w: age_gte requires an explicit value", ErrValidation)
			}
			if *p.Value < 1 || *p.Value > 150 {
				return fmt.Errorf("%w: age_gte value must be 1-150", ErrValidation)
			}
		case PredExists:
			if p.Value != nil {
				return fmt.Errorf("%w: exists takes no value", ErrValidation)
			}
		default:
			return fmt.Errorf("%w: unknown predicate op %q (supported: age_gte, exists)", ErrValidation, p.Op)
		}
	}
	return nil
}

// evalPredicates evaluates predicates against the issuer-scope blob inside
// the verification transaction. A missing blob or attribute yields
// Known=false, Result=false.
func (o *OTI) evalPredicates(ctx context.Context, tx pgx.Tx, issuerCID string, preds []Predicate) ([]PredicateResult, error) {
	results := make([]PredicateResult, 0, len(preds))
	if len(preds) == 0 {
		return results, nil
	}
	var blob []byte
	var keyID, alg string
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(pii_encrypted,''::bytea), COALESCE(pii_key_id,'v1'), COALESCE(pii_alg,'aes256gcm') FROM cids WHERE cid=$1`,
		issuerCID).Scan(&blob, &keyID, &alg); err != nil {
		return nil, err
	}
	attrs := map[string]string{}
	if len(blob) > 0 {
		var err error
		if attrs, err = o.Contacts.PII.Decrypt(ctx, issuerCID, blob, keyID, alg); err != nil {
			return nil, err
		}
	}
	now := time.Now().UTC()
	for _, p := range preds {
		r := PredicateResult{Predicate: p}
		val, present := attrs[p.Attr]
		switch p.Op {
		case PredExists:
			r.Known = true
			r.Result = present && val != ""
		case PredAgeGTE:
			if bd, ok := parseDate(val); present && ok {
				r.Known = true
				r.Result = fullYears(bd, now) >= p.Threshold()
			}
		}
		results = append(results, r)
	}
	return results, nil
}

func parseDate(s string) (time.Time, bool) {
	for _, layout := range []string{"2006-01-02", time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// fullYears counts completed years between birth and now (birthday not yet
// reached this year counts one less). Notes for integrators: dates are
// evaluated at UTC (a date-only birthdate attains the age at 00:00 UTC on
// the birthday), and Feb-29 birthdays normalize to Mar 1 in non-leap years
// (AddDate semantics) - leaplings attain the age one day "late", which some
// jurisdictions define differently. Document the policy where it matters.
func fullYears(birth, now time.Time) int {
	years := now.Year() - birth.Year()
	anniversary := birth.AddDate(years, 0, 0)
	if anniversary.After(now) {
		years--
	}
	return years
}
