package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/fvisic/sunder/internal/audit"
	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/crypto"
)

// LookupInput carries search identifiers. Valid combinations: email alone,
// phone alone, or name plus one of email/phone (name never stands alone -
// it is a narrowing key; docs/DESIGN.md). LOOKUP != AUTHENTICATION: a match
// returns a pseudonym, never asserts the caller talked to that person.
type LookupInput struct {
	Email string `json:"email"`
	Phone string `json:"phone"`
	Name  string `json:"name"`
	// PhoneSuffix looks a contact up by the last digits of a phone number
	// (>= 8 digits supplied; the last 8 are used). It answers ONLY when it
	// narrows to exactly one person - a multi-hit is a miss, so partial
	// lookup cannot enumerate. Requires SUNDER_SEARCH_PHONE_SUFFIX.
	PhoneSuffix string `json:"phone_suffix"`
	// UserID is the operator inside the calling system (client-asserted,
	// see audit.Entry.UserID). Body field on this POST route; GET routes
	// use the X-Sunder-User-Id header. When both are present, the body
	// wins - it is the more deliberate act.
	UserID string `json:"user_id"`
}

// Lookup resolves identifiers to the caller-scope CID. Misses and hits are
// both audited; a person without a CID in the caller's scope is a miss -
// auto-issuing here would let one scope enumerate another scope's contacts.
func (c *Contacts) Lookup(ctx context.Context, client *auth.Client, in LookupInput) (string, error) {
	if !client.Can(auth.ActLookup) {
		return "", ErrForbidden
	}
	// The F3 attribute allowlist gates lookup BY that identifier kind too: a
	// client narrowed to {iban} must not probe emails, phones or names via
	// 200-vs-404 - lookup was the one read surface the allowlist did not
	// cover (a name oracle). An unrestricted client (no allowlist) is
	// unchanged.
	for kind, present := range map[string]bool{
		"email": in.Email != "",
		"phone": in.Phone != "" || in.PhoneSuffix != "",
		"name":  in.Name != "",
	} {
		if present && !client.CanReadAttribute(kind) {
			return "", ErrForbidden
		}
	}
	if in.PhoneSuffix != "" {
		if !c.PhoneSuffix {
			return "", fmt.Errorf("%w: phone_suffix lookup is not enabled on this instance (SUNDER_SEARCH_PHONE_SUFFIX)", ErrValidation)
		}
		if in.Email != "" || in.Phone != "" {
			return "", fmt.Errorf("%w: phone_suffix cannot be combined with email or phone - use the full identifier", ErrValidation)
		}
	}
	if in.Email == "" && in.Phone == "" && in.PhoneSuffix == "" {
		if in.Name != "" {
			return "", fmt.Errorf("%w: name alone is not a lookup key; add email or phone", ErrValidation)
		}
		return "", fmt.Errorf("%w: email or phone required", ErrValidation)
	}

	// Tokens under every live key version (dual-key rotation window).
	var emailToks, phoneToks, nameToks []string
	if in.Email != "" {
		norm, err := crypto.NormalizeEmail(in.Email)
		if err != nil {
			return "", fmt.Errorf("%w: %v", ErrValidation, err)
		}
		if emailToks, err = c.tokensAllVersions(ctx, crypto.KeyHMACEmail, norm, c.Tok.EmailToken); err != nil {
			return "", err
		}
	}
	if in.Phone != "" {
		norm, err := crypto.NormalizePhone(in.Phone)
		if err != nil {
			return "", fmt.Errorf("%w: %v", ErrValidation, err)
		}
		if phoneToks, err = c.tokensAllVersions(ctx, crypto.KeyHMACPhone, norm, c.Tok.PhoneToken); err != nil {
			return "", err
		}
	}
	var phoneticToks, suffixToks []string
	if in.Name != "" {
		norm, err := crypto.NormalizeName(in.Name)
		if err != nil {
			return "", fmt.Errorf("%w: %v", ErrValidation, err)
		}
		if nameToks, err = c.tokensAllVersions(ctx, crypto.KeyHMACName, norm, c.Tok.NameToken); err != nil {
			return "", err
		}
		if c.FuzzyName {
			for _, code := range crypto.PhoneticNameCodes(norm) {
				toks, err := c.tokensAllVersions(ctx, crypto.KeyHMACName, code, c.Tok.NamePhoneticToken)
				if err != nil {
					return "", err
				}
				phoneticToks = append(phoneticToks, toks...)
			}
		}
	}
	if in.PhoneSuffix != "" {
		digits := strings.Map(func(r rune) rune {
			if r >= '0' && r <= '9' {
				return r
			}
			return -1
		}, in.PhoneSuffix)
		if len(digits) < 8 {
			return "", fmt.Errorf("%w: phone_suffix needs at least 8 digits", ErrValidation)
		}
		var err error
		if suffixToks, err = c.tokensAllVersions(ctx, crypto.KeyHMACPhone,
			crypto.PhoneSuffix("+"+digits), c.Tok.PhoneSuffixToken); err != nil {
			return "", err
		}
	}

	// The primary identifier is email (priority) or phone; any additional
	// identifier narrows SOFTLY: it must match when the person has tokens of
	// that kind, but a person registered without any is not excluded
	// (otherwise a contact registered email-only could never be found by
	// email+phone). All of a person's identifiers of a kind participate.
	by := "email"
	primary := emailToks
	if in.Email == "" {
		by, primary = "phone", phoneToks
	}
	if in.PhoneSuffix != "" {
		by, primary = "phone_suffix", suffixToks
	}
	// The persons join is the tombstone predicate: Lookup was the only
	// cid-producing read path without one, relying entirely on erasure
	// having deleted the token rows. Any path that re-creates a token row
	// for an erased person (the rekey sweep did, GDPR-ERASURE-2) made the
	// forgotten person searchable by e-mail, phone and name again, and the
	// answer carries their stable pseudonym. Defence in depth: even a stray
	// row cannot re-expose a tombstone.
	q := `SELECT DISTINCT pt.person_id FROM person_tokens pt
	       JOIN persons pe ON pe.id = pt.person_id AND pe.erased_at IS NULL
	      WHERE pt.kind = $1 AND pt.token = ANY($2)`
	args := []any{by, primary}
	if in.PhoneSuffix != "" {
		// Single-hit is decided WITHIN the caller's scope: suffixes
		// collide legitimately, and a person visible only to some other
		// scope must neither block a hit that is unambiguous here (the
		// CRM+ERP coexistence case) nor leak, via that blocking, that a
		// colliding number exists somewhere else. The clause is part of
		// the query on every outcome, so no timing split is introduced,
		// and the always-run scope query below stays as the second check.
		q += fmt.Sprintf(` AND EXISTS (SELECT 1 FROM cids sc WHERE sc.person_id = pt.person_id AND sc.scope = $%d)`, len(args)+1)
		args = append(args, client.Scope)
	}
	narrow := func(kind string, toks []string) {
		q += fmt.Sprintf(` AND (
			NOT EXISTS (SELECT 1 FROM person_tokens n WHERE n.person_id = pt.person_id AND n.kind = '%s')
			OR EXISTS (SELECT 1 FROM person_tokens n WHERE n.person_id = pt.person_id AND n.kind = '%s' AND n.token = ANY($%d)))`,
			kind, kind, len(args)+1)
		args = append(args, toks)
	}
	if in.Email != "" && in.Phone != "" {
		by += "+phone"
		narrow("phone", phoneToks)
	}
	if in.Name != "" {
		by += "+name"
		if len(phoneticToks) > 0 {
			// Fuzzy narrowing: a person with name tokens passes on an
			// exact OR a phonetic match; a person with none is not
			// excluded (same soft semantics as exact narrowing).
			q += fmt.Sprintf(` AND (
				NOT EXISTS (SELECT 1 FROM person_tokens n WHERE n.person_id = pt.person_id AND n.kind IN ('name','name_phonetic'))
				OR EXISTS (SELECT 1 FROM person_tokens n WHERE n.person_id = pt.person_id AND n.kind = 'name' AND n.token = ANY($%d))
				OR EXISTS (SELECT 1 FROM person_tokens n WHERE n.person_id = pt.person_id AND n.kind = 'name_phonetic' AND n.token = ANY($%d)))`,
				len(args)+1, len(args)+2)
			args = append(args, nameToks, phoneticToks)
		} else {
			narrow("name", nameToks)
		}
	}

	// fuzzy is true when a phonetic name match was actually able to widen
	// this query - not merely that SUNDER_SEARCH_FUZZY_NAME is on. A name
	// that produces no phonetic codes searched exactly, and recording it as
	// fuzzy would overstate the search surface the trail describes.
	fuzzy := in.Name != "" && len(phoneticToks) > 0

	var personID string
	var matched, ambiguous bool
	if in.PhoneSuffix != "" {
		// Partial lookup answers only when unambiguous: two persons
		// sharing the suffix (after narrowing) is a MISS, never a list
		// and never a count - bulk-deny holds for partial search too.
		rows, err := c.Pool.Query(ctx, q+" ORDER BY pt.person_id LIMIT 2", args...)
		if err != nil {
			return "", err
		}
		var ids []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return "", err
			}
			ids = append(ids, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return "", err
		}
		switch len(ids) {
		case 1:
			personID, matched = ids[0], true
		case 2:
			ambiguous = true
		}
	} else {
		err := c.Pool.QueryRow(ctx, q+" ORDER BY pt.person_id LIMIT 1", args...).Scan(&personID)
		matched = err == nil
		if err != nil && err != pgx.ErrNoRows {
			return "", err
		}
	}

	// The scope query always runs (with an impossible person id on a miss) so
	// "person does not exist" and "person exists in another scope" burn the
	// same work - no timing oracle for cross-scope enumeration.
	if !matched {
		personID = "00000000-0000-0000-0000-000000000000"
	}
	cid := ""
	err := c.Pool.QueryRow(ctx,
		`SELECT cid FROM cids WHERE person_id=$1 AND scope=$2`, personID, client.Scope).Scan(&cid)
	if err == pgx.ErrNoRows {
		matched, cid = false, ""
	} else if err != nil {
		return "", err
	}
	// Fail closed: a lookup that cannot be audited must not answer.
	// ReadEvent buckets hourly under the default read-audit mode and
	// falls back to a chained row otherwise (or when so configured).
	if err := audit.ReadEvent(ctx, c.Pool, audit.Entry{
		ClientID: client.ID, Action: c.lookupAction(in.PhoneSuffix != "", fuzzy),
		CID: cid, UserID: in.UserID,
		Detail: map[string]any{"by": by, "matched": matched, "ambiguous": ambiguous},
	}); err != nil {
		return "", fmt.Errorf("audit append: %w", err)
	}
	if !matched {
		return "", ErrNotFound
	}
	return cid, nil
}

// lookupAction picks the audit action for one lookup.
//
// With SUNDER_AUDIT_LOOKUP_ACTIONS=single (the default) every form records
// as `lookup`, exactly as it always has. That is the safe default because
// the split costs read-bucket rows: buckets key on
// (client_id, user_id, cid, action, hour), so a client that resolves exact
// identifiers AND probes suffixes in the same hour now occupies two rows
// where it occupied one. The multiplier is bounded by the number of forms
// and is measured in TestSplitLookupActionsBucketMultiplier.
//
// With =split the forms separate, and they are worth separating: an exact
// e-mail lookup, a phonetic name match and an 8-digit suffix probe have
// visibly different enumeration profiles, and under bucketed reads the
// Detail that used to carry `by` is dropped before the hour is sealed. The
// action is the only field that reaches the auditor.
//
// suffix and fuzzy are INDEPENDENT wideners, not alternatives. Lookup
// refuses email/phone alongside a suffix but accepts a name, so
// `phone_suffix + name` with phonetic search on is a real request - and the
// widest one the API offers. An earlier version of this function treated the
// two as mutually exclusive and let suffix win, which recorded that widest
// form as an ordinary suffix probe and hid the fuzzy half from the auditor.
func (c *Contacts) lookupAction(suffix, fuzzy bool) string {
	if !c.SplitLookupActions {
		return audit.ActionLookup
	}
	switch {
	case suffix && fuzzy:
		return audit.ActionLookupSuffixFuzzy
	case suffix:
		return audit.ActionLookupSuffix
	case fuzzy:
		return audit.ActionLookupFuzzy
	default:
		return audit.ActionLookup
	}
}
