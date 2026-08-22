package service

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/fvisic/sunder/internal/audit"
	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/crypto"
)

// LookupInput carries search identifiers. Valid combinations: email alone,
// phone alone, or name plus one of email/phone (name never stands alone —
// it is a narrowing key, PLAN section 5). LOOKUP != AUTHENTICATION: a match
// returns a pseudonym, never asserts the caller talked to that person.
type LookupInput struct {
	Email string `json:"email"`
	Phone string `json:"phone"`
	Name  string `json:"name"`
}

// Lookup resolves identifiers to the caller-scope CID. Misses and hits are
// both audited; a person without a CID in the caller's scope is a miss —
// auto-issuing here would let one scope enumerate another scope's contacts.
func (c *Contacts) Lookup(ctx context.Context, client *auth.Client, in LookupInput) (string, error) {
	if !client.Can(auth.ActLookup) {
		return "", ErrForbidden
	}
	if in.Email == "" && in.Phone == "" {
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
	if in.Name != "" {
		norm, err := crypto.NormalizeName(in.Name)
		if err != nil {
			return "", fmt.Errorf("%w: %v", ErrValidation, err)
		}
		if nameToks, err = c.tokensAllVersions(ctx, crypto.KeyHMACName, norm, c.Tok.NameToken); err != nil {
			return "", err
		}
	}

	// The primary identifier is email (priority) or phone; any additional
	// identifier narrows SOFTLY: it must match when the person has that
	// token, but a person registered without it is not excluded (otherwise a
	// contact registered email-only could never be found by email+phone).
	by := "email"
	q := `SELECT id FROM persons WHERE email_token = ANY($1)`
	args := []any{emailToks}
	if in.Email == "" {
		by, q, args = "phone", `SELECT id FROM persons WHERE phone_token = ANY($1)`, []any{phoneToks}
	} else if in.Phone != "" {
		by += "+phone"
		q += fmt.Sprintf(" AND (phone_token = ANY($%d) OR phone_token IS NULL)", len(args)+1)
		args = append(args, phoneToks)
	}
	if in.Name != "" {
		by += "+name"
		q += fmt.Sprintf(" AND (name_token = ANY($%d) OR name_token IS NULL)", len(args)+1)
		args = append(args, nameToks)
	}

	var personID string
	err := c.Pool.QueryRow(ctx, q+" LIMIT 1", args...).Scan(&personID)
	matched := err == nil
	if err != nil && err != pgx.ErrNoRows {
		return "", err
	}

	// The scope query always runs (with an impossible person id on a miss) so
	// "person does not exist" and "person exists in another scope" burn the
	// same work — no timing oracle for cross-scope enumeration.
	if !matched {
		personID = "00000000-0000-0000-0000-000000000000"
	}
	cid := ""
	err = c.Pool.QueryRow(ctx,
		`SELECT cid FROM cids WHERE person_id=$1 AND scope=$2`, personID, client.Scope).Scan(&cid)
	if err == pgx.ErrNoRows {
		matched, cid = false, ""
	} else if err != nil {
		return "", err
	}
	// Fail closed: a lookup that cannot be audited must not answer.
	if err := audit.Append(ctx, c.Pool, audit.Entry{
		ClientID: client.ID, Action: "lookup", CID: cid,
		Detail: map[string]any{"by": by, "matched": matched},
	}); err != nil {
		return "", fmt.Errorf("audit append: %w", err)
	}
	if !matched {
		return "", ErrNotFound
	}
	return cid, nil
}
