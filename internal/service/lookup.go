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

	var emailToks, phoneToks, nameToks []string
	for _, v := range crypto.KeyVersions() { // all active versions: dual-key rotation window
		if in.Email != "" {
			norm, err := crypto.NormalizeEmail(in.Email)
			if err != nil {
				return "", fmt.Errorf("%w: %v", ErrValidation, err)
			}
			tok, err := c.Tok.EmailToken(ctx, v, norm)
			if err != nil {
				return "", err
			}
			emailToks = append(emailToks, tok)
		}
		if in.Phone != "" {
			norm, err := crypto.NormalizePhone(in.Phone)
			if err != nil {
				return "", fmt.Errorf("%w: %v", ErrValidation, err)
			}
			tok, err := c.Tok.PhoneToken(ctx, v, norm)
			if err != nil {
				return "", err
			}
			phoneToks = append(phoneToks, tok)
		}
		if in.Name != "" {
			norm, err := crypto.NormalizeName(in.Name)
			if err != nil {
				return "", fmt.Errorf("%w: %v", ErrValidation, err)
			}
			tok, err := c.Tok.NameToken(ctx, v, norm)
			if err != nil {
				return "", err
			}
			nameToks = append(nameToks, tok)
		}
	}

	by := "email"
	q := `SELECT id FROM persons WHERE email_token = ANY($1)`
	args := []any{emailToks}
	switch {
	case in.Phone != "" && in.Email == "":
		by, q, args = "phone", `SELECT id FROM persons WHERE phone_token = ANY($1)`, []any{phoneToks}
	case in.Phone != "" && in.Email != "":
		by = "email+phone"
		q = `SELECT id FROM persons WHERE email_token = ANY($1) AND phone_token = ANY($2)`
		args = []any{emailToks, phoneToks}
	}
	if in.Name != "" {
		by += "+name"
		q += fmt.Sprintf(" AND name_token = ANY($%d)", len(args)+1)
		args = append(args, nameToks)
	}

	var personID string
	err := c.Pool.QueryRow(ctx, q+" LIMIT 1", args...).Scan(&personID)
	matched := err == nil
	if err != nil && err != pgx.ErrNoRows {
		return "", err
	}

	cid := ""
	if matched {
		err = c.Pool.QueryRow(ctx,
			`SELECT cid FROM cids WHERE person_id=$1 AND scope=$2`, personID, client.Scope).Scan(&cid)
		if err == pgx.ErrNoRows {
			matched, cid = false, ""
		} else if err != nil {
			return "", err
		}
	}
	_ = audit.Append(ctx, c.Pool, audit.Entry{
		ClientID: client.ID, Action: "lookup", CID: cid,
		Detail: map[string]any{"by": by, "matched": matched},
	})
	if !matched {
		return "", ErrNotFound
	}
	return cid, nil
}
