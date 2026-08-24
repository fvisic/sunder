package sunder

import (
	"errors"
	"fmt"
)

// Error is returned by every SunderClient method on a non-success outcome.
// Code is the API's machine-readable "error" field (or a synthetic code such
// as "service_unavailable" for network failures), Status the HTTP status (0
// for pure network failures), Detail the optional human-readable detail the
// API attaches to validation errors only.
type Error struct {
	Code   string
	Status int
	Detail string
}

func (e *Error) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("sunder: %s (HTTP %d): %s", e.Code, e.Status, e.Detail)
	}
	return fmt.Sprintf("sunder: %s (HTTP %d)", e.Code, e.Status)
}

// Is makes every Error match its sentinel via errors.Is, so callers branch on
// the taxonomy rather than on strings:
//
//	if errors.Is(err, sunder.ErrTokenUsed) { ... }
func (e *Error) Is(target error) bool {
	s, ok := target.(*sentinel)
	return ok && s.code == e.Code
}

// sentinel is a comparable stand-in for one taxonomy code.
type sentinel struct{ code string }

func (s *sentinel) Error() string { return "sunder: " + s.code }

// The taxonomy is identical across all Sunder SDKs (docs/API.md).
var (
	// ErrUnauthorized - missing or wrong credential (401).
	ErrUnauthorized = &sentinel{"unauthorized"}
	// ErrCredentialExpired - the secret is correct but past its expiry
	// (401). Rotate it (`sunder client rotate-secret`); do not retry.
	ErrCredentialExpired = &sentinel{"credential_expired"}
	// ErrForbidden - the client lacks the action for this call (403).
	ErrForbidden = &sentinel{"forbidden"}
	// ErrConsentDenied - the data subject withdrew consent for this purpose
	// (403). Distinct from ErrPurposeNotAllowed, which is a missing grant on
	// the client rather than a decision by the person.
	ErrConsentDenied = &sentinel{"consent_denied"}
	// ErrPurposeNotAllowed - the purpose is outside the client's grants (403).
	ErrPurposeNotAllowed = &sentinel{"purpose_not_allowed"}
	// ErrAudienceMismatch - the token is addressed to another scope (403).
	ErrAudienceMismatch = &sentinel{"audience_mismatch"}
	// ErrNotFound - no such contact in the caller's scope (404). Also
	// returned for an erased person: absence and erasure are deliberately
	// indistinguishable.
	ErrNotFound = &sentinel{"not_found"}
	// ErrValidation - the request was rejected (400); Detail says why.
	ErrValidation = &sentinel{"validation"}
	// ErrTokenInvalid - bad signature, wrong purpose, or malformed (400).
	ErrTokenInvalid = &sentinel{"token_invalid"}
	// ErrTokenUsed - the one-time identifier was already consumed (409).
	ErrTokenUsed = &sentinel{"token_used"}
	// ErrTokenExpired - past its five-minute default lifetime (410).
	ErrTokenExpired = &sentinel{"token_expired"}
	// ErrRateLimited - the caller exceeded its per-minute budget (429).
	ErrRateLimited = &sentinel{"rate_limited"}
	// ErrServiceUnavailable - 5xx, or a network-level failure (Status 0).
	ErrServiceUnavailable = &sentinel{"service_unavailable"}
	// ErrBadResponse - a 2xx whose body was not the expected JSON shape.
	ErrBadResponse = &sentinel{"bad_response"}
)

// codeMap resolves a server code to its canonical taxonomy entry. Code-first,
// then status - the same order every other Sunder SDK uses, so one server
// code maps identically in every language.
var codeMap = map[string]*sentinel{
	"unauthorized":        ErrUnauthorized,
	"credential_expired":  ErrCredentialExpired,
	"forbidden":           ErrForbidden,
	"consent_denied":      ErrConsentDenied,
	"purpose_not_allowed": ErrPurposeNotAllowed,
	"audience_mismatch":   ErrAudienceMismatch,
	"not_found":           ErrNotFound,
	"validation":          ErrValidation,
	"bad_json":            ErrValidation,
	"token_invalid":       ErrTokenInvalid,
	"token_used":          ErrTokenUsed,
	"token_expired":       ErrTokenExpired,
	"rate_limited":        ErrRateLimited,
	"service_unavailable": ErrServiceUnavailable,
	"bad_response":        ErrBadResponse,
}

// mapError builds the Error for one failed response.
func mapError(status int, serverCode, detail string) error {
	code := serverCode
	if s, ok := codeMap[serverCode]; ok {
		code = s.code
	} else {
		switch {
		case status >= 500:
			code = ErrServiceUnavailable.code
		case status == 401:
			code = ErrUnauthorized.code
		case status == 403:
			code = ErrForbidden.code
		case status == 404:
			code = ErrNotFound.code
		case status == 409:
			code = ErrTokenUsed.code
		case status == 410:
			code = ErrTokenExpired.code
		case status == 429:
			code = ErrRateLimited.code
		case status == 400:
			code = ErrValidation.code
		case code == "":
			code = fmt.Sprintf("http_%d", status)
		}
	}
	return &Error{Code: code, Status: status, Detail: detail}
}

// retryable reports whether a failure is worth one more attempt: 5xx and
// network errors are, a definite 4xx verdict is not.
func retryable(err error) bool {
	var e *Error
	if errors.As(err, &e) {
		return e.Status == 0 || e.Status >= 500
	}
	return false
}
