package crypto

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

var e164 = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)

// clean applies Unicode NFKC (so visually-identical composed/decomposed or
// fullwidth forms produce the same HMAC token — otherwise a deliberate
// variant bypasses dedup) and rejects control characters.
func clean(s string) (string, error) {
	s = norm.NFKC.String(s)
	for _, r := range s {
		if unicode.IsControl(r) {
			return "", fmt.Errorf("control character not allowed")
		}
	}
	return s, nil
}

// NormalizeEmail lowercases and trims. Both ends of every lookup must apply
// the same normalization or HMAC tokens will not match.
func NormalizeEmail(s string) (string, error) {
	s, err := clean(s)
	if err != nil {
		return "", err
	}
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) > 320 || strings.ContainsAny(s, " \t") {
		return "", fmt.Errorf("invalid email")
	}
	local, domain, found := strings.Cut(s, "@")
	if !found || local == "" || domain == "" || strings.Contains(domain, "@") {
		return "", fmt.Errorf("invalid email")
	}
	return s, nil
}

// NormalizePhone strips formatting characters and validates E.164
// (+385911234567). A leading 00 is rewritten to +.
func NormalizePhone(s string) (string, error) {
	var b strings.Builder
	for i, r := range strings.TrimSpace(s) {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '+' && i == 0:
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '(' || r == ')' || r == '.' || r == '/':
		default:
			return "", fmt.Errorf("invalid phone character %q", r)
		}
	}
	out := b.String()
	if strings.HasPrefix(out, "00") {
		out = "+" + out[2:]
	}
	if !e164.MatchString(out) {
		return "", fmt.Errorf("phone not in E.164 form")
	}
	return out, nil
}

// NormalizeName lowercases and collapses internal whitespace. Names are only
// ever a narrowing key, never a unique one (LOOKUP != AUTHENTICATION).
func NormalizeName(s string) (string, error) {
	s, err := clean(s)
	if err != nil {
		return "", err
	}
	out := strings.Join(strings.Fields(strings.ToLower(s)), " ")
	if out == "" {
		return "", fmt.Errorf("empty name")
	}
	return out, nil
}
