package api

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/service"
)

// enumerationThreshold is how many lookup misses per client per 10 minutes
// trigger the mass-search warning (docs/DESIGN.md: enumeration detection).
const enumerationThreshold = 100

func (s *Server) handleLookup(w http.ResponseWriter, r *http.Request) {
	client := auth.FromContext(r.Context())
	if !s.Limiter.Allow(client.ID, client.RateLimit) {
		s.Metrics.Inc(fmt.Sprintf(`sunder_ratelimited_total{client=%q}`, client.ID))
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate_limited"})
		return
	}
	in, ok := decode[service.LookupInput](w, r)
	if !ok {
		return
	}
	if in.UserID != "" && !userIDPattern.MatchString(in.UserID) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "validation", "detail": "user_id must be an id: 1-64 of [A-Za-z0-9._@:-]"})
		return
	}
	// F3 strict posture: fuzzy/partial lookups spend an unlock token. The
	// gate is placed AFTER the permission and shape checks (review F4) so a
	// request that would never search - no lookup action, a suffix on an
	// instance where suffix search is disabled, a malformed suffix - does
	// not burn a single-use token or write an "intent spent" audit row for
	// a search that never happens. It only fires when the request will
	// actually take a fuzzy or suffix path that this instance serves.
	// A suffix must be well-formed (>= 8 digits) BEFORE the gate: this is
	// the caller's own input, so validating it here leaks nothing, and it
	// keeps a malformed suffix from burning a single-use token (review F4).
	if in.PhoneSuffix != "" {
		if countDigits(in.PhoneSuffix) < 8 {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "validation", "detail": "phone_suffix needs at least 8 digits"})
			return
		}
	}
	usesFuzzy := in.PhoneSuffix != "" && s.Cfg.SearchPhoneSuffix
	usesFuzzy = usesFuzzy || (in.Name != "" && in.PhoneSuffix == "" && s.Cfg.SearchFuzzyName &&
		(in.Email != "" || in.Phone != ""))
	if s.Cfg.SearchUnlock && usesFuzzy && client.Can(auth.ActLookup) {
		if err := s.Unlock.Consume(r.Context(), client, "search", r.Header.Get("X-Sunder-Unlock")); err != nil {
			if errors.Is(err, service.ErrUnlockRequired) {
				writeJSON(w, http.StatusForbidden, map[string]string{
					"error": "unlock_required", "detail": "mint a token at POST /v1/admin/unlock {\"purpose\":\"search\"} and send it as X-Sunder-Unlock"})
				return
			}
			s.logErr(r, err)
			writeErr(w, err)
			return
		}
	}
	cid, err := s.Contacts.Lookup(r.Context(), client, in)
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			misses := s.Detector.Miss(client.ID)
			s.Metrics.Inc(fmt.Sprintf(`sunder_lookup_misses_total{client=%q}`, client.ID))
			// ">=" with a per-client latch: the sliding-window count is not
			// monotonic (decay between calls), so an exact "==" crossing can
			// be skipped entirely.
			if misses >= enumerationThreshold && s.warnLatch(client.ID) {
				s.Log.Warn("possible enumeration attack", "client", client.ID, "misses_10m", misses)
			}
		}
		s.logErr(r, err)
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"cid": cid})
}

// warnLatch reports whether the enumeration warning for this client should
// log now (at most once per 10-minute window).
func (s *Server) warnLatch(clientID string) bool {
	now := time.Now()
	if v, ok := s.enumWarned.Load(clientID); ok && now.Sub(v.(time.Time)) < 10*time.Minute {
		return false
	}
	s.enumWarned.Store(clientID, now)
	return true
}

// handleAdminUnlock mints the F3 unlock token: the explicit, chained
// declaration of bulk intent, spent within 60 seconds or not at all.
func (s *Server) handleAdminUnlock(w http.ResponseWriter, r *http.Request) {
	client := auth.FromContext(r.Context())
	// Mint writes a chained audit row (global advisory lock under sync
	// sealing); rate-limit it like the other audit-writing endpoints
	// (review F3) so one credential cannot serialize the instance or flood
	// the never-pruned audit table.
	if !s.Limiter.Allow(client.ID, client.RateLimit) {
		s.Metrics.Inc(fmt.Sprintf(`sunder_ratelimited_total{client=%q}`, client.ID))
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate_limited"})
		return
	}
	in, ok := decode[struct {
		Purpose string `json:"purpose"`
	}](w, r)
	if !ok {
		return
	}
	token, expiresAt, err := s.Unlock.Issue(r.Context(), client, in.Purpose)
	if err != nil {
		s.logErr(r, err)
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{
		"unlock_token": token,
		"expires_at":   expiresAt.Format(time.RFC3339),
	})
}

// countDigits counts ASCII digits, ignoring separators.
func countDigits(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			n++
		}
	}
	return n
}
