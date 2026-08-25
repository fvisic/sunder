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
