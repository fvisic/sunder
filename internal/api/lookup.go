package api

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/service"
)

// enumerationThreshold is how many lookup misses per client per 10 minutes
// trigger the mass-search warning (PLAN section 5: enumeration detection).
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
	cid, err := s.Contacts.Lookup(r.Context(), client, in)
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			misses := s.Detector.Miss(client.ID)
			s.Metrics.Inc(fmt.Sprintf(`sunder_lookup_misses_total{client=%q}`, client.ID))
			if misses == enumerationThreshold {
				// Logged once per window at the crossing point; ops alerting
				// keys off this line and the misses counter.
				s.Log.Warn("possible enumeration attack", "client", client.ID, "misses_10m", misses)
			}
		}
		s.logErr(r, err)
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"cid": cid})
}
