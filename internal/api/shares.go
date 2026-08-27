package api

// Shared-record endpoints (F8). Create and revoke are authenticated
// (action shares.create). Fetch has two modes, chosen at startup: default
// requires any valid client credential (registered inside the auth-guarded
// v1 mux); with SUNDER_SHARES_PUBLIC the fetch route is registered on the
// public mux so a partner holding only the UUID can read it.

import (
	"net/http"

	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/service"
)

func (s *Server) handleShareCreate(w http.ResponseWriter, r *http.Request) {
	client := auth.FromContext(r.Context())
	in, ok := decode[struct {
		CID          string   `json:"cid"`
		Fields       []string `json:"fields"`
		PartnerLabel string   `json:"partner_label"`
		Purpose      string   `json:"purpose"`
		TTLSeconds   int64    `json:"ttl_seconds"`
	}](w, r)
	if !ok {
		return
	}
	uuid, expiresAt, err := s.Shares.Create(r.Context(), client, service.ShareInput{
		CID: in.CID, Fields: in.Fields, PartnerLabel: in.PartnerLabel, Purpose: in.Purpose, TTLSeconds: in.TTLSeconds})
	if err != nil {
		s.logErr(r, err)
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"uuid": uuid, "expires_at": expiresAt})
}

func (s *Server) handleShareRevoke(w http.ResponseWriter, r *http.Request) {
	client := auth.FromContext(r.Context())
	if err := s.Shares.Revoke(r.Context(), client, r.PathValue("uuid")); err != nil {
		s.logErr(r, err)
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// handleShareFetchAuthed is the default-mode fetch: the caller is an
// authenticated client, labeled by its id in the audit trail.
func (s *Server) handleShareFetchAuthed(w http.ResponseWriter, r *http.Request) {
	client := auth.FromContext(r.Context())
	s.fetchShare(w, r, client.ID)
}

// handleShareFetchPublic is the SUNDER_SHARES_PUBLIC fetch: no credential,
// audited as the "public" actor. It lives outside the auth middleware, so
// it carries its own PER-IP rate limit - every fetch writes an audit read
// event (a chained row under the instance-wide lock in chained mode), and
// an unauthenticated, unlimited endpoint that writes to the chain is a DoS
// on that lock.
func (s *Server) handleShareFetchPublic(w http.ResponseWriter, r *http.Request) {
	// The API listener's own header knob, not the portal's: this route is
	// registered on the API mux (AUTHZ-5).
	ip := s.apiClientIP(r)
	if s.Limiter != nil && !s.Limiter.Allow("share-public:"+ip, publicShareRateLimit) {
		s.Metrics.Inc(`sunder_ratelimited_total{client="share-public"}`)
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate_limited"})
		return
	}
	s.fetchShare(w, r, "public")
}

// publicShareRateLimit bounds credential-less share fetches per source IP.
const publicShareRateLimit = 120

func (s *Server) fetchShare(w http.ResponseWriter, r *http.Request, actor string) {
	out, err := s.Shares.Fetch(r.Context(), actor, r.PathValue("uuid"))
	if err != nil {
		s.logErr(r, err)
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"fields": out})
}
