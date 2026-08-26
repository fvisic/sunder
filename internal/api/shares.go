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
	if !s.allow(w, client) {
		return
	}
	in, ok := decode[struct {
		CID          string   `json:"cid"`
		Fields       []string `json:"fields"`
		PartnerLabel string   `json:"partner_label"`
		TTLSeconds   int64    `json:"ttl_seconds"`
	}](w, r)
	if !ok {
		return
	}
	uuid, expiresAt, err := s.Shares.Create(r.Context(), client, service.ShareInput{
		CID: in.CID, Fields: in.Fields, PartnerLabel: in.PartnerLabel, TTLSeconds: in.TTLSeconds})
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
// audited as the "public" actor.
func (s *Server) handleShareFetchPublic(w http.ResponseWriter, r *http.Request) {
	s.fetchShare(w, r, "public")
}

func (s *Server) fetchShare(w http.ResponseWriter, r *http.Request, actor string) {
	out, err := s.Shares.Fetch(r.Context(), actor, r.PathValue("uuid"))
	if err != nil {
		s.logErr(r, err)
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"fields": out})
}
