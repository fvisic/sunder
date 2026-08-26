package api

// Sub-account (person link) endpoints (F7).

import (
	"net/http"

	"github.com/fvisic/sunder/internal/auth"
)

func (s *Server) handleLinkCreate(w http.ResponseWriter, r *http.Request) {
	client := auth.FromContext(r.Context())
	if !s.allow(w, client) {
		return
	}
	in, ok := decode[struct {
		ParentCID string `json:"parent_cid"`
		ChildCID  string `json:"child_cid"`
		LinkType  string `json:"link_type"`
	}](w, r)
	if !ok {
		return
	}
	if err := s.Links.Link(r.Context(), client, in.ParentCID, in.ChildCID, in.LinkType); err != nil {
		s.logErr(r, err)
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "linked"})
}

func (s *Server) handleLinkDelete(w http.ResponseWriter, r *http.Request) {
	client := auth.FromContext(r.Context())
	if !s.allow(w, client) {
		return
	}
	in, ok := decode[struct {
		ParentCID string `json:"parent_cid"`
		ChildCID  string `json:"child_cid"`
	}](w, r)
	if !ok {
		return
	}
	if err := s.Links.Unlink(r.Context(), client, in.ParentCID, in.ChildCID); err != nil {
		s.logErr(r, err)
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "unlinked"})
}

func (s *Server) handleLinkList(w http.ResponseWriter, r *http.Request) {
	client := auth.FromContext(r.Context())
	if !s.allow(w, client) {
		return
	}
	out, err := s.Links.List(r.Context(), client, r.PathValue("cid"))
	if err != nil {
		s.logErr(r, err)
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"links": out})
}
