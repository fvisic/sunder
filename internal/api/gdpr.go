package api

import (
	"net/http"

	"github.com/fvisic/sunder/internal/auth"
)

func (s *Server) handleConsentSet(w http.ResponseWriter, r *http.Request) {
	in, ok := decode[struct {
		CID     string `json:"cid"`
		Purpose string `json:"purpose"`
		Granted *bool  `json:"granted"`
	}](w, r)
	if !ok {
		return
	}
	granted := in.Granted != nil && *in.Granted
	err := s.GDPR.SetConsent(r.Context(), auth.FromContext(r.Context()), in.CID, in.Purpose, granted)
	if err != nil {
		s.logErr(r, err)
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"cid": in.CID, "purpose": in.Purpose, "granted": granted})
}

func (s *Server) handleConsentList(w http.ResponseWriter, r *http.Request) {
	consents, err := s.GDPR.ListConsents(r.Context(), auth.FromContext(r.Context()), r.PathValue("cid"))
	if err != nil {
		s.logErr(r, err)
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"consents": consents})
}

func (s *Server) handleDSRAccess(w http.ResponseWriter, r *http.Request) {
	out, err := s.GDPR.Access(r.Context(), auth.FromContext(r.Context()), r.URL.Query().Get("cid"))
	if err != nil {
		s.logErr(r, err)
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleDSRErase(w http.ResponseWriter, r *http.Request) {
	in, ok := decode[struct {
		CID string `json:"cid"`
	}](w, r)
	if !ok {
		return
	}
	erasureID, scopes, err := s.GDPR.Erase(r.Context(), auth.FromContext(r.Context()), in.CID)
	if err != nil {
		s.logErr(r, err)
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"erasure_id": erasureID, "scopes": scopes})
}

func (s *Server) handleDSRExport(w http.ResponseWriter, r *http.Request) {
	out, err := s.GDPR.Export(r.Context(), auth.FromContext(r.Context()), r.URL.Query().Get("cid"))
	if err != nil {
		s.logErr(r, err)
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
