package api

import (
	"context"
	"net/http"
	"time"

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
	// A missing granted field must be a validation error, never a silent
	// consent withdrawal.
	if in.Granted == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "validation", "detail": "granted (true/false) is required"})
		return
	}
	granted := *in.Granted
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
		// Cascade names the link types (guardian|member|owner) whose linked
		// children are erased along with this person (F7). Omitted = the
		// children are only listed, never touched.
		Cascade []string `json:"cascade"`
	}](w, r)
	if !ok {
		return
	}
	// A cascade commits ONE TRANSACTION PER PERSON, so a cancelled request
	// context part-way through leaves children un-erased. Detaching the
	// cancellation (with a deadline of its own) means the officer's HTTP
	// client giving up no longer decides how much of an Article 17 request
	// is carried out; the durable plan makes what is left resumable either
	// way (GDPR-ERASURE-4).
	eraseCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), cascadeTimeout)
	defer cancel()
	erasureID, scopes, linked, err := s.GDPR.EraseWithCascade(eraseCtx, auth.FromContext(r.Context()), in.CID, in.Cascade)
	if err != nil {
		s.logErr(r, err)
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"erasure_id": erasureID, "scopes": scopes, "linked": linked})
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

// cascadeTimeout bounds a detached cascade erasure. Generous: each child is
// its own transaction plus its webhook fan-out, and the alternative to
// finishing is a partial erasure.
const cascadeTimeout = 10 * time.Minute
