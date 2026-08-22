package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/service"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeErr maps service sentinel errors to HTTP statuses. Validation detail
// is safe to return; everything else is generic to avoid oracle behavior.
func writeErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, service.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
	case errors.Is(err, service.ErrForbidden):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
	case errors.Is(err, service.ErrPurposeNotAllowed):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "purpose_not_allowed"})
	case errors.Is(err, service.ErrConsentDenied):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "consent_denied"})
	case errors.Is(err, service.ErrValidation):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "validation", "detail": err.Error()})
	case errors.Is(err, service.ErrTokenUsed):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "token_used"})
	case errors.Is(err, service.ErrTokenExpired):
		writeJSON(w, http.StatusGone, map[string]string{"error": "token_expired"})
	case errors.Is(err, service.ErrAudienceMismatch):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "audience_mismatch"})
	case errors.Is(err, service.ErrTokenInvalid):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "token_invalid"})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
	}
}

func decode[T any](w http.ResponseWriter, r *http.Request) (T, bool) {
	var v T
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_json"})
		return v, false
	}
	return v, true
}

func (s *Server) handleContactsRegister(w http.ResponseWriter, r *http.Request) {
	in, ok := decode[service.RegisterInput](w, r)
	if !ok {
		return
	}
	cid, err := s.Contacts.Register(r.Context(), auth.FromContext(r.Context()), in)
	if err != nil {
		s.logErr(r, err)
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"cid": cid})
}

func (s *Server) handleScopesIssue(w http.ResponseWriter, r *http.Request) {
	in, ok := decode[struct {
		Scope string `json:"scope"`
	}](w, r)
	if !ok {
		return
	}
	cid, err := s.Contacts.IssueScopedCid(r.Context(), auth.FromContext(r.Context()), r.PathValue("cid"), in.Scope)
	if err != nil {
		s.logErr(r, err)
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"cid": cid})
}

func (s *Server) handleAttributeGet(w http.ResponseWriter, r *http.Request) {
	val, err := s.Contacts.GetAttribute(r.Context(),
		auth.FromContext(r.Context()), r.PathValue("cid"), r.PathValue("name"), r.URL.Query().Get("purpose"))
	if err != nil {
		s.logErr(r, err)
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"value": val})
}

// logErr records internal failures without request payloads (no PII in logs).
func (s *Server) logErr(r *http.Request, err error) {
	for _, expected := range []error{
		service.ErrNotFound, service.ErrForbidden, service.ErrPurposeNotAllowed,
		service.ErrValidation, service.ErrTokenInvalid, service.ErrTokenExpired,
		service.ErrTokenUsed, service.ErrAudienceMismatch, service.ErrConsentDenied,
	} {
		if errors.Is(err, expected) {
			return
		}
	}
	s.Log.Error("handler error", "pattern", r.Pattern, "err", err.Error())
}
