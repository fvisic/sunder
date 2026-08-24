package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/service"
)

func (s *Server) handleOTIIssue(w http.ResponseWriter, r *http.Request) {
	// Strict decoding HERE only: a typo'd "share_predicate" key silently
	// issuing a token WITHOUT the predicate would be fail-open for the
	// integrator. Other endpoints stay lenient for forward compatibility.
	var in service.IssueInput
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_json", "detail": err.Error()})
		return
	}
	token, expiresAt, err := s.OTI.IssueFull(r.Context(), auth.FromContext(r.Context()), in)
	if err != nil {
		s.logErr(r, err)
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{
		"token": token, "expires_at": expiresAt.Format(time.RFC3339),
	})
}

func (s *Server) handleOTIVerify(w http.ResponseWriter, r *http.Request) {
	in, ok := decode[struct {
		Token    string `json:"token"`
		Purpose  string `json:"purpose"`
		Audience string `json:"audience"`
	}](w, r)
	if !ok {
		return
	}
	out, err := s.OTI.VerifyFull(r.Context(), auth.FromContext(r.Context()), in.Token, in.Purpose, in.Audience)
	if err != nil {
		s.logErr(r, err)
		writeErr(w, err)
		return
	}
	resp := map[string]any{"cid": out.CID}
	if len(out.Shared) > 0 {
		resp["shared"] = out.Shared
	}
	if len(out.Predicates) > 0 {
		resp["predicates"] = out.Predicates
	}
	writeJSON(w, http.StatusOK, resp)
}
