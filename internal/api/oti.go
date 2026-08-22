package api

import (
	"net/http"
	"time"

	"github.com/fvisic/sunder/internal/auth"
)

func (s *Server) handleOTIIssue(w http.ResponseWriter, r *http.Request) {
	in, ok := decode[struct {
		CID      string `json:"cid"`
		Purpose  string `json:"purpose"`
		Audience string `json:"audience"`
	}](w, r)
	if !ok {
		return
	}
	token, expiresAt, err := s.OTI.Issue(r.Context(), auth.FromContext(r.Context()), in.CID, in.Purpose, in.Audience)
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
	cid, err := s.OTI.Verify(r.Context(), auth.FromContext(r.Context()), in.Token, in.Purpose, in.Audience)
	if err != nil {
		s.logErr(r, err)
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"cid": cid})
}
