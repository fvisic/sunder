package api

// Value tokenization endpoints (F4). Single-item calls ride on the
// caller's actions alone; BULK calls additionally spend an unlock token
// (purpose "bulk-tokens") no matter how the instance is configured -
// Databunker gates its bulk dumps the same way, and bulk is where quiet
// exfiltration lives.

import (
	"errors"
	"net/http"

	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/service"
)

func (s *Server) handleTokenCreate(w http.ResponseWriter, r *http.Request) {
	client := auth.FromContext(r.Context())
	in, ok := decode[service.TokenizeInput](w, r)
	if !ok {
		return
	}
	token, err := s.ValueTokens.Tokenize(r.Context(), client, in)
	if err != nil {
		s.logErr(r, err)
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"token": token})
}

func (s *Server) handleTokenRead(w http.ResponseWriter, r *http.Request) {
	client := auth.FromContext(r.Context())
	value, err := s.ValueTokens.Detokenize(r.Context(), client, r.PathValue("token"))
	if err != nil {
		s.logErr(r, err)
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"value": value})
}

func (s *Server) handleTokenDelete(w http.ResponseWriter, r *http.Request) {
	client := auth.FromContext(r.Context())
	if err := s.ValueTokens.Delete(r.Context(), client, r.PathValue("token")); err != nil {
		s.logErr(r, err)
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// requireUnlock spends the bulk unlock token or refuses the request.
func (s *Server) requireUnlock(w http.ResponseWriter, r *http.Request, purpose string) bool {
	client := auth.FromContext(r.Context())
	if err := s.Unlock.Consume(r.Context(), client, purpose, r.Header.Get("X-Sunder-Unlock")); err != nil {
		if errors.Is(err, service.ErrUnlockRequired) {
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error":  "unlock_required",
				"detail": "mint a token at POST /v1/admin/unlock {\"purpose\":\"" + purpose + "\"} and send it as X-Sunder-Unlock"})
			return false
		}
		s.logErr(r, err)
		writeErr(w, err)
		return false
	}
	return true
}

func (s *Server) handleTokenBulkCreate(w http.ResponseWriter, r *http.Request) {
	client := auth.FromContext(r.Context())
	// Action and body shape are checked BEFORE the unlock token is spent
	// (M7): a request that would never tokenize must not burn a single-use
	// token or write an "intent spent" audit row.
	if !client.Can(auth.ActTokensCreate) {
		writeErr(w, service.ErrForbidden)
		return
	}
	in, ok := decode[struct {
		Items []service.TokenizeInput `json:"items"`
	}](w, r)
	if !ok {
		return
	}
	// Shape-check the whole batch BEFORE spending the single-use unlock
	// token (L9): a malformed item must not burn the token.
	if err := s.ValueTokens.ValidateInputs(in.Items); err != nil {
		writeErr(w, err)
		return
	}
	if !s.requireUnlock(w, r, "bulk-tokens") {
		return
	}
	tokens, err := s.ValueTokens.TokenizeBulk(r.Context(), client, in.Items)
	if err != nil {
		s.logErr(r, err)
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"tokens": tokens})
}

func (s *Server) handleTokenBulkRead(w http.ResponseWriter, r *http.Request) {
	client := auth.FromContext(r.Context())
	if !client.Can(auth.ActTokensRead) {
		writeErr(w, service.ErrForbidden)
		return
	}
	in, ok := decode[struct {
		Tokens []string `json:"tokens"`
	}](w, r)
	if !ok {
		return
	}
	if !s.requireUnlock(w, r, "bulk-tokens") {
		return
	}
	values, err := s.ValueTokens.DetokenizeBulk(r.Context(), client, in.Tokens)
	if err != nil {
		s.logErr(r, err)
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"values": values})
}
