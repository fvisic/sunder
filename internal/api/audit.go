package api

import (
	"fmt"
	"net/http"

	"github.com/fvisic/sunder/internal/audit"
	"github.com/fvisic/sunder/internal/auth"
)

// The read-only audit surface. `sunder verify-audit` has always been able
// to recompute the chain from the CLI; these two endpoints expose the same
// verdict over HTTP so a dashboard - or the playground's chain panel - can
// show it without shell access to the host.
//
// Read-only and PII-free by construction: the verdict is a boolean plus a
// position, and the chain view carries actions and hash links, never cids
// or detail blobs. What it does reveal is activity volume and client ids,
// which is why it needs its own action (audit.verify) instead of riding on
// an existing admin privilege.
//
// Not itself audited: a verification is a read of the tamper evidence, and
// appending a row per check would make a monitoring loop the loudest
// writer in the chain it is checking. The CLI has the same stance.

func (s *Server) handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	client := auth.FromContext(r.Context())
	if !client.Can(auth.ActAuditVerify) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	// Verify walks the whole sealed chain: cheap on a demo, linear on a
	// real instance. Rate-limited per client so a monitoring loop with a
	// tight interval cannot turn it into a self-inflicted table scan storm.
	if !s.Limiter.Allow("audit-verify:"+client.ID, client.RateLimit) {
		s.Metrics.Inc(fmt.Sprintf(`sunder_ratelimited_total{client=%q}`, client.ID))
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate_limited"})
		return
	}
	broken, reason, pending, err := audit.Verify(r.Context(), s.Store.Pool)
	if err != nil {
		s.logErr(r, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	out := map[string]any{"ok": broken == 0, "pending": pending, "sealing": audit.Mode()}
	if broken != 0 {
		// A break is reported, not hidden behind a 500: the caller asked
		// whether the chain is intact and the answer is "no, here".
		out["broken_chain_seq"], out["reason"] = broken, reason
	} else if audit.Mode() == audit.ModeSync && pending > 0 {
		// Under sync sealing, pending rows cannot be in-flight work: sync
		// seals at insert. A backlog means rows stranded OUTSIDE the chain,
		// which the CLI already refuses to call success - and one surface
		// answering "intact" where the other answers "broken" would make
		// the verdict worthless.
		out["ok"] = false
		out["reason"] = fmt.Sprintf("%d unsealed row(s) under sync sealing: outside the chain, "+
			"and they will not seal on their own - drain them with `sunder sealer -once` "+
			"under SUNDER_AUDIT_SEALING=async", pending)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleAuditChain(w http.ResponseWriter, r *http.Request) {
	client := auth.FromContext(r.Context())
	if !client.Can(auth.ActAuditVerify) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	if !s.Limiter.Allow("audit-chain:"+client.ID, client.RateLimit) {
		s.Metrics.Inc(fmt.Sprintf(`sunder_ratelimited_total{client=%q}`, client.ID))
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate_limited"})
		return
	}
	limit := 20
	if v := r.URL.Query().Get("limit"); v != "" {
		parsed, err := parsePositiveInt(v)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "validation", "detail": "limit must be a positive integer"})
			return
		}
		limit = parsed
	}
	rows, err := audit.Tail(r.Context(), s.Store.Pool, limit)
	if err != nil {
		s.logErr(r, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	unsealed, err := audit.UnsealedCount(r.Context(), s.Store.Pool)
	if err != nil {
		s.logErr(r, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	if rows == nil {
		rows = []audit.ChainRow{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"rows": rows, "unsealed": unsealed})
}

// parsePositiveInt parses a positive integer without pulling strconv error
// text into a response body. The digit cap only guards overflow: any
// well-formed number is accepted here and clamped by audit.Tail, which is
// what the contract promises ("values above 200 are clamped") - rejecting
// limit=99999 while accepting limit=9999 was an accident of the cap.
func parsePositiveInt(s string) (int, error) {
	n := 0
	if s == "" || len(s) > 9 {
		return 0, fmt.Errorf("out of range")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("not a number")
		}
		n = n*10 + int(s[i]-'0')
	}
	if n == 0 {
		return 0, fmt.Errorf("must be positive")
	}
	return n, nil
}
