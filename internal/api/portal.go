package api

// P2.5 self-service privacy portal HTTP surface. Deliberately NOT behind
// the client-credential middleware: citizens authenticate with a magic
// link. Sessions ride an HttpOnly cookie; every route is rate-limited per
// source IP through the shared limiter; the static SPA is CSP-locked and
// self-contained.

import (
	"crypto/rand"
	"encoding/base64"
	"net"
	"net/http"
	"strings"

	"github.com/fvisic/sunder/internal/service"
)

const portalSessionCookie = "sunder_portal"

// portalClientIP identifies the requester for rate limiting. RemoteAddr by
// default; a proxy header only when the operator explicitly names one
// (SUNDER_PORTAL_CLIENT_IP_HEADER) - a blindly trusted header is a limiter
// bypass, and behind an ingress RemoteAddr alone collapses every citizen
// into one bucket.
func (s *Server) portalClientIP(r *http.Request) string {
	if h := s.Cfg.PortalClientIPHeader; h != "" {
		if v := r.Header.Get(h); v != "" {
			// The RIGHT-most entry is the address the adjacent proxy
			// appended; the left-most is whatever the caller sent, so
			// reading it hands every requester a fresh rate-limit bucket
			//. With more than one trusted hop, skip that many
			// entries from the right.
			parts := strings.Split(v, ",")
			idx := len(parts) - 1 - s.Cfg.PortalTrustedProxyHops
			if idx < 0 {
				idx = 0
			}
			if idx > len(parts)-1 {
				idx = len(parts) - 1
			}
			if ip := strings.TrimSpace(parts[idx]); ip != "" {
				return ip
			}
		}
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// portalLimit applies a PER-ROUTE, per-requester rate limit: the mail-
// sending route is abuse bait and must be far stricter than reading your
// own data, and one bucket for all six routes let 31 requests lock every
// citizen out of the portal entirely.
func (s *Server) portalLimit(bucket string, limit int, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.Limiter != nil && !s.Limiter.Allow("portal:"+bucket+":"+s.portalClientIP(r), limit) {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate_limited"})
			return
		}
		// Portal responses carry decrypted PII and the cross-scope audit
		// trail: never cacheable, never in bfcache or on disk after the
		// session dies.
		w.Header().Set("Cache-Control", "no-store, max-age=0")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next(w, r)
	}
}

func (s *Server) handlePortalStart(w http.ResponseWriter, r *http.Request) {
	in, ok := decode[struct {
		Email string `json:"email"`
	}](w, r)
	if !ok {
		return
	}
	if err := s.Portal.Start(r.Context(), in.Email); err != nil {
		s.logErr(r, err)
		// Same body as success: the response must not reveal whether the
		// address exists or the mailer works.
	}
	writeJSON(w, http.StatusAccepted, map[string]string{
		"status": "if the address is known, a login link is on its way",
	})
}

func (s *Server) handlePortalSession(w http.ResponseWriter, r *http.Request) {
	in, ok := decode[struct {
		Token string `json:"token"`
	}](w, r)
	if !ok {
		return
	}
	session, err := s.Portal.Redeem(r.Context(), in.Token)
	if err != nil {
		s.logErr(r, err)
		writeErr(w, err)
		return
	}
	// Secure unless explicitly opted out for local development: TLS usually
	// terminates at the ingress, so keying this off our own certificate
	// left the cookie unprotected in the standard deployment.
	http.SetCookie(w, &http.Cookie{
		Name: portalSessionCookie, Value: session, Path: "/portal",
		HttpOnly: true, Secure: !s.Cfg.PortalCookieInsecure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(service.PortalSessionTTL.Seconds()),
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "session started"})
}

// portalSession authenticates the cookie and hands the person id to next.
func (s *Server) portalSession(next func(w http.ResponseWriter, r *http.Request, personID string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(portalSessionCookie)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "no_session"})
			return
		}
		personID, err := s.Portal.SessionPerson(r.Context(), c.Value)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "session_expired"})
			return
		}
		next(w, r, personID)
	}
}

func (s *Server) handlePortalData(w http.ResponseWriter, r *http.Request, personID string) {
	out, err := s.Portal.Data(r.Context(), personID)
	if err != nil {
		s.logErr(r, err)
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handlePortalConsent(w http.ResponseWriter, r *http.Request, personID string) {
	in, ok := decode[struct {
		CID     string `json:"cid"`
		Purpose string `json:"purpose"`
		Granted bool   `json:"granted"`
	}](w, r)
	if !ok {
		return
	}
	if err := s.Portal.SetConsent(r.Context(), personID, in.CID, in.Purpose, in.Granted); err != nil {
		s.logErr(r, err)
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "recorded"})
}

func (s *Server) handlePortalEraseRequest(w http.ResponseWriter, r *http.Request, personID string) {
	if err := s.Portal.RequestErase(r.Context(), personID); err != nil {
		s.logErr(r, err)
		writeErr(w, err)
		return
	}
	// The confirmation token is NOT in this response: it is mailed to the
	// address on file, so holding the session cookie is not enough to
	// finish an irreversible cross-scope erasure.
	writeJSON(w, http.StatusAccepted, map[string]string{
		"status": "a confirmation link has been sent to the address on file",
	})
}

func (s *Server) handlePortalEraseConfirm(w http.ResponseWriter, r *http.Request, personID string) {
	in, ok := decode[struct {
		ConfirmToken string `json:"confirm_token"`
	}](w, r)
	if !ok {
		return
	}
	id, scopes, err := s.Portal.ConfirmErase(r.Context(), personID, in.ConfirmToken)
	if err != nil {
		s.logErr(r, err)
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"erasure_id": id, "scopes": scopes})
}

// registerPortal wires the portal routes and the static SPA.
func (s *Server) registerPortal() {
	if s.Portal == nil {
		return
	}
	mux := s.portalMux()
	s.mux.Handle("/portal/", mux)
}

// portalMux builds the portal routes. Returned separately so the portal can
// also be served on its own listener (SUNDER_PORTAL_LISTEN), which is how a
// deployment keeps mTLS on the API while citizens reach the portal without
// a client certificate.
func (s *Server) portalMux() *http.ServeMux {
	mux := http.NewServeMux()
	// Mail-sending is the abuse-bait route; reads are cheap and shared.
	mux.HandleFunc("POST /portal/api/start", s.portalLimit("start", 5, s.handlePortalStart))
	mux.HandleFunc("POST /portal/api/session", s.portalLimit("session", 20, s.handlePortalSession))
	mux.HandleFunc("GET /portal/api/me", s.portalLimit("read", 60, s.portalSession(s.handlePortalData)))
	mux.HandleFunc("POST /portal/api/consent", s.portalLimit("write", 30, s.portalSession(s.handlePortalConsent)))
	mux.HandleFunc("POST /portal/api/erase", s.portalLimit("erase", 5, s.portalSession(s.handlePortalEraseRequest)))
	mux.HandleFunc("POST /portal/api/erase/confirm", s.portalLimit("erase", 5, s.portalSession(s.handlePortalEraseConfirm)))
	mux.HandleFunc("POST /portal/api/logout", s.portalLimit("write", 30, s.handlePortalLogout))
	mux.HandleFunc("GET /portal/", s.handlePortalSPA)
	return mux
}

func (s *Server) handlePortalLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(portalSessionCookie); err == nil {
		if err := s.Portal.Logout(r.Context(), c.Value); err != nil {
			s.logErr(r, err)
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name: portalSessionCookie, Value: "", Path: "/portal",
		HttpOnly: true, Secure: !s.Cfg.PortalCookieInsecure,
		SameSite: http.SameSiteStrictMode, MaxAge: -1,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "signed out"})
}

// handlePortalSPA serves the single-file UI. The script carries a
// per-response nonce and the page has no inline event handlers, so the CSP
// needs no 'unsafe-inline' and actually mitigates XSS.
func (s *Server) handlePortalSPA(w http.ResponseWriter, r *http.Request) {
	nonceRaw := make([]byte, 16)
	if _, err := rand.Read(nonceRaw); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	nonce := base64.StdEncoding.EncodeToString(nonceRaw)
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; script-src 'nonce-"+nonce+"'; style-src 'unsafe-inline'; "+
			"connect-src 'self'; img-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(strings.Replace(string(portalSPA), "__NONCE__", nonce, 1)))
}
