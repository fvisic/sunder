package api

// P2.5 self-service privacy portal HTTP surface. Deliberately NOT behind
// the client-credential middleware: citizens authenticate with a magic
// link. Sessions ride an HttpOnly cookie; every route is rate-limited per
// source IP through the shared limiter; the static SPA is CSP-locked and
// self-contained.

import (
	"net"
	"net/http"
	"time"

	"github.com/fvisic/sunder/internal/service"
)

const portalSessionCookie = "sunder_portal"

// portalLimit applies a per-IP rate limit to portal routes (magic-link
// starts are abuse bait: mail bombing, token grinding).
func (s *Server) portalLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}
		if s.Limiter != nil && !s.Limiter.Allow("portal:"+ip, 30) {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate_limited"})
			return
		}
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
	http.SetCookie(w, &http.Cookie{
		Name: portalSessionCookie, Value: session, Path: "/portal",
		HttpOnly: true, Secure: s.Cfg.TLSCert != "", SameSite: http.SameSiteStrictMode,
		MaxAge: int((30 * time.Minute).Seconds()),
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
	token, err := s.Portal.RequestErase(r.Context(), personID)
	if err != nil {
		s.logErr(r, err)
		writeErr(w, err)
		return
	}
	// The confirmation token goes back to the SAME authenticated session -
	// the second step guards against a hijacked session firing erasure in
	// one call, and gives the UI a deliberate "are you sure" moment.
	writeJSON(w, http.StatusOK, map[string]string{"confirm_token": token})
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
	s.mux.HandleFunc("POST /portal/api/start", s.portalLimit(s.handlePortalStart))
	s.mux.HandleFunc("POST /portal/api/session", s.portalLimit(s.handlePortalSession))
	s.mux.HandleFunc("GET /portal/api/me", s.portalLimit(s.portalSession(s.handlePortalData)))
	s.mux.HandleFunc("POST /portal/api/consent", s.portalLimit(s.portalSession(s.handlePortalConsent)))
	s.mux.HandleFunc("POST /portal/api/erase", s.portalLimit(s.portalSession(s.handlePortalEraseRequest)))
	s.mux.HandleFunc("POST /portal/api/erase/confirm", s.portalLimit(s.portalSession(s.handlePortalEraseConfirm)))
	s.mux.HandleFunc("GET /portal/", func(w http.ResponseWriter, r *http.Request) {
		// Locked-down CSP: the SPA is a single self-contained file.
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(portalSPA)
	})
}

var _ = service.PortalMailerScope // documented linkage
