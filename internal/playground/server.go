package playground

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/fvisic/sunder/internal/ratelimit"
)

const sessionCookie = "sunder_playground"

// Config wires the playground to a running Sunder instance.
type Config struct {
	// BaseURL is the instance the steps are executed against.
	BaseURL string
	// Creds maps role name -> "<client_id>.<secret>". Server-side only.
	Creds map[string]string
	// Scenarios in display order.
	Scenarios []*Scenario
	// RatePerMin caps requests per source IP. A demo that anyone can reach
	// is also a way to spend someone else's database.
	RatePerMin int
	// CookieSecure marks the session cookie Secure; set it whenever the
	// playground is served over TLS.
	CookieSecure bool
	SessionTTL   time.Duration
	MaxSessions  int
	// TrustedProxyHops mirrors the portal's stance: a blindly trusted
	// X-Forwarded-For is a rate-limit bypass, so the header is only read
	// when the operator names it.
	ClientIPHeader   string
	TrustedProxyHops int
	// WebhookSecret verifies the erasure webhooks this playground receives
	// (the inbox panel).
	WebhookSecret string
	Log           *slog.Logger
}

// Server is the playground HTTP surface.
type Server struct {
	cfg      Config
	runner   *Runner
	sessions *Sessions
	limiter  ratelimit.Allower
	byID     map[string]*Scenario
	log      *slog.Logger
	inbox    *inbox
	ui       fs.FS
	index    []byte
	// reference is the RapiDoc document for the API-reference tab.
	reference []byte
	specs     specCache
}

const defaultRatePerMin = 120

// NewServer validates the configuration and builds the handler.
func NewServer(cfg Config) (*Server, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("playground: base URL of the Sunder instance is required")
	}
	cfg.BaseURL = strings.TrimSuffix(cfg.BaseURL, "/")
	if len(cfg.Scenarios) == 0 {
		return nil, fmt.Errorf("playground: no scenarios loaded")
	}
	if cfg.RatePerMin <= 0 {
		cfg.RatePerMin = defaultRatePerMin
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	sub, err := fs.Sub(uiFS, "ui")
	if err != nil {
		return nil, err
	}
	index, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		return nil, err
	}
	reference, err := fs.ReadFile(sub, "reference.html")
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:       cfg,
		runner:    &Runner{BaseURL: cfg.BaseURL, Creds: cfg.Creds, Client: &http.Client{Timeout: 15 * time.Second}},
		sessions:  NewSessions(cfg.SessionTTL, cfg.MaxSessions),
		limiter:   ratelimit.NewLimiter(),
		byID:      map[string]*Scenario{},
		log:       cfg.Log,
		inbox:     newInbox(cfg.WebhookSecret),
		ui:        sub,
		index:     index,
		reference: reference,
	}
	for _, sc := range cfg.Scenarios {
		s.byID[sc.ID] = sc
	}
	return s, nil
}

// Handler returns the routed handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /{$}", s.limited(s.handleIndex))
	mux.HandleFunc("GET /ui/{file}", s.limited(s.handleAsset))
	mux.HandleFunc("GET /reference", s.limited(s.handleReference))
	mux.HandleFunc("GET /reference/openapi.yaml", s.limited(s.handleSpec))
	mux.HandleFunc("GET /ui/vendor/rapidoc-min.js", s.limited(s.handleVendorAsset))
	mux.HandleFunc("GET /api/scenarios", s.limited(s.handleScenarios))
	mux.HandleFunc("POST /api/run", s.limited(s.handleRun))
	mux.HandleFunc("POST /api/reset", s.limited(s.handleReset))
	// The erasure webhook receiver: Sunder posts here, not a browser, so it
	// carries no session and is rate-limited under its own bucket.
	mux.HandleFunc("POST /hooks/erasure", s.limited(s.handleWebhook))
	mux.HandleFunc("GET /api/inbox", s.limited(s.handleInbox))
	return mux
}

// limited applies the per-IP rate limit and the response headers every
// playground route shares.
func (s *Server) limited(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.limiter.Allow("pg:"+s.clientIP(r), s.cfg.RatePerMin) {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate_limited"})
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next(w, r)
	}
}

func (s *Server) clientIP(r *http.Request) string {
	if h := s.cfg.ClientIPHeader; h != "" {
		if v := r.Header.Get(h); v != "" {
			parts := strings.Split(v, ",")
			idx := len(parts) - 1 - s.cfg.TrustedProxyHops
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

// session resolves (and refreshes) the visitor's cookie.
func (s *Server) session(w http.ResponseWriter, r *http.Request) *Session {
	var id string
	if c, err := r.Cookie(sessionCookie); err == nil {
		id = c.Value
	}
	sess := s.sessions.Get(id)
	if sess.ID != id {
		http.SetCookie(w, &http.Cookie{
			Name: sessionCookie, Value: sess.ID, Path: "/",
			HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteLaxMode,
			MaxAge: int((2 * time.Hour).Seconds()),
		})
	}
	return sess
}

// handleIndex serves the SPA shell. The CSP is strict and needs no
// 'unsafe-inline': the script and the stylesheet are separate same-origin
// files, so there is nothing inline to allow (the API-reference tab lives
// in its own document for the same reason).
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	s.session(w, r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "+
			"img-src 'self' data:; font-src 'self'; frame-src 'self'; base-uri 'none'; form-action 'none'")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(s.index)
}

func (s *Server) handleAsset(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	// Only the files that ship in the binary, by exact name: no path
	// traversal to reason about because no path is ever constructed.
	ctype, ok := map[string]string{
		"app.js":    "application/javascript; charset=utf-8",
		"style.css": "text/css; charset=utf-8",
	}[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	raw, err := s.uiFile(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(raw)
}

// scenarioView is the browser-facing shape of a scenario: the steps with
// their teaching notes, plus whether the operator actually configured the
// credentials each role needs.
type scenarioView struct {
	*Scenario
	MissingRoles []string `json:"missing_roles"`
}

func (s *Server) handleScenarios(w http.ResponseWriter, r *http.Request) {
	sess := s.session(w, r)
	views := make([]scenarioView, 0, len(s.cfg.Scenarios))
	for _, sc := range s.cfg.Scenarios {
		var missing []string
		for _, name := range sc.RoleNames() {
			if s.cfg.Creds[name] == "" {
				missing = append(missing, name)
			}
		}
		views = append(views, scenarioView{Scenario: sc, MissingRoles: missing})
	}
	vars, results := sess.Snapshot()
	writeJSON(w, http.StatusOK, map[string]any{
		"instance":  s.cfg.BaseURL,
		"scenarios": views,
		"vars":      vars,
		"results":   results,
	})
}

func (s *Server) handleRun(w http.ResponseWriter, r *http.Request) {
	sess := s.session(w, r)
	var in struct {
		Scenario string `json:"scenario"`
		Step     int    `json:"step"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_json"})
		return
	}
	sc, ok := s.byID[in.Scenario]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown_scenario"})
		return
	}
	if in.Step < 0 || in.Step >= len(sc.Steps) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown_step"})
		return
	}
	var res *StepResult
	// One step at a time per visitor: a double-clicked Run must not have two
	// goroutines writing the same variable map.
	sess.Do(func(vars map[string]string) {
		res = s.runner.RunStep(r.Context(), sc, in.Step, vars)
	})
	sess.Record(fmt.Sprintf("%s/%d", sc.ID, in.Step), res)
	writeJSON(w, http.StatusOK, map[string]any{"result": res, "vars": sess.Vars()})
}

func (s *Server) handleReset(w http.ResponseWriter, r *http.Request) {
	sess := s.session(w, r)
	if fresh := s.sessions.Reset(sess.ID); fresh != nil {
		sess = fresh
	}
	writeJSON(w, http.StatusOK, map[string]any{"vars": sess.Vars()})
}

// uiFile reads one embedded asset by exact name.
func (s *Server) uiFile(name string) ([]byte, error) {
	return fs.ReadFile(s.ui, name)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
