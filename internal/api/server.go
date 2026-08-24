// Package api wires HTTP routing, health endpoints and observability.
package api

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	apispec "github.com/fvisic/sunder/api"
	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/config"
	"github.com/fvisic/sunder/internal/crypto"
	"github.com/fvisic/sunder/internal/metrics"
	"github.com/fvisic/sunder/internal/ratelimit"
	"github.com/fvisic/sunder/internal/service"
	"github.com/fvisic/sunder/internal/store"
)

// Server holds shared dependencies for all handlers.
type Server struct {
	Cfg        config.Config
	Portal     *service.Portal
	Store      *store.Store
	Metrics    *metrics.Registry
	Log        *slog.Logger
	Contacts   *service.Contacts
	OTI        *service.OTI
	GDPR       *service.GDPR
	Auth       *auth.Authenticator
	Limiter    ratelimit.Allower
	Detector   ratelimit.MissCounter
	enumWarned sync.Map // client id -> last enumeration warning (F3 latch)
	mux        *http.ServeMux
}

// OpenKeystore builds the configured keystore driver, wrapped
// in an in-memory cache (key material per name is immutable, so caching is
// safe and keeps keystore I/O off the request hot path).
func OpenKeystore(cfg config.Config) crypto.Keystore {
	var inner crypto.Keystore
	switch cfg.Keystore {
	case "vault":
		inner = &crypto.VaultKeystore{Addr: cfg.VaultAddr, Token: cfg.VaultToken, Mount: cfg.VaultMount}
	case "pkcs11":
		inner = &crypto.PKCS11Keystore{}
	default:
		inner = &crypto.FileKeystore{Dir: cfg.KeystorePath}
	}
	return crypto.NewCachingKeystore(inner)
}

// OpenEngine returns the crypto engine for cfg: a RemoteEngine speaking to
// the `sunder signer` process when SUNDER_SIGNER_SOCKET is set (the main
// process then never holds key material), otherwise an in-process
// LocalEngine over the configured keystore.
func OpenEngine(cfg config.Config) crypto.Engine {
	if cfg.SignerSocket != "" {
		return crypto.NewRemoteEngine(cfg.SignerSocket)
	}
	return crypto.NewLocalEngine(OpenKeystore(cfg))
}

// New builds the server, bootstraps key material (the strict keystore never
// creates keys per request - see crypto.Keystore) and registers routes.
func New(cfg config.Config, st *store.Store) (*Server, error) {
	s := &Server{
		Cfg:     cfg,
		Store:   st,
		Metrics: metrics.New(),
		Log:     slog.New(slog.NewJSONHandler(os.Stderr, nil)),
		mux:     http.NewServeMux(),
	}
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
	s.mux.HandleFunc("GET /readyz", s.handleReadyz)
	// The service serves its own API contract (also in the repo under
	// api/openapi.yaml; point any Swagger UI / Redoc at this endpoint).
	s.mux.HandleFunc("GET /openapi.yaml", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write(apispec.OpenAPI)
	})
	// Per-client counters reveal client ids and activity; an optional token
	// gates the scrape endpoint where network isolation is not enough.
	metricsHandler := http.Handler(s.Metrics)
	if cfg.MetricsToken != "" {
		metricsHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+cfg.MetricsToken)) != 1 {
				w.Header().Set("WWW-Authenticate", "Bearer")
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
				return
			}
			s.Metrics.ServeHTTP(w, r)
		})
	}
	s.mux.Handle("GET /metrics", metricsHandler)

	if st != nil {
		eng := OpenEngine(cfg)
		ring := &service.KeyRing{Pool: st.Pool}
		// Bootstrap/rotation is the ONLY place key material comes into
		// existence (the keystore itself is strict).
		if err := ring.EnsureAll(context.Background(), eng); err != nil {
			return nil, fmt.Errorf("keystore bootstrap: %w", err)
		}
		pii := crypto.NewPIIBox(eng)
		pii.Alg = cfg.PIIAlg
		s.Contacts = &service.Contacts{Pool: st.Pool, Tok: crypto.NewTokenizer(eng), PII: pii, Ring: ring}
		s.OTI = &service.OTI{Pool: st.Pool, Eng: eng, Ring: ring, Contacts: s.Contacts, TTL: cfg.OTITTL}
		s.GDPR = &service.GDPR{Pool: st.Pool, Contacts: s.Contacts,
			HTTPTimeout: cfg.WebhookTimeout, MaxAttempts: cfg.WebhookMaxAttempts}
		if cfg.PortalEnabled {
			s.Portal = &service.Portal{GDPR: s.GDPR, Contacts: s.Contacts, BaseURL: cfg.PortalBaseURL}
		}
		s.Auth = &auth.Authenticator{Pool: st.Pool}

		if cfg.RedisAddr != "" {
			// Multi-replica deployments share windows via Redis; the same
			// instance serves both the limiter and the enumeration detector.
			rl := ratelimit.NewRedisLimiter(cfg.RedisAddr, cfg.RedisPassword, cfg.RedisFailClosed)
			rl.OnFailure = func() {
				s.Metrics.Inc(`sunder_ratelimit_backend_failures_total`)
			}
			s.Limiter, s.Detector = rl, rl
		} else {
			s.Limiter = ratelimit.NewLimiter()
			s.Detector = ratelimit.NewDetector()
		}

		v1 := http.NewServeMux()
		v1.HandleFunc("POST /v1/contacts", s.handleContactsRegister)
		v1.HandleFunc("POST /v1/contacts/{cid}/scopes", s.handleScopesIssue)
		v1.HandleFunc("GET /v1/contacts/{cid}/attributes/{name}", s.handleAttributeGet)
		v1.HandleFunc("POST /v1/lookup", s.handleLookup)
		v1.HandleFunc("POST /v1/oti", s.handleOTIIssue)
		v1.HandleFunc("POST /v1/oti/verify", s.handleOTIVerify)
		v1.HandleFunc("POST /v1/claims/external", s.handleExternalClaims)
		v1.HandleFunc("POST /v1/consent", s.handleConsentSet)
		v1.HandleFunc("GET /v1/consent/{cid}", s.handleConsentList)
		v1.HandleFunc("GET /v1/dsr/access", s.handleDSRAccess)
		v1.HandleFunc("POST /v1/dsr/erase", s.handleDSRErase)
		v1.HandleFunc("GET /v1/dsr/export", s.handleDSRExport)
		s.Auth.Limiter = s.Limiter
		s.mux.Handle("/v1/", s.Auth.Middleware(capturePattern(v1)))
		// The portal is only mounted on the main listener when it has no
		// dedicated one: with mTLS on the API, citizens could never present
		// a client certificate.
		if s.Portal != nil && s.Cfg.PortalListen == "" {
			s.registerPortal()
		}
	}
	return s, nil
}

// Handler returns the outermost HTTP handler (middleware applied).
func (s *Server) Handler() http.Handler { return s.instrument(s.mux) }

// patternKey carries a *string through the request context so the route
// pattern stamped by the INNER v1 mux (on the shallow request copy the
// auth middleware makes) reaches the outer instrument wrapper - reading
// r.Pattern out here would always see "/v1/".
type patternKey struct{}

// capturePattern runs inside the middleware chain, right around the inner
// mux: the mux stamps r.Pattern on THIS request copy, and the pointer in
// the context hands it back out to instrument.
func capturePattern(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		if ptr, ok := r.Context().Value(patternKey{}).(*string); ok {
			*ptr = r.Pattern
		}
	})
}

// instrument logs each request and records metrics. Never logs bodies,
// query strings or headers - they can carry PII (emails, phone numbers).
func (s *Server) instrument(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		var inner string
		r = r.WithContext(context.WithValue(r.Context(), patternKey{}, &inner))
		next.ServeHTTP(rec, r)
		dur := time.Since(start)
		pattern := inner
		if pattern == "" {
			pattern = r.Pattern
		}
		if pattern == "" {
			pattern = "unmatched"
		}
		s.Metrics.Inc(fmt.Sprintf(`sunder_requests_total{handler=%q,code="%d"}`, pattern, rec.status))
		s.Metrics.Observe(fmt.Sprintf(`sunder_request_seconds{handler=%q}`, pattern), dur.Seconds())
		s.Log.Info("request", "pattern", pattern, "method", r.Method, "status", rec.status, "ms", dur.Milliseconds())
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.Store.Pool.Ping(ctx); err != nil {
		http.Error(w, "db unavailable", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready"))
}

// Run serves until ctx is cancelled, then shuts down gracefully.
// TLS is enabled when a cert/key pair is configured; a configured client CA
// enforces full mTLS (connections without a valid client cert are refused).
func (s *Server) Run(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.Cfg.Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if s.Cfg.TLSCert != "" {
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	}
	if s.Cfg.MTLSCA != "" {
		caPEM, err := os.ReadFile(s.Cfg.MTLSCA)
		if err != nil {
			return fmt.Errorf("read mTLS CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return errors.New("mTLS CA file contains no certificates")
		}
		srv.TLSConfig.ClientCAs = pool
		// A configured client CA means mTLS, fully: connections without a
		// valid client certificate are refused, not merely unverified.
		srv.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	// Erasure webhook delivery worker: retries PENDING events on the
	// configured cadence (Erase also attempts an immediate delivery inline).
	if s.GDPR != nil {
		interval := s.Cfg.DeliverInterval
		if interval <= 0 {
			interval = time.Minute
		}
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					// The two queues drain CONCURRENTLY: sequentially, a
					// hanging mailer starved erasure webhook delivery and
					// vice versa. Each sweep claims its own
					// rows, so replicas and ticks cannot double-send.
					var wg sync.WaitGroup
					wg.Add(1)
					go func() {
						defer wg.Done()
						if n, err := s.GDPR.DeliverPending(ctx); err != nil {
							s.Log.Error("erasure delivery", "err", err.Error())
						} else if n > 0 {
							s.Log.Info("erasure events delivered", "count", n)
						}
					}()
					if s.Portal != nil {
						wg.Add(1)
						go func() {
							defer wg.Done()
							if n, err := s.Portal.DeliverPendingMail(ctx); err != nil {
								s.Log.Error("portal mail delivery", "err", err.Error())
							} else if n > 0 {
								s.Log.Info("portal mail delivered", "count", n)
							}
						}()
					}
					wg.Wait()
				}
			}
		}()
	}

	errCh := make(chan error, 1)
	go func() {
		if s.Cfg.TLSCert != "" {
			errCh <- srv.ListenAndServeTLS(s.Cfg.TLSCert, s.Cfg.TLSKey)
		} else {
			errCh <- srv.ListenAndServe()
		}
	}()

	// A dedicated portal listener: TLS (server-side) but never a client
	// certificate requirement, so the API can stay behind mTLS while
	// citizens reach the portal from a browser.
	var portalSrv *http.Server
	if s.Portal != nil && s.Cfg.PortalListen != "" {
		// The same timeout set as the API server: this is the
		// UNAUTHENTICATED public listener, so a slow-loris there is
		// cheaper for the attacker than anywhere else.
		portalSrv = &http.Server{
			Addr:              s.Cfg.PortalListen,
			Handler:           s.instrument(s.portalMux()),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		if s.Cfg.TLSCert != "" {
			portalSrv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13}
		}
		go func() {
			if s.Cfg.TLSCert != "" {
				errCh <- portalSrv.ListenAndServeTLS(s.Cfg.TLSCert, s.Cfg.TLSKey)
			} else {
				errCh <- portalSrv.ListenAndServe()
			}
		}()
		s.Log.Info("portal listening", "addr", s.Cfg.PortalListen, "tls", s.Cfg.TLSCert != "")
	}

	if s.Cfg.TLSCert == "" {
		s.Log.Warn("serving WITHOUT TLS - credentials and PII cross the network in the clear; terminate TLS at an ingress or set SUNDER_TLS_CERT/KEY")
	} else if s.Cfg.MTLSCA == "" {
		s.Log.Warn("TLS is enabled WITHOUT mutual TLS - any network peer can reach the API with just a bearer credential; set SUNDER_MTLS_CA in production (docs/RUNBOOK-MTLS-ROTATION.md)")
	}
	if s.Portal != nil && s.Cfg.PortalListen == "" && s.Cfg.MTLSCA != "" {
		s.Log.Warn("the portal is mounted on the mTLS-protected API listener: browsers cannot present a client certificate, so citizens will be refused - set SUNDER_PORTAL_LISTEN")
	}
	s.Log.Info("listening", "addr", s.Cfg.Listen, "tls", s.Cfg.TLSCert != "",
		"mtls", s.Cfg.MTLSCA != "", "portal", s.Portal != nil)

	shutdown := func() error {
		shCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err := srv.Shutdown(shCtx)
		if portalSrv != nil {
			if perr := portalSrv.Shutdown(shCtx); err == nil {
				err = perr
			}
		}
		return err
	}
	select {
	case <-ctx.Done():
		return shutdown()
	case err := <-errCh:
		_ = shutdown()
		return err
	}
}
