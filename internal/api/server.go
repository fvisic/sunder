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
	"time"

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
	Cfg      config.Config
	Store    *store.Store
	Metrics  *metrics.Registry
	Log      *slog.Logger
	Contacts *service.Contacts
	OTI      *service.OTI
	GDPR     *service.GDPR
	Auth     *auth.Authenticator
	Limiter  ratelimit.Allower
	Detector ratelimit.MissCounter
	mux      *http.ServeMux
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

// New builds the server, bootstraps key material (the strict keystore never
// creates keys per request — see crypto.Keystore) and registers routes.
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
		ks := OpenKeystore(cfg)
		ring := &service.KeyRing{Pool: st.Pool}
		// Bootstrap/rotation is the ONLY place key material comes into
		// existence (the keystore itself is strict).
		if err := ring.EnsureAll(context.Background(), ks); err != nil {
			return nil, fmt.Errorf("keystore bootstrap: %w", err)
		}
		s.Contacts = &service.Contacts{Pool: st.Pool, Tok: crypto.NewTokenizer(ks), PII: crypto.NewPIIBox(ks), Ring: ring}
		s.OTI = &service.OTI{Pool: st.Pool, KS: ks, Ring: ring, Contacts: s.Contacts}
		s.GDPR = &service.GDPR{Pool: st.Pool, Contacts: s.Contacts}
		s.Auth = &auth.Authenticator{Pool: st.Pool}

		if cfg.RedisAddr != "" {
			// Multi-replica deployments share windows via Redis; the same
			// instance serves both the limiter and the enumeration detector.
			rl := ratelimit.NewRedisLimiter(cfg.RedisAddr, cfg.RedisPassword, cfg.RedisFailClosed)
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
		v1.HandleFunc("POST /v1/consent", s.handleConsentSet)
		v1.HandleFunc("GET /v1/consent/{cid}", s.handleConsentList)
		v1.HandleFunc("GET /v1/dsr/access", s.handleDSRAccess)
		v1.HandleFunc("POST /v1/dsr/erase", s.handleDSRErase)
		v1.HandleFunc("GET /v1/dsr/export", s.handleDSRExport)
		s.mux.Handle("/v1/", s.Auth.Middleware(v1))
	}
	return s, nil
}

// Handler returns the outermost HTTP handler (middleware applied).
func (s *Server) Handler() http.Handler { return s.instrument(s.mux) }

// instrument logs each request and records metrics. Never logs bodies,
// query strings or headers — they can carry PII (emails, phone numbers).
func (s *Server) instrument(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		dur := time.Since(start)
		pattern := r.Pattern
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

	// Erasure webhook delivery worker: retries PENDING events every minute
	// (Erase also attempts an immediate delivery inline).
	if s.GDPR != nil {
		go func() {
			ticker := time.NewTicker(time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if n, err := s.GDPR.DeliverPending(ctx); err != nil {
						s.Log.Error("erasure delivery", "err", err.Error())
					} else if n > 0 {
						s.Log.Info("erasure events delivered", "count", n)
					}
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
	s.Log.Info("listening", "addr", s.Cfg.Listen, "tls", s.Cfg.TLSCert != "", "mtls", s.Cfg.MTLSCA != "")

	select {
	case <-ctx.Done():
		shCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shCtx)
	case err := <-errCh:
		return err
	}
}
