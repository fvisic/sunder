// Package api wires HTTP routing, health endpoints and observability.
package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/fvisic/sunder/internal/config"
	"github.com/fvisic/sunder/internal/metrics"
	"github.com/fvisic/sunder/internal/store"
)

// Server holds shared dependencies for all handlers.
type Server struct {
	Cfg     config.Config
	Store   *store.Store
	Metrics *metrics.Registry
	Log     *slog.Logger
	mux     *http.ServeMux
}

// New builds the server and registers routes.
func New(cfg config.Config, st *store.Store) *Server {
	s := &Server{
		Cfg:     cfg,
		Store:   st,
		Metrics: metrics.New(),
		Log:     slog.New(slog.NewJSONHandler(os.Stderr, nil)),
		mux:     http.NewServeMux(),
	}
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
	s.mux.HandleFunc("GET /readyz", s.handleReadyz)
	s.mux.Handle("GET /metrics", s.Metrics)
	return s
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
// TLS is enabled when a cert/key pair is configured; a client CA additionally
// enforces mTLS (VerifyClientCertIfGiven now, strict mapping lands in M5).
func (s *Server) Run(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.Cfg.Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
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
		srv.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS13,
			ClientCAs:  pool,
			ClientAuth: tls.VerifyClientCertIfGiven,
		}
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
