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
	"regexp"
	"strings"
	"sync"
	"time"

	apispec "github.com/fvisic/sunder/api"
	"github.com/fvisic/sunder/internal/audit"
	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/config"
	"github.com/fvisic/sunder/internal/crypto"
	"github.com/fvisic/sunder/internal/debugsrv"
	"github.com/fvisic/sunder/internal/metrics"
	"github.com/fvisic/sunder/internal/ratelimit"
	"github.com/fvisic/sunder/internal/service"
	"github.com/fvisic/sunder/internal/storage"
	"github.com/fvisic/sunder/internal/store"
)

// Server holds shared dependencies for all handlers.
type Server struct {
	Cfg         config.Config
	Portal      *service.Portal
	Store       *store.Store
	Metrics     *metrics.Registry
	Log         *slog.Logger
	Contacts    *service.Contacts
	OTI         *service.OTI
	GDPR        *service.GDPR
	Auth        *auth.Authenticator
	Unlock      *service.Unlock
	ValueTokens *service.ValueTokens
	Files       *service.Files
	Links       *service.Links
	Shares      *service.Shares
	Limiter     ratelimit.Allower
	Detector    ratelimit.MissCounter
	enumWarned  sync.Map // client id -> last enumeration warning (F3 latch)
	mux         *http.ServeMux
	// closerInterval overrides the bucket-closer cadence in tests; zero
	// means the production minute.
	closerInterval time.Duration
	// syncBacklogInterval overrides the sync-mode backlog sealer's cadence
	// in tests; zero means syncBacklogSealInterval.
	syncBacklogInterval time.Duration
	// gaugeInterval overrides the operational-gauge cadence in tests; zero
	// means the production 30 seconds.
	gaugeInterval time.Duration

	// The two constructed listeners, published by Run for ServersForTest.
	testServersMu sync.Mutex
	apiServer     *http.Server
	portalServer  *http.Server
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
		ring := &service.KeyRing{Pool: st.Pool, RetireGrace: cfg.KeyRetireGrace}
		// Bootstrap/rotation is the ONLY place key material comes into
		// existence (the keystore itself is strict).
		// `serve` does NOT mint by default. Minting on boot turns a lost or
		// misconfigured keystore volume into a healthy-looking empty vault:
		// /healthz 200, /readyz 200, every lookup a 404, every attribute
		// undecryptable, and no signal anywhere (OPS-CLI-CONFIG-1). A first
		// boot against a vault with no data still mints, because nothing
		// references the missing versions.
		ensure := ring.EnsureAll
		if cfg.KeystoreAllowMint {
			ensure = ring.EnsureAllAllowingMint
		}
		if err := ensure(context.Background(), eng); err != nil {
			return nil, fmt.Errorf("keystore bootstrap: %w", err)
		}
		pii := crypto.NewPIIBox(eng)
		pii.Alg = cfg.PIIAlg
		s.Contacts = &service.Contacts{Pool: st.Pool, Tok: crypto.NewTokenizer(eng), PII: pii, Ring: ring,
			FuzzyName: cfg.SearchFuzzyName, PhoneSuffix: cfg.SearchPhoneSuffix,
			SplitLookupActions: cfg.AuditLookupActions == "split",
			VersionsKeep:       cfg.VersionsKeep}
		s.OTI = &service.OTI{Pool: st.Pool, Eng: eng, Ring: ring, Contacts: s.Contacts, TTL: cfg.OTITTL}
		s.GDPR = &service.GDPR{Pool: st.Pool, Contacts: s.Contacts,
			HTTPTimeout: cfg.WebhookTimeout, MaxAttempts: cfg.WebhookMaxAttempts,
			ClaimTTL: cfg.WorkerClaimTTL, Log: s.Log,
			MaxCascadeChildren: cfg.MaxCascadeChildren}
		if cfg.PortalEnabled {
			s.Portal = &service.Portal{GDPR: s.GDPR, Contacts: s.Contacts, BaseURL: cfg.PortalBaseURL}
		}
		s.Auth = &auth.Authenticator{Pool: st.Pool}
		s.Unlock = &service.Unlock{Pool: st.Pool}
		s.ValueTokens = &service.ValueTokens{Pool: st.Pool, Eng: eng, Ring: ring, Tok: s.Contacts.Tok}
		s.Links = &service.Links{Pool: st.Pool, Contacts: s.Contacts}
		s.Shares = &service.Shares{Pool: st.Pool, Contacts: s.Contacts}
		if cfg.FilesStorage != "" {
			drv, err := storage.Open(storage.Config{Kind: cfg.FilesStorage, Dir: cfg.FilesDir,
				S3Endpoint: cfg.FilesS3Endpoint, S3Bucket: cfg.FilesS3Bucket, S3Region: cfg.FilesS3Region,
				S3AccessKey: cfg.FilesS3AccessKey, S3SecretKey: cfg.FilesS3SecretKey, S3PathStyle: cfg.FilesS3PathStyle})
			if err != nil {
				return nil, fmt.Errorf("file storage: %w", err)
			}
			s.Files = &service.Files{Pool: st.Pool, Eng: eng, Ring: ring, Store: drv,
				Contacts: s.Contacts, MaxBytes: cfg.FilesMaxMB << 20,
				MaxConcurrentUploads: cfg.FilesMaxConcurrentUploads}
		}

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
		v1.HandleFunc("GET /v1/contacts/{cid}/versions", s.handleVersionList)
		v1.HandleFunc("GET /v1/contacts/{cid}/versions/{version}/attributes/{name}", s.handleVersionAttribute)
		v1.HandleFunc("POST /v1/lookup", s.handleLookup)
		v1.HandleFunc("POST /v1/admin/unlock", s.handleAdminUnlock)
		// Read-only tamper-evidence surface (audit.verify): the CLI verdict
		// over HTTP, for dashboards and the playground's chain panel.
		v1.HandleFunc("GET /v1/admin/audit/verify", s.handleAuditVerify)
		v1.HandleFunc("GET /v1/admin/audit/chain", s.handleAuditChain)
		v1.HandleFunc("POST /v1/tokens", s.handleTokenCreate)
		v1.HandleFunc("GET /v1/tokens/{token}", s.handleTokenRead)
		v1.HandleFunc("DELETE /v1/tokens/{token}", s.handleTokenDelete)
		v1.HandleFunc("POST /v1/tokens/bulk", s.handleTokenBulkCreate)
		v1.HandleFunc("POST /v1/tokens/bulk/read", s.handleTokenBulkRead)
		if s.Files != nil {
			v1.HandleFunc("POST /v1/contacts/{cid}/files", s.handleFileUpload)
			v1.HandleFunc("GET /v1/contacts/{cid}/files", s.handleFileList)
			v1.HandleFunc("GET /v1/files/{id}", s.handleFileDownload)
			v1.HandleFunc("DELETE /v1/files/{id}", s.handleFileDelete)
		}
		v1.HandleFunc("POST /v1/oti", s.handleOTIIssue)
		v1.HandleFunc("POST /v1/oti/verify", s.handleOTIVerify)
		v1.HandleFunc("POST /v1/claims/external", s.handleExternalClaims)
		v1.HandleFunc("POST /v1/consent", s.handleConsentSet)
		v1.HandleFunc("GET /v1/consent/{cid}", s.handleConsentList)
		v1.HandleFunc("GET /v1/dsr/access", s.handleDSRAccess)
		v1.HandleFunc("POST /v1/dsr/erase", s.handleDSRErase)
		v1.HandleFunc("POST /v1/links", s.handleLinkCreate)
		v1.HandleFunc("DELETE /v1/links", s.handleLinkDelete)
		v1.HandleFunc("GET /v1/contacts/{cid}/links", s.handleLinkList)
		v1.HandleFunc("POST /v1/shares", s.handleShareCreate)
		v1.HandleFunc("DELETE /v1/shares/{uuid}", s.handleShareRevoke)
		if !cfg.SharesPublic {
			// Default: fetch needs any valid credential - inside the guard.
			v1.HandleFunc("GET /v1/shares/{uuid}", s.handleShareFetchAuthed)
		}
		v1.HandleFunc("GET /v1/dsr/export", s.handleDSRExport)
		s.Auth.Limiter = s.Limiter
		// The per-client rate limit is enforced HERE, once, for every /v1/
		// route - not per handler. It used to be a per-handler call added
		// feature by feature, and eleven routes never got it: the whole
		// contacts surface (including GET .../attributes/{name}, the primary
		// PII read), the whole consent and DSR surface (including
		// POST /v1/dsr/erase, the most destructive call in the product),
		// both OTI routes and the authed share fetch. The `rate_limit`
		// column on `clients` - which THREAT-MODEL names as the mitigation
		// for a stolen bearer credential - was silently inoperative on them
		// (AUTHZ-1). One enforcement point means a new route cannot skip it.
		s.mux.Handle("/v1/", s.Auth.Middleware(s.rateLimitMiddleware(userIDMiddleware(capturePattern(v1)))))
		if cfg.SharesPublic {
			// Credential-less partner fetch: a more specific pattern than the
			// /v1/ guard, so it bypasses auth by design (the UUID is the bearer).
			s.mux.HandleFunc("GET /v1/shares/{uuid}", s.handleShareFetchPublic)
		}
		// The portal is only mounted on the main listener when it has no
		// dedicated one: with mTLS on the API, citizens could never present
		// a client certificate.
		if s.Portal != nil && s.Cfg.PortalListen == "" {
			s.registerPortal()
		}
	}
	return s, nil
}

// rateLimitMiddleware applies the per-client budget to every authenticated
// v1 request. Narrower per-route buckets (claims:, audit-verify:,
// audit-chain:, share-public:) stay layered on top as ADDITIONAL limits.
func (s *Server) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		client := auth.FromContext(r.Context())
		if client == nil {
			// Unauthenticated requests never reach here (the auth middleware
			// wraps this one), but fail closed rather than assume it.
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		if !s.allow(w, client) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

// allow applies the per-client rate limit to an audit-writing endpoint and
// writes a 429 if the client is over budget (L1: these endpoints append to
// the chain under a global lock, so an unbounded caller can serialize the
// instance). Returns false when the request must stop.
func (s *Server) allow(w http.ResponseWriter, client *auth.Client) bool {
	if s.Limiter != nil && !s.Limiter.Allow(client.ID, client.RateLimit) {
		s.Metrics.Inc(fmt.Sprintf(`sunder_ratelimited_total{client=%q}`, client.ID))
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate_limited"})
		return false
	}
	return true
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
	if err := s.startAuditSealing(ctx); err != nil {
		return err
	}
	if err := debugsrv.Start(ctx, s.Cfg.DebugAddr, s.Log); err != nil {
		return err
	}
	// Takes the key ring's epoch check off the request path. Without it the
	// check runs inline, under a lock, while the caller holds a database
	// transaction - which deadlocked writes for thirty seconds at a time
	// once concurrency reached the pool size (see KeyRing.refresh).
	if s.Contacts != nil && s.Contacts.Ring != nil {
		s.Contacts.Ring.StartRefresher(ctx, s.Log)
	}
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
	// configured cadence (Erase also dispatches a detached, erasure-scoped
	// delivery of its own). deliveryDone closes once the delivery ticker goroutine has returned,
	// so shutdown can WAIT for an in-flight sweep instead of abandoning its
	// claims to the reaper's grace period (H1 / QUEUE-WORKER-3).
	deliveryDone := make(chan struct{})
	if s.GDPR == nil {
		close(deliveryDone)
	} else {
		interval := s.Cfg.DeliverInterval
		if interval <= 0 {
			interval = time.Minute
		}
		go func() {
			defer close(deliveryDone)
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
					// Cascades interrupted mid-flight. The durable plan made
					// them recoverable; this is what makes them recover
					// without an operator noticing and re-issuing the call.
					wg.Add(1)
					go func() {
						defer wg.Done()
						if n, err := s.GDPR.RunPendingCascades(ctx); err != nil {
							s.Log.Error("pending cascades", "err", err.Error())
						} else if n > 0 {
							s.Log.Info("interrupted cascades finished", "erasures", n)
						}
					}()
					wg.Wait()
				}
			}
		}()
	}

	// TWO producers whenever a dedicated portal listener is configured, and
	// the ctx.Done() branch returns without draining - so a one-slot buffer
	// parked one sender forever, holding its *http.Server and handler graph
	// alive for the lifetime of the process (CONCURRENCY-CORE-5). Buffered
	// for both, and every send is non-blocking so no future third producer
	// can reintroduce it.
	errCh := make(chan error, 2)
	report := func(err error) {
		select {
		case errCh <- err:
		default:
		}
	}
	go func() {
		if s.Cfg.TLSCert != "" {
			report(srv.ListenAndServeTLS(s.Cfg.TLSCert, s.Cfg.TLSKey))
		} else {
			report(srv.ListenAndServe())
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
				report(portalSrv.ListenAndServeTLS(s.Cfg.TLSCert, s.Cfg.TLSKey))
			} else {
				report(portalSrv.ListenAndServe())
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
	// The installed base: rows that predate the clients_unlock_needs_expiry
	// constraint (migration 0037), which is NOT VALID precisely so an
	// upgrade does not refuse to start on a state the bug created (AUTHZ-2).
	if s.Store != nil {
		var standing []string
		if rows, err := s.Store.Pool.Query(ctx,
			`SELECT client_id FROM clients
			  WHERE 'admin.unlock' = ANY(allowed_actions) AND credential_expires_at IS NULL
			  ORDER BY client_id`); err == nil {
			for rows.Next() {
				var id string
				if rows.Scan(&id) == nil {
					standing = append(standing, id)
				}
			}
			rows.Close()
		}
		if len(standing) > 0 {
			s.Log.Warn("client(s) hold admin.unlock on a NON-EXPIRING credential - a standing unlock grant makes the bulk-read second factor a permanent self-service dump; give them an expiry with `sunder client rotate-secret -id <id> -ttl 90d`",
				"clients", strings.Join(standing, ","))
		}
	}
	if s.Cfg.MetricsToken == "" {
		// The series carry client ids and per-client volumes -
		// sunder_lookup_misses_total{client=...} IS the enumeration
		// detector's own signal, so an enumerating client that can scrape
		// it paces itself under the threshold that only ever logs. The
		// startup-warning block covered TLS, the portal and SharesPublic
		// and said nothing about this (AUTHZ-6).
		s.Log.Warn("/metrics is served WITHOUT a token on the API listener: its series name every client and their per-client volumes, including the enumeration-detector counter - set SUNDER_METRICS_TOKEN, or keep the listener off the network a scraper-less caller can reach")
	}
	if s.Cfg.FilesStorage == "local" {
		// The file vault's `local` driver writes ciphertext to a
		// PER-PROCESS directory while its metadata and wrapped DEK live in
		// the shared database - so a second replica answers a download with
		// 200, the recorded Content-Length and a body it does not have. The
		// docs called Sunder stateless (true of everything else) and said
		// nothing about this (DOCS-4).
		s.Log.Warn("SUNDER_FILES_STORAGE=local keeps file ciphertext in a per-process directory: this is SINGLE-INSTANCE ONLY - a second replica cannot read files uploaded through the first, and `retention run` on one replica garbage-collects only its own objects. Use SUNDER_FILES_STORAGE=s3 for more than one replica",
			"dir", s.Cfg.FilesDir)
		s.Log.Warn("SUNDER_FILES_STORAGE=local is also a SEPARATE BACKUP UNIT: a database-and-keystore restore leaves every files row intact with its DEK and no object behind it (docs/RUNBOOK-BACKUP-DR.md)",
			"dir", s.Cfg.FilesDir)
	}
	if s.Cfg.SharesPublic {
		s.Log.Warn("SUNDER_SHARES_PUBLIC is on: GET /v1/shares/{uuid} answers WITHOUT any client credential (per-IP rate-limited, audited as \"public\") - every holder of a share UUID can read its fields until expiry or revocation")
	}
	s.Log.Info("listening", "addr", s.Cfg.Listen, "tls", s.Cfg.TLSCert != "",
		"mtls", s.Cfg.MTLSCA != "", "portal", s.Portal != nil)

	s.testServersMu.Lock()
	s.apiServer, s.portalServer = srv, portalSrv
	s.testServersMu.Unlock()

	shutdown := func() error {
		shCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err := srv.Shutdown(shCtx)
		if portalSrv != nil {
			if perr := portalSrv.Shutdown(shCtx); err == nil {
				err = perr
			}
		}
		// Drain the queue workers. Both settle on a detached context, so
		// what this buys is that the process does not exit while a POST is
		// still in flight - the delivery either completes and is recorded,
		// or its claim is released, instead of waiting out the lease.
		select {
		case <-deliveryDone:
		case <-shCtx.Done():
			s.Log.Warn("delivery worker did not drain before shutdown deadline; claims will be reaped after SUNDER_WORKER_CLAIM_TTL")
		}
		if s.GDPR != nil {
			s.GDPR.Drain()
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

// ServersForTest exposes the two constructed http.Servers so a test can
// assert on their timeout sets. The portal is the UNAUTHENTICATED public
// listener, and the only test that named its timeouts never looked at them
// (TESTS-1); an accessor is what makes that assertable at all.
func (s *Server) ServersForTest() (portal, api *http.Server) {
	s.testServersMu.Lock()
	defer s.testServersMu.Unlock()
	return s.portalServer, s.apiServer
}

// startAuditSealing applies the configured sealing mode (P4.1). The mode
// and whether this process seals are logged unconditionally: the sealing
// window is a security property and must never be discoverable only by
// reading code.
func (s *Server) startAuditSealing(ctx context.Context) error {
	// An unset mode (Config literal built in tests, not via FromEnv) must
	// not override the process mode the environment selected - the CI
	// matrix runs the whole suite under SUNDER_AUDIT_SEALING=async|sync.
	if s.Cfg.AuditSealing != "" {
		audit.SetMode(s.Cfg.AuditSealing)
	}
	if s.Cfg.AuditReads != "" {
		audit.SetReadsMode(s.Cfg.AuditReads)
	}
	if s.Store == nil {
		// A server can be built without a store (config-validation tests);
		// nothing to seal and nothing to drain against.
		return nil
	}

	if audit.Mode() == audit.ModeSync {
		// The async -> sync switch: unsealed rows left by a previous async
		// run must be drained BEFORE serving, or the first synchronous
		// append would chain onto the sealed head and strand them above it.
		n, err := audit.Drain(ctx, s.Store.Pool, s.sealBatch())
		if err != nil {
			return fmt.Errorf("audit drain before sync serving: %w", err)
		}
		if n > 0 {
			s.Log.Info("audit backlog drained for sync mode", "sealed", n)
		}
		s.Log.Info("audit sealing", "mode", "sync", "window", "none (sealed at insert)", "reads", audit.ReadsMode())
		if s.Metrics != nil {
			s.Metrics.Set("sunder_audit_unsealed_rows", 0)
		}
		s.startUnsealedGauge(ctx)
		if !s.Cfg.AuditSealExternal {
			s.startBucketCloser(ctx)
			// A low-frequency sealer runs in SYNC mode too. The drain above
			// is point-in-time on state shared with every other replica: in
			// a rolling async -> sync restart, replicas still on async keep
			// inserting unsealed rows AFTER this process drained, and once
			// the last async replica stops there is no sealer left in the
			// fleet. Those rows are then stranded outside the chain
			// indefinitely - `verify-audit` fails hard, /v1/admin/audit/verify
			// answers ok:false, and the only cure is running `sunder sealer
			// -once` under a DIFFERENT mode than the one configured
			// (AUDIT-CHAIN-7). A tick that finds an empty backlog takes the
			// lock, sees zero rows and commits: it costs nothing and makes
			// the invariant self-healing regardless of restart order.
			s.startSyncBacklogSealer(ctx)
		}
		return nil
	}

	s.startUnsealedGauge(ctx)
	sealsHere := !s.Cfg.AuditSealExternal
	s.Log.Info("audit sealing", "mode", "async",
		"interval", s.sealInterval().String(), "delay", s.sealDelay().String(),
		"batch", s.sealBatch(), "seals_in_this_process", sealsHere, "reads", audit.ReadsMode())
	if !sealsHere {
		return nil // `sunder sealer` owns sealing AND bucket closing
	}

	s.startBucketCloser(ctx)
	go func() {
		ticker := time.NewTicker(s.sealInterval())
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := audit.SealOnce(ctx, s.Store.Pool, s.sealBatch(), s.sealDelay()); err != nil {
					if ctx.Err() == nil {
						s.Log.Error("audit sealing", "err", err.Error())
					}
					continue
				}
				if s.Metrics != nil {
					if n, err := audit.UnsealedCount(ctx, s.Store.Pool); err == nil {
						// The operational alarm for a stalled sealer: this
						// gauge growing without bound IS the incident.
						s.Metrics.Set("sunder_audit_unsealed_rows", float64(n))
					}
				}
			}
		}
	}()
	return nil
}

// Config defaults are re-applied here because tests construct Config
// literals without going through FromEnv.
func (s *Server) sealInterval() time.Duration {
	if s.Cfg.AuditSealInterval <= 0 {
		return 200 * time.Millisecond
	}
	return s.Cfg.AuditSealInterval
}

func (s *Server) sealDelay() time.Duration {
	if s.Cfg.AuditSealDelay <= 0 {
		return 2 * time.Second
	}
	return s.Cfg.AuditSealDelay
}

func (s *Server) sealBatch() int {
	if s.Cfg.AuditSealBatch <= 0 {
		return 5000
	}
	return s.Cfg.AuditSealBatch
}

// userIDPattern keeps the client-asserted operator id an opaque ID: no
// spaces, no free text, bounded length. It lands in a log that is never
// pruned, so it must stay an identifier, not a name.
var userIDPattern = regexp.MustCompile(`^[A-Za-z0-9._@:-]{1,64}$`)

// userIDMiddleware extracts X-Sunder-User-Id, the optional CLIENT-ASSERTED
// operator id (P4.2): with it, the audit trail and the hourly read buckets
// answer "which operator behind this credential" instead of only "which
// system". A malformed value is a 400, not a silent drop - silently
// discarding attribution would corrupt the very record it exists for.
func userIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Sunder-User-Id")
		if id != "" {
			if !userIDPattern.MatchString(id) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"validation","detail":"X-Sunder-User-Id must be an id: 1-64 of [A-Za-z0-9._@:-]"}`))
				return
			}
			r = r.WithContext(audit.WithUserID(r.Context(), id))
		}
		next.ServeHTTP(w, r)
	})
}

// startBucketCloser turns each finished hour of read buckets into one
// chained audit row (P4.2). Independent of the sealing mode: bucketed
// reads exist under sync sealing too, and the closer's chained row goes
// through the normal write path of whichever mode is active. A minute
// cadence bounds how long a finished hour stays unsummarized; the try-lock
// inside CloseReadBuckets makes N replicas cheap.
// startUnsealedGauge refreshes sunder_audit_unsealed_rows periodically in
// EVERY sealing mode. It was previously set only inside the in-process async
// seal loop - so under SUNDER_AUDIT_SEAL_EXTERNAL (the recommended
// hardening) the documented stalled-sealer alarm was emitted nowhere, and in
// sync mode a backlog created by a mode switch without a drain was
// invisible. This process is where /metrics lives, so this is where the
// gauge must be fed.
func (s *Server) startUnsealedGauge(ctx context.Context) {
	if s.Metrics == nil {
		return
	}
	interval := s.gaugeInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if n, err := audit.UnsealedCount(ctx, s.Store.Pool); err == nil {
					s.Metrics.Set("sunder_audit_unsealed_rows", float64(n))
				}
				// Key material this process created. Non-zero on anything
				// other than a deliberate bootstrap means a lost keystore
				// volume (OPS-CLI-CONFIG-1).
				s.Metrics.Set("sunder_keystore_minted_total", float64(crypto.MintedKeys()))
				// AES-GCM invocations per key version, so rotation can be
				// driven by usage and not only by incident (CRYPTO-8).
				for key, n := range crypto.SealCounts() {
					s.Metrics.Set(fmt.Sprintf(`sunder_kek_seals_total{version=%q}`, key), float64(n))
				}
				// Claimed-but-unsettled erasure notifications. A value that
				// does not return to zero means Article 19 notifications are
				// stuck behind a dead worker (H1).
				if s.GDPR != nil {
					if sending, failed, err := service.ErasureQueueDepth(ctx, s.Store.Pool); err == nil {
						s.Metrics.Set("sunder_erasure_events_sending", float64(sending))
						s.Metrics.Set("sunder_erasure_events_failed", float64(failed))
					}
					// Children named by an erasure and not yet erased. The
					// AGE matters more than the count: a large cascade in
					// progress and a cascade that stopped an hour ago look
					// identical by count alone, and the second is an Article
					// 17 breach in progress (L6).
					if pending, oldest, err := service.PendingCascades(ctx, s.Store.Pool); err == nil {
						s.Metrics.Set("sunder_erasure_cascade_pending", float64(pending))
						s.Metrics.Set("sunder_erasure_cascade_oldest_seconds", oldest)
					}
				}
			}
		}
	}()
}

// startSyncBacklogSealer drains any rows that appear outside the chain while
// this process is in sync mode. See the call site for why that can happen at
// all.
func (s *Server) startSyncBacklogSealer(ctx context.Context) {
	interval := s.syncBacklogInterval
	if interval <= 0 {
		interval = syncBacklogSealInterval
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				n, err := audit.Drain(ctx, s.Store.Pool, s.sealBatch())
				if err != nil {
					if ctx.Err() == nil {
						s.Log.Error("sync-mode backlog drain", "err", err.Error())
					}
					continue
				}
				if n > 0 {
					s.Log.Warn("sealed rows that appeared outside the chain under sync sealing - another replica is still running in async mode",
						"sealed", n)
				}
			}
		}
	}()
}

// syncBacklogSealInterval is deliberately slow: in a converged sync fleet
// this finds nothing, every time.
const syncBacklogSealInterval = 10 * time.Second

func (s *Server) startBucketCloser(ctx context.Context) {
	if audit.ReadsMode() != audit.ReadsBucketed {
		return
	}
	interval := s.closerInterval
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
				if n, err := audit.CloseReadBuckets(ctx, s.Store.Pool); err != nil {
					if ctx.Err() == nil {
						s.Log.Error("read-bucket close", "err", err.Error())
					}
				} else if n > 0 {
					s.Log.Info("read buckets closed", "hours", n)
				}
			}
		}
	}()
}
