// Package config loads server configuration from SUNDER_* environment variables.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fvisic/sunder/internal/crypto"
)

// Config holds all runtime settings. TLS is optional for local development
// and mandatory in production deployments (enforced by deployment docs, not code).
type Config struct {
	DBURL        string // SUNDER_DB_URL (required)
	Listen       string // SUNDER_LISTEN, default ":8080"
	TLSCert      string // SUNDER_TLS_CERT (path; enables TLS together with SUNDER_TLS_KEY)
	TLSKey       string // SUNDER_TLS_KEY
	MTLSCA       string // SUNDER_MTLS_CA (path; presence enables client-cert verification)
	Keystore     string // SUNDER_KEYSTORE: file|vault|pkcs11, default "file"
	KeystorePath string // SUNDER_KEYSTORE_PATH, default "./keystore"
	VaultAddr    string // SUNDER_VAULT_ADDR
	VaultToken   string // SUNDER_VAULT_TOKEN
	VaultMount   string // SUNDER_VAULT_MOUNT: KV v2 mount, default "secret"
	SignerSocket string // SUNDER_SIGNER_SOCKET: when set, all crypto runs in a separate `sunder signer` process on this Unix socket; this process never holds key material
	TSAURL       string // SUNDER_TSA_URL; the freetsa.org default suits pilots - production should point at a qualified or internal TSA
	MetricsToken string // SUNDER_METRICS_TOKEN: when set, /metrics requires this bearer token (per-client counters reveal client ids and activity)
	TSACA        string // SUNDER_TSA_CACERT: TSA root CA bundle; falls back to the vendored deploy/freetsa/cacert.pem when present
	AnchorDir    string // SUNDER_ANCHOR_DIR: directory where `sunder anchor` exports .tsr files - sync it to write-once storage off this host
	// Shared rate-limit counters for multi-replica deployments; unset =
	// in-memory per-replica windows.
	RedisAddr       string // SUNDER_REDIS_ADDR (host:port)
	RedisPassword   string // SUNDER_REDIS_PASSWORD
	RedisFailClosed bool   // SUNDER_REDIS_FAIL_CLOSED=true blocks lookups when Redis is unreachable (default: fail open)

	// Self-service privacy portal (P2.5). OFF by default: an upgrade must
	// never silently open a new unauthenticated public surface.
	PortalEnabled bool   // SUNDER_PORTAL_ENABLED=true
	PortalListen  string // SUNDER_PORTAL_LISTEN: separate bind address for the portal, so the API can stay behind mTLS while citizens reach the portal (empty = same listener)
	PortalBaseURL string // SUNDER_PORTAL_BASE_URL: public base URL used to build the magic link in the mail payload (e.g. https://privacy.acme.example)
	// PortalCookieInsecure drops the Secure flag on the session cookie -
	// local development only. Default (false) keeps Secure set even when
	// TLS terminates at the ingress.
	PortalCookieInsecure bool // SUNDER_PORTAL_COOKIE_INSECURE=true
	// PortalClientIPHeader, when set, is trusted for per-IP rate limiting
	// behind a reverse proxy (e.g. "X-Forwarded-For"). Opt-in only: a
	// blindly trusted header is a limiter bypass.
	PortalClientIPHeader string // SUNDER_PORTAL_CLIENT_IP_HEADER
	// PortalTrustedProxyHops is how many proxies sit between the client and
	// this service. The right-most header entry minus this many hops is
	// taken as the client address; the left-most entry is always
	// caller-supplied and must never be trusted. Default 0 = the immediate
	// proxy appended the address.
	PortalTrustedProxyHops int // SUNDER_PORTAL_TRUSTED_PROXY_HOPS

	// Tunables. Defaults match the documented v1 behaviour; see docs/CONFIG.md
	// before changing them - several are security trade-offs, not preferences.
	OTITTL             time.Duration // SUNDER_OTI_TTL: one-time-identifier lifetime, default "5m", range [30s, 24h]
	PIIAlg             string        // SUNDER_PII_ALG: AEAD for NEW blobs, "aes256gcm" (default) or "xchacha20poly1305"; reads follow each blob's stored algorithm
	WebhookTimeout     time.Duration // SUNDER_WEBHOOK_TIMEOUT: per-delivery HTTP timeout, default "5s", range [1s, 5m]
	WebhookMaxAttempts int           // SUNDER_WEBHOOK_MAX_ATTEMPTS: failed deliveries before FAILED, default 10, min 1
	DeliverInterval    time.Duration // SUNDER_DELIVER_INTERVAL: background webhook retry cadence, default "1m", range [5s, 1h]

	// Audit sealing (P4.1). "async" keeps the instance-wide chain lock off
	// the request path: audited operations INSERT unsealed rows and a
	// single sealer chains them shortly after. "sync" is the pre-P4.1
	// behaviour - lock in the business transaction, hash immediate, zero
	// sealing window. This is a security trade-off, not a preference: see
	// docs/THREAT-MODEL.md ("Audit chain") before changing either way.
	AuditSealing      string        // SUNDER_AUDIT_SEALING: "async" (default) or "sync"
	AuditSealInterval time.Duration // SUNDER_AUDIT_SEAL_INTERVAL: sealer cadence, default "200ms", range [50ms, 30s]
	AuditSealDelay    time.Duration // SUNDER_AUDIT_SEAL_DELAY: how long a row must settle before it may be sealed, default "2s", range [100ms, 5m]
	AuditSealBatch    int           // SUNDER_AUDIT_SEAL_BATCH: rows per sealing transaction, default 5000, min 100
	AuditSealExternal bool          // SUNDER_AUDIT_SEAL_EXTERNAL=true: this process runs no sealer; a separate `sunder sealer` process does
	// Audit read events (P4.2). "bucketed" (default) aggregates lookups and
	// attribute reads into hourly buckets, chained once per hour via a
	// digest; "chained" keeps every read as its own chained row. See
	// docs/THREAT-MODEL.md - tamper evidence for reads drops to hour
	// granularity under "bucketed".
	AuditReads string // SUNDER_AUDIT_READS: "bucketed" (default) or "chained"

	// Derived search indexes (Phase 3, F1/F2). OFF by default: each one
	// widens the search surface and adds token rows per contact, and an
	// upgrade must never do that silently. Enabling later backfills
	// existing contacts via `sunder keys rekey`.
	SearchFuzzyName   bool // SUNDER_SEARCH_FUZZY_NAME=true: phonetic name narrowing (ph1)
	SearchPhoneSuffix bool // SUNDER_SEARCH_PHONE_SUFFIX=true: last-8-digits phone lookup, single-hit
	// SearchUnlock=true (F3 strict posture, Databunker-like) additionally
	// requires a 60s single-use unlock token (X-Sunder-Unlock, minted at
	// POST /v1/admin/unlock) for fuzzy and partial lookups. Default false:
	// those are single-hit, rate-limited and audited, and a pre-flight
	// round trip per caller-ID lookup kills the flow. Genuinely bulk
	// surfaces always require unlock regardless of this switch.
	SearchUnlock bool // SUNDER_SEARCH_UNLOCK=true

	// File vault (F5). Off unless a storage driver is configured: files
	// are a new data class with their own lifecycle, so an upgrade must
	// not silently start accepting them.
	FilesStorage     string // SUNDER_FILES_STORAGE: "" (disabled) | "local" | "s3"
	FilesDir         string // SUNDER_FILES_DIR: local driver directory
	FilesMaxMB       int64  // SUNDER_FILES_MAX_MB: per-file cap, default 25
	FilesS3Endpoint  string // SUNDER_FILES_S3_ENDPOINT (https://... ; MinIO/R2 compatible)
	FilesS3Bucket    string // SUNDER_FILES_S3_BUCKET
	FilesS3Region    string // SUNDER_FILES_S3_REGION
	FilesS3AccessKey string // SUNDER_FILES_S3_ACCESS_KEY
	FilesS3SecretKey string // SUNDER_FILES_S3_SECRET_KEY
	FilesS3PathStyle bool   // SUNDER_FILES_S3_PATH_STYLE=true (MinIO)

	// Attribute blob versioning (F6). 0 = off; N keeps the N most recent
	// prior versions per cid. History extends the storage-limitation clock
	// (GDPR), hence off by default.
	VersionsKeep int           // SUNDER_VERSIONS_KEEP
	VersionsTTL  time.Duration // SUNDER_VERSIONS_TTL: prune history older than this (0 = only the count cap)
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// getdur parses an env duration with a default and inclusive bounds.
func getdur(key, def string, min, max time.Duration) (time.Duration, error) {
	raw := getenv(key, def)
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not a duration (e.g. \"5m\", \"90s\")", key, raw)
	}
	if d < min || d > max {
		return 0, fmt.Errorf("%s: %s is outside [%s, %s]", key, d, min, max)
	}
	return d, nil
}

// FromEnv builds a Config from the environment, validating required values.
func FromEnv() (Config, error) {
	c, err := FromEnvNoDB()
	if err != nil {
		return c, err
	}
	if c.DBURL == "" {
		return c, fmt.Errorf("SUNDER_DB_URL is required")
	}
	return c, nil
}

// FromEnvNoDB is FromEnv without the database requirement - for the signer
// process, which holds keys and must never need database credentials.
func FromEnvNoDB() (Config, error) {
	c := Config{
		DBURL:           os.Getenv("SUNDER_DB_URL"),
		Listen:          getenv("SUNDER_LISTEN", ":8080"),
		TLSCert:         os.Getenv("SUNDER_TLS_CERT"),
		TLSKey:          os.Getenv("SUNDER_TLS_KEY"),
		MTLSCA:          os.Getenv("SUNDER_MTLS_CA"),
		Keystore:        getenv("SUNDER_KEYSTORE", "file"),
		KeystorePath:    getenv("SUNDER_KEYSTORE_PATH", "./keystore"),
		VaultAddr:       os.Getenv("SUNDER_VAULT_ADDR"),
		VaultToken:      os.Getenv("SUNDER_VAULT_TOKEN"),
		VaultMount:      getenv("SUNDER_VAULT_MOUNT", "secret"),
		SignerSocket:    os.Getenv("SUNDER_SIGNER_SOCKET"),
		TSAURL:          getenv("SUNDER_TSA_URL", "https://freetsa.org/tsr"),
		MetricsToken:    os.Getenv("SUNDER_METRICS_TOKEN"),
		TSACA:           os.Getenv("SUNDER_TSA_CACERT"),
		AnchorDir:       os.Getenv("SUNDER_ANCHOR_DIR"),
		RedisAddr:       os.Getenv("SUNDER_REDIS_ADDR"),
		RedisPassword:   os.Getenv("SUNDER_REDIS_PASSWORD"),
		RedisFailClosed: os.Getenv("SUNDER_REDIS_FAIL_CLOSED") == "true",

		PortalEnabled:        os.Getenv("SUNDER_PORTAL_ENABLED") == "true",
		PortalListen:         os.Getenv("SUNDER_PORTAL_LISTEN"),
		PortalBaseURL:        os.Getenv("SUNDER_PORTAL_BASE_URL"),
		PortalCookieInsecure: os.Getenv("SUNDER_PORTAL_COOKIE_INSECURE") == "true",
		PortalClientIPHeader: os.Getenv("SUNDER_PORTAL_CLIENT_IP_HEADER"),
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return c, fmt.Errorf("SUNDER_TLS_CERT and SUNDER_TLS_KEY must be set together")
	}
	if c.MTLSCA != "" && c.TLSCert == "" {
		return c, fmt.Errorf("SUNDER_MTLS_CA requires SUNDER_TLS_CERT/KEY")
	}
	switch c.Keystore {
	case "file", "vault", "pkcs11":
	default:
		return c, fmt.Errorf("SUNDER_KEYSTORE must be file, vault or pkcs11")
	}
	if c.Keystore == "vault" && (c.VaultAddr == "" || c.VaultToken == "") {
		return c, fmt.Errorf("vault keystore requires SUNDER_VAULT_ADDR and SUNDER_VAULT_TOKEN")
	}

	if c.PortalBaseURL != "" && !strings.HasPrefix(c.PortalBaseURL, "https://") &&
		!strings.HasPrefix(c.PortalBaseURL, "http://localhost") &&
		!strings.HasPrefix(c.PortalBaseURL, "http://127.0.0.1") {
		return c, fmt.Errorf("SUNDER_PORTAL_BASE_URL must be https:// (or loopback http for development)")
	}
	if c.PortalListen != "" && !c.PortalEnabled {
		return c, fmt.Errorf("SUNDER_PORTAL_LISTEN requires SUNDER_PORTAL_ENABLED=true")
	}

	var err error
	if c.OTITTL, err = getdur("SUNDER_OTI_TTL", "5m", 30*time.Second, 24*time.Hour); err != nil {
		return c, err
	}
	if c.WebhookTimeout, err = getdur("SUNDER_WEBHOOK_TIMEOUT", "5s", time.Second, 5*time.Minute); err != nil {
		return c, err
	}
	if c.DeliverInterval, err = getdur("SUNDER_DELIVER_INTERVAL", "1m", 5*time.Second, time.Hour); err != nil {
		return c, err
	}
	c.PIIAlg = getenv("SUNDER_PII_ALG", crypto.AlgAES256GCM)
	if !crypto.KnownAlg(c.PIIAlg) {
		return c, fmt.Errorf("SUNDER_PII_ALG must be %q or %q", crypto.AlgAES256GCM, crypto.AlgXChaCha20)
	}
	hops := getenv("SUNDER_PORTAL_TRUSTED_PROXY_HOPS", "0")
	if c.PortalTrustedProxyHops, err = strconv.Atoi(hops); err != nil || c.PortalTrustedProxyHops < 0 {
		return c, fmt.Errorf("SUNDER_PORTAL_TRUSTED_PROXY_HOPS: %q must be a non-negative integer", hops)
	}
	raw := getenv("SUNDER_WEBHOOK_MAX_ATTEMPTS", "10")
	if c.WebhookMaxAttempts, err = strconv.Atoi(raw); err != nil || c.WebhookMaxAttempts < 1 {
		return c, fmt.Errorf("SUNDER_WEBHOOK_MAX_ATTEMPTS: %q must be an integer >= 1", raw)
	}

	c.AuditSealing = getenv("SUNDER_AUDIT_SEALING", "async")
	if c.AuditSealing != "async" && c.AuditSealing != "sync" {
		return c, fmt.Errorf("SUNDER_AUDIT_SEALING must be \"async\" or \"sync\", got %q", c.AuditSealing)
	}
	if c.AuditSealInterval, err = getdur("SUNDER_AUDIT_SEAL_INTERVAL", "200ms", 50*time.Millisecond, 30*time.Second); err != nil {
		return c, err
	}
	if c.AuditSealDelay, err = getdur("SUNDER_AUDIT_SEAL_DELAY", "2s", 100*time.Millisecond, 5*time.Minute); err != nil {
		return c, err
	}
	rawBatch := getenv("SUNDER_AUDIT_SEAL_BATCH", "5000")
	if c.AuditSealBatch, err = strconv.Atoi(rawBatch); err != nil || c.AuditSealBatch < 100 {
		return c, fmt.Errorf("SUNDER_AUDIT_SEAL_BATCH: %q must be an integer >= 100", rawBatch)
	}
	c.AuditSealExternal = os.Getenv("SUNDER_AUDIT_SEAL_EXTERNAL") == "true"
	c.SearchFuzzyName = os.Getenv("SUNDER_SEARCH_FUZZY_NAME") == "true"
	c.SearchPhoneSuffix = os.Getenv("SUNDER_SEARCH_PHONE_SUFFIX") == "true"
	c.SearchUnlock = os.Getenv("SUNDER_SEARCH_UNLOCK") == "true"
	c.FilesStorage = os.Getenv("SUNDER_FILES_STORAGE")
	c.FilesDir = getenv("SUNDER_FILES_DIR", "./filestore")
	c.FilesS3Endpoint = os.Getenv("SUNDER_FILES_S3_ENDPOINT")
	c.FilesS3Bucket = os.Getenv("SUNDER_FILES_S3_BUCKET")
	c.FilesS3Region = getenv("SUNDER_FILES_S3_REGION", "us-east-1")
	c.FilesS3AccessKey = os.Getenv("SUNDER_FILES_S3_ACCESS_KEY")
	c.FilesS3SecretKey = os.Getenv("SUNDER_FILES_S3_SECRET_KEY")
	c.FilesS3PathStyle = os.Getenv("SUNDER_FILES_S3_PATH_STYLE") == "true"
	rawVK := getenv("SUNDER_VERSIONS_KEEP", "0")
	if c.VersionsKeep, err = strconv.Atoi(rawVK); err != nil || c.VersionsKeep < 0 || c.VersionsKeep > 1000 {
		return c, fmt.Errorf("SUNDER_VERSIONS_KEEP: %q must be 0-1000", rawVK)
	}
	if c.VersionsTTL, err = getdur("SUNDER_VERSIONS_TTL", "0s", 0, 3650*24*time.Hour); err != nil {
		return c, err
	}
	switch c.FilesStorage {
	case "", "local":
	case "s3":
		if c.FilesS3Endpoint == "" || c.FilesS3Bucket == "" || c.FilesS3AccessKey == "" || c.FilesS3SecretKey == "" {
			return c, fmt.Errorf("SUNDER_FILES_STORAGE=s3 requires SUNDER_FILES_S3_ENDPOINT, _BUCKET, _ACCESS_KEY and _SECRET_KEY")
		}
	default:
		return c, fmt.Errorf("SUNDER_FILES_STORAGE must be \"local\" or \"s3\", got %q", c.FilesStorage)
	}
	rawMB := getenv("SUNDER_FILES_MAX_MB", "25")
	mb, err := strconv.ParseInt(rawMB, 10, 64)
	if err != nil || mb < 1 || mb > 4096 {
		return c, fmt.Errorf("SUNDER_FILES_MAX_MB: %q must be 1-4096", rawMB)
	}
	c.FilesMaxMB = mb
	if c.FilesStorage == "s3" && c.FilesMaxMB > 256 {
		return c, fmt.Errorf("SUNDER_FILES_MAX_MB must be <= 256 with the s3 driver (its single-PUT cap)")
	}
	c.AuditReads = getenv("SUNDER_AUDIT_READS", "bucketed")
	if c.AuditReads != "bucketed" && c.AuditReads != "chained" {
		return c, fmt.Errorf("SUNDER_AUDIT_READS must be \"bucketed\" or \"chained\", got %q", c.AuditReads)
	}
	if c.AuditSealExternal && c.AuditSealing == "sync" {
		return c, fmt.Errorf("SUNDER_AUDIT_SEAL_EXTERNAL is meaningless with SUNDER_AUDIT_SEALING=sync (sync mode seals inline and runs no sealer)")
	}
	return c, nil
}
