// Package config loads server configuration from SUNDER_* environment variables.
package config

import (
	"fmt"
	"os"
	"strconv"
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
	TSAURL       string // SUNDER_TSA_URL; the freetsa.org default suits pilots — production should point at a qualified or internal TSA
	MetricsToken string // SUNDER_METRICS_TOKEN: when set, /metrics requires this bearer token (per-client counters reveal client ids and activity)
	TSACA        string // SUNDER_TSA_CACERT: TSA root CA bundle; falls back to the vendored deploy/freetsa/cacert.pem when present
	AnchorDir    string // SUNDER_ANCHOR_DIR: directory where `sunder anchor` exports .tsr files — sync it to write-once storage off this host
	// Shared rate-limit counters for multi-replica deployments; unset =
	// in-memory per-replica windows.
	RedisAddr       string // SUNDER_REDIS_ADDR (host:port)
	RedisPassword   string // SUNDER_REDIS_PASSWORD
	RedisFailClosed bool   // SUNDER_REDIS_FAIL_CLOSED=true blocks lookups when Redis is unreachable (default: fail open)

	// Tunables. Defaults match the documented v1 behaviour; see docs/CONFIG.md
	// before changing them — several are security trade-offs, not preferences.
	OTITTL             time.Duration // SUNDER_OTI_TTL: one-time-identifier lifetime, default "5m", range [30s, 24h]
	PIIAlg             string        // SUNDER_PII_ALG: AEAD for NEW blobs, "aes256gcm" (default) or "xchacha20poly1305"; reads follow each blob's stored algorithm
	WebhookTimeout     time.Duration // SUNDER_WEBHOOK_TIMEOUT: per-delivery HTTP timeout, default "5s", range [1s, 5m]
	WebhookMaxAttempts int           // SUNDER_WEBHOOK_MAX_ATTEMPTS: failed deliveries before FAILED, default 10, min 1
	DeliverInterval    time.Duration // SUNDER_DELIVER_INTERVAL: background webhook retry cadence, default "1m", range [5s, 1h]
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
		TSAURL:          getenv("SUNDER_TSA_URL", "https://freetsa.org/tsr"),
		MetricsToken:    os.Getenv("SUNDER_METRICS_TOKEN"),
		TSACA:           os.Getenv("SUNDER_TSA_CACERT"),
		AnchorDir:       os.Getenv("SUNDER_ANCHOR_DIR"),
		RedisAddr:       os.Getenv("SUNDER_REDIS_ADDR"),
		RedisPassword:   os.Getenv("SUNDER_REDIS_PASSWORD"),
		RedisFailClosed: os.Getenv("SUNDER_REDIS_FAIL_CLOSED") == "true",
	}
	if c.DBURL == "" {
		return c, fmt.Errorf("SUNDER_DB_URL is required")
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
	raw := getenv("SUNDER_WEBHOOK_MAX_ATTEMPTS", "10")
	if c.WebhookMaxAttempts, err = strconv.Atoi(raw); err != nil || c.WebhookMaxAttempts < 1 {
		return c, fmt.Errorf("SUNDER_WEBHOOK_MAX_ATTEMPTS: %q must be an integer >= 1", raw)
	}
	return c, nil
}
