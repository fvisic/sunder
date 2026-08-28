package config

import (
	"testing"
	"time"
)

func setBase(t *testing.T) {
	t.Setenv("SUNDER_DB_URL", "postgres://localhost/sunder")
}

func TestFromEnvDefaults(t *testing.T) {
	setBase(t)
	c, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":8080" || c.Keystore != "file" || c.TSAURL != "https://freetsa.org/tsr" {
		t.Fatalf("unexpected defaults: %+v", c)
	}
}

func TestFromEnvRequiresDB(t *testing.T) {
	t.Setenv("SUNDER_DB_URL", "")
	if _, err := FromEnv(); err == nil {
		t.Fatal("expected error for missing SUNDER_DB_URL")
	}
}

func TestTLSPairValidation(t *testing.T) {
	setBase(t)
	t.Setenv("SUNDER_TLS_CERT", "/tmp/cert.pem")
	if _, err := FromEnv(); err == nil {
		t.Fatal("expected error for cert without key")
	}
}

func TestMTLSRequiresTLS(t *testing.T) {
	setBase(t)
	t.Setenv("SUNDER_MTLS_CA", "/tmp/ca.pem")
	if _, err := FromEnv(); err == nil {
		t.Fatal("expected error for mTLS CA without server TLS")
	}
}

func TestInvalidKeystore(t *testing.T) {
	setBase(t)
	t.Setenv("SUNDER_KEYSTORE", "hsm9000")
	if _, err := FromEnv(); err == nil {
		t.Fatal("expected error for unknown keystore driver")
	}
}

func TestValidFullConfigsAccepted(t *testing.T) {
	setBase(t)
	t.Setenv("SUNDER_TLS_CERT", "/tmp/cert.pem")
	t.Setenv("SUNDER_TLS_KEY", "/tmp/key.pem")
	t.Setenv("SUNDER_MTLS_CA", "/tmp/ca.pem")
	t.Setenv("SUNDER_KEYSTORE", "vault")
	t.Setenv("SUNDER_VAULT_ADDR", "https://vault.internal:8200")
	t.Setenv("SUNDER_VAULT_TOKEN", "tok")
	c, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if c.MTLSCA != "/tmp/ca.pem" || c.Keystore != "vault" || c.VaultMount != "secret" {
		t.Fatalf("fields lost: %+v", c)
	}
}

func TestVaultKeystoreValidation(t *testing.T) {
	setBase(t)
	t.Setenv("SUNDER_KEYSTORE", "vault")
	if _, err := FromEnv(); err == nil {
		t.Fatal("expected error for vault keystore without addr/token")
	}
}

func TestTunableDefaults(t *testing.T) {
	t.Setenv("SUNDER_DB_URL", "postgres://x/y")
	c, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if c.OTITTL != 5*time.Minute {
		t.Fatalf("OTITTL default: %s", c.OTITTL)
	}
	if c.PIIAlg != "aes256gcm" {
		t.Fatalf("PIIAlg default: %s", c.PIIAlg)
	}
	if c.WebhookTimeout != 5*time.Second {
		t.Fatalf("WebhookTimeout default: %s", c.WebhookTimeout)
	}
	if c.WebhookMaxAttempts != 10 {
		t.Fatalf("WebhookMaxAttempts default: %d", c.WebhookMaxAttempts)
	}
	if c.DeliverInterval != time.Minute {
		t.Fatalf("DeliverInterval default: %s", c.DeliverInterval)
	}
}

func TestTunableOverridesAndValidation(t *testing.T) {
	t.Setenv("SUNDER_DB_URL", "postgres://x/y")
	t.Setenv("SUNDER_OTI_TTL", "90s")
	t.Setenv("SUNDER_PII_ALG", "xchacha20poly1305")
	t.Setenv("SUNDER_WEBHOOK_TIMEOUT", "30s")
	t.Setenv("SUNDER_WEBHOOK_MAX_ATTEMPTS", "3")
	t.Setenv("SUNDER_DELIVER_INTERVAL", "10s")
	c, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if c.OTITTL != 90*time.Second || c.PIIAlg != "xchacha20poly1305" ||
		c.WebhookTimeout != 30*time.Second || c.WebhookMaxAttempts != 3 ||
		c.DeliverInterval != 10*time.Second {
		t.Fatalf("overrides not applied: %+v", c)
	}

	bad := map[string]string{
		"SUNDER_OTI_TTL":              "5 minutes", // not a Go duration
		"SUNDER_PII_ALG":              "rot13",
		"SUNDER_WEBHOOK_TIMEOUT":      "0s",  // below minimum
		"SUNDER_WEBHOOK_MAX_ATTEMPTS": "0",   // below minimum
		"SUNDER_DELIVER_INTERVAL":     "48h", // above maximum
	}
	for key, val := range bad {
		t.Run(key, func(t *testing.T) {
			t.Setenv("SUNDER_DB_URL", "postgres://x/y")
			t.Setenv(key, val)
			if _, err := FromEnv(); err == nil {
				t.Fatalf("%s=%q must be rejected", key, val)
			}
		})
	}
}

func TestOTITTLBounds(t *testing.T) {
	for env, ok := range map[string]bool{"30s": true, "24h": true, "29s": false, "25h": false} {
		t.Run(env, func(t *testing.T) {
			t.Setenv("SUNDER_DB_URL", "postgres://x/y")
			t.Setenv("SUNDER_OTI_TTL", env)
			_, err := FromEnv()
			if ok && err != nil {
				t.Fatalf("%s must be accepted: %v", env, err)
			}
			if !ok && err == nil {
				t.Fatalf("%s must be rejected", env)
			}
		})
	}
}

func TestPortalConfig(t *testing.T) {
	t.Setenv("SUNDER_DB_URL", "postgres://x/y")
	c, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if c.PortalEnabled {
		t.Fatal("the portal must be OFF by default: an upgrade must not open a public surface")
	}

	t.Setenv("SUNDER_PORTAL_ENABLED", "true")
	t.Setenv("SUNDER_PORTAL_LISTEN", ":8081")
	t.Setenv("SUNDER_PORTAL_BASE_URL", "https://privacy.example")
	t.Setenv("SUNDER_PORTAL_CLIENT_IP_HEADER", "X-Forwarded-For")
	c, err = FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if !c.PortalEnabled || c.PortalListen != ":8081" ||
		c.PortalBaseURL != "https://privacy.example" || c.PortalClientIPHeader != "X-Forwarded-For" {
		t.Fatalf("portal config not applied: %+v", c)
	}
	if c.PortalCookieInsecure {
		t.Fatal("the session cookie must be Secure by default")
	}

	// A plaintext public base URL would put the login token on the wire.
	t.Setenv("SUNDER_PORTAL_BASE_URL", "http://privacy.example")
	if _, err := FromEnv(); err == nil {
		t.Fatal("a non-https portal base URL must be rejected")
	}
	t.Setenv("SUNDER_PORTAL_BASE_URL", "http://localhost:8081")
	if _, err := FromEnv(); err != nil {
		t.Fatalf("loopback http is allowed for development: %v", err)
	}

	// A separate listener without the portal enabled is a misconfiguration.
	t.Setenv("SUNDER_PORTAL_ENABLED", "")
	if _, err := FromEnv(); err == nil {
		t.Fatal("SUNDER_PORTAL_LISTEN without SUNDER_PORTAL_ENABLED must be rejected")
	}
}

func TestAuditSealingDefaults(t *testing.T) {
	t.Setenv("SUNDER_DB_URL", "postgres://localhost/sunder")
	// The CI matrix exports SUNDER_AUDIT_SEALING for the whole process;
	// this test is about the DEFAULT, so the variable must be absent.
	t.Setenv("SUNDER_AUDIT_SEALING", "")
	c, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if c.AuditSealing != "async" {
		t.Fatalf("default sealing mode = %q, want async", c.AuditSealing)
	}
	if c.AuditSealInterval != 200*time.Millisecond {
		t.Fatalf("default seal interval = %s", c.AuditSealInterval)
	}
	if c.AuditSealDelay != 2*time.Second {
		t.Fatalf("default seal delay = %s", c.AuditSealDelay)
	}
	if c.AuditSealBatch != 5000 {
		t.Fatalf("default seal batch = %d", c.AuditSealBatch)
	}
	if c.AuditSealExternal {
		t.Fatal("external sealer must be opt-in")
	}
}

func TestAuditSealingValidation(t *testing.T) {
	t.Setenv("SUNDER_DB_URL", "postgres://localhost/sunder")

	t.Setenv("SUNDER_AUDIT_SEALING", "eventually")
	if _, err := FromEnv(); err == nil {
		t.Fatal("unknown sealing mode must be rejected")
	}
	t.Setenv("SUNDER_AUDIT_SEALING", "sync")
	if _, err := FromEnv(); err != nil {
		t.Fatalf("sync mode must be accepted: %v", err)
	}

	// External sealer combined with sync is a contradiction: sync seals
	// inline, so "someone else seals" would silently mean "nobody checks".
	t.Setenv("SUNDER_AUDIT_SEAL_EXTERNAL", "true")
	if _, err := FromEnv(); err == nil {
		t.Fatal("external+sync must be rejected")
	}
	t.Setenv("SUNDER_AUDIT_SEALING", "async")
	if _, err := FromEnv(); err != nil {
		t.Fatalf("external+async must be accepted: %v", err)
	}
	t.Setenv("SUNDER_AUDIT_SEAL_EXTERNAL", "")

	t.Setenv("SUNDER_AUDIT_SEAL_INTERVAL", "10ms") // below the 50ms floor
	if _, err := FromEnv(); err == nil {
		t.Fatal("interval below range must be rejected")
	}
	t.Setenv("SUNDER_AUDIT_SEAL_INTERVAL", "")

	t.Setenv("SUNDER_AUDIT_SEAL_DELAY", "10m") // above the 5m ceiling
	if _, err := FromEnv(); err == nil {
		t.Fatal("delay above range must be rejected")
	}
	t.Setenv("SUNDER_AUDIT_SEAL_DELAY", "")

	t.Setenv("SUNDER_AUDIT_SEAL_BATCH", "50") // below the 100 floor
	if _, err := FromEnv(); err == nil {
		t.Fatal("batch below 100 must be rejected")
	}
}

func TestVersioningConfig(t *testing.T) {
	t.Setenv("SUNDER_DB_URL", "postgres://localhost/sunder")
	c, err := FromEnv()
	if err != nil || c.VersionsKeep != 0 {
		t.Fatalf("default versions keep: %d %v", c.VersionsKeep, err)
	}
	t.Setenv("SUNDER_VERSIONS_KEEP", "5")
	t.Setenv("SUNDER_VERSIONS_TTL", "720h")
	c, err = FromEnv()
	if err != nil || c.VersionsKeep != 5 || c.VersionsTTL == 0 {
		t.Fatalf("versions config: %+v %v", c, err)
	}
	t.Setenv("SUNDER_VERSIONS_KEEP", "5000")
	if _, err := FromEnv(); err == nil {
		t.Fatal("versions keep over 1000 must be rejected")
	}
	t.Setenv("SUNDER_VERSIONS_KEEP", "-1")
	if _, err := FromEnv(); err == nil {
		t.Fatal("negative versions keep must be rejected")
	}
	t.Setenv("SUNDER_VERSIONS_KEEP", "notanumber")
	if _, err := FromEnv(); err == nil {
		t.Fatal("non-numeric versions keep must be rejected")
	}
}

// TestRekeyBatchConfig pins the knob that decides whether a key rotation is
// performable at all. `1` is deliberately ALLOWED - it restores the old
// one-token-per-statement behaviour, which an operator might want on a
// database too loaded to take a batch - so the test asserts it is accepted
// rather than rejected, and that 0 is not.
func TestRekeyBatchConfig(t *testing.T) {
	t.Setenv("SUNDER_DB_URL", "postgres://localhost/sunder")
	c, err := FromEnv()
	if err != nil || c.RekeyBatch != 500 {
		t.Fatalf("default rekey batch: %d %v", c.RekeyBatch, err)
	}
	t.Setenv("SUNDER_REKEY_BATCH", "2000")
	if c, err = FromEnv(); err != nil || c.RekeyBatch != 2000 {
		t.Fatalf("rekey batch 2000: %d %v", c.RekeyBatch, err)
	}
	// The degenerate-but-legitimate setting: one person per page.
	t.Setenv("SUNDER_REKEY_BATCH", "1")
	if c, err = FromEnv(); err != nil || c.RekeyBatch != 1 {
		t.Fatalf("rekey batch 1 must be accepted: %d %v", c.RekeyBatch, err)
	}
	for _, bad := range []string{"0", "-5", "10001", "500.5", "lots"} {
		t.Setenv("SUNDER_REKEY_BATCH", bad)
		if _, err := FromEnv(); err == nil {
			t.Fatalf("SUNDER_REKEY_BATCH=%q must be rejected at startup, not silently coerced", bad)
		}
	}
}

func TestFileVaultConfigValidation(t *testing.T) {
	t.Setenv("SUNDER_DB_URL", "postgres://localhost/sunder")
	// Invalid storage kind.
	t.Setenv("SUNDER_FILES_STORAGE", "gcs")
	if _, err := FromEnv(); err == nil {
		t.Fatal("unknown storage kind must be rejected")
	}
	// S3 without required fields.
	t.Setenv("SUNDER_FILES_STORAGE", "s3")
	if _, err := FromEnv(); err == nil {
		t.Fatal("s3 without endpoint/bucket/keys must be rejected")
	}
	t.Setenv("SUNDER_FILES_S3_ENDPOINT", "https://s3.example.com")
	t.Setenv("SUNDER_FILES_S3_BUCKET", "b")
	t.Setenv("SUNDER_FILES_S3_ACCESS_KEY", "ak")
	t.Setenv("SUNDER_FILES_S3_SECRET_KEY", "sk")
	// Over the S3 single-PUT cap.
	t.Setenv("SUNDER_FILES_MAX_MB", "512")
	if _, err := FromEnv(); err == nil {
		t.Fatal("s3 with max > 256 MB must be rejected")
	}
	t.Setenv("SUNDER_FILES_MAX_MB", "128")
	if c, err := FromEnv(); err != nil || c.FilesStorage != "s3" {
		t.Fatalf("valid s3 config: %+v %v", c, err)
	}
	// Bad max value.
	t.Setenv("SUNDER_FILES_STORAGE", "local")
	t.Setenv("SUNDER_FILES_MAX_MB", "0")
	if _, err := FromEnv(); err == nil {
		t.Fatal("max 0 must be rejected")
	}
	t.Setenv("SUNDER_FILES_MAX_MB", "nope")
	if _, err := FromEnv(); err == nil {
		t.Fatal("non-numeric max must be rejected")
	}
	// Bad versions TTL.
	t.Setenv("SUNDER_FILES_MAX_MB", "25")
	t.Setenv("SUNDER_VERSIONS_TTL", "notaduration")
	if _, err := FromEnv(); err == nil {
		t.Fatal("bad versions TTL must be rejected")
	}
}

// DOCS-7: CONFIG.md promises a typo can never silently fall back to a
// default. Boolean settings were `os.Getenv(k) == "true"`, so `1` - which
// most container tooling produces - silently selected the OPPOSITE security
// posture from the one the configuration declared.
func TestBooleanTyposAreRefusedNotIgnored(t *testing.T) {
	t.Setenv("SUNDER_DB_URL", "postgres://x/y")
	for _, v := range []string{"1", "TRUE", "True", "yes", "on"} {
		t.Setenv("SUNDER_REDIS_FAIL_CLOSED", v)
		c, err := FromEnv()
		if err != nil {
			t.Fatalf("%q must be accepted as true: %v", v, err)
		}
		if !c.RedisFailClosed {
			t.Fatalf("%q must mean true, not a silent false", v)
		}
	}
	for _, v := range []string{"0", "no", "off", "FALSE"} {
		t.Setenv("SUNDER_REDIS_FAIL_CLOSED", v)
		c, err := FromEnv()
		if err != nil {
			t.Fatalf("%q must be accepted as false: %v", v, err)
		}
		if c.RedisFailClosed {
			t.Fatalf("%q must mean false", v)
		}
	}
	t.Setenv("SUNDER_REDIS_FAIL_CLOSED", "maybe")
	if _, err := FromEnv(); err == nil {
		t.Fatal("an unrecognised boolean must fail startup, not default to false")
	}
	// The empty string means unset.
	t.Setenv("SUNDER_REDIS_FAIL_CLOSED", "")
	c, err := FromEnv()
	if err != nil || c.RedisFailClosed {
		t.Fatalf("an empty value must mean unset: %v %v", c.RedisFailClosed, err)
	}
}
