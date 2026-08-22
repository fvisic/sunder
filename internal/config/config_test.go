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
