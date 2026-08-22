package config

import "testing"

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

func TestVaultKeystoreValidation(t *testing.T) {
	setBase(t)
	t.Setenv("SUNDER_KEYSTORE", "vault")
	if _, err := FromEnv(); err == nil {
		t.Fatal("expected error for vault keystore without addr/token")
	}
}
