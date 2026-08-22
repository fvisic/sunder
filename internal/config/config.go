// Package config loads server configuration from SUNDER_* environment variables.
package config

import (
	"fmt"
	"os"
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
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// FromEnv builds a Config from the environment, validating required values.
func FromEnv() (Config, error) {
	c := Config{
		DBURL:        os.Getenv("SUNDER_DB_URL"),
		Listen:       getenv("SUNDER_LISTEN", ":8080"),
		TLSCert:      os.Getenv("SUNDER_TLS_CERT"),
		TLSKey:       os.Getenv("SUNDER_TLS_KEY"),
		MTLSCA:       os.Getenv("SUNDER_MTLS_CA"),
		Keystore:     getenv("SUNDER_KEYSTORE", "file"),
		KeystorePath: getenv("SUNDER_KEYSTORE_PATH", "./keystore"),
		VaultAddr:    os.Getenv("SUNDER_VAULT_ADDR"),
		VaultToken:   os.Getenv("SUNDER_VAULT_TOKEN"),
		VaultMount:   getenv("SUNDER_VAULT_MOUNT", "secret"),
		TSAURL:       getenv("SUNDER_TSA_URL", "https://freetsa.org/tsr"),
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
	return c, nil
}
