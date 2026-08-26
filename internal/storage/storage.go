// Package storage provides the blob drivers behind the F5 file vault.
package storage

// Two drivers, one interface. The vault owns confidentiality (it encrypts
// before Put and decrypts after Get), so a driver is a dumb byte store and
// must never be trusted with, or handed, plaintext. That split is what lets
// the S3 driver talk to third-party endpoints (MinIO, R2) at all.
//
// Stdlib-first: the S3 driver is hand-rolled over net/http with AWS
// Signature V4 implemented from the spec, the same way the Redis limiter
// hand-rolls RESP. Three object operations do not justify pulling the AWS
// SDK - and its transitive dependency tree - into this module.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// Driver is the blob store behind the file vault. Keys are opaque; the
// vault encrypts before Put, so a driver never sees plaintext.
type Driver interface {
	Put(ctx context.Context, key string, r io.Reader, size int64) error
	Get(ctx context.Context, key string) (io.ReadCloser, error)
	Delete(ctx context.Context, key string) error
}

// Config selects and configures a driver. The zero value is a local driver,
// which is invalid until Dir is set - there is no implicit temp directory,
// because silently storing the vault in /tmp is a data-loss bug that only
// shows up after a reboot.
type Config struct {
	// Kind is "local" (default) or "s3".
	Kind string

	// Dir is the backing directory for the local driver.
	Dir string

	// S3Endpoint is the full base URL of the service, scheme included
	// (https://s3.eu-central-1.amazonaws.com, http://127.0.0.1:9000).
	S3Endpoint  string
	S3Bucket    string
	S3Region    string
	S3AccessKey string
	S3SecretKey string

	// S3PathStyle addresses objects as {endpoint}/{bucket}/{key} instead of
	// the virtual-host form {bucket}.{host}/{key}. MinIO and most on-prem
	// gateways need this; AWS proper prefers virtual-host.
	S3PathStyle bool
}

// IsNotExist reports whether err means "that key is not in the store",
// across drivers. The vault's GC walks its index and deletes blobs it no
// longer references; a key that is already gone is the expected outcome of a
// retried or interrupted sweep, not a failure, and the GC must be able to
// tell that apart from a permissions or connectivity error without knowing
// which driver is configured.
//
// The local driver surfaces os.ErrNotExist from the filesystem; the S3
// driver maps a 404 - or a NoSuchKey error document - onto the same
// sentinel.
func IsNotExist(err error) bool {
	return errors.Is(err, os.ErrNotExist)
}

// Open builds the driver described by cfg. Configuration errors are returned
// here, at startup, rather than surfacing on the first upload: a vault that
// cannot store is a fatal misconfiguration, not a runtime degradation.
func Open(cfg Config) (Driver, error) {
	switch kind := strings.ToLower(strings.TrimSpace(cfg.Kind)); kind {
	case "", "local":
		return newLocal(cfg.Dir)
	case "s3":
		return newS3(cfg)
	default:
		return nil, fmt.Errorf("storage: unknown driver kind %q", cfg.Kind)
	}
}
