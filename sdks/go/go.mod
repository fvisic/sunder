// The Go SDK is its own module so that importing it never pulls in the
// server's dependency tree (pgx, x/crypto, x/text). It has no dependencies
// of its own: net/http and encoding/json only.
module github.com/fvisic/sunder/sdks/go

go 1.25
