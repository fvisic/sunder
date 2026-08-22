// Package apispec embeds the OpenAPI contract so the running service can
// serve its own documentation (GET /openapi.yaml).
package apispec

import _ "embed"

//go:embed openapi.yaml
var OpenAPI []byte
