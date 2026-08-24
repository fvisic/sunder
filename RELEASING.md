# Releasing

## Server release

```sh
git tag v0.1.0 && git push origin v0.1.0
```

The `release` workflow then: builds static binaries (linux/darwin ×
amd64/arm64), generates an SPDX SBOM, signs the checksums, the SBOM and the
GHCR container image with cosign (keyless, GitHub OIDC), and publishes a
GitHub release with everything attached.

Verify a download:

```sh
cosign verify-blob --signature SHA256SUMS.sig --certificate SHA256SUMS.pem \
  --certificate-identity-regexp 'github.com/.+/.github/workflows/release.yml' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
shasum -a 256 -c SHA256SUMS
```

## SDK releases

Bump the version in the SDK manifests, then run the `release-sdks` workflow
(manual dispatch). Each registry job is gated twice: a repository **variable**
enables it and a **secret** authenticates it - nothing publishes until both
exist.

| Registry | Enable (variable) | Credential (secret) | Notes |
|---|---|---|---|
| Go module proxy | - | - | nothing to publish: `sdks/go` is its own module, so `go get github.com/fvisic/sunder/sdks/go@vX.Y.Z` resolves from the repo tag. The SDK's own version constant lives in `sdks/go/sunder.go` |
| npm | `PUBLISH_NPM=true` | `NPM_TOKEN` | register the `@sunder-id` scope first; publishes with provenance |
| PyPI | `PUBLISH_PYPI=true` | `PYPI_API_TOKEN` | project name `sunder-client` |
| NuGet | `PUBLISH_NUGET=true` | `NUGET_API_KEY` | package `SunderId.Client` |
| Packagist | - | - | submit the repo URL once at packagist.org; git tags become versions |
| Maven Central | - | - | manual: Sonatype OSSRH onboarding for `io.sunderid` + GPG signing; `sdks/java/pom.xml` is release-ready |

## Versioning

Server and SDKs version independently but share the `v1` API contract:
SDK major version = API version. Keep `api/openapi.yaml` the source of truth
for any surface change.
