---
name: release
description: Cut a Sunder release - version bumps, the full verification gauntlet, the PR into main, the tag, and the post-tag check that the release actually carries its artifacts. Use when asked to release, tag, cut a version, publish SDKs, or "are we ready to tag?"
---

# Releasing Sunder

A tag is a promise that the artifacts behind it are complete and verified.
v0.4.0 was published with **zero assets** - no binaries, no `SHA256SUMS`, no
signatures, no SBOM - because the release workflow failed after building and
signing everything, and nobody looked at the release page afterwards. Every
step below that says "verify" exists because trusting the previous step
failed at least once.

## 1. Decide what is being released

Server and SDKs version independently but share the `v1` API contract
(`RELEASING.md`). A release usually moves both; say which explicitly before
touching anything.

## 2. Version bumps

| Component | File | Note |
|---|---|---|
| Server | git tag only | `-X main.version` comes from `GITHUB_REF_NAME` |
| Go SDK | `sdks/go/sunder.go` (`const Version`) | published via the repo tag, no registry |
| TypeScript | `sdks/typescript/package.json` | |
| Python | `sdks/python/pyproject.toml` | |
| Java | `sdks/java/pom.xml` (the project `<version>`, not a plugin's) | |
| .NET | `sdks/dotnet/src/SunderId.Client/SunderId.Client.csproj` | |
| PHP | none | Packagist derives the version from the git tag |

Verify all six agree afterwards:

```sh
grep -m1 'const Version' sdks/go/sunder.go
grep -m1 '"version"' sdks/typescript/package.json
grep -m1 '^version' sdks/python/pyproject.toml
grep -m1 '<version>' sdks/java/pom.xml
grep -m1 '<Version>' sdks/dotnet/src/SunderId.Client/SunderId.Client.csproj
```

Also update the version in `docs-site/docs/dev/sdks-and-api.md`'s Maven
snippet - it is the one place a version string hides in prose.

## 3. CHANGELOG

A dated section, describing what an operator or integrator can now do.
Sections that have earned their place: behaviour changes worth a deployment
note, new configuration, and known limitations. Do not leave a "Known"
section listing something that was fixed during the release.

## 4. The gauntlet, locally

```sh
gofmt -l . && go vet ./...
go build ./...
go test -race -shuffle=on -count=1 -timeout=25m ./...
go test -count=1 -timeout=25m -covermode=atomic \
  -coverprofile=cover.out -coverpkg=./internal/...,./cmd/... ./...
./ops/coverage-gate.sh cover.out 90.0
./ops/check-config-docs.sh
(cd docs-site && mkdocs build --strict)
helm template deploy/helm/sunder >/dev/null && helm lint deploy/helm/sunder
python3 -c "import yaml,json;yaml.safe_load(open('api/openapi.yaml'));json.load(open('api/sunder.postman_collection.json'))"
```

Every SDK suite, and say which ones you could not run:

```sh
(cd sdks/go && go test ./...)
(cd sdks/typescript && npm test)
(cd sdks/python && python3 -m unittest discover -s tests -q)
(cd sdks/php && ./vendor/bin/phpunit tests/)
(cd sdks/java && bash run-tests.sh)
(cd sdks/dotnet && dotnet test SunderId.sln --nologo)
```

End-to-end on a clean stack - `down -v` matters, because the bugs that hide
here are cold-boot bugs:

```sh
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.playground.yml down -v
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.playground.yml up --build -d --wait
python3 ops/playground_e2e.py
for s in demo/*.sh; do bash "$s" || echo "FAILED: $s"; done
```

## 5. CI must actually run

`ci.yml` triggers on `push: branches: [main]` and on `pull_request`. A push
to a release branch runs **nothing**. Open the PR and wait for green:

```sh
gh pr create --base main --head release/vX.Y.Z --title "..." --body "..."
gh run list --limit 1
gh run view <id> --json jobs --jq '.jobs[] | "\(.conclusion)\t\(.name)"'
```

All thirteen jobs green - four sealing/reads matrix legs, six SDK legs,
`e2e-demo`, `e2e-playground`, `docs-site`. A single red leg is a finding, not
a flake, until you have reproduced it locally and shown otherwise. The
keystore race, the migration race and the playground alphabet bug were all
"one leg, once".

## 6. Merge, then tag

```sh
gh pr merge 1 --merge            # or --squash, per the repo's habit
git checkout main && git pull
git tag vX.Y.Z && git push origin vX.Y.Z
```

## 7. Verify the release carries its artifacts

**Do not skip this.** It is the step whose absence published an empty
v0.4.0.

```sh
gh run list --limit 1                                    # the release workflow
gh api repos/fvisic/sunder/releases/tags/vX.Y.Z --jq '.assets | length'
gh api repos/fvisic/sunder/releases/tags/vX.Y.Z --jq '.assets[].name'
```

Expect 10+ assets: four binaries, `SHA256SUMS` with its `.sig` and `.pem`,
the SBOM with its `.sig` and `.pem`. Zero assets means the workflow died
after building and signing - read the log, fix the workflow, re-run it. The
release step is idempotent by design and will upload into the existing
release.

Then verify a download the way a user would:

```sh
cosign verify-blob --signature SHA256SUMS.sig --certificate SHA256SUMS.pem \
  --certificate-identity-regexp 'github.com/.+/.github/workflows/release.yml' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
shasum -a 256 -c SHA256SUMS
```

## 8. SDK publication

Manual dispatch of `release-sdks`. Each registry job is gated twice: a
repository **variable** enables it and a **secret** authenticates it, so
nothing publishes until both exist. Go needs nothing (the module resolves
from the repo tag); Packagist needs the repo submitted once; Maven Central
is manual until Sonatype onboarding for `io.sunderid` is done.

## What blocks a tag

- Any CI leg red.
- Coverage below the gate, or the excluded-statement share over its ceiling.
- A version string disagreeing across the six SDK manifests.
- A `Known` section describing something you fixed on this branch.
- The previous release still missing its artifacts (fix the workflow first -
  the same failure will repeat).

## What does NOT block a tag, but must be said out loud

An SDK suite you could not run locally (a missing toolchain), a scenario the
CI matrix covers but you did not reproduce, a benchmark taken on different
hardware than the numbers it is compared against. Put those in the PR body.
A release note that omits what was not verified is worse than one that says
so plainly.
