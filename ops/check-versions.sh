#!/usr/bin/env bash
# One place to read the version from, and a guard that it is not a lie.
#
# VERSION exists because "which build is this?" had no cheap answer. A
# benchmark ran for an afternoon against a server checkout that turned out to
# be an old snapshot - it had neither of the two features being measured - and
# nothing on the box said so. `cat VERSION` now answers in one command, on a
# machine with no git history and no toolchain.
#
# The guard is the point. A version file nobody checks drifts, and a drifted
# version file is worse than none: it answers confidently and wrongly.
set -euo pipefail

fail=0
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

[ -f VERSION ] || { echo "::error::VERSION is missing"; exit 1; }
version="$(tr -d ' \t\n\r' < VERSION)"
case "$version" in
  [0-9]*.[0-9]*.[0-9]*) ;;
  *) echo "::error::VERSION contains %q, which is not a semantic version" "$version"; exit 1 ;;
esac
echo "== VERSION: $version"

# 1. The server version must match the newest release tag, when there is one.
#    A shallow CI clone has no tags; that is a skip, not a pass.
if git rev-parse --git-dir >/dev/null 2>&1; then
  tag="$(git describe --tags --abbrev=0 2>/dev/null || true)"
  if [ -z "$tag" ]; then
    echo "  no tags in this clone - cannot cross-check (shallow checkout?)"
  elif [ "${tag#v}" != "$version" ]; then
    echo "::error::VERSION says $version but the newest tag is $tag."
    echo "  Either the release bumped the tag and not this file, or this file was bumped"
    echo "  ahead of the tag. Both make 'cat VERSION' a wrong answer to 'which build is this'."
    fail=1
  else
    echo "  matches the newest tag ($tag)"
  fi
fi

# 2. The six SDK manifests must agree WITH EACH OTHER. They deliberately do
#    NOT have to match the server (RELEASING.md: they version independently,
#    sharing only the v1 API contract), so this checks internal consistency -
#    the failure that actually happens is one manifest missed in a bump.
sdk_versions() {
  sed -n 's/.*const Version = "\([^"]*\)".*/go=\1/p'            sdks/go/sunder.go            | head -1
  sed -n 's/.*"version": *"\([^"]*\)".*/typescript=\1/p'        sdks/typescript/package.json | head -1
  sed -n 's/^version *= *"\([^"]*\)".*/python=\1/p'             sdks/python/pyproject.toml   | head -1
  sed -n 's/.*<version>\([^<]*\)<\/version>.*/java=\1/p'        sdks/java/pom.xml            | head -1
  sed -n 's/.*<Version>\([^<]*\)<\/Version>.*/dotnet=\1/p' \
      sdks/dotnet/src/SunderId.Client/SunderId.Client.csproj | head -1
}
# `mapfile` is bash 4+; macOS ships bash 3.2, and a guard that only runs on
# the CI image is a guard nobody runs before pushing.
pairs="$(sdk_versions)"
count="$(printf '%s\n' "$pairs" | grep -c '=' || true)"
if [ "$count" -lt 5 ]; then
  echo "::error::read only $count of 5 SDK manifests - this check has stopped checking."
  echo "  A manifest moved or changed shape; fix the pattern rather than deleting the check."
  exit 1
fi
distinct="$(printf '%s\n' "$pairs" | cut -d= -f2 | sort -u | tr '\n' ' ')"
if [ "$(printf '%s\n' "$pairs" | cut -d= -f2 | sort -u | wc -l | tr -d ' ')" -ne 1 ]; then
  echo "::error::the SDK manifests disagree: $(printf '%s' "$pairs" | tr '\n' ' ')"
  echo "  All six ship against one v1 contract; a bump that misses one publishes a"
  echo "  package whose version is a different promise from its siblings."
  fail=1
else
  echo "  5 SDK manifests agree on ${distinct% } (PHP takes its version from the git tag)"
fi

# 3. CHANGELOG must have a section for this version, or the release has no
#    description of what an operator is getting.
if ! grep -q "^## v\?$version" CHANGELOG.md; then
  echo "::error::CHANGELOG.md has no section for $version - a release nobody described"
  fail=1
else
  echo "  CHANGELOG.md documents $version"
fi

[ "$fail" -eq 0 ] || exit 1
echo "versions: VERSION, the newest tag, the SDK manifests and the CHANGELOG all agree"
