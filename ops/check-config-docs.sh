#!/usr/bin/env bash
# DOCS-16: every SUNDER_*/PLAYGROUND_* variable the code reads must appear in
# a reference table. Config drift is invisible otherwise - the code grows a
# knob, the table does not, and an operator cannot find it.
set -euo pipefail
cd "$(dirname "$0")/.."

# Derived from the TREE, not from a list of files: the list this used to
# name (config.go, the two mains, audit, api) missed a variable read with a
# bare os.Getenv from internal/crypto - documented nowhere, invisible to this
# guard, and it passed. Non-test Go under internal/, cmd/ and the bulk
# loader; a name ending in "_" is a documented prefix (PLAYGROUND_CRED_<ROLE>),
# not a variable.
vars=$(grep -rhoE '"(SUNDER|PLAYGROUND)_[A-Z0-9_]+"' \
        --include='*.go' --exclude='*_test.go' internal cmd benchmark/bulkload \
        2>/dev/null | tr -d '"' | grep -v '_$' | sort -u)

missing=0
for v in $vars; do
  # SUNDER_TEST_* are test-harness only.
  case "$v" in SUNDER_TEST_*) continue;; esac
  if ! grep -rqF -- "$v" docs/CONFIG.md docs-site/docs/get-started/playground.md \
                        docs-site/docs/install/configuration.md \
                        docs-site/docs/install/bootstrap.md 2>/dev/null; then
    echo "undocumented config variable: $v"
    missing=1
  fi
done
if [ "$missing" -ne 0 ]; then
  echo "Add each to docs/CONFIG.md (or the playground table) - an operator cannot configure what is not written down." >&2
  exit 1
fi
echo "config reference: every variable documented"
