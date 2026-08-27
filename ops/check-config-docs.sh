#!/usr/bin/env bash
# DOCS-16: every SUNDER_*/PLAYGROUND_* variable the code reads must appear in
# a reference table. Config drift is invisible otherwise - the code grows a
# knob, the table does not, and an operator cannot find it.
set -euo pipefail
cd "$(dirname "$0")/.."

vars=$(grep -rhoE '"(SUNDER|PLAYGROUND)_[A-Z0-9_]+"' \
        internal/config/config.go cmd/playground/main.go cmd/sunder/main.go internal/audit internal/api \
        2>/dev/null | tr -d '"' | sort -u)

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
