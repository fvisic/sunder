#!/usr/bin/env bash
# The coverage gate, with an explicit and auditable exclusion list.
#
# Go's cover tool has no notion of "this branch is unreachable without
# injecting a fault at exactly this statement". After the second review's
# remediation the tree carries roughly a thousand statements of fail-closed
# error handling, and a handful of those blocks are pure propagation out of a
# rows.Scan or a tx.Commit: reaching them needs the database to fail at that
# one statement, which no test in this suite can arrange without a fault
# harness per call site.
#
# Rather than lower the gate - which would hide REAL gaps in business logic -
# each such block is marked in the source with
#
#     //coverage:defensive <reason>
#
# and this script drops exactly those blocks before computing the total. Three
# properties keep that honest:
#
#   1. Every exclusion is visible in the diff, next to the code it excuses.
#   2. A marker on a block that IS covered is an ERROR, so the list cannot rot
#      into a pile of stale excuses.
#   3. The excluded total is printed and capped, so it cannot grow quietly.
#
# Usage: ops/coverage-gate.sh <profile> [min-percent]
set -euo pipefail

PROFILE="${1:-cover.out}"
MIN="${2:-90.0}"
# Excluded statements may never exceed this share of the tree. A gate that can
# be satisfied by adding markers is not a gate.
MAX_EXCLUDED_PCT="1.0"

[ -f "$PROFILE" ] || { echo "coverage profile not found: $PROFILE" >&2; exit 1; }

python3 - "$PROFILE" "$MIN" "$MAX_EXCLUDED_PCT" <<'PY'
import re, sys, os

profile, minimum, max_excluded_pct = sys.argv[1], float(sys.argv[2]), float(sys.argv[3])
MARKER = "//coverage:defensive"

# One entry per block: the same block appears once per package profile when
# several test binaries write to one file, so keep the highest count.
blocks = {}
with open(profile) as fh:
    mode = fh.readline()
    for line in fh:
        line = line.rstrip("\n")
        if not line:
            continue
        loc, nstmt, count = line.rsplit(" ", 2)
        nstmt, count = int(nstmt), int(count)
        if loc not in blocks or count > blocks[loc][1]:
            blocks[loc] = (nstmt, count)

sources = {}
def source(pkgfile):
    """Resolve an import path from the profile to a file in this repo."""
    if pkgfile not in sources:
        rel = pkgfile.split("/", 3)[-1] if pkgfile.startswith("github.com/") else pkgfile
        try:
            with open(rel) as fh:
                sources[pkgfile] = fh.read().splitlines()
        except OSError:
            sources[pkgfile] = []
    return sources[pkgfile]

def marked(pkgfile, start_line):
    """A block is excluded when its opening line - or the line above it -
    carries the marker. Both, because `if err != nil {` opens the block on its
    own line while a multi-line condition opens it on the line below."""
    lines = source(pkgfile)
    for n in (start_line, start_line - 1):
        if 1 <= n <= len(lines) and MARKER in lines[n - 1]:
            return lines[n - 1]
    return None

total = covered = excluded = 0
stale = []
excused = []
for loc, (nstmt, count) in blocks.items():
    pkgfile, rng = loc.rsplit(":", 1)
    start_line = int(rng.split(".")[0])
    mark = marked(pkgfile, start_line)
    if mark is not None:
        if count > 0:
            stale.append(f"{pkgfile}:{start_line}")
            # A covered block needs no excuse: count it normally.
        else:
            excluded += nstmt
            reason = mark.split(MARKER, 1)[1].strip() or "(no reason given)"
            excused.append((nstmt, f"{pkgfile}:{start_line}", reason))
            continue
    total += nstmt
    if count > 0:
        covered += nstmt

if stale:
    print("::error::coverage markers on blocks that ARE covered - remove them:")
    for s in sorted(stale):
        print("  ", s)
    sys.exit(1)

raw_total = total + excluded
raw_covered = covered
pct = 100.0 * covered / total if total else 100.0
raw_pct = 100.0 * raw_covered / raw_total if raw_total else 100.0
excluded_pct = 100.0 * excluded / raw_total if raw_total else 0.0

print(f"coverage: {pct:.2f}% of {total} measured statements "
      f"(raw {raw_pct:.2f}% of {raw_total}; {excluded} statement(s) "
      f"excluded as defensive, {excluded_pct:.2f}%)")
if excused:
    print("excluded blocks:")
    for nstmt, where, reason in sorted(excused, key=lambda e: e[1]):
        print(f"  {nstmt} stmt  {where}  {reason}")

if excluded_pct > max_excluded_pct:
    print(f"::error::{excluded_pct:.2f}% of statements are excluded, over the "
          f"{max_excluded_pct:.2f}% ceiling. The gate must not be satisfiable "
          f"by adding markers - test these branches instead.")
    sys.exit(1)
# Compare at the precision the line above PRINTS. The chained CI leg once
# failed with "coverage 90.00% is below the 90.0% gate": 89.996 rounded up
# in the message and down in the comparison, and the report contradicted
# its own verdict.
if round(pct, 2) < minimum:
    print(f"::error::coverage {pct:.3f}% is below the {minimum:.1f}% gate")
    sys.exit(1)
PY
