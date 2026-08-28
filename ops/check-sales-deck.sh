#!/usr/bin/env bash
# Every number the sales deck shows a customer must be traceable to a
# measurement in this repository.
#
# The deck lives in sales/, which is gitignored - so CI cannot check it and
# this script is deliberately a LOCAL and RELEASE-TIME check that skips
# cleanly when the file is absent. That is not a workaround; it is the honest
# consequence of the deck not being in the repo.
#
# Why it exists: the deck quotes ten latency figures, a dataset size and a
# coverage percentage. They come from four different sources
# (benchmark/README.md, docs-site/.../performance.md, docs/WHITEPAPER.md,
# docs-site/.../comparisons/databunker.md). Phase 7.4 re-measures the whole
# benchmark on the v0.5 build; when those numbers move, the four sources get
# updated because guards and reviewers touch them - and the deck, which is
# the ONE artifact a customer actually reads, is the thing nobody opens.
#
# The check is deliberately weak in one direction and strict in the other: it
# does not verify a number is used in the RIGHT context (only a human can say
# whether a p99 was labelled as a median), but a number appearing in the deck
# and nowhere in the repo is a hard failure.
set -euo pipefail

DECK_DIR="${1:-sales}"

shopt -s nullglob
decks=("$DECK_DIR"/*.html)
if [ ${#decks[@]} -eq 0 ]; then
  echo "sales deck: no HTML deck under $DECK_DIR/ - nothing to check"
  exit 0
fi

python3 - "${decks[@]}" <<'PY'
import html, os, re, sys

decks = sys.argv[1:]

SOURCES = [
    "benchmark/README.md",
    "docs/WHITEPAPER.md",
    "docs/THREAT-MODEL.md",
    "docs/CONFIG.md",
    "docs-site/docs/get-started/performance.md",
    "docs-site/docs/comparisons/databunker.md",
    "docs-site/docs/comparisons/key-protection.md",
    "README.md",
    "CHANGELOG.md",
]

def numbers(text):
    """Every number in the text, as floats, under both conventions.

    The deck is Croatian - `1.569` means one thousand five hundred and
    sixty-nine, `5,62` means five point six two. The sources are English -
    `1,568.9` and `5.62`. Comparing the STRINGS reports three false alarms on
    a deck that is perfectly in sync, and a check that cries wolf is one
    nobody runs. So both sides are parsed into values.
    """
    out = set()
    for tok in re.findall(r"\d[\d.,]*\d|\d", text):
        for candidate in _interpretations(tok):
            out.add(round(candidate, 4))
    return out

def _interpretations(tok):
    """A token like 2.466,9 / 2,466.9 / 2.467 has more than one reading.
    Yield every plausible one rather than guessing the locale."""
    vals = []
    plain = tok.replace(",", "").replace(".", "")
    if plain.isdigit():
        # English thousands: 2,466.9 -> 2466.9 ; Croatian: 2.466,9 -> 2466.9
        for dec, thou in ((".", ","), (",", ".")):
            t = tok
            if t.count(dec) <= 1:
                try:
                    vals.append(float(t.replace(thou, "").replace(dec, ".")))
                except ValueError:
                    pass
        # And the bare reading with separators stripped: 2.467 -> 2467
        try:
            vals.append(float(plain))
        except ValueError:
            pass
    return vals

def close(a, b):
    """Rounding tolerance: a deck rounds 2,466.9 rps to 2.467."""
    if a == b:
        return True
    scale = max(abs(a), abs(b), 1.0)
    return abs(a - b) / scale <= 0.005

AUTH_RE = re.compile(r"<!--\s*authoritative:begin.*?-->(.*?)<!--\s*authoritative:end\s*-->", re.S)

def authoritative(path, text):
    """Use only the regions a document marks as current.

    These files keep every historical run deliberately - the deltas between
    them are the record of what changed. But a figure from a SUPERSEDED
    section is exactly the kind a deck keeps quoting after a re-measurement,
    and matching against the whole file would bless it as sourced.

    A file with no markers is used whole, so adding a source costs nothing
    until it starts carrying figures that age."""
    regions = AUTH_RE.findall(text)
    if not regions:
        return text
    return "\n".join(regions)

corpus_text = ""
missing_sources = []
for s in SOURCES:
    try:
        raw = open(s, encoding="utf-8", errors="replace").read()
        corpus_text += authoritative(s, raw) + "\n"
    except OSError:
        missing_sources.append(s)
if missing_sources:
    print("::error::these measurement sources are gone, so the check is weaker than it looks:")
    for m in missing_sources:
        print("   ", m)
    sys.exit(1)

source_values = sorted(numbers(corpus_text))

def structural(v):
    """Not a measurement: small counts, years, whole percentages - and long
    digit runs, which are identifiers in the worked example (an OIB, a card
    number), never claims about the product."""
    if v >= 10**8:
        return True
    return float(v).is_integer() and (v <= 100 or 1900 <= v <= 2100)

fail = 0
for deck in decks:
    raw = open(deck, encoding="utf-8", errors="replace").read()
    body = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", raw, flags=re.S | re.I)
    body = html.unescape(re.sub(r"<[^>]+>", " ", body))
    # Illustrative data in the worked example is not a claim about the
    # product: a made-up debt in EUR, a made-up churn score.
    body = re.sub(r"\d[\d.,]*\s*EUR", " ", body)
    body = re.sub(r"rizik odustajanja:\s*[\d.,]+", " ", body)
    # Sequence numbers in the illustrated audit chain (#8841, #8842, ...)
    # are part of a drawn example, not a claim about throughput.
    body = re.sub(r"#\s*\d+", " ", body)

    claims = {}
    for m in re.finditer(r"\b(\d[\d.,]*\d)\s*(ms|s|%|x|×|/s|rps|M)?\b", body):
        tok = m.group(1)
        for v in _interpretations(tok):
            if structural(v):
                continue
            claims.setdefault(round(v, 4), tok)

    unbacked = []
    for v, tok in sorted(claims.items()):
        if not any(close(v, sv) for sv in source_values):
            unbacked.append(f"{tok} (read as {v:g})")

    name = os.path.basename(deck)
    if unbacked:
        fail = 1
        print(f"::error::{name}: figures shown to a customer that match no measurement in the repo:")
        for u in unbacked:
            print("   ", u)
        print("  Either a re-measurement landed and the deck did not follow,")
        print("  or the figure was never sourced. Both read the same to a customer.")
        print("  Sources checked: " + ", ".join(SOURCES))
    else:
        print(f"  {name}: {len(claims)} measured figure(s), all traceable to a source in the repo")

sys.exit(fail)
PY

echo "sales deck: every quoted figure is backed by a measurement in the repo"
