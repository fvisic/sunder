#!/usr/bin/env bash
# Regenerate the sales deck PDF from its HTML - one command, no manual export.
#
# The PDF exists because some prospects get the deck as an attachment, and an
# attachment cannot be corrected after it is sent. That is exactly why it must
# be REGENERATED whenever the HTML changes, never edited separately and never
# left stale: the HTML carried re-measured v0.5.0 numbers while the PDF still
# said whatever it said the day someone last exported it by hand.
#
# Uses headless Chrome (present on the workstation); prints each
# sales/*.html - except explicitly offline/print variants' duplicates - to a
# PDF next to it.
set -euo pipefail

CHROME="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
[ -x "$CHROME" ] || { echo "Chrome not found at: $CHROME (set CHROME=...)" >&2; exit 1; }

root="$(cd "$(dirname "$0")/.." && pwd)"
deck_dir="$root/sales"
[ -d "$deck_dir" ] || { echo "sales/: nothing to regenerate (directory absent)"; exit 0; }

shopt -s nullglob
made=0
for html in "$deck_dir"/*.html; do
  base="$(basename "$html" .html)"
  pdf="$deck_dir/$base.pdf"
  # The offline variant embeds its assets for exactly this purpose - it is
  # the printable one. A plain variant with an offline sibling is skipped so
  # we do not ship two PDFs that differ only in asset loading.
  if [[ "$base" != *offline* ]] && [ -f "$deck_dir/$base-offline.html" ]; then
    echo "skip: $base.html (its -offline variant is the printable one)"
    continue
  fi
  "$CHROME" --headless --disable-gpu --no-pdf-header-footer \
    --print-to-pdf="$pdf" "file://$html" 2>/dev/null
  echo "written: ${pdf#$root/} ($(du -h "$pdf" | cut -f1 | tr -d ' '))"
  made=$((made+1))
done

if [ "$made" -eq 0 ]; then
  echo "no HTML decks found under sales/" >&2
  exit 1
fi
echo "regenerated $made PDF(s) from HTML - the PDFs are derived files; edit the HTML"
