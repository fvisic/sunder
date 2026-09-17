#!/usr/bin/env bash
# Session-independent tail of the person-id experiment. Runs under setsid on
# the server: waits out the interleaved matrix, runs the low-shared_buffers
# round (the 200M index-to-RAM simulation), then writes ~/phase7/SUMMARY.txt
# with per-variant MEDIANS and the deterministic metrics. Nothing about it
# needs a live operator session - read SUMMARY.txt whenever.
set -uo pipefail
M=~/phase7/import-matrix-sb12GB.txt
until grep -q "ALL DONE" "$M" 2>/dev/null; do sleep 120; done

# low-SB round: same protocol, shared_buffers shrunk so the token pkey no
# longer fits - the ratio a 200M deployment would live with.
SB=2GB ROUNDS=1 ~/import-matrix.sh
L=~/phase7/import-matrix-sb2GB.txt

python3 - "$M" "$L" > ~/phase7/SUMMARY.txt <<'PY'
import re, statistics, sys

def parse(path):
    runs = {}
    cur = None
    try:
        text = open(path).read()
    except OSError:
        return runs
    for block in text.split("=== round ")[1:]:
        head, rest = block.split("===", 1)
        parts = head.strip().split()
        rnd, variant = parts[0], parts[2] if len(parts) > 2 else parts[-1]
        m = re.search(r"TOTAL exit=(\d+) wall=(\d+)s\s+rows/s=(\d+)\s+WAL=([\d.]+)GB", rest)
        if not m or m.group(1) != "0":
            continue
        e = runs.setdefault(variant, {"wall": [], "rps": [], "wal": [], "sizes": {}})
        e["wall"].append(int(m.group(2)))
        e["rps"].append(int(m.group(3)))
        e["wal"].append(float(m.group(4)))
        for sm in re.finditer(r"(person_tokens\w*|persons\w*)\|(\d+ \w+)", rest):
            e["sizes"][sm.group(1)] = sm.group(2)  # last run's sizes win; deterministic anyway
    return runs

def report(title, runs):
    print("==", title)
    for v, e in sorted(runs.items()):
        med = statistics.median
        print("  %-8s runs=%d  wall median=%ds (%s)  rows/s median=%d  WAL median=%.1fGB"
              % (v, len(e["wall"]), med(e["wall"]),
                 "/".join(str(x) for x in sorted(e["wall"])), med(e["rps"]), med(e["wal"])))
        for k in sorted(e["sizes"]):
            print("      %-26s %s" % (k, e["sizes"][k]))
    print()

report("import matrix, shared_buffers=12GB (index fits)", parse(sys.argv[1]))
report("low-SB round, shared_buffers=2GB (200M-like ratio)", parse(sys.argv[2]))
print("raw files: import-matrix-sb12GB.txt, import-matrix-sb2GB.txt")
PY
echo "CHAIN DONE $(date -Is)" >> ~/phase7/SUMMARY.txt
