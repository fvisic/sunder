# Person-id matrix, reference server, 2026-08-31

Recovered from `~/phase7` on the bench host (`ssh AI`) on 2026-09-17. These
are the raw outputs behind the "Person id shape" section of
`benchmark/README.md`; the scripts that produced them are kept beside them so
the protocol is auditable, not just the numbers.

| file | what it is |
|---|---|
| `import-matrix-sb12GB.txt` | the decision run: 10M rows, v7 and bigint interleaved, 3 rounds, `shared_buffers` 12 GB. Per run: wall, rows/s, WAL delta, relation sizes after load and after VACUUM |
| `import-matrix-sb2GB.txt` | the same protocol, 1 round, `shared_buffers` shrunk to 2 GB to reproduce the index-to-RAM ratio of a much larger deployment |
| `SUMMARY.txt` | medians per variant, written by `chain.sh` |
| `import-matrix.sh` | the harness for both files above |
| `chain.sh` | waited out the matrix, ran the low-`shared_buffers` round, wrote the summary - so no live session was needed |
| `variant-bench.sh`, `variant-*.txt` | an EARLIER, superseded shape: one full protocol per variant including rps cells |

**The `variant-*.txt` files are kept as a record and decide nothing.**
`variant-v4.txt` and `variant-bigint.txt` ran with `SKIP_IMPORT=1` against
whatever dataset was standing, so their cells do not describe the id shape in
their own filename. The cells that did run against their own import
contradict themselves - v7 lookup falls from 1,203 rps at c=8 to 1,140 at
c=32, which is not physical on a read-only path, and the three-instance totals
reach only ~1.7x of one instance, so they measured the server's ceiling rather
than the variable under test. `.claude/skills/measure/SKILL.md` was written
from these mistakes.

The laptop v4-vs-v7 runs are in `../A-fits-1M/` and `../B-tight-1M/`,
produced by `benchmark/personid/measure.sh`.
