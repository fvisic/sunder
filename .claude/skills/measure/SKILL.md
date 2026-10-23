---
name: measure
description: Run a performance measurement that survives review - interleaved variants, medians, deterministic metrics before rps cells, and the operational traps that produced six invalid runs in one day. Use when benchmarking, comparing variants (schema, index, id shape, PG version), measuring import/lookup/read throughput, or when a number is about to be published or quoted.
---

# Measuring performance

A measurement that cannot survive the reviewer's questions is a run, not a
result. Every rule here is paid for: the person-id experiment (2026-08-31)
produced six invalid runs in one afternoon before these rules existed, and
the review that followed struck half the conclusions of the runs that did
complete.

## The two kinds of variance - never conflate them

A short rps benchmark carries **~±30% run-to-run noise**: burstiness,
checkpoint timing, autovacuum waking at the wrong moment. Measured directly:
the same lookup cell gave 635 then 999 rps minutes apart, nothing changed.

A long batch (a 10M-row import) **averages all of that out** and repeats
within a few percent.

A noise bound measured on one must never (dis)qualify a difference measured
on the other. "±30% harness noise, therefore the 14% import delta is noise"
is the exact mistake the reviewer caught.

## Design rules

- **Interleave variants: ABC ABC ABC, never AAA BBB CCC.** Blocked ordering
  lets thermal drift, cache history and autovacuum cycles correlate with the
  variant and enter the result as signal.
- **Median of >= 3 runs.** One run per variant is an anecdote. Report the
  median; keep every raw run in the output file.
- **Deterministic metrics FIRST** - they have zero variance and explain the
  rest:
  - `pg_relation_size` on heap and each index, after the load AND after
    `VACUUM ANALYZE` - bloat as a number, not a hypothesis;
  - the WAL delta over the run: `pg_current_wal_lsn()` before and after,
    `pg_wal_lsn_diff` between. **If WAL ratios track time ratios, the run is
    I/O bound and the timing comparison means something. If they do not, it
    is CPU bound and measures something else.**
- **Tails beside means.** p95/p99 are often stabler than averages under
  variance, and effects like B-tree page splits show up as tail latency, not
  as mean throughput.
- **rps cells never decide a storage/schema question.** They answer service
  questions. For a schema variant, the long batch plus the deterministic
  metrics decide; rps is a cross-check at 5 runs/median if kept at all.

## Read your own table before publishing it

Internal contradictions are proof the harness resolution is below the effect
size - say that, instead of quoting the cells:

- throughput falling as concurrency rises on a read-only path is not physical
  (v7 lookup: 1,203 at c=8, 1,140 at c=32);
- an ordering that flips between two measurements of the same thing
  (read c=32 said v7 > bigint; 3-instance read said bigint > v7).

A multi-instance total reaching only ~1.7x of a single instance means a
shared resource saturated - those cells measure the SERVER's ceiling, not the
variable under test. Explain the column or drop it from the decision.

## Projecting beyond the measured scale

Small-scale numbers do not transfer upward: at 10M rows the 4.7 GB token
pkey fits in a 12 GB shared_buffers and random inserts are nearly free
(page splits are pure CPU); at 200M nothing fits and the same pattern
generates real reads. Measured: -26% per 10x for random UUIDs.

To say anything about the target scale, **shrink shared_buffers to reproduce
the target index-to-RAM ratio** and run the same protocol once per variant.
One such run says more than every rps cell combined.

## Operational traps - each of these invalidated at least one real run

- **One measurement at a time, enforced.** `mkdir /tmp/<name>.lock` +
  `trap 'rm -rf' EXIT`, refuse if present. Two concurrent runs interleaved
  into one output file twice, and slowed each other into garbage numbers.
- **`setsid nohup ... < /dev/null &`** for anything long on the server - a
  broken ssh pipe killed a waiter mid-run; setsid is why the run survived.
  And `pkill -f <script>` kills the script, NOT its in-flight `docker exec`
  child - a zombie import contaminated the next run's dataset.
- **Assert the service is alive before timing it**, and refuse to report
  otherwise. A dead container turned every cell into an instant 0.1s
  "measurement" that looked like a result.
- **Fresh, run-stamped seeds.** Reused seeds hit the dedup path of data a
  previous (or killed) run imported: 18 rows/s, 160 errors, all fiction.
  Ops share a namespace in order: WRITE seeds it, lookup/read consume it -
  per-op seeds made lookup search for contacts nobody wrote.
- **Rebuild EVERY image the run touches.** `compose build sunder` left
  sunder2/3 on a stale binary: they errored against the new schema in one
  run and silently minted the WRONG id shape in another - which contaminated
  a cell that looked perfectly healthy.
- **`pgrep -f <name>` matches your own ssh command line** carrying that
  name; the false positive both lied about progress and once killed the
  querying shell itself. Match the script path exactly (`pgrep -f
  "bash.*name.sh"`) or check a pidfile.
- **Parse harness output as one JSON document**, not with a flat-brace
  regex: the moment error output got structured (nested objects), the regex
  reported the most diagnosable cells as NO-JSON.
- **Bind-mount permissions:** the container runs as uid 65532; a
  root-or-user-owned keystore dir let bootstrap mint (via exec) but made
  `serve` die at startup - visible only as "connection refused" at bench
  time. `chmod 777` the mount before `up`.
- **Fixed host ports are per-stack.** The import stack's instance answered
  on 18090, not the 18080 the bench targeted - six cells of pure connection
  errors reported as if they were the service's numbers.

## Publishing

Quote a rate WITH its conditions (dataset size, RAM/shared_buffers, PG
major, flags) or quote nothing. Fence current figures with
`<!-- authoritative:begin/end -->` so `ops/check-sales-deck.sh` holds the
deck to them, and move the fence when a newer measurement lands. A version
bump of PostgreSQL re-baselines every published number - the old ones name
the old major.
