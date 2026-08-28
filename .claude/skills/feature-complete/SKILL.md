---
name: feature-complete
description: Verify a feature or config knob landed in EVERY artifact it must reach - server, OpenAPI, all six SDKs, docs/CONFIG.md, docs-site, Helm chart, Postman collection, tests and the playground. Use before opening a PR that adds a route, an endpoint, a SUNDER_* variable, a CLI command or a metric, and when asked "is this documented / wired / covered everywhere?"
---

# Feature completeness

A feature is not done when it works. It is done when nothing in the tree
still describes a world where it does not exist.

## Why this exists

v0.5.0 shipped with the Helm chart missing five config variables, the
Postman collection covering 14 of ~40 routes while the docs claimed it
covered the rest, and `docs-site` missing 20 variables `docs/CONFIG.md` had.
Every one was found by a person asking, not by a check. The two guards that
DO exist (`ops/check-config-docs.sh`, `TestEveryRouteIsDocumented`) have
never let a gap through - the answer is more guards of that shape, and this
checklist is what you run until they exist.

## Run the automated guards first

```sh
./ops/check-config-docs.sh          # every SUNDER_* is in a reference table
./ops/check-artifact-coverage.sh    # helm reachability, Postman coverage, SDK
                                    # parity, the CONFIG.md<->docs-site mirror,
                                    # test-corruption style, demo scripts in CI
./ops/check-sales-deck.sh           # local only: figures in sales/ trace to a
                                    # measurement in the repo (skips if absent)

go test ./internal/api/ -run TestEveryRouteIsDocumented -count=1
go test ./internal/api/ -run TestOpenAPI -count=1        # field-level drift
go test ./internal/audit/ -count=1                # the closed audit action set
cd docs-site && mkdocs build --strict            # dangling links, bad mermaid
helm template deploy/helm/sunder >/dev/null      # chart still renders
helm lint deploy/helm/sunder
python3 -c "import yaml,json; yaml.safe_load(open('api/openapi.yaml')); json.load(open('api/sunder.postman_collection.json'))"
```

Each guard prints its counts AND its exemptions. Read the exemptions: an
exemption is a decision someone wrote down, and the guard is only as honest
as that list. Two of them were found lying within a day of being written -
one exempted a call site that had moved, the other described a mechanism
that no longer ran.

Green there means only that the guards that exist are satisfied. The table
below is the part no guard covers yet.

## The matrix

Work out which rows the change touches, then verify each one by opening the
file - not by remembering.

### A new or changed `/v1` route

| Artifact | What must be true | How to check |
|---|---|---|
| `api/openapi.yaml` | operation + every request/response field | `TestEveryRouteIsDocumented`, `TestOpenAPI*` |
| `docs/API.md` | prose entry: what it does, what it refuses, what it audits | grep the path |
| All six SDKs | a method in Go, TS, Python, PHP, Java, .NET - or a written reason it is deliberately not wrapped | see "SDK parity" below |
| SDK tests | one test per SDK asserting method, path, body shape and the retry decision | `grep -c` the method name in each suite |
| `docs-site/docs/dev/sdks-and-api.md` | the surface table lists it as wrapped or not | read the table |
| `api/sunder.postman_collection.json` | one request, with the auth and headers it needs | run the coverage check below |
| Playground | a walkthrough step, or an entry in the deliberate-omissions list | `internal/playground/scenarios/` |
| Server tests | happy path, refusal path, audit row, rate limit | the package's `_test.go` |

### A new `SUNDER_*` variable

| Artifact | What must be true |
|---|---|
| `internal/config/config.go` | parsed at startup, range-checked, fails fast on garbage |
| `docs/CONFIG.md` | a row in a reference table: default, range, and what you GIVE UP by changing it |
| `docs-site/docs/install/configuration.md` | the same variable, same default (the two must not disagree) |
| `deploy/helm/sunder/values.yaml` | settable, with a comment explaining the trade-off on Kubernetes specifically |
| `deploy/helm/sunder/templates/_helpers.tpl` | actually rendered into the pod env |
| `CHANGELOG.md` | listed under "New configuration" |
| Tests | one asserting the default, one asserting an out-of-range value is refused - a typo must fail at STARTUP, never fall back to the default silently |
| The measured cost | if the knob has a price (rows, latency, storage), a test that MEASURES it and pins the number the docs quote. `TestSplitLookupActionsBucketMultiplier` is the shape: it asserts exact counts, not "under the ceiling", so the figure in three documents cannot drift away from the test cited as its source |

Helm is the row that was missed. Verify it by rendering, not by reading:

```sh
helm template deploy/helm/sunder --set <path>=<value> | grep -A1 SUNDER_<NAME>
```

### A new CLI command or flag

`cmd/sunder/main.go` -> `docs/CONFIG.md` or the relevant runbook -> a test in
`cmd/sunder/*_test.go` -> the operations page in `docs-site` if an operator
would ever run it.

### A new audit action

`action` is a CLOSED SET. Register it in `internal/audit/actions.go` with a
one-line meaning that tells a reader what its PRESENCE in the trail signifies.
The AST guard in `internal/audit/scan_test.go` will fail the build otherwise -
and it sees through helpers that take the action as a parameter, which the
first regexp version did not (four actions, three of them privileged operator
acts, were unregistered for months behind `auditOperator` and `terminal`).

If the action is produced by a shape the scanner does not understand, the
build fails asking you to teach the scanner. Do that; do not add an unchecked
exemption.

### A new demo script

`demo/*.sh` -> a step in the `e2e-demo` CI job with whatever credentials it
needs. The `demos` check refuses any script no job runs. `escalation.sh` sat
broken (403 at step 2) while `docs/API.md` pointed readers at it, because
nothing executed it.

### A new metric

`internal/api/server.go` (or wherever it is set) -> `ops/prometheus-alerts.yaml`
if it can indicate an incident -> `docs-site/docs/admin/monitoring.md` alarm
table -> `ops/grafana-dashboard.json` if it belongs on a panel.

A metric with no alert and no panel is a metric nobody will look at. That is
a decision - make it explicitly, in the monitoring page's prose.

### A new database migration

Sequential number, idempotent, and a comment saying what it fixes and why
`NOT VALID` / `IF NOT EXISTS` is or is not safe here. If it adds a
person-linked table, `TestErasureInvariantSweep` will demand an explicit
erasure decision - give it one.

## SDK parity check

```sh
# Every SDK should mention the new method. Adjust the name per language.
for f in sdks/go/api.go sdks/typescript/src/index.ts \
         sdks/python/sunder_client/__init__.py sdks/php/src/SunderClient.php \
         sdks/java/src/main/java/io/sunderid/client/SunderClient.java \
         sdks/dotnet/src/SunderId.Client/SunderClient.cs; do
  printf '%-60s %s\n' "$f" "$(grep -ci '<methodName>' "$f")"
done
```

A zero in that column is either a gap or a decision. If it is a decision,
write it in `docs-site/docs/dev/sdks-and-api.md` - the surface table is where
a reader looks, and an unexplained omission reads as an oversight.

Then run every suite, because a method that compiles is not a method that
works:

```sh
(cd sdks/go && go test ./...)
(cd sdks/typescript && npm test)
(cd sdks/python && python3 -m unittest discover -s tests -q)
(cd sdks/php && ./vendor/bin/phpunit tests/)
(cd sdks/java && bash run-tests.sh)
(cd sdks/dotnet && dotnet test SunderId.sln --nologo)   # needs a dotnet toolchain
```

## Postman coverage check

```sh
python3 - <<'PY'
import json, re, yaml
spec = yaml.safe_load(open('api/openapi.yaml'))
col = json.load(open('api/sunder.postman_collection.json'))
seen = set()
def walk(x):
    if isinstance(x, dict):
        if 'request' in x:
            u = x['request'].get('url'); raw = u.get('raw') if isinstance(u, dict) else u
            p = re.sub(r'^\{\{baseUrl\}\}', '', str(raw)).split('?')[0]
            seen.add((x['request']['method'].lower(), re.sub(r'\{\{[^}]+\}\}', '{}', p)))
        for v in x.values(): walk(v)
    elif isinstance(x, list):
        for v in x: walk(v)
walk(col)
missing = []
for path, ops in spec['paths'].items():
    shape = re.sub(r'\{[^}]+\}', '{}', path)
    for m in ops:
        if m in ('get','post','put','delete','patch') and (m, shape) not in seen:
            missing.append(f"{m.upper()} {path}")
print("documented routes with no Postman request:" if missing else "Postman covers every documented route")
for x in sorted(missing): print("  ", x)
PY
```

## Deliberate omissions

Skipping a row is allowed. Skipping it silently is not. Portal routes are
not in the SDKs because they are browser-facing; the admin audit reads are
not wrapped because they are an operator surface. Both are written down. If
you skip a row, write the reason where a reader will look for it, and say so
in the PR description.

## Before you call it done

- [ ] The automated guards pass.
- [ ] Every row of the relevant matrix section is verified by opening the file.
- [ ] Deliberate omissions are written down where a reader looks.
- [ ] `CHANGELOG.md` describes the change in terms of what an operator or
      integrator can now do, not in terms of which files moved.

## The artifact outside the repo: `sales/`

The pitch deck under `sales/` is **gitignored**, so no CI job can guard it -
and it is the one artifact a customer actually reads. It quotes ten latency
figures, throughput comparisons, a dataset size and a coverage number, drawn
from four different sources (`benchmark/README.md`,
`docs-site/docs/get-started/performance.md`, `docs/WHITEPAPER.md`,
`docs-site/docs/comparisons/databunker.md`).

Anything that moves a measured number moves the deck. In particular: a
benchmark re-run, a coverage change, a new comparison row.

```sh
./ops/check-sales-deck.sh    # exits 0 when sales/ is absent
```

It parses both number conventions (the deck is Croatian - `1.569` is one
thousand five hundred sixty-nine, `5,62` is five point six two - the sources
are English) and flags any figure matching no measurement in the repo. It
found three on its first run: a "10,6 ms median search under full load" that
exists nowhere (it had been matching only as a substring of `110.6 rps`, a
different quantity entirely), a "28.000/s bulk import" with no source, and a
"1,4x at 8 clients" write claim drawn from the one measurement
`benchmark/README.md` explicitly calls run-to-run noise.

It cannot tell whether a number is used in the RIGHT context - only a human
can say whether a p99 got labelled a median. Read its output; do not just
check the exit code.
