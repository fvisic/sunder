# Alignment checklist

A change is not done when it works. It is done when nothing in the tree, and
nothing a customer reads, still describes a world where it does not exist.

This page is the canonical list of what has to move together, and - just as
important - **which layer enforces each row**. Three layers, in order of how
much you should rely on them:

1. **Automated** - a guard fails the build. Nothing else is trustworthy over
   time; a checklist is only a staging area for guards that do not exist yet.
2. **Checklist** - judgement a guard cannot make (is that CONFIG.md row
   honest about what you give up? does this feature deserve a playground
   walkthrough?). Lives in the `feature-complete` skill.
3. **Release-time, manual** - artifacts outside the repository. Exactly one
   today: the sales deck.

## What runs automatically

Every one of these fails the build in CI's `guards` job or the test matrix.

| Guard | Fails when | Where |
|---|---|---|
| Config reference | a `SUNDER_*` the code reads is in no reference table | `ops/check-config-docs.sh` |
| Helm reachability | a documented variable is not settable through the chart | `ops/check-artifact-coverage.sh` |
| Postman coverage | a documented route has no request in the collection | same |
| SDK parity | a capability wrapped by some SDKs is missing from others | same |
| Cross-doc mirror | `docs/CONFIG.md` and the docs-site page disagree | same |
| Test corruption style | a test corrupts data by assignment (a no-op 1 time in 256) instead of XOR | same |
| Demo coverage | a `demo/*.sh` no CI job executes | same |
| Route documentation | a `/v1` route is absent from `api/openapi.yaml` | `TestEveryRouteIsDocumented` |
| OpenAPI field drift | a request/response field disagrees with the schema | `TestOpenAPI*` |
| Audit vocabulary | the code can write an action `internal/audit/actions.go` does not register - **including through helpers**, via an AST scan | `internal/audit/scan_test.go` |
| Erasure completeness | a person-linked table has no explicit erasure decision | `TestErasureInvariantSweep` |
| Coverage | below 90%, or defensive exclusions over 1% of statements | `ops/coverage-gate.sh` |
| Docs build | a dead link or broken diagram | `mkdocs build --strict` |
| **Version agreement** | `VERSION` disagrees with the newest tag, the six SDK manifests disagree with each other, or the CHANGELOG has no section for this version | `ops/check-versions.sh` |
| Pool inversion | a function holding a `pgx.Tx` can reach a pool acquisition - the shape that deadlocked writes | `TestNoPoolAcquireWhileHoldingATransaction` |

Run the lot locally:

```sh
./ops/check-config-docs.sh
./ops/check-artifact-coverage.sh
./ops/check-versions.sh
./ops/check-sales-deck.sh            # local only; exits 0 if sales/ is absent
go test ./... -count=1
(cd docs-site && mkdocs build --strict)
helm template deploy/helm/sunder >/dev/null && helm lint deploy/helm/sunder
```

**Read the exemptions each guard prints.** A guard is only as honest as its
exemption list, and two of ours were found describing call sites that had
moved within a day of being written.

## By kind of change

### A new `SUNDER_*` variable

| # | Artifact | Guarded? |
|---|---|---|
| 1 | `internal/config/config.go` - parsed, range-checked, **fails at startup** on garbage rather than falling back to the default | no |
| 2 | `docs/CONFIG.md` - a row: default, range, and what you GIVE UP by changing it | yes |
| 3 | `docs-site/docs/install/configuration.md` - same variable, same default | yes (mirror) |
| 4 | `deploy/helm/sunder/values.yaml` - settable, with the Kubernetes-specific trade-off | yes |
| 5 | `deploy/helm/sunder/templates/_helpers.tpl` - actually rendered into the pod env | yes |
| 6 | `CHANGELOG.md` under "New configuration" | no |
| 7 | Tests: the default, and an out-of-range value refused | no |
| 8 | If the knob has a measurable cost, a test that MEASURES it and pins the number the docs quote | no |

Row 8 is the one people skip. `TestSplitLookupActionsBucketMultiplier`
asserts exact counts rather than "under the ceiling", so the figure quoted in
three documents cannot drift away from the test named as its source.

### A new or changed `/v1` route

`internal/api/` -> `api/openapi.yaml` -> `docs/API.md` -> all six SDKs plus a
test each -> `docs-site/docs/dev/sdks-and-api.md` -> the Postman collection ->
a playground walkthrough (or a written omission) -> server tests for the
happy path, the refusal, the audit row and the rate limit.

Guarded: OpenAPI presence and fields, Postman coverage, SDK parity. Not
guarded: whether `docs/API.md` describes what the route REFUSES, and whether
the playground should show it.

### A new audit action

Register it in `internal/audit/actions.go` with a one-line meaning saying what
its PRESENCE in the trail signifies. The AST guard fails the build otherwise.

If it is produced by an expression shape the scanner does not understand, the
build fails asking you to teach the scanner - do that rather than adding an
unchecked exemption. The first version of this guard was a regexp and missed
four actions written through helpers, three of them privileged operator acts.

### A new demo script

Add a step to the `e2e-demo` job with the credentials it needs. The `demos`
check refuses any script no job runs. `demo/escalation.sh` sat broken - a 403
at step 2 - while `docs/API.md` pointed readers at it, because nothing ran it.

### A release

| # | Artifact | Guarded? |
|---|---|---|
| 1 | `VERSION` at the repo root - the answer to "which build is this?" on a box with no git and no toolchain | yes |
| 2 | the git tag, matching `VERSION` | yes |
| 3 | the six SDK manifests, agreeing with each other (they version independently of the server - `RELEASING.md`) | yes |
| 4 | `CHANGELOG.md`, with a section describing what an operator can now do | yes (presence), no (content) |
| 5 | `docs-site/docs/dev/sdks-and-api.md` - the Maven snippet is the one place a version hides in prose | no |
| 6 | the release page actually carrying its assets - v0.4.0 shipped with **zero** | no; the `release` skill's step 7 |
| 7 | **the sales deck** - see below | partly |

`VERSION` exists because that question had no cheap answer. A benchmark ran
for an afternoon against a server checkout that turned out to be an old
snapshot missing both features under test, and nothing on the machine said
so.

### A new CLI command, flag or metric

CLI: `cmd/sunder/main.go` -> `docs/CONFIG.md` or the runbook -> a test in
`cmd/sunder/*_test.go` -> the docs-site operations page.

Metric: where it is set -> `ops/prometheus-alerts.yaml` if it can be wrong at
3am -> `docs-site/docs/admin/monitoring.md`.

### Anything that moves a measured number

A benchmark re-run, a coverage change, a new comparison row touches:
`benchmark/README.md`, `docs-site/docs/get-started/performance.md`,
`docs/WHITEPAPER.md`, `docs-site/docs/comparisons/databunker.md` - **and the
sales deck**, which is the only one a customer reads.

Those files keep their historical runs on purpose: the deltas between them
are the record of what changed. So the current figures are fenced with

```html
<!-- authoritative:begin - ops/check-sales-deck.sh trusts ONLY what is between these markers -->
...
<!-- authoritative:end -->
```

and the deck checker reads only what is inside. Without that fence a figure
from a superseded run still "matches a source", which is precisely the
mistake a deck makes after a re-measurement - and it did: the fence is what
revealed that the deck's entire comparison table was v0.4-era.

**Move the fence when you add a newer run.** A fence left around last
quarter's numbers is worse than none.

## The artifact outside the repo

`sales/` is gitignored, so no CI job can guard it. `ops/check-sales-deck.sh`
parses the deck and flags any figure matching no measurement in the repo. It
handles both number conventions - the deck is Croatian (`1.569` is one
thousand five hundred sixty-nine; `5,62` is five point six two), the sources
are English - because comparing the strings reports false alarms on a deck
that is perfectly in sync, and a check that cries wolf is one nobody runs.

It cannot tell whether a figure is used in the RIGHT context: only a person
can say whether a p99 got labelled a median. Read the output, not the exit
code.

## Where to put a new check

If you can express it mechanically, it belongs in the automated layer -
`ops/check-artifact-coverage.sh` for artifact alignment, a `*_test.go` when
Go's syntax or type information is needed. The `write-a-guard` skill covers
the traps: matching syntax instead of meaning, having no failure mode for the
unrecognised, exemption lists nobody checks, and guards that go vacuous when
a directory is renamed.

Anything that still needs judgement stays in the `feature-complete` skill
until someone works out how to mechanise it.
