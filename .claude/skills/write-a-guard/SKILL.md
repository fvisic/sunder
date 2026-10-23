---
name: write-a-guard
description: Turn a class of gap into a build failure - the guards that read the tree rather than trusting a list, and the traps that make a guard pass while the gap it names is wide open. Use when a review or a person finds a missing artifact, a stale document, an undocumented value, or any defect that "should have been caught", and when adding a check to ops/ or a *_test.go that enforces a repo-wide invariant.
---

# Writing a guard

Every alignment gap in this repository was found by a person asking. The
answer is never "be more careful next time" - it is a check that fails the
build. This skill is how to write one that actually holds.

## The rule that decides the design

**A guard must derive the truth from the tree, not from a list someone
maintains.** The list is the thing that rots.

Compare:

```python
# Rots. Someone adds a variable and forgets this file.
EXPECTED_VARS = ["SUNDER_DB_URL", "SUNDER_LISTEN", ...]
```

```python
# Holds. The code is the source; the docs are checked against it.
found = grep_for(r'getenv\("(SUNDER_[A-Z0-9_]+)"', "internal/config/")
documented = parse_table("docs/CONFIG.md")
fail_on(found - documented)
```

`ops/check-config-docs.sh` and `TestEveryRouteIsDocumented` have never let a
gap through, and both work this way.

## The four traps

### 1. Matching syntax instead of meaning

The audit action guard was a regexp for `Action: "..."`. It passed green
while four actions - `client.create`, `webhook.set`, `retention.set`,
`dsr.erase.delivered` - were being written and were in no registry, because
each reaches the audit Entry through a HELPER that takes the action as an
ordinary string parameter:

```go
auditOperator(ctx, pool, "client.create", ...)     // invisible to the regexp
terminal(e, "DELIVERED", "dsr.erase.delivered")    // likewise
```

Three of the four were privileged operator acts - exactly the category the
registry claimed to cover.

The fix was to parse with `go/ast` (`internal/audit/scan_test.go`) and follow
one level of forwarding. When a regexp is not enough, `go/parser` is in the
standard library and costs an afternoon.

### 2. No failure mode for the unrecognised

This is the property that separates a guard from a better guess:

> An input shape the guard does not understand must FAIL, not be skipped.

`TestScannerUnderstandsEveryActionExpression` fails on any `Action:`
expression it cannot resolve, with "teach the scanner about this shape". A
new way of producing an action cannot slip through quietly - somebody has to
make a deliberate edit. Without that clause, the guard silently stops
covering whatever it stopped understanding, and stays green while doing it.

### 3. An exemption list nobody checks

Every real guard needs exemptions - a variable that genuinely has no Helm
equivalent, a route the SDKs deliberately do not wrap. Two rules:

- **The reason lives next to the entry**, and the guard prints it on every
  run. A reader of the output sees what was excused and why.
- **The exemption is itself verified.** An entry saying "produced by
  `internal/service/gdpr.go terminal()`" must be checked against that file -
  otherwise deleting the last call site leaves a green build describing a
  dead action.

Both failed within a day of being written here: one exemption named a call
site that had moved, another described a mechanism that no longer ran.

Where the exemption can be replaced by a mechanical test, do that instead.
`Verify` and `Drain` rebuild an audit Entry from a database row rather than
producing one, and instead of listing them as exceptions the scanner checks
that the value arrives through `rows.Scan(&ident)`.

### 4. Vacuous when the world changes

A guard that finds nothing to check must fail, not pass:

```python
if not scripts:
    fail("no demo scripts found - this check has stopped checking")
if len(sources) < 40:
    fail("the scanner found %d action sources - every guard on it is now vacuous")
```

A rename, a moved directory, a changed helper name - each can turn a guard
into an expensive no-op that reports success forever.

## Prove it fails

**Never commit a guard you have not seen fail.** Break the thing it guards,
watch it go red, put it back:

```sh
printf '#!/usr/bin/env bash\nexit 0\n' > demo/zz-probe.sh
./ops/check-artifact-coverage.sh; echo "exit=$?"   # must be 1
rm demo/zz-probe.sh
./ops/check-artifact-coverage.sh; echo "exit=$?"   # must be 0
```

Check the EXIT CODE, not the output: `./guard.sh | tail -5` reports tail's
status, and a guard that prints `::error::` while exiting 0 passes CI.

## Where it goes

| Kind | Home | Runs in |
|---|---|---|
| Repo-wide artifact alignment | `ops/check-artifact-coverage.sh` | the `guards` CI job |
| Config reference completeness | `ops/check-config-docs.sh` | the `guards` CI job |
| Anything needing Go's type or syntax information | a `*_test.go` in the package | the test matrix |
| Something outside the repo (gitignored) | `ops/check-*.sh`, exiting 0 when absent, named in the `release` skill | locally and at release |

Add the shell ones to `.github/workflows/ci.yml`'s guards job in the same
commit. A guard nobody runs is the thing it was written to prevent.

## Write the message for the person who trips it

They do not have your context. Say what is wrong, what it costs, and the two
or three ways out:

```
audit actions the code can write but actions.go does not register:
  client.create  (written at cmd/sunder/main.go:1020)

Add each with a one-line meaning. Until then, docs/API.md and
docs-site/docs/admin/audit-chain.md promise a closed set that is not closed.
```

Naming the documents that become false is what makes the fix feel worth
doing rather than a hoop.
