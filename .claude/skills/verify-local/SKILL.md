---
name: verify-local
description: Run Sunder's full verification gauntlet locally with the environment it actually needs - test database, Redis, demo credentials, the right compose stack. Use before opening a PR, when CI is unavailable, when a test or demo script "fails" for no obvious reason, or when asked to check that a change is green.
---

# Verifying locally

Most of what looks like a failure here is a missing environment variable.
Two examples from one afternoon:

- `go test ./...` reported **SKIP: SUNDER_TEST_DB_URL not set** on every
  test that matters, and the suite exited 0. A green run that tested
  nothing.
- `for s in demo/*.sh; do bash "$s"; done` reported **seven failures**.
  All seven were "Missing SUNDER_CRED_*". Nothing was broken.

Both cost a diagnosis cycle. Set the environment first, every time.

## The environment

Two long-lived containers hold the test database and Redis. They are NOT on
the default ports - the deployment stack uses those.

```sh
docker ps --format '{{.Names}}\t{{.Ports}}' | grep sunder
# sunder-test-pg     0.0.0.0:55432->5432/tcp
# sunder-test-redis  0.0.0.0:56379->6379/tcp
```

```sh
export SUNDER_TEST_DB_URL='postgres://sunder:sunder@localhost:55432/sunder_test'
export SUNDER_TEST_REDIS_ADDR='127.0.0.1:56379'
```

If the containers are gone, CI's own values (`localhost:5432`,
`127.0.0.1:6379`) are in `.github/workflows/ci.yml` under `env:` - start
equivalents on whatever ports are free and point the variables at them.

**Confirm the variables took effect before trusting a result.** A suite that
skips is not a suite that passes:

```sh
go test ./internal/service/ -run TestNothing -count=1 -v 2>&1 | grep -c SKIP
# non-zero output here means the DB URL is not reaching the tests
```

## The gauntlet

```sh
gofmt -l . | grep -v '^docs-site/'      # must be empty
go vet ./...
go build ./...
"$(go env GOPATH)"/bin/staticcheck ./...

go test -race -shuffle=on -count=1 -timeout=25m ./...

go test -count=1 -timeout=25m -covermode=atomic -coverprofile=cover.out \
  -coverpkg=./internal/...,./cmd/... ./...
./ops/coverage-gate.sh cover.out 90.0
```

The gate applies the `//coverage:defensive` exclusions and caps them at 1%
of statements, so it is the number that counts - not `go tool cover -func`,
which does not take the max across duplicate blocks and will disagree.

### Guards

```sh
./ops/check-config-docs.sh          # every SUNDER_* is in a reference table
./ops/check-artifact-coverage.sh    # helm, postman, SDK parity, docs mirror,
                                    # test-corruption style, demo scripts
(cd docs-site && mkdocs build --strict)
helm template deploy/helm/sunder >/dev/null && helm lint deploy/helm/sunder
python3 -c "import yaml,json;yaml.safe_load(open('api/openapi.yaml'));json.load(open('api/sunder.postman_collection.json'))"
```

### The six SDK suites

Read the OUTPUT of each, not just the exit code - warnings do not fail a
suite, and .NET's xUnit warnings hid behind a green run for a release.

```sh
(cd sdks/go && go test ./...)
(cd sdks/typescript && npm test)
(cd sdks/python && python3 -m unittest discover -s tests -q)
(cd sdks/php && ./vendor/bin/phpunit tests/ && ./vendor/bin/phpstan analyse)
(cd sdks/java && bash run-tests.sh)
(cd sdks/dotnet && dotnet test SunderId.sln --nologo)
```

## End to end

Two stacks, and they are different. Bringing up the wrong one is the other
way demo scripts "fail".

### The demo scripts: the PLAIN stack, plus credentials

`down -v` matters - the bugs that hide here are cold-boot bugs.

```sh
docker compose -f deploy/docker-compose.yml down -v
docker compose -f deploy/docker-compose.yml up --build -d --wait

C='docker compose -f deploy/docker-compose.yml exec sunder /sunder'
export SUNDER_CRED_CRM=$($C client create -id crm -name CRM -scope crm \
  -actions contacts.register,lookup,attributes.read,oti.issue \
  -purposes support,create_order -rate 1000 | tail -1)
export SUNDER_CRED_ERP=$($C client create -id erp -name ERP -scope erp \
  -actions oti.verify -purposes create_order | tail -1)
bash demo/quickstart.sh

export SUNDER_CRED_VAULT=$($C client create -id vault -name Vault -scope crm \
  -actions contacts.register,attributes.read,tokens.create,tokens.read,tokens.delete,admin.unlock,files.write,files.read,attributes.history,links.manage,shares.create,consent.manage,dsr.erase \
  -purposes support -rate 1000 -ttl 1d | tail -1)
for s in f4-value-tokens f5-file-vault f6-versioning f7-sub-accounts f8-shared-records; do
  echo "=== $s"; bash "demo/$s.sh"
done

SUNDER_EXEC="$C" bash demo/f9-shamir-recovery.sh
```

`escalation.sh` needs its own pair, in a second scope. The issuer needs
`attributes.read` because an OTI carrying `share_attributes` IS a delegated
read (TOKENS-LOOKUP-6) - omitting it is a 403 at step 2:

```sh
export SUNDER_CRED_CRM=$($C client create -id crm-esc -name CRM -scope crm \
  -actions contacts.register,oti.issue,attributes.read \
  -purposes escalation_notify -rate 1000 | tail -1)
export SUNDER_CRED_NOTIFIER=$($C client create -id notifier -name Notifier \
  -scope notifier -actions oti.verify,attributes.read,consent.manage \
  -purposes escalation_notify -rate 1000 | tail -1)
bash demo/escalation.sh
```

**Do not run `for s in demo/*.sh` as a smoke test.** Each script needs a
different credential set, they overwrite each other's variables, and
`lib.sh` is a sourced helper with no main. The loop's output is noise. Run
them in the groups above, which is what CI does.

### The playground: the OVERLAY stack

```sh
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.playground.yml down -v
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.playground.yml up --build -d --wait
python3 ops/playground_e2e.py       # expect: every walkthrough passed
```

The two stacks share a compose project, so `down -v` before switching.

## When CI is unavailable

It happens - jobs failing in under 15 seconds with an empty `steps` array is
the platform, not the change. Run everything above, and then **say in the PR
body exactly what was verified locally and what was not**. A release note
that omits what could not be checked is worse than one that says so.

Confirm the platform is at fault before concluding it:

```sh
gh api repos/fvisic/sunder/actions/runs/<id>/jobs \
  --jq '[.jobs[]|select(.steps|length>0)]|length'   # 0 = nothing ever started
```

## What a clean run looks like

Numbers to compare against, from a green local run:

- `-race -shuffle=on` across the tree: no failures, no data races
- coverage: **~90%** measured, excluded statements well under the 1% ceiling
- `staticcheck`: 0
- all guards: green, each printing its counts and its exemptions
- playground: `every walkthrough passed`
- demos: quickstart, F4-F8, F9 and escalation all pass
