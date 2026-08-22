# Migrating from Databunker to Sunder

Moves user records out of a [Databunker](https://databunker.org) instance
and registers them as Sunder contacts. Identifiers (email, phone) become
searchable HMAC tokens; the rest of the profile lands in the caller-scope
encrypted attribute blob; a CSV maps every Databunker token to its new
Sunder CID so client systems can re-key their references.

## Prerequisites

1. Databunker must allow the admin list API: in `databunker.yaml` set
   `list_users: true` under `generic:` and restart. Use the root token.
2. A Sunder client with the `contacts.register` action (and a generous rate
   limit for the import):

   ```sh
   docker compose -f deploy/docker-compose.yml exec sunder /sunder client create \
     -id migrator -name Migrator -scope crm \
     -actions contacts.register -rate 100000
   ```

## Run

```sh
go run ./migrate/databunker \
  -source http://localhost:3000 -source-token <root token> \
  -target http://localhost:8080 -cred '<client_id.secret>' \
  -map-out mapping.csv
```

Flags: `-batch` (page size, default 100), `-c` (concurrent registrations,
default 8), `-dry-run` (read and validate only),
`-keep-source-token=false` (drop the `databunker_token` attribute).

## What maps to what

| Databunker | Sunder |
|---|---|
| `email`, `phone` | searchable identifiers (HMAC tokens + attributes) |
| `name`, or `first` + `last` | contact name (narrowing key + attribute) |
| every other profile field | custom attribute (values stringified) |
| user token | `databunker_token` attribute + a row in `mapping.csv` |
| agreements / consents | **not migrated** - map them to Sunder consent purposes per your own legal analysis (`POST /v1/consent`) |

Records with neither email nor phone cannot be registered (nothing
searchable) and are reported as skipped. Re-running the migration is safe:
Sunder dedups by identifier, so existing contacts are merged, not
duplicated.

## After the migration

1. Distribute `mapping.csv` to the systems that stored Databunker tokens
   and re-key their references to CIDs (or drop stored handles entirely and
   resolve via `POST /v1/lookup` at need).
2. Spot-check: `lookup` a few migrated emails/phones, fetch a few
   attributes.
3. Decommission Databunker only after the mapping is applied everywhere -
   then delete `mapping.csv` copies (they are linkage material).
