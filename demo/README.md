# Sunder demos

`quickstart.sh` walks the core storyline - *"the national identifier out of the CRM lookup in
30 days"* - end to end against a running stack, using nothing but `curl`
and `python3` (no jq).

Two clients play the roles:

| Client | Scope | Actions | Purposes |
|---|---|---|---|
| `crm` | `crm` | `contacts.register`, `lookup`, `attributes.read`, `oti.issue` | `support`, `create_order` |
| `erp` | `erp` | `oti.verify` | `create_order` |

## The storyline

1. **Register** - a customer calls for the first time; the CRM registers
   name, email, phone and a loyalty tier, and gets back a stable pseudonym
   (CID). No searchable PII key ever lands in the CRM database.
2. **Lookup hit** - the customer calls again; the agent finds her by phone.
   The identifier is HMAC-tokenized server-side; the same CID comes back.
3. **Attribute read** - the agent fetches exactly one field (`email`) and
   must state a purpose (`support`). The read is audited.
4. **Name-alone rejection** - `{"name": "..."}` is a 400: a name is a
   narrowing key, never an identifier. No fishing for "every Ana Horvat".
5. **Miss** - a nonexistent email is a 404; misses feed the enumeration
   detector, and past the per-client rate limit lookups become 429.
6. **OTI issue** - the customer places an order; the CRM asks for a
   one-time identifier addressed to the ERP (5 minutes, one use, one
   audience, one purpose).
7. **OTI verify** - the ERP redeems the token and receives **its own**
   scoped CID. The script prints both pseudonyms side by side: they
   differ, so leaked CRM and ERP databases cannot be joined on them.
8. **Replay** - verifying the same token again is a 409 `token_used`:
   single use is an atomic database transition, not just a signature.

## Running it

Start the stack:

```sh
docker compose -f deploy/docker-compose.yml up --build
```

Create the two demo clients (each prints its credential **exactly once**):

```sh
docker compose -f deploy/docker-compose.yml exec sunder /sunder client create \
    -id crm -name "Demo CRM" -scope crm \
    -actions contacts.register,lookup,attributes.read,oti.issue \
    -purposes support,create_order

docker compose -f deploy/docker-compose.yml exec sunder /sunder client create \
    -id erp -name "Order ERP" -scope erp \
    -actions oti.verify \
    -purposes create_order
```

Export the credentials and run the demo:

```sh
export SUNDER_CRED_CRM='crm.<secret>'
export SUNDER_CRED_ERP='erp.<secret>'
./demo/quickstart.sh
```

`SUNDER_URL` overrides the base URL (default `http://localhost:8080`).
Run without the env vars to get these instructions printed by the script
itself.

The script is idempotent: re-running it re-registers the same contact
(dedup by email/phone token returns the same CID) and issues a fresh OTI
each time. Steps 4, 5 and 8 intentionally receive non-2xx responses; the
script asserts each step's expected status and exits non-zero on any
deviation, so it doubles as a smoke test.

## Feature demos (F4-F9)

Beyond the core lookup/handoff storyline, one script per Phase 3 feature.
They share `demo/lib.sh` (the same `api`/`expect` helpers) and each asserts
its expected status codes, so they double as smoke tests.

| Script | Feature | Needs |
|---|---|---|
| `f4-value-tokens.sh` | Value tokenization | `SUNDER_CRED_VAULT` |
| `f5-file-vault.sh` | File vault (crypto-shredding) | `SUNDER_CRED_VAULT`; stack with `SUNDER_FILES_STORAGE` |
| `f6-versioning.sh` | Attribute versioning | `SUNDER_CRED_VAULT`; stack with `SUNDER_VERSIONS_KEEP>0` |
| `f7-sub-accounts.sh` | Person links + erasure cascade | `SUNDER_CRED_VAULT` |
| `f8-shared-records.sh` | Shared records | `SUNDER_CRED_VAULT` |
| `f9-shamir-recovery.sh` | Shamir keystore recovery (CLI) | `SUNDER_EXEC` (docker exec or a local binary) |

Create one client with the actions the HTTP demos need (F9 is CLI-only):

```sh
docker compose -f deploy/docker-compose.yml exec sunder /sunder client create \
    -id vault -name Vault -scope crm \
    -actions contacts.register,attributes.read,tokens.create,tokens.read,tokens.delete,admin.unlock,files.write,files.read,attributes.history,links.manage,shares.create,consent.manage,dsr.erase \
    -purposes support -rate 1000
export SUNDER_CRED_VAULT='vault.<secret>'

./demo/f4-value-tokens.sh
./demo/f5-file-vault.sh      # needs the file vault enabled on the stack
./demo/f6-versioning.sh      # needs versioning enabled on the stack
./demo/f7-sub-accounts.sh
./demo/f8-shared-records.sh

# F9 runs the CLI via the compose stack by default:
./demo/f9-shamir-recovery.sh
```

The bundled `deploy/docker-compose.yml` already enables the file vault and
versioning, so all six run against it out of the box. CI (the `e2e-demo`
job) runs every one against the freshly built image on each push.
