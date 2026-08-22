# Sunder demo - the call-center lookup flow

`callcenter.sh` is the M6 demo (decision D8): it walks the adoption-wedge
adoption storyline - *"the national identifier out of the call-center/CRM lookup in
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
    -id crm -name "Call-center CRM" -scope crm \
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
./demo/callcenter.sh
```

`SUNDER_URL` overrides the base URL (default `http://localhost:8080`).
Run without the env vars to get these instructions printed by the script
itself.

The script is idempotent: re-running it re-registers the same contact
(dedup by email/phone token returns the same CID) and issues a fresh OTI
each time. Steps 4, 5 and 8 intentionally receive non-2xx responses; the
script asserts each step's expected status and exits non-zero on any
deviation, so it doubles as a smoke test.
