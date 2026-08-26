# FAQ

Short, honest answers to the questions integrators and security teams ask
most. Where a claim has a caveat, the caveat is here too - not in a
footnote. For depth, each answer links to the page that covers it.

## Security model

### What does an attacker get from a stolen client (CRM) database?

The CIDs that scope holds and whatever attributes it stored under them -
and nothing that links to another scope. There is no OIB (national ID), no
search key, and the CIDs are per-scope, so a CRM dump cannot be joined
against a billing dump. See [scoped pseudonyms](concepts/scoped-pseudonyms.md).

### What does an attacker get from a stolen Sunder database, without the keys?

Keyed-HMAC tokens (no dictionary attack without the key), AEAD-encrypted
attribute blobs, and the hash-chained audit log. The keys live outside the
database - in the file keystore, HashiCorp Vault, or behind the signer
split - so a database-only theft yields ciphertext. See
[keys and keystores](admin/keys-and-keystores.md).

### How do two systems share a person without sharing an identifier?

Through a one-time identifier (OTI): a signed (PASETO v4), single-use,
5-minute token bound to a purpose and an audience. The issuer can attach a
few explicitly named attributes; the verifier receives only those. It is
the only identity currency between systems. See [OTI handoff](concepts/oti-handoff.md).

### Can a caller prove a fact about a person without reading the value?

Yes - predicate sharing. An OTI can carry an assertion like "age >= 18"
and the verifier learns the boolean, not the birthdate. The audit chain
records what was *asked*, never the result. See
[selective disclosure](concepts/selective-disclosure.md).

### Can the audit log be rewritten by someone with database access?

A hash chain plus append-only triggers make a rewrite break at a provable
position, and RFC 3161 anchoring with **off-host export** (`sunder anchor
-out <dir>` synced to write-once storage) means a full-chain rewrite
orphans anchors the attacker cannot forge. Anchors kept only in the same
database are circular and defeat nobody privileged. See
[audit chain](admin/audit-chain.md).

### What if the service process itself is compromised?

Working keys are in that instance's RAM - that is a bad day for its crypto.
The signer split (`SUNDER_SIGNER_SOCKET`) mitigates it: the API process
holds no keys, only a small operation socket, so a compromised API can use
operations at its rate limit (bounded and audited) but cannot exfiltrate
key material.

## GDPR and data lifecycle

### Does erasure actually delete the data, or just flag it?

It deletes. The attribute blob is wiped, derived search tokens removed, and
for files and value tokens the per-person **record key** is destroyed in
the same transaction - which makes every file of that person cryptographically
unrecoverable at commit, with no storage round trip. See
[rights and consent](gdpr/rights-and-consent.md) and [file vault](concepts/file-vault.md).

### What happens to shares and history when a person is erased?

Both die with the person: standing [shared records](concepts/shared-records.md)
are revoked (also on consent withdrawal), and [attribute version
history](concepts/attribute-versioning.md) is deleted, all in the erasure
transaction. Nothing points at the data after erasure.

### How is consent enforced?

Consent is recorded per `(cid, purpose)` and checked on reads, OTI handoffs,
file downloads and version reads. Withdrawing a purpose stops those
operations and revokes that person's standing shares.

### Is there a self-service privacy portal for citizens?

Yes, optional and off by default (`SUNDER_PORTAL_ENABLED`) - it needs
citizen authentication, so it runs on its own listener and is enumeration-
resistant. See [privacy portal](gdpr/privacy-portal.md).

## Features and configuration

### Which of the newer features are on by default?

None of the surface-widening ones. Fuzzy/partial search
(`SUNDER_SEARCH_FUZZY_NAME`, `SUNDER_SEARCH_PHONE_SUFFIX`), attribute
versioning (`SUNDER_VERSIONS_KEEP=0`), and the file vault
(`SUNDER_FILES_STORAGE`) are all off until you enable them; shared-record
fetch is authenticated unless you opt into `SUNDER_SHARES_PUBLIC`. An
upgrade never silently opens a new surface. See [configuration](install/configuration.md).

### Does fuzzy search weaken the crypto?

No. It adds keyed-HMAC narrowing keys (phonetic name codes, phone suffix) -
still no plaintext, still narrowing-only, and it is **bulk-deny**: a value
matching two or more people in your scope returns a miss, never a list.
See [fuzzy and partial search](concepts/fuzzy-and-partial-search.md) and
the residual-risk note in the threat model.

### Can I tokenize a single value (an IBAN, a card) instead of a whole person?

Yes - [value tokenization](concepts/value-tokenization.md). Scope-bound,
optionally expiring, card tokens are Luhn-valid and length-preserving with
no BIN. Bulk create/read always require an unlock token.

### How do I recover if the file keystore is lost?

Shamir 3-of-5 recovery shares for the file keystore
([Shamir recovery](admin/shamir-recovery.md)). The recovery key never
touches disk; give each share to a separate custodian. The Vault driver
delegates recovery to Vault's own unseal.

### How do I run across jurisdictions (EU/US)?

One independent instance per region, with cross-border handoffs over the
OTI mechanism - no in-product data-plane federation, by design. There is a
runnable two-instance example. See [multi-jurisdiction](install/multi-jurisdiction.md).

## Operations

### What does it take to run?

One container plus PostgreSQL (16+), and a keystore. Docker Compose or Helm;
`sunder bootstrap` creates the first admin credential. See
[Docker Compose](install/docker-compose.md), [Helm](install/helm.md),
[bootstrap](install/bootstrap.md).

### Which databases and keystores are supported?

PostgreSQL only (a deliberate decision - see [the Databunker comparison](comparisons/databunker.md)).
Keystores: `file` for pilots, HashiCorp Vault for production. PKCS#11 (HSM)
is announced but not yet implemented.

### How does it scale, and how fast is it?

Lookups and writes are HMAC-index hits; the measured ceiling and the async
audit-sealing default (which keeps the chain lock off the request path) are
covered with real numbers on the [performance page](get-started/performance.md),
and the head-to-head against Databunker is in the [comparison](comparisons/databunker.md).
Rate limiting is Redis-backed for multi-replica deployments.

## Project status

### Is this production-ready?

It is pre-1.0. The code is tested (90% coverage gate on both audit modes),
has been through repeated critical code review, ships signed with an SBOM,
and is Apache-2.0 with no license keys or record limits. But there are **no
production users yet** and **no external security audit** - there is a
threat model and a vulnerability-disclosure policy, so treat the security
claims as the author's until an independent review exists. Interfaces may
still change before 1.0.

### Is there a paid tier that hides features?

No. Apache-2.0, all features in the open, no seat or record limits, no
license mechanism. The project is looking for a first pilot partner, not
selling a license.
