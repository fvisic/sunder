# Sunder: an identity decoupling layer for internal systems

Sunder is a self-hosted service that stops your internal systems from
sharing a person identifier. Instead of a CRM, a billing platform and a
data warehouse all keying customer records on the same email address,
phone number or national identifier, each system keys on its own random
pseudonym, and only Sunder can map between them. Every mapping and every
attribute read goes into a tamper-evident audit chain.

Sunder is an independent personal open-source project under Apache-2.0,
not affiliated with, endorsed by, or developed for any employer or
commercial product. It is pre-1.0: interfaces may still move, and there
are no production users yet.

## 1. The problem: shared identifiers as permanent join keys

Most organisations end up with the same identifier in every system. The
web shop stores an email address, the CRM stores the same address, and so
do the ticketing tool, the analytics warehouse and the ERP, because it is
the obvious way to recognise that these records describe the same person.
Where a national identifier is administratively convenient it ends up in
the same role: in Croatia, the OIB.

The cost is invisible until something leaks, and then it is structural. A
leaked email column from a ticketing tool joins to a CRM export from two
years ago, which joins to an analytics extract. Each leak may be modest;
together they form a profile, because they share a join key. Nothing has
to be misconfigured for this to work: the linkability is a property of the
schema choice, not of the breach.

What makes it worse than an ordinary exposure is that the join key is
permanent and not internal. A password rotates; a national identifier does
not, and in practice neither does a long-lived email address or mobile
number. And because everyone picks the same natural key, your dump joins to
someone else's, including data you exported and deleted years ago.

The EU regulatory direction points the other way. The eIDAS 2.0 framework
and the EUDI Wallet work are built around relying-party-specific
pseudonyms, selective disclosure and data minimisation: the verifier learns
what it needs for its own purpose, not a universal handle. GDPR Article 25
asks for data protection by design and Article 32 lists pseudonymisation
as a measure. Whether a particular schema satisfies a particular obligation
is a legal question depending on facts this paper cannot know, and nothing
here is a legal conclusion. The engineering observation is narrower and
does not depend on the legal one: a design that gives every system its own
unlinkable handle removes the join, and a design that shares one identifier
cannot.

Sunder applies that principle inside a single organisation. No central
party, no shared identifiers between systems, self-hosted by design.

## 2. The approach: scoped pseudonyms and one-time identifiers

Sunder splits identity into two objects with different lifetimes.

**CID** is a random 128-bit pseudonym, one per `(person, scope)`, where a
scope is an internal domain (`crm`, `billing`, `analytics`). It is not
derived from anything, so there is no preimage to reverse and no dictionary
to search. Each system stores its own scope's CID as its customer key and
knows no other. The `persons` table holds one row per real person, carrying
HMAC search tokens only; `cids` maps a person to one pseudonym per scope.

**OTI** is a one-time identifier: a signed token, valid five minutes by
default, bound to one purpose and one audience, consumed exactly once. It
is the currency systems exchange when one hands a person to another. The
issuer's pseudonym never crosses the boundary; the verifier receives its
own scope's CID for the same person.

Per-scope pseudonyms rather than one token per person is the whole point. A
single organisation-wide token is easier to operate, but it is a join key
again. If the CRM and the analytics warehouse both store token `T` for the
same customer, a leak of both databases is joinable on `T` exactly as it
was joinable on the email address. Such a token is pseudonymous with
respect to the outside world and fully linkable across your own systems,
which is where the aggregation risk actually lives, because it is your own
systems that collectively hold the profile.

Per-scope pseudonyms remove that. Three databases hold three unrelated
random values for the same person. Leak one, or all three, and there is
nothing to join on. The mapping exists in exactly one place, behind
authentication, with every use recorded.

The cost is that cross-system correlation stops being free: following a
person across scopes needs an explicit, audited call rather than a `JOIN`.
Sunder provides two such paths, both deliberately privileged: the
`scopes.issue` action, which returns another scope's CID, and the `dsr.*`
actions for privacy-officer tooling. An organisation that grants
`scopes.issue` to everything has rebuilt the shared identifier with extra
steps. The design makes that visible rather than preventing it.

## 3. Mechanisms

Every system is a registered *client* with its own credential (bearer key
hashed at rest, optional mTLS), a scope, a set of allowed actions and a set
of allowed purposes. A compromised credential is capped by its grants and
fully audited.

### Keyed-HMAC search tokens

Systems still need to find a person by email or phone. Sunder normalises
the identifier (Unicode NFKC, email lowercased, phone to E.164) and stores
a keyed HMAC-SHA256 token, with separate keys per attribute and one row per
token per live key version. Lookup recomputes the token and does an exact
index match. No searchable plaintext exists in the database.

*Buys*: a stolen database yields no identifiers. A plain hash would not
achieve this, because the space of email addresses and phone numbers is
small enough to enumerate, making unkeyed hashes effectively reversible.
The key lives outside the database, so a database-only compromise cannot
regenerate tokens.

*Costs*: exact match only, so no fuzzy or partial search. A name alone is
rejected with a 400, since a name is a narrowing key beside an email or
phone, never an identifier. Lookup is an enumeration surface, so it is
rate-limited per client with a sliding window, audited on hits and misses,
and warns when a client crosses 100 weighted misses in ten minutes. And a
hit proves nothing about who is calling: `LOOKUP != AUTHENTICATION` is a
stated doctrine because it is the mistake that turns a directory into an
impersonation oracle.

### Per-scope AEAD attribute blobs

Attributes are stored encrypted per scope, on the `cids` row, as one AEAD
blob. The default is AES-256-GCM; XChaCha20-Poly1305 is selectable. The
additional authenticated data binds the blob to its CID and key version
(and, for non-default algorithms, to the algorithm name), so an attacker
with `UPDATE` access to the database cannot transplant one person's
ciphertext into another person's row, nor silently downgrade the key
version or algorithm. Reads are field-level: one named attribute per call,
with a mandatory `purpose` that must be in the caller's grants, a consent
check, and an audit record written before the value is released.

*Buys*: deduplication onto a shared person never exposes what another scope
stored, so if billing and the CRM both register the same customer each
reads exactly what it wrote. Field-level reads mean the chain records which
field was wanted and why, not "someone opened the record".

*Costs*: an attribute held in two scopes is encrypted and updated twice,
and there is no cross-scope view except through the privileged DSR path.

Each blob records its own algorithm in `cids.pii_alg`. Reads follow the
stored value, writes use the configured one. That is what makes algorithm
agility operational rather than aspirational: if the current AEAD is ever
deprecated, migration is a configuration change plus one idempotent `keys
rekey` sweep, with no downtime and no flag day. Key versions work the same
way: `keys rotate` mints the next version and demotes the previous one to
RETIRING, lookups and token verification accept every live version during
the dual-key window, rows re-key on touch, and `keys retire` is the cure
for a leaked key, after which retired versions stop matching and their
token rows are purged.

### OTI purpose and audience binding, atomic single use

An OTI is a PASETO v4.public token (Ed25519). The version pins the
algorithm, removing the JWT-style algorithm-confusion class entirely, since
there is no `alg` field to attack. The payload carries a JTI, the issuer's
CID, purpose, audience, timestamps, and the signing key version as `kid`.
Verification only tries key versions the keyring lists as live, so a forged
`kid` cannot point the verifier at an arbitrary key name.

The signature is not the replay guard. Single use is enforced by an atomic
database transition: `UPDATE oti SET status='USED' ... WHERE jti=$1 AND
cid=$3 AND purpose=$4 AND audience=$5 AND status='VALID' AND expires_at >
now()`, treating zero affected rows as the failure. Matching the row's
parameters against the signed claims is defence in depth: even with a
compromised signing key, a crafted token cannot consume a JTI bound to
different parameters. The whole verification, including the mapping to the
verifier's CID and the audit append, is one transaction, so a failure
anywhere rolls the token back to VALID rather than burning a handoff that
was never delivered. The verifier must also hold the purpose in its own
grants and its scope must equal the token's audience, and consent is
checked at issue and re-checked at verification, so a withdrawal inside the
token's five-minute life stops the handoff.

By default a handoff shares no attributes. An issuer may list
`share_attributes`, copying named fields from the issuer's blob into the
verifier's blob at verification. This is the pattern behind delayed flows
such as an escalation email: consume the token immediately, fetch the
shared attribute just in time when the delayed action fires, store nothing
in between.

*Costs*: five minutes means the receiving system must act within five
minutes or the operator must widen the window deliberately. The TTL is
configurable from 30 seconds to 24 hours, and raising it widens the window
in which an intercepted token is usable. Verification is never
blind-retried by the SDKs, because a retry after an ambiguous failure would
legitimately return `token_used`.

### Selective disclosure through predicate claims

An OTI can carry issuer-authorised predicates, evaluated against the
issuer's data at verification. Two operations exist: `age_gte`, which reads
the attribute as an ISO date or RFC 3339 timestamp and compares completed
years, and `exists`. A token carries at most eight predicates, unknown
operations are rejected at issue time, and `age_gte` requires an explicit
threshold between 1 and 150, so an omitted threshold is a loud validation
failure rather than a silently always-true zero.

Only booleans cross the boundary. The verifier receives, per predicate, the
attribute name, the operation, the threshold, a `result` and a `known`. The
value never leaves the issuer's scope and nothing is copied into the
verifier's blob. A web shop can learn `age_gte 18: true` without ever
holding a birthdate.

`known` is operation-specific, and the distinction matters. For `age_gte`
it is false when the attribute is absent or unparseable, so "we do not know
the birthdate" never reads as "under 18". For `exists` it is always true,
because absence *is* the answer that predicate asks for. A verifier that
treats `known` uniformly will misread one of the two.

*Costs*: this is predicate evaluation by a trusted evaluator, not a
zero-knowledge proof. It is a data-minimisation mechanism, not a
cryptographic one.

### Hash-chained audit log, RFC 3161 anchoring, off-host export

Every operation writes an audit record: client, action, CID,
purpose/outcome. Mutating operations (register, scope issuance, OTI issue
and verify, consent, DSR, external claims) write it inside the same
transaction as the operation, so the log cannot record what did not happen
nor miss what did. Read paths (`attributes.read`, `lookup`) and the
portal's own actions append in a separate transaction that must succeed
*before* any value is released; the guarantee there is fail-closed
disclosure rather than atomicity. The chain is `hash_N =
SHA-256(canonical(prev_hash, record))` with a JSON-array canonical
encoding, so field contents cannot shift across boundaries, and append-only
triggers block UPDATE, DELETE and TRUNCATE at the database layer on both
the `audit` and `audit_anchor` tables.

One invariant deserves calling out, because it is a deliberate trade-off
rather than an oversight: **the chain records what was asked and by whom,
never what the data said.** Attribute reads log the attribute name, not its
value. Predicate verifications log `predicates_asked: ["birthdate age_gte
18"]` and not the boolean outcome, which is a one-bit derived assertion
about an identified person; since the chain is never pruned and outlives
erasure, recording it would retain a derived personal-data assertion about
someone who exercised Article 17. The accepted consequence: from the chain
alone you can reconstruct what a verifier was authorised to ask and when,
but not what it concluded.

A bare hash chain proves internal consistency, not existence at a time, so
a privileged attacker could rewrite the whole chain consistently. `sunder
anchor` therefore timestamps the chain head at an RFC 3161 Time Stamp
Authority (only a 32-byte digest ever leaves the system) and exports the
token as a `.tsr` file intended for write-once storage **off the database
host**. Anchors kept only in the database are circular and defeat nobody
privileged. `sunder verify-audit` recomputes the chain, validates every
token offline against a CA bundle, and cross-checks the export directory,
so deleted anchor rows are exposed by the surviving files; it refuses to
report success when anchors exist but cannot be verified.

*Costs*: the audit table grows without pruning, by design. Anchoring is a
scheduled job the operator must actually schedule, and the mechanism is
worth nothing if the `.tsr` files sit on the database host.

### The signer process split

The worst case in the threat model is malicious code inside the API process
reading working keys from RAM. The codebase is compiled against a single
crypto interface, `crypto.Engine`, with six operations (MAC, Seal, Open,
Sign, VerifyToken, Ensure), none of which returns key bytes. With
`SUNDER_SIGNER_SOCKET` unset, the default in-process implementation opens
the keystore directly. With it set, every cryptographic operation goes over
a Unix socket (mode 0600 in a 0700 directory) to a separate `sunder signer`
process that is the sole keystore holder, needs no database credentials,
and as a container needs no network at all.

*Buys*: a compromised API process holds no key material. It can still *use*
the six operations at whatever rate it can drive, which the rate limiter
and the audit chain bound and record, but it cannot exfiltrate keys.

*Costs*: a socket round-trip per crypto operation, one more process to run
and monitor, and a hard failure mode - a dead signer fails every crypto
path closed, with no local fallback, deliberately.

The signer is the honest limit of the design, and the dependency posture
supports it. The crypto hot path is Go standard library (Ed25519, HMAC,
AES-GCM, TLS) plus `golang.org/x/crypto` for the optional
XChaCha20-Poly1305. Runtime dependencies number three, all direct: pgx,
`golang.org/x/text` for NFKC normalisation, and `golang.org/x/crypto`.
Builds are `CGO_ENABLED=0`, images distroless and non-root, and CI gates on
`govulncheck`, `go vet` and 90 percent test coverage.

## 4. GDPR posture

Sunder is designed in line with data-protection-by-design principles and
implements concrete mechanisms for data-subject rights. It is not a
compliance certificate, and deploying it does not make an organisation
compliant with anything: compliance is a property of an organisation's
processing, legal bases, records and governance, most of which lives
outside any single piece of software. What follows is what the code does.

**Consent** is recorded per `(cid, purpose)`. An explicit `granted=false`
blocks attribute reads and OTI issuance for that purpose with a distinct
`consent_denied` error, and is re-checked when a token is verified. The
absence of a record means the purpose is governed by another legal basis,
which is the honest default: not every purpose is consent-based, and
treating a missing record as refusal would misrepresent contract and
legitimate-interest processing. Enforcement runs only after scope-ownership
checks, so consent state can never become an oracle about foreign CIDs.
Decisions survive erasure, for accountability.

**Right of access** is org-wide, because Sunder is the only component that
knows which scopes hold a given person: `GET /v1/dsr/access` returns every
scope's data plus the audit trail of who touched it. It is a
linkage-capable, high-privilege action for privacy-officer tooling only.

**Erasure** runs in one transaction: every scope's blob is wiped, all
search tokens deleted, outstanding OTIs revoked, and the person becomes a
tombstone so client-side CID references do not break. One erasure event per
scope is queued and delivered to that scope's registered webhook as JSON
signed with `X-Sunder-Signature: hex(HMAC-SHA256(secret, body))`, with a
bounded retry queue, a configurable attempt cap and audited delivery
tracking. Sunder cannot delete data inside your CRM; the signed webhook is
how it tells the CRM to.

**Portability** is a per-scope JSON export, deliberately not per-attribute
purpose-gated, because portability is its own legal basis and a withdrawn
marketing consent should not block a subject's access to their own data.
That makes it a bulk read, to be granted as sparingly as `scopes.issue`.

**Retention** is a per-scope TTL keyed on last activity, applied by a
scheduled run that wipes expired blobs and prunes long-expired OTI rows.
Search tokens survive a retention wipe, because retention is not erasure.
Audit rows are never pruned.

**The self-service privacy portal** lets a person see everything every
scope stores about them, flip consents, and erase, without going through
your support desk. It is off by default, because an upgrade must never
silently open a new unauthenticated public surface. Authentication is a
single-use magic link with a 15-minute lifetime, delivered by the
organisation's own mailer through a signed webhook; Sunder sends no email
itself. Portal erasure requires a second, separately confirmed step, so a
hijacked session cannot erase in one call. The login-start endpoint answers
identically for known and unknown addresses in body, status and timing:
mail is queued to an outbox rather than sent inline, the address lookup
queries every live key version on both outcomes, and a constant-time floor
of 40 ms dominates the remaining difference. That property is measured by a
test that fails the build on perfect separation, not asserted in prose. The
outbox holds a live login token, so it is sealed with the PII KEK, and the
per-address send throttle is keyed by an HMAC token rather than a bare hash
of the address.

What Sunder does not do: decide your legal bases, produce your records of
processing, cover data your systems hold outside it, or assert eIDAS
conformance. The EUDI-related positioning is "designed in line with eIDAS
2.0 / EUDI Wallet principles", never "certified".

## 5. Deployment model

One instance per organisation: a single stateless Go binary in front of
PostgreSQL 16.

There is no multi-tenant mode, and that is a decision rather than a missing
feature. The threat motivating the entire design is the existence of one
place where identities from many contexts can be joined. A multi-tenant
instance holding CID mappings for many companies would be exactly that
place, at a larger scale than any of its tenants: the super-target the
per-scope model exists to eliminate. Row-level isolation inside a shared
database does not change the fact that one compromise reaches every
tenant's mappings and keys. The answer for organisations that do not want
to run their own instance is therefore **managed single-tenant**: an
isolated instance per customer, with its own Kubernetes namespace,
database, keystore mount, audit chain and anchors, and admin credential.
Operations are centralised; the isolation is not.

Provisioning is one script that creates the namespace and database secret,
installs the Helm chart, and runs `sunder bootstrap -unattended`, which
applies migrations, ensures key material for every live key version, and
emits the first admin credential once. Bootstrap is idempotent, so the
script is safe to re-run after a failed step. Offboarding follows an
ordered runbook: export, erase with webhooks, anchor the final state
off-host, destroy the keys (crypto-shredding is the real deletion, since
without the KEK surviving ciphertext backups are unreadable), then delete
the deployment and the database.

The operational surface is deliberately small:

- **PostgreSQL only.** No message broker, no search cluster, no object
  store. Redis is optional, and only for sharing rate-limit windows across
  replicas.
- **Configuration is environment variables only.** No config files, and
  invalid values fail startup with a specific error, so a typo cannot
  silently fall back to a default.
- **Helm chart** with TLS and mTLS, Vault keystore, the signer sidecar, a
  NetworkPolicy, and CronJobs for anchoring, retention and webhook
  delivery. Nothing is centralised across instances by default.
- **Cron anchoring**, with the `.tsr` export directory synced to write-once
  storage off the database host.
- **Observability**: Prometheus text-format metrics (optionally
  bearer-gated, since per-client counters reveal client identities and
  activity), a Grafana dashboard and alert rules. No PII in logs or
  metrics: the logging middleware records method, route pattern, status and
  duration, never query strings, bodies or headers.

Integration goes through six SDKs (Go, TypeScript, Python, PHP, Java, .NET)
with identical method names, error taxonomy and retry policy. They contain
zero cryptography and are roughly 500-line transport clients, so nothing
security-critical exists in five copies.

## 6. Performance

The closest open-source comparison is Databunker, so the benchmark is a
head-to-head: same machine, same database engine (PostgreSQL 16 in Docker
for both), same load harness, comparable operations, both systems
interleaved in the same measurement window. Five rounds of n=3000 at 16
concurrent clients, plus one clean 5,000-request pass per operation, zero
errors on both sides in the clean pass. Neither system was tuned.

Clean pass, measured 2026-08-23:

| Operation | Sunder | Databunker | Advantage |
|---|---|---|---|
| write | 2,729 rps, p50 5.62 ms, p99 9.77 ms | 1,295 rps, p50 12.09 ms, p99 26.29 ms | +111%, p99 2.7x lower |
| lookup | 3,439 rps, p50 4.53 ms, p99 6.25 ms | 2,032 rps, p50 7.18 ms, p99 20.02 ms | +69%, p99 3.2x lower |
| read | 3,443 rps, p50 4.51 ms, p99 5.64 ms | 2,139 rps, p50 6.45 ms, p99 19.33 ms | +61%, p99 3.4x lower |

Medians of the five interleaved rounds agree and are slightly wider: write
+134%, lookup +78%, read +75%.

The caveats belong in the same breath as the numbers.

**This is a laptop under a real desktop load, not a controlled server
benchmark.** Load average was around 4 at the start and drifted to about 8
under the benchmark's own load. Quote the ratios, not the absolute numbers.
An earlier run on the same code measured a read advantage of +30%, which
turned out to be machine noise at load average 10 to 14 - a fair
illustration of how load-dependent these figures are.

**Part of the advantage is Databunker degrading with table size inside a
single run.** Across the five rounds both systems accumulate rows and their
trends diverge: Sunder's write throughput rose from 2,108 to 2,824 rps as
caches warmed, while Databunker's fell from 1,325 to 1,076 rps. Two
Databunker measurements in round 5 were discarded as a failed run rather
than averaged in, noted here because silently dropping them would flatter
the comparison.

**The operations are comparable but not identical.** Sunder's read returns
one field-level, purpose-checked attribute; Databunker's returns the full
record. Sunder's search index is a keyed HMAC per identifier per live key
version; Databunker's is a hash index. Sunder writes a hash-chained,
same-transaction, globally ordered audit record per operation; Databunker
has its own audit that is not hash-chained.

That last asymmetry is the interesting part: Sunder does more work per
request throughout and is still faster on this hardware. The reasons are
unglamorous. Hot paths are single indexed point queries, because an HMAC
token is an exact match; key material is immutable per versioned name and
cached in process memory, so there is no keystore I/O per request; and the
audit chain's global ordering lock is held only for the final
append-and-commit window of each transaction.

## 7. Limitations and open gaps

- **No external security audit.** There is a written threat model, a
  disclosure policy and a 90 percent CI coverage gate, and none of that
  substitutes for independent review. Treat the security claims as author
  claims until someone else has checked them.
- **No production users.** Pre-1.0; interfaces may still move.
- **The PKCS#11 keystore driver is a stub** that returns "not implemented
  yet". HSM-backed key storage is a placeholder, not a capability. The
  working drivers are file (pilots) and HashiCorp Vault (production).
- **No fuzzy or partial search.** This follows directly from keyed HMAC
  indexes: exact match is the only match. Roadmap.
- **No file vault and no value tokenization.** Sunder stores attribute
  maps, not documents, and issues no format-preserving surrogate values.
  Roadmap.
- **The OpenID4VP bridge is deferred.** What exists today is the
  external-issuer trust registry and signed claim-envelope intake:
  registered issuers with Ed25519 keys and per-issuer claim allowlists, and
  a `POST /v1/claims/external` endpoint that accepts a PASETO envelope only
  when the issuer is registered and not retired, the signature verifies
  against the registered key, the expiry is in the future and at most 24
  hours ahead, the signed CID matches the target (so an attestation for one
  person cannot be attached to another), the JTI has never been used, and
  every claim name is in the issuer's allowlist. Claims land with
  provenance in the attribute name (`age_gte_18@gov.wallet`). The
  wallet-facing protocol bridge - OpenID4VP presentation flows, SD-JWT VC
  or mdoc verification, EU trust-list and revocation checks - is
  deliberately deferred to a separate gateway process while those
  specifications are still moving, so the core's small security surface
  does not absorb a large evolving protocol stack. The envelope contract is
  stable; gateways are replaceable.
- **The audit log grows without pruning, by design.** The chain and its
  anchors are the tamper evidence, so capacity planning must account for
  one audit row per operation, permanently.
- **Rate limiting is per replica unless you configure Redis.**
- **The instance is still the organisation's crown jewel.** Removing the
  central multi-organisation party does not remove the value of the single
  instance holding the mappings. Reviewing which clients hold
  `scopes.issue`, `dsr.access` and `dsr.export` remains a human governance
  duty that no mechanism performs for you.
- **A client system that stores a national identifier next to its CID has
  defeated the design**, and Sunder cannot see that happening. Its own
  schema has no column for one and the service neither accepts nor returns
  one, but that only covers Sunder's own storage.

## 8. Comparison

**Databunker** is the closest open-source neighbour and solves an
overlapping problem: encrypted PII storage with searchable indexes, GDPR
tooling and its own audit. The architectural difference is the identifier
model - Databunker issues one token per person, organisation-wide, while
Sunder issues one pseudonym per person per scope. If the concern is
"encrypt customer PII in one place and support subject requests",
Databunker addresses it. If the concern is specifically that your own
systems can be joined to each other, a single organisation-wide token does
not break that join. Databunker's core is MIT with a paid Pro edition;
Sunder is Apache-2.0 with no separate tier. A migration tool for Databunker
records to Sunder contacts is in the repository.

**HashiCorp Vault** is a different category: a secrets and key management
system, which Sunder uses as one, since Vault is the recommended production
keystore driver. Vault does not model people, pseudonyms, purposes, consent
or subject requests, and is not trying to. These compose rather than
compete.

**DIY encryption** in each application is where most organisations start,
and it can be done well. What it rarely delivers in practice is the parts
that only pay off later: keyed rather than plain search indexes, key
rotation that actually runs, an audit trail a privileged database user
cannot rewrite, and consistent purpose and consent enforcement across every
system. Each is a project of its own.

**AWS Cognito** and similar managed identity services solve authentication
and user directory management: sign-in, federation, tokens for end users.
Sunder solves neither. It has no authentication of end users at all
(`LOOKUP != AUTHENTICATION` is an explicit doctrine) and no sign-in flows.
An organisation can reasonably run Cognito for authenticating people and
Sunder for decoupling how its internal systems store them.

## 9. Roadmap

Everything in this section is a plan, not a shipped capability.

- **Fuzzy and partial search** over the keyed index, without reintroducing
  searchable plaintext. The hardest item on the list, because the security
  property and the feature are in direct tension.
- **File vault**: encrypted document storage attached to a CID, with the
  same per-scope AAD binding and audited access as attributes.
- **Value tokenization**: format-preserving surrogate values for legacy
  systems that need something shaped like the original identifier.
- **The EUDI gateway**: the deferred OpenID4VP bridge as a separate
  process, speaking presentation requests to wallets, validating against EU
  trust and status lists, and translating verified attestations into the
  existing stable envelope contract. Member-state wallet deadlines in
  December 2026 are the natural trigger.
- **A working PKCS#11 driver** for HSM-backed keystores.
- **Independent security review**, and the 1.0 interface freeze that should
  follow it.

The composition of the wallet work with the existing predicate mechanism is
why the envelope contract was built first: a wallet attests `age_gte_18`
once through the gateway, and internal systems then use ordinary OTI
handoffs with `share_predicates: [{"attr": "age_gte_18@gateway", "op":
"exists"}]`. The attestation stays in one scope, and every downstream
system only ever learns a boolean.

---

Sunder is at `github.com/fvisic/sunder` under Apache-2.0, with no license
keys and no paid tier. The design rationale is in `docs/DESIGN.md`, the
adversary analysis in `docs/THREAT-MODEL.md`, the API surface and error
taxonomy in `docs/API.md`, and the benchmark harness and raw results in
`benchmark/`, reproducible with one script. Read the threat model before
production use.
