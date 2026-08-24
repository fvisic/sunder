# Design: EUDI Wallet / OpenID4VP gateway

Status: DESIGN ONLY. The external-issuer trust registry and the signed
claim-envelope intake (`POST /v1/claims/external`, `sunder issuer ...`) are
implemented; the OpenID4VP protocol bridge described here is deliberately
deferred until the EUDI wallet ecosystem stabilizes (member-state wallet
deadline: December 2026). Sunder's positioning stays "designed in line with
eIDAS 2.0 / EUDI Wallet principles" - never "certified".

## What exists today (P2.4)

```
wallet/attribute provider          gateway (yours)                Sunder
        |  OpenID4VP / OIDC / any  |                                |
        |<------------------------>|  PASETO v4.public envelope     |
        |                          |  {iss, jti, cid, claims{...},  |
        |                          |   iat, exp}                    |
        |                          |------------------------------->|
        |                          |     POST /v1/claims/external   |
        |                          |                                |
        |                          |   verified against the trust   |
        |                          |   registry; stored with        |
        |                          |   provenance: claim@issuer     |
```

- `trusted_issuers`: issuer id, Ed25519 public key, allowed claim names.
  Managed by `sunder issuer add/list/remove`, audited.
- An envelope is accepted only when: the issuer is registered, the
  signature verifies against the REGISTERED key, `exp` is in the future,
  the SIGNED `cid` matches the target pseudonym (subject binding - an
  attestation for Alice cannot be attached to Bob), the `jti` has never
  been consumed (anti-replay, enforced in the same transaction as the
  write), and every claim name is in the issuer's allowlist (`*` = any;
  an EMPTY allowlist permits nothing - deny by default).
- Claim names must not contain `@` (provenance separator), values are
  capped at 4 KB, and client-supplied attribute names with `@` are
  rejected at registration - provenance cannot be forged from either side.
- Claims land in the caller-scope blob as `<claim>@<issuer>` - provenance
  is part of the attribute name, so a wallet-asserted `age_gte_18` can
  never be confused with a self-declared one.

## The deferred bridge

A production EUDI integration adds a GATEWAY component (separate process,
like the signer) that:

1. Speaks **OpenID4VP** to wallets: presentation request (presentation
   definition asking e.g. for an age-over attestation), response
   verification (SD-JWT VC or mdoc/ISO 18013-5 as mandated by the
   implementing acts).
2. Validates the wallet presentation against the **EU trust framework**
   (issuer trust lists / status lists), including revocation checks.
3. Translates the verified attestation into the Sunder envelope above and
   posts it with its own client credential. The gateway's Ed25519 key is
   the ONE key in Sunder's trust registry - wallet ecosystem complexity
   never enters the core.

Why a bridge, not native protocol support in the core: the OpenID4VP and
attestation-format specs are still moving; the core's security surface
(six-operation signer boundary, strict keystore, small dependency tree)
must not absorb a large evolving protocol stack. The envelope contract is
stable; gateways are replaceable.

## Predicates and wallets

The natural composition: a wallet attests `age_gte_18` once via the
gateway; internal systems then use standard OTI handoffs with
`share_predicates: [{"attr": "age_gte_18@gateway", "op": "exists"}]` - the
attestation stays in one scope, downstream systems only ever learn
booleans.
