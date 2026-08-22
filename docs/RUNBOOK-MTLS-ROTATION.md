# Runbook: TLS / mTLS certificate rotation

Sunder's transport security has three independent pieces:

| Piece | Config | Rotation impact |
|---|---|---|
| Server certificate | `SUNDER_TLS_CERT` / `SUNDER_TLS_KEY` | clients must trust the issuer |
| Client CA bundle | `SUNDER_MTLS_CA` | which client certs are accepted |
| Client certificates | held by each integrating system | must chain to a CA in the bundle |

Bearer credentials (`clients.key_hash`) are independent of all of this and
rotate via `sunder client create` + config swap on the client side.

## 1. Rotating the server certificate

1. Obtain the new cert/key (same SAN/hostname).
2. Replace the files (or the Kubernetes TLS secret) and restart/roll the
   replicas - the files are read at listener start.
3. Clients verify against their trust store, so nothing changes for them as
   long as the issuing CA is already trusted. If you are ALSO changing the
   issuing CA, update client trust stores first, server cert second.

## 2. Rotating the client CA (the mTLS trust anchor) - zero downtime

The `SUNDER_MTLS_CA` file may contain multiple CA certificates; the server
accepts a client cert chaining to ANY of them. Rotation is therefore a
three-step overlap, never a flag-day:

1. **Add**: append the new CA cert to the bundle file (old + new), roll the
   service. Existing client certs keep working.
2. **Migrate**: reissue client certificates under the new CA, system by
   system, at each team's pace. Verify with:
   ```sh
   curl --cert client.crt --key client.key --cacert server-ca.crt \
        https://sunder.internal:8443/healthz
   ```
3. **Remove**: once no traffic authenticates under the old CA, remove it
   from the bundle and roll again. From this moment old certs are refused
   at the TLS handshake.

How to see who is still on the old CA: mTLS failures happen before HTTP, so
they are not in Sunder's request log - watch the connection errors on the
client side, or stand the old CA down in a staging bundle first.

## 3. Rotating one client's certificate

Reissue under a CA already in the bundle and swap it in the client system.
No Sunder-side action: the server validates the chain, while the
application-level identity stays the bearer credential. (This is deliberate:
losing a client cert is contained by the CA trust; losing a bearer
credential is contained by `allowed_actions`/`allowed_purposes` and the
audit trail. Rotate both on personnel changes.)

## 4. Expiry hygiene

- Alert 30 days before `not_after` on the server cert, every client cert,
  and both CAs (your PKI or cert-manager does this; Sunder does not parse
  certificate expiries).
- Keep CA lifetimes >> client-cert lifetimes so step 2 of the CA rotation
  never races expiry.
- After ANY bundle change run the demo flow (`demo/callcenter.sh`) against
  the environment - it exercises the full authenticated path.
