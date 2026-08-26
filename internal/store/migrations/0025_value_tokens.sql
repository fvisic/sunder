-- Phase 3, F4: value tokenization.
--
-- A client swaps an arbitrary sensitive value (IBAN, card number, national
-- id it is legally forced to keep somewhere) for an opaque token and
-- stores only the token; the value lives here, sealed under the PII KEK
-- through the crypto engine, scope-bound like everything else. Two token
-- shapes: "string" (opaque) and "card" (Luhn-valid, length-preserving
-- random digits so legacy card-shaped columns keep validating - the BIN is
-- deliberately NOT preserved: preserved BINs leak issuer and geography).
--
-- unique_hash implements `unique: true` dedup: the keyed HMAC of the value
-- (never the value) under a partial unique index, so tokenizing the same
-- IBAN twice returns the same token instead of breeding aliases.
CREATE TABLE value_tokens (
    token       TEXT PRIMARY KEY,
    scope       TEXT NOT NULL,
    token_type  TEXT NOT NULL CHECK (token_type IN ('string','card')),
    ciphertext  BYTEA NOT NULL,
    key_id      TEXT NOT NULL,
    alg         TEXT NOT NULL,
    unique_hash BYTEA,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Two independent expiries, either or both may be set: final is a hard
    -- deadline; sliding extends on every read (last_used tracks it).
    expires_final   TIMESTAMPTZ,
    sliding_seconds BIGINT,
    last_used       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX value_tokens_unique_uq ON value_tokens (scope, unique_hash)
    WHERE unique_hash IS NOT NULL;
-- The retention sweep's queue.
CREATE INDEX value_tokens_expiry_idx ON value_tokens (expires_final)
    WHERE expires_final IS NOT NULL;
CREATE INDEX value_tokens_sliding_idx ON value_tokens (last_used)
    WHERE sliding_seconds IS NOT NULL;
