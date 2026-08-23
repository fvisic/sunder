-- P2.4 external-issuer federation: registry of issuers (e.g. a wallet
-- gateway) whose signed claim envelopes this instance accepts. Public keys
-- only - nothing here is secret; trust, not confidentiality.
CREATE TABLE trusted_issuers (
    issuer_id      TEXT PRIMARY KEY CHECK (issuer_id ~ '^[a-z0-9._-]{1,64}$'),
    public_key     BYTEA NOT NULL CHECK (octet_length(public_key) = 32),
    -- Claim names this issuer may assert; empty = any claim name.
    allowed_claims TEXT[] NOT NULL DEFAULT '{}',
    added_by       TEXT NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
