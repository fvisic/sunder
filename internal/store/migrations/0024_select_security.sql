-- Phase 3, F3 (select security) + F12 (roles).
--
-- allowed_attributes narrows WHICH fields a client may read: NULL keeps
-- today's behaviour (all attributes its purposes allow), a list makes
-- GetAttribute refuse anything else and filters Export/Access output. A
-- billing system that only ever needs `iban` should never be able to read
-- `birthdate`, even with a valid purpose.
ALTER TABLE clients ADD COLUMN allowed_attributes TEXT[];

-- role is an INTROSPECTION label plus a creation-time preset - enforcement
-- stays allowed_actions, single source of truth. 'custom' is every
-- existing client and anything created with explicit -actions.
ALTER TABLE clients ADD COLUMN role TEXT NOT NULL DEFAULT 'custom';

-- Unlock tokens (Databunker-style select security): a 60-second,
-- single-use, purpose-bound second credential for operations with bulk
-- potential. Deliberate friction plus a chained audit anchor proving
-- explicit intent. Stored hashed - the raw token is shown exactly once.
CREATE TABLE unlock_tokens (
    token_hash  BYTEA PRIMARY KEY,
    client_id   TEXT NOT NULL REFERENCES clients(client_id),
    purpose     TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ
);
-- The pruning worker's queue (spent and expired rows are swept, they are
-- not audit data - the audit chain carries issue and use separately).
CREATE INDEX unlock_tokens_prune_idx ON unlock_tokens (expires_at);
