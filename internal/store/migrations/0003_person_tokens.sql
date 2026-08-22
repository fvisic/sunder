-- Multi-value identifiers (decision in session, 2026-08-22): a contact can
-- have several searchable emails and phone numbers (and accumulated name
-- variants). Tokens move from single columns to one row per token.

CREATE TABLE person_tokens (
    person_id   UUID NOT NULL REFERENCES persons(id),
    kind        TEXT NOT NULL CHECK (kind IN ('email','phone','name')),
    token       TEXT NOT NULL,
    key_version TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (person_id, kind, token)
);
-- An email or phone identifies exactly one person (dedup invariant); names
-- are shared by many people and only ever narrow.
CREATE UNIQUE INDEX person_tokens_ident_uq ON person_tokens (kind, token)
    WHERE kind IN ('email','phone');
CREATE INDEX person_tokens_lookup_idx ON person_tokens (kind, token);
CREATE INDEX person_tokens_person_idx ON person_tokens (person_id, kind);

-- Carry over existing single-column tokens. key_version is best-effort 'v1'
-- (pre-release data only); rows under later versions re-appear on touch.
INSERT INTO person_tokens (person_id, kind, token, key_version)
    SELECT id, 'email', email_token, 'v1' FROM persons WHERE email_token IS NOT NULL
    ON CONFLICT DO NOTHING;
INSERT INTO person_tokens (person_id, kind, token, key_version)
    SELECT id, 'phone', phone_token, 'v1' FROM persons WHERE phone_token IS NOT NULL
    ON CONFLICT DO NOTHING;
INSERT INTO person_tokens (person_id, kind, token, key_version)
    SELECT id, 'name', name_token, 'v1' FROM persons WHERE name_token IS NOT NULL
    ON CONFLICT DO NOTHING;

ALTER TABLE persons
    DROP COLUMN email_token,
    DROP COLUMN phone_token,
    DROP COLUMN name_token;
