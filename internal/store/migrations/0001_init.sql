-- Core schema: pseudonymous identity layer. No OIB column exists anywhere
-- by design (PLAN.md section 7 / decision D4).

CREATE TABLE persons (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email_token   TEXT,
    phone_token   TEXT,
    name_token    TEXT,
    pii_encrypted BYTEA,
    pii_key_id    TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX persons_email_token_idx ON persons (email_token) WHERE email_token IS NOT NULL;
CREATE INDEX persons_phone_token_idx ON persons (phone_token) WHERE phone_token IS NOT NULL;
CREATE INDEX persons_name_token_idx  ON persons (name_token)  WHERE name_token  IS NOT NULL;

CREATE TABLE cids (
    cid        TEXT PRIMARY KEY,
    person_id  UUID NOT NULL REFERENCES persons(id),
    scope      TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (person_id, scope)
);

CREATE TABLE clients (
    client_id        TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    key_hash         BYTEA NOT NULL,
    scope            TEXT NOT NULL,
    allowed_actions  TEXT[] NOT NULL DEFAULT '{}',
    allowed_purposes TEXT[] NOT NULL DEFAULT '{}',
    rate_limit       INT NOT NULL DEFAULT 60,
    mtls_cn          TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE oti (
    jti        UUID PRIMARY KEY,
    cid        TEXT NOT NULL REFERENCES cids(cid),
    purpose    TEXT NOT NULL,
    audience   TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    status     TEXT NOT NULL DEFAULT 'VALID',
    used_at    TIMESTAMPTZ,
    used_by    TEXT
);

CREATE TABLE audit (
    seq       BIGSERIAL PRIMARY KEY,
    ts        TIMESTAMPTZ NOT NULL DEFAULT now(),
    client_id TEXT,
    action    TEXT NOT NULL,
    cid       TEXT,
    detail    JSONB,
    prev_hash TEXT,
    hash      TEXT NOT NULL
);

CREATE TABLE audit_anchor (
    id         BIGSERIAL PRIMARY KEY,
    root_hash  TEXT NOT NULL,
    tsa_url    TEXT NOT NULL,
    stamped_at TEXT,
    tsr        BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE keys (
    key_id     TEXT PRIMARY KEY,
    kind       TEXT NOT NULL,
    status     TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
