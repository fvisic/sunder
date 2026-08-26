-- Phase 3, F5: file vault + per-person record keys.
--
-- The record key is the future home of crypto-shredding: one random key
-- per person, wrapped by the PII KEK through the crypto engine. File DEKs
-- are wrapped by the record key, so ERASING THE ONE ROW BELOW makes every
-- file of that person permanently unrecoverable the instant the erasure
-- commits - the ciphertext in the blob store becomes garbage that the
-- retention sweep garbage-collects at leisure. No storage round trip sits
-- on the erasure path.
CREATE TABLE person_record_keys (
    person_id  UUID PRIMARY KEY REFERENCES persons(id),
    wrapped    BYTEA NOT NULL,
    key_id     TEXT NOT NULL,
    alg        TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- File metadata. The content lives in the configured storage driver under
-- storage_key, encrypted in 4 MiB AES-256-GCM chunks under a random
-- per-file DEK (chunk index in the AAD, so chunks cannot be reordered or
-- transplanted); the driver never sees plaintext. cid scopes the file:
-- like attributes, files belong to a person AS SEEN BY one scope.
CREATE TABLE files (
    id           UUID PRIMARY KEY,
    cid          TEXT NOT NULL REFERENCES cids(cid),
    name         TEXT NOT NULL,
    content_type TEXT NOT NULL,
    size_bytes   BIGINT NOT NULL,
    sha256       TEXT NOT NULL,
    dek_wrapped  BYTEA NOT NULL,
    storage_key  TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ,
    -- Set when the row is only awaiting storage garbage collection: the
    -- person was erased (record key gone) or expiry passed. GC'd rows are
    -- deleted after the driver confirms the object is gone.
    gc_at        TIMESTAMPTZ
);
CREATE INDEX files_cid_idx ON files (cid);
CREATE INDEX files_expiry_idx ON files (expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX files_gc_idx ON files (gc_at) WHERE gc_at IS NOT NULL;
