-- Phase 3, F6: attribute blob versioning.
--
-- OFF by default (SUNDER_VERSIONS_KEEP unset/0): keeping history extends
-- the storage-limitation clock, a real GDPR tension, so an upgrade must
-- not silently start retaining superseded values. When enabled, every
-- overwrite of a cid's attribute blob appends the PREVIOUS value here
-- before the new one lands, so a mistaken update can be inspected or
-- rolled back. History is erased and pruned with the live blob - it is
-- the same personal data, one generation older.
CREATE TABLE cid_blob_versions (
    cid         TEXT NOT NULL REFERENCES cids(cid),
    version_no  BIGINT NOT NULL,
    blob        BYTEA NOT NULL,
    key_id      TEXT NOT NULL,
    alg         TEXT NOT NULL,
    written_by  TEXT NOT NULL,
    written_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (cid, version_no)
);
CREATE INDEX cid_blob_versions_prune_idx ON cid_blob_versions (written_at);
