-- Phase 3, F8: shared records.
--
-- A share is an expiring, revocable, read-only projection of a FEW named
-- attributes of one person, addressed by an unguessable UUID, handed to an
-- external partner. It is strictly narrower than a scoped pseudonym: only
-- the listed fields, only until expiry, and revocable at any time - by the
-- creator (DELETE), or automatically when the person is erased or withdraws
-- consent. Databunker's equivalent expires only; ours also revokes.
CREATE TABLE shared_records (
    uuid          UUID PRIMARY KEY,
    cid           TEXT NOT NULL REFERENCES cids(cid),
    scope         TEXT NOT NULL,
    fields        TEXT[] NOT NULL,
    partner_label TEXT NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,
    revoked_at    TIMESTAMPTZ,
    created_by    TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX shared_records_cid_idx ON shared_records (cid) WHERE revoked_at IS NULL;
CREATE INDEX shared_records_prune_idx ON shared_records (expires_at);
