-- GDPR / data-subject rights layer (PLAN section 14, v1.5).

-- Consent decisions per (cid, purpose). Absence of a row means "not
-- consent-governed" (contract/legitimate-interest bases); an explicit
-- granted=false row BLOCKS attribute reads and OTI issuance for that
-- purpose. Rows survive erasure for accountability.
CREATE TABLE consents (
    cid        TEXT NOT NULL REFERENCES cids(cid),
    purpose    TEXT NOT NULL,
    granted    BOOLEAN NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (cid, purpose)
);

-- One webhook per scope: erasure events are pushed to the systems holding
-- that scope's CIDs, signed with the per-scope secret.
CREATE TABLE webhooks (
    scope      TEXT PRIMARY KEY,
    url        TEXT NOT NULL,
    secret     TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Erasure orchestration: one erasure per person, one event per scope that
-- held a CID; deliveries are tracked until confirmed.
CREATE TABLE erasures (
    id           BIGSERIAL PRIMARY KEY,
    person_id    UUID NOT NULL,
    requested_by TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE erasure_events (
    id           BIGSERIAL PRIMARY KEY,
    erasure_id   BIGINT NOT NULL REFERENCES erasures(id),
    scope        TEXT NOT NULL,
    cid          TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'PENDING', -- PENDING | DELIVERED | NO_WEBHOOK
    attempts     INT NOT NULL DEFAULT 0,
    delivered_at TIMESTAMPTZ
);
CREATE INDEX erasure_events_pending_idx ON erasure_events (status) WHERE status = 'PENDING';

-- Erased persons stay as tombstones so CID references in client systems
-- never break; tokens and blobs are gone, so nothing resolves to them.
ALTER TABLE persons ADD COLUMN erased_at TIMESTAMPTZ;

-- Per-scope contact retention: blobs older than the TTL are wiped by
-- `sunder retention run` (full-person erasure remains the DSR path).
CREATE TABLE retention_policies (
    scope             TEXT PRIMARY KEY,
    contacts_ttl_days INT NOT NULL CHECK (contacts_ttl_days >= 0)
);
