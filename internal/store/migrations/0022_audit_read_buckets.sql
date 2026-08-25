-- P4.2: aggregate read events instead of chaining each one.
--
-- Lookups and attribute reads are the highest-volume audited events and
-- the least interesting individually: the same operator opening the same
-- contact on four screens in one hour produced four identical rows in a
-- log that is never pruned. Under SUNDER_AUDIT_READS=bucketed (the
-- default) those events UPSERT into hourly buckets instead; at the top of
-- each hour a closer computes one digest over the finished hour's buckets
-- and writes a SINGLE chained audit row for it, then marks the buckets
-- sealed. Mutations (register, erase, consent, OTI) are untouched: they
-- stay chained per event, where tamper evidence matters most.
--
-- user_id is the optional, CLIENT-ASSERTED operator identifier
-- (X-Sunder-User-Id header): an opaque ID such as an employee number or
-- directory GUID, deliberately an ID and not a name so the never-pruned
-- log carries the minimum about employees. Sunder cannot verify it - it
-- is attribution the client asserts, not authentication.
-- The access log is also personal data; aggregation is a privacy
-- improvement as much as a size one.
CREATE TABLE audit_read_buckets (
    client_id    TEXT NOT NULL,
    user_id     TEXT NOT NULL DEFAULT '',
    cid          TEXT NOT NULL DEFAULT '',
    action       TEXT NOT NULL,
    bucket_start TIMESTAMPTZ NOT NULL,
    count        BIGINT NOT NULL DEFAULT 1,
    first_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
    sealed_at    TIMESTAMPTZ,
    PRIMARY KEY (client_id, user_id, cid, action, bucket_start)
);
-- The closer's work queue and the Article 15 trail query.
CREATE INDEX audit_read_buckets_open_idx ON audit_read_buckets (bucket_start)
    WHERE sealed_at IS NULL;
CREATE INDEX audit_read_buckets_cid_idx ON audit_read_buckets (cid);

-- Buckets are audit data: counting up is the only legal mutation while the
-- hour is open, sealing is the only legal transition after, and nothing is
-- ever deleted. A sealed bucket is covered by the digest in its hour's
-- chained audit row, so any edit after sealing must be refused outright.
CREATE FUNCTION audit_read_buckets_guard() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND OLD.sealed_at IS NULL
       AND NEW.client_id = OLD.client_id
       AND NEW.user_id = OLD.user_id
       AND NEW.cid = OLD.cid
       AND NEW.action = OLD.action
       AND NEW.bucket_start = OLD.bucket_start
       AND NEW.first_seen = OLD.first_seen
       AND NEW.count >= OLD.count THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'audit read buckets are append-only (open buckets may only count up or be sealed)';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER audit_read_buckets_no_edit BEFORE UPDATE OR DELETE ON audit_read_buckets
    FOR EACH ROW EXECUTE FUNCTION audit_read_buckets_guard();
CREATE TRIGGER audit_read_buckets_no_truncate BEFORE TRUNCATE ON audit_read_buckets
    FOR EACH STATEMENT EXECUTE FUNCTION audit_read_buckets_guard();

-- The chained audit rows get the same operator attribution as a REAL
-- column - queryable with plain SQL (WHERE user_id = ...), NULL when the
-- client asserted nothing. Deliberately NOT part of the chain hash: the
-- canonical tuple must keep verifying every pre-existing chain. What
-- protects it is the same append-only trigger that protects everything
-- else, which now also refuses any change to user_id during sealing.
ALTER TABLE audit ADD COLUMN user_id TEXT;
CREATE INDEX audit_user_idx ON audit (user_id) WHERE user_id IS NOT NULL;

CREATE OR REPLACE FUNCTION audit_append_only() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND OLD.hash IS NULL
       AND OLD.chain_seq IS NULL
       AND NEW.hash IS NOT NULL
       AND NEW.chain_seq IS NOT NULL
       AND NEW.seq = OLD.seq
       AND NEW.ts = OLD.ts
       AND NEW.client_id IS NOT DISTINCT FROM OLD.client_id
       AND NEW.action = OLD.action
       AND NEW.cid IS NOT DISTINCT FROM OLD.cid
       AND NEW.detail IS NOT DISTINCT FROM OLD.detail
       AND NEW.user_id IS NOT DISTINCT FROM OLD.user_id THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'audit log is append-only (only sealing an unsealed row is allowed)';
END;
$$ LANGUAGE plpgsql;
