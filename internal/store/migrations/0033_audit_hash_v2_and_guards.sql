-- Review mediums, audit integrity block.
--
-- (1) user_id joins the chain hash. It was the ONE audited field a database
-- attacker could edit without tripping verification - the field that says
-- WHO did it. The canonical tuple is versioned so every pre-existing chain
-- keeps verifying: rows sealed before this migration carry hash_v=1 (the
-- old tuple, without user_id), rows sealed from now on carry hash_v=2 (with
-- it). Verification recomputes each row under its own version. Flipping a
-- row's hash_v cannot hide an edit: the stored hash matches only the tuple
-- it was computed over, and recomputing it breaks the prev_hash linkage the
-- external anchor pins. Stated plainly: rows sealed BEFORE this migration
-- keep the v1 tuple, so their user_id remains outside the hash forever -
-- a sealed chain cannot retroactively cover a new field; only the
-- append-only trigger protects it there.
ALTER TABLE audit ADD COLUMN hash_v SMALLINT NOT NULL DEFAULT 1;

-- (2) The sealer's age filter compared the APPLICATION-stamped ts against
-- the DATABASE clock: an app clock running ahead of the database by more
-- than the seal delay stalls sealing silently (rows forever "too young").
-- db_ts records insertion on the database clock, so the filter compares
-- like with like. Nullable + default (no table rewrite); pre-existing rows
-- are NULL and count as old, which they are.
ALTER TABLE audit ADD COLUMN db_ts TIMESTAMPTZ;
ALTER TABLE audit ALTER COLUMN db_ts SET DEFAULT now();

-- (3) audit_read_buckets accepted an INSERT of an ALREADY-SEALED row: the
-- guard triggers fired on UPDATE/DELETE/TRUNCATE, but INSERT is exactly the
-- privilege the API role must hold, so one forged sealed row broke bucket
-- verification permanently and could never be repaired (rows are
-- undeletable). Legitimate inserts are always open (sealed_at NULL); only
-- the closer seals, via UPDATE.
CREATE FUNCTION audit_read_buckets_no_forged_seal() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit read buckets are inserted OPEN; only the closer seals (sealed_at must be NULL at insert)';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER audit_read_buckets_open_insert BEFORE INSERT ON audit_read_buckets
    FOR EACH ROW WHEN (NEW.sealed_at IS NOT NULL)
    EXECUTE FUNCTION audit_read_buckets_no_forged_seal();

-- The sealing transition may now also stamp hash_v (1 -> 2) and must leave
-- db_ts alone; everything else stays refused.
CREATE OR REPLACE FUNCTION audit_append_only() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND OLD.hash IS NULL
       AND OLD.chain_seq IS NULL
       AND NEW.hash IS NOT NULL
       AND NEW.chain_seq IS NOT NULL
       AND NEW.seq = OLD.seq
       AND NEW.ts = OLD.ts
       AND NEW.db_ts IS NOT DISTINCT FROM OLD.db_ts
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

-- The closer skips an hour whose chained hourly row already exists (see
-- CloseReadBuckets): summarizing it again would poison verification with a
-- duplicate. This partial index makes that existence check O(1) instead of
-- an audit-table scan. detail stays TEXT deliberately - it is hashed into
-- the chain byte-for-byte and JSONB does not preserve bytes (key order,
-- whitespace, number forms), so a JSONB column would make verification
-- depend on the database's serialization. The ::jsonb cast below runs once
-- per hourly row (one per hour) at index maintenance, never on a request
-- path, and the closer reads the precomputed value from the index.
CREATE INDEX audit_reads_hourly_idx ON audit (((detail::jsonb)->>'hour'))
    WHERE action = 'audit.reads_hourly';
