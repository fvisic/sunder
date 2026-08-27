-- Review #2, audit-integrity block. Migration 0033 hardened
-- audit_read_buckets against a FORGED INSERT and noted in its own comment
-- that "INSERT is exactly the privilege the API role must hold". The same
-- class was left open on `audit` itself and on the closer's hour marker.

-- (1) AUDIT-CHAIN-1. The invariant "hash and chain_seq are set together, or
-- neither is" was enforced only by application convention, while every
-- consumer scanned chain_seq into a non-nullable target. ORDER BY chain_seq
-- DESC defaults to NULLS FIRST, so ONE plain INSERT of a row with a hash and
-- a NULL chain_seq sorted itself to the head and permanently broke
-- sealedHead, Verify, SealOnce and Head - and, in sync mode, every audited
-- mutation, i.e. the whole API. The row could not be deleted (append-only)
-- nor updated (the sealing branch requires OLD.hash IS NULL), so there was
-- no repair short of a DBA disabling the trigger.
--
-- Legal for both write modes: async inserts both NULL, sync inserts both
-- set, sealing transitions NULL -> value for both together.
ALTER TABLE audit ADD CONSTRAINT audit_seal_consistent
    CHECK ((hash IS NULL) = (chain_seq IS NULL));

-- (2) The constraint above stops the NULL variant; a bogus NON-NULL
-- chain_seq (say 10^9) instead makes Verify report a permanent, unrepairable
-- "chain_seq gap". A sealed row may only be inserted at the dense head.
-- Only sync-mode appends insert a sealed row, and they hold
-- pg_advisory_xact_lock(0x53554E44) while doing so, so max(chain_seq)+1 is
-- exactly the value they compute. The subquery is an index-only backward
-- scan of audit_chain_seq_uq.
CREATE FUNCTION audit_sealed_insert_at_head() RETURNS trigger AS $$
DECLARE
    expected BIGINT;
BEGIN
    SELECT COALESCE(max(chain_seq), 0) + 1 INTO expected FROM audit;
    IF NEW.chain_seq <> expected THEN
        RAISE EXCEPTION 'a sealed audit row may only be inserted at the chain head (expected chain_seq %, got %)',
            expected, NEW.chain_seq;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER audit_sealed_insert_head BEFORE INSERT ON audit
    FOR EACH ROW WHEN (NEW.chain_seq IS NOT NULL)
    EXECUTE FUNCTION audit_sealed_insert_at_head();

-- (3) AUDIT-CHAIN-2. The read-bucket closer skips any hour that already has
-- a chained `audit.reads_hourly` row, to avoid summarizing an hour twice.
-- That existence check reads a table the API role can INSERT into, and the
-- filter is byte-compatible with what the closer writes - so one forged
-- marker kept a real hour's read buckets OPEN forever (outside the chain,
-- and open buckets are the one place THREAT-MODEL concedes counts can be
-- inflated), while VerifyReadBuckets reported that hour BROKEN forever.
--
-- Making the index UNIQUE refuses the second row for an hour outright: the
-- closer's own AppendTx for an hour that already has a marker now fails
-- loudly instead of the hour being abandoned silently. 0033 created this
-- index non-unique; recreate it.
DROP INDEX IF EXISTS audit_reads_hourly_idx;
CREATE UNIQUE INDEX audit_reads_hourly_idx ON audit (((detail::jsonb)->>'hour'))
    WHERE action = 'audit.reads_hourly';
