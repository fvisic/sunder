-- P4.1: decouple audit chaining from the request path.
--
-- A 26.8M-contact scale test showed every audited operation serializing on
-- the instance-wide advisory lock in audit.AppendTx: 298 tps at c=32 with
-- the lock, 4,114 without, on identical hardware and durability settings
-- (benchmark/README.md). Rows may now be INSERTed unsealed (hash IS NULL)
-- and a single sealer fills prev_hash/hash later, batched under one lock.
--
-- chain_seq, not seq, is the chain position. BIGSERIAL does not guarantee
-- commit order: a transaction can commit after a later seq has been sealed,
-- which under seq-ordering would strand it below the watermark forever.
-- The sealer assigns a dense chain_seq at sealing time instead, so a seq
-- hole burned by a rollback simply never enters the chain. chain_seq is
-- not part of the hashed content - integrity comes from prev_hash linkage,
-- which Verify walks in chain_seq order; a permuted chain_seq therefore
-- cannot pass verification, and the UNIQUE index below makes a fork
-- impossible even if sealer logic were wrong.

ALTER TABLE audit ALTER COLUMN hash DROP NOT NULL;
ALTER TABLE audit ADD COLUMN chain_seq BIGINT;

-- Backfill: every existing row was sealed synchronously in seq order, so
-- seq order IS its chain order. The append-only trigger would refuse this
-- UPDATE (the rows are already sealed); disabling it inside the migration
-- transaction is safe because the whole migration commits or rolls back
-- atomically and the advisory migration lock keeps this exclusive.
ALTER TABLE audit DISABLE TRIGGER audit_no_update;
UPDATE audit a
   SET chain_seq = r.rn
  FROM (SELECT seq, row_number() OVER (ORDER BY seq) AS rn
          FROM audit WHERE hash IS NOT NULL) r
 WHERE a.seq = r.seq;
ALTER TABLE audit ENABLE TRIGGER audit_no_update;

CREATE UNIQUE INDEX audit_chain_seq_uq ON audit (chain_seq);
-- The sealer's work queue: only unsealed rows, walked in seq order.
CREATE INDEX audit_unsealed_idx ON audit (seq) WHERE hash IS NULL;

-- The append-only trigger now allows exactly one transition: sealing an
-- unsealed row (NULL -> value on prev_hash/hash/chain_seq) with every
-- hashed column bit-identical. Anything else - re-sealing, edits to
-- content, edits alongside sealing, DELETE, TRUNCATE - is still refused.
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
       AND NEW.detail IS NOT DISTINCT FROM OLD.detail THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'audit log is append-only (only sealing an unsealed row is allowed)';
END;
$$ LANGUAGE plpgsql;
