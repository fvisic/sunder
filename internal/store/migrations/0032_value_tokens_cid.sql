-- S4 fix: F4 value tokens carried no link back to a subject, so erasure
-- could not reach them - a tokenized national id, IBAN or card for an erased
-- person stayed sealed-but-decryptable indefinitely (the value_tokens table
-- appeared nowhere in erasePerson).
--
-- Add an optional cid the tokenize path sets when a value is minted on behalf
-- of a specific person; erasure then deletes that person's tokens. A token
-- minted with no cid (a scope-wide value not tied to one subject) stays
-- unattributed and is only reachable by its own expiry - documented, not a
-- silent gap.
--
-- The cid also refines `unique: true` dedup: dedup is now per (scope, cid,
-- unique_hash), so two different people tokenizing the same value each get
-- their own erasable token, while a caller that passes no cid keeps the old
-- scope-wide dedup. Existing rows have cid NULL.
ALTER TABLE value_tokens ADD COLUMN cid TEXT;
CREATE INDEX value_tokens_cid_idx ON value_tokens (cid) WHERE cid IS NOT NULL;

-- The old partial unique index was (scope, unique_hash); replace it with one
-- that also keys on cid so per-person dedup holds. COALESCE keeps NULL-cid
-- (unattributed) rows deduping scope-wide as before.
DROP INDEX value_tokens_unique_uq;
CREATE UNIQUE INDEX value_tokens_unique_uq ON value_tokens (scope, COALESCE(cid, ''), unique_hash)
    WHERE unique_hash IS NOT NULL;
