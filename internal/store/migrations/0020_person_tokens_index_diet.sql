-- Scale test at 26.8M contacts (53.6M token rows): person_tokens carried
-- 6.9 GB of heap under 23 GB of indexes - 452 bytes of index per 135-byte
-- row. Two of the four indexes bought nothing, and `EXPLAIN` on that
-- dataset proved it rather than suggesting it (Phase 4 / P4.3 in PLAN.md).
--
-- person_tokens_person_idx (person_id, kind) is a strict prefix of the
-- primary key (person_id, kind, token). The planner already preferred the
-- PK with the index present, and produced a byte-identical plan with it
-- dropped. It was 2712 MB of index that nothing read.
DROP INDEX IF EXISTS person_tokens_person_idx;

-- person_tokens_lookup_idx (kind, token) duplicated
-- person_tokens_ident_uq UNIQUE (kind, token) WHERE kind IN ('email','phone')
-- for every email and phone row - the whole hot path. It only won the plan
-- because a non-partial index beats a partial one on tie-break. With it
-- gone, email and phone lookups fall through to ident_uq with the same
-- Index Scan shape, on an index the dedup invariant already pays for.
--
-- Names are the exception and the reason this is a replacement rather than
-- a deletion: ident_uq deliberately excludes kind='name' (names are shared
-- by many people and only ever narrow), so without a name index the name
-- path collapses to a scan of every name row with the token as a filter.
DROP INDEX IF EXISTS person_tokens_lookup_idx;
-- IF NOT EXISTS mirrors the IF EXISTS drops above: this migration was
-- validated by applying it out-of-band during the 26.8M scale test, and a
-- database in that state must converge, not fail.
CREATE INDEX IF NOT EXISTS person_tokens_name_idx ON person_tokens (kind, token)
    WHERE kind = 'name';
