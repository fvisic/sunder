-- Phase 3, F1/F2: derived search tokens.
--
-- name_phonetic carries the keyed HMAC of a ph1 phonetic word code (fuzzy
-- name narrowing: Anić/Anic/Djurdjevic-style variants fold together);
-- phone_suffix carries the keyed HMAC of a number's last eight digits
-- (partial lookup that answers ONLY when it narrows to exactly one
-- person - a multi-hit is a miss, so it cannot enumerate). Both are
-- domain-separated from their parent kinds at the tokenizer, minted only
-- when SUNDER_SEARCH_FUZZY_NAME / SUNDER_SEARCH_PHONE_SUFFIX are on, and
-- backfilled for existing contacts by `sunder keys rekey`.
-- IF EXISTS / IF NOT EXISTS throughout, like 0020: at scale the index build
-- below wants to run out of band (the runner applies all pending migrations
-- in ONE transaction, so CONCURRENTLY is not available here), and a database
-- prepared that way must converge on the next boot, not hard-fail it. Note
-- the limit of that convergence: the DROP+ADD CONSTRAINT pair re-runs its
-- validating scan on the boot regardless of pre-application - only the
-- index build is actually skipped.
ALTER TABLE person_tokens DROP CONSTRAINT IF EXISTS person_tokens_kind_check;
ALTER TABLE person_tokens ADD CONSTRAINT person_tokens_kind_check
    CHECK (kind IN ('email','phone','name','name_phonetic','phone_suffix'));

-- One partial index serves every non-unique search kind. Deliberately NOT
-- unique: names, phonetic codes and suffixes are all legitimately shared
-- by many people - only email and phone identify exactly one person
-- (person_tokens_ident_uq, untouched). NOTE: the predicate includes
-- kind='name', which is written for EVERY named contact - the index is
-- populated even with the derived-search features off; only the
-- name_phonetic and phone_suffix entries wait on their switches.
DROP INDEX IF EXISTS person_tokens_name_idx;
CREATE INDEX IF NOT EXISTS person_tokens_search_idx ON person_tokens (kind, token)
    WHERE kind IN ('name','name_phonetic','phone_suffix');
