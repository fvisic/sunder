-- CONCURRENCY-CORE-4: KeyRing.Invalidate() nils ONE process's map, while the
-- authoritative change (keys.status, plus Retire's destructive DELETE on
-- person_tokens) happens in shared Postgres. Every other replica kept serving
-- its cached snapshot for up to keyRingTTL (30s), stamping new person_tokens
-- rows with a key_version that had already been retired and purged - rows the
-- one-shot DELETE could not have covered because they did not exist yet, and
-- that no later probe ever computes again. The person written in that window
-- becomes permanently unfindable, and a re-registration of the same address
-- mints a SECOND person for one identifier.
--
-- Two changes, one narrowing the window and one closing it.

-- (1) A cheap cross-process epoch. Every replica compares (count, max) before
-- serving a cached ring, so a rotation or retirement anywhere converges the
-- fleet in about a second instead of thirty.
ALTER TABLE keys ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

-- (2) The grace period that makes retirement safe BY CONSTRUCTION rather than
-- by timing. A version may not be retired until every replica has certainly
-- observed the rotation that demoted it, so nothing can still be writing rows
-- under it when the purge runs.
ALTER TABLE keys ADD COLUMN retiring_since TIMESTAMPTZ;
UPDATE keys SET retiring_since = now() WHERE status = 'RETIRING';
