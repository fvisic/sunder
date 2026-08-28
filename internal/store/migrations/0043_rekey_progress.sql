-- The rekey sweep restarted from the first person every time.
--
-- `lastID` lived in a local variable, so an interrupted sweep - a finished
-- maintenance window, a SIGTERM, a database too loaded to continue - paid
-- for all of its previous progress again on the next run. Measured on the
-- 26.9M-contact dataset mid-backfill: 4.1M persons already processed cost
-- 2.7 HOURS of doing nothing but re-reading them before the sweep reached
-- any outstanding work, and that number grows as the backfill advances.
--
-- The scope column is what makes resuming safe. A resume point is only valid
-- for the exact work the interrupted sweep was doing: the same newest key
-- version per kind, the same KEK, the same reencrypt-pii choice, and the
-- same derived-search flags. Rotate a key, flip SUNDER_SEARCH_FUZZY_NAME, or
-- rerun with -reencrypt-pii after a run without it, and the outstanding set
-- now includes persons BEFORE the resume point - so the scope no longer
-- matches and the sweep correctly starts from the beginning.
--
-- Single row by construction: the sweep is not safe to run concurrently with
-- itself (two sweeps would interleave their pages and each record the
-- other's position), and a one-row table makes that structural rather than a
-- convention in a comment.
CREATE TABLE rekey_progress (
    id             BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    scope          TEXT NOT NULL,
    last_person_id UUID NOT NULL,
    persons_done   BIGINT NOT NULL DEFAULT 0,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE rekey_progress IS
    'Resume point for `sunder keys rekey`. One row. `scope` fingerprints the '
    'work being done; a resume is only valid when it still matches.';
COMMENT ON COLUMN rekey_progress.scope IS
    'Fingerprint of the sweep''s parameters: newest version per key kind, the '
    'KEK, reencrypt-pii, and the derived-search flags. A mismatch means the '
    'outstanding set changed and the sweep must restart from the first person.';
