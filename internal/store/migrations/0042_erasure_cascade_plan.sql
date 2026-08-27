-- GDPR-ERASURE-4: a cascading erasure was neither atomic nor resumable, and
-- the parent's own transaction deleted the person_links rows that were the
-- ONLY map to the un-erased children. The child list lived in a Go slice on
-- a cancellable request goroutine; a client timeout, a SIGTERM or a pod
-- eviction between the parent's commit and the last child left children with
-- their full attribute blobs, files, record keys and search tokens intact -
-- and unrecoverable by any query, because a retry for the parent's cid hits
-- personForClientCID's tombstone check and 404s before it reaches the loop.
--
-- The plan is now durable and written in the SAME transaction that opens the
-- erasure, so it survives the link deletion, the crash and the retry.
CREATE TABLE erasure_cascade (
    erasure_id   BIGINT NOT NULL REFERENCES erasures(id),
    child_person UUID NOT NULL,
    child_cid    TEXT NOT NULL,
    link_type    TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'DONE')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    done_at      TIMESTAMPTZ,
    PRIMARY KEY (erasure_id, child_person)
);
CREATE INDEX erasure_cascade_pending_idx ON erasure_cascade (erasure_id) WHERE status = 'PENDING';
