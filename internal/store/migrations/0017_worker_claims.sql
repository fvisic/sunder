-- P3: both delivery workers now CLAIM their batch (FOR UPDATE SKIP LOCKED
-- plus a SENDING state), so concurrent replicas cannot both deliver the
-- same row. A crash mid-send leaves rows in SENDING; the reaper below
-- returns them to PENDING after a grace period.
ALTER TABLE portal_outbox DROP CONSTRAINT portal_outbox_status_check;
ALTER TABLE portal_outbox ADD CONSTRAINT portal_outbox_status_check
    CHECK (status IN ('PENDING', 'SENDING', 'DELIVERED', 'FAILED', 'NO_MAILER'));

-- erasure_events.status is an unconstrained TEXT column (see 0005), so it
-- needs no change; SENDING is simply another value it already accepts.
