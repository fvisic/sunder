-- H1: erasure_events had no lease and no reaper, so SENDING was an absorbing
-- state. The claim commits before the POST (correct - it is what stops two
-- replicas double-sending), but nothing ever returned an abandoned claim to
-- the queue: the claim SELECT filters status='PENDING', so a row stranded by
-- a shutdown, a cancelled request context or a settle failure was invisible
-- to every later sweep on every replica, forever. portal_outbox got this
-- treatment in 0017/0018; the sibling queue was explicitly recorded there as
-- needing no change. It did.
ALTER TABLE erasure_events ADD COLUMN claimed_at TIMESTAMPTZ;

-- Reaping keys off claim age, so the index is on claimed_at over the claimed
-- rows only.
CREATE INDEX erasure_events_sending_idx ON erasure_events (claimed_at) WHERE status = 'SENDING';

-- The status column was unconstrained TEXT (0005). Naming the states makes a
-- typo in a future writer a constraint violation instead of a row that no
-- sweep and no reaper will ever match again.
ALTER TABLE erasure_events ADD CONSTRAINT erasure_events_status_check
    CHECK (status IN ('PENDING', 'SENDING', 'DELIVERED', 'FAILED', 'NO_WEBHOOK'));

-- portal_outbox.claimed_at (0018) was never written - its reaper keyed off
-- created_at, so an aged row was reap-eligible the instant it was claimed and
-- could be handed to a second worker while the first was still sending
-- (QUEUE-WORKER-2). Backfill the existing claims so the corrected reaper does
-- not treat them as never-claimed.
UPDATE portal_outbox SET claimed_at = created_at WHERE status = 'SENDING' AND claimed_at IS NULL;
CREATE INDEX portal_outbox_sending_idx ON portal_outbox (claimed_at) WHERE status = 'SENDING';
