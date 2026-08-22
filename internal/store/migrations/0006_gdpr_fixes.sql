-- Fixes from the v1.5 GDPR review.

-- Retention must track activity, not creation: a contact re-registered
-- yesterday is not "400 days old" even if first seen 400 days ago.
ALTER TABLE cids ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

-- Erasure delivery gets a terminal failure state so one dead endpoint
-- cannot starve the queue forever.
-- (No schema change needed for status values; documented here:
--  PENDING -> DELIVERED | NO_WEBHOOK | FAILED after 10 attempts.)
