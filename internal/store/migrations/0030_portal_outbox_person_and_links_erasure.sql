-- Erasure-invariant fixes (Phase 3 follow-up).
--
-- portal_outbox carried no link back to the person, so erasure could not
-- delete a queued login / erase-confirm mail for the erased person (the old
-- cleanup query was uncorrelated and ran after the tokens it tried to match
-- were already gone - it deleted nothing). Add the person_id the enqueue
-- path now sets, so erasure can scope the delete. Existing rows are NULL and
-- age out via the pending index / retention.
ALTER TABLE portal_outbox ADD COLUMN person_id UUID REFERENCES persons(id);
CREATE INDEX portal_outbox_person_idx ON portal_outbox (person_id) WHERE person_id IS NOT NULL;
