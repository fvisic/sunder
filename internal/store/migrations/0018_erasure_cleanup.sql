-- P10: an envelope row must be deletable when its subject is erased, so it
-- carries the CID it was accepted for. Without it, an issuer-chosen jti
-- (which may reference the subject) outlived an Article 17 erasure by up to
-- the envelope lifetime plus a cron interval.
ALTER TABLE external_envelopes ADD COLUMN cid TEXT;
CREATE INDEX external_envelopes_cid ON external_envelopes (cid);

-- P4: a stalled batch must be recoverable. A row claimed by a worker that
-- died stays SENDING; the reaper in `retention run` returns it to PENDING.
ALTER TABLE portal_outbox ADD COLUMN claimed_at TIMESTAMPTZ;
