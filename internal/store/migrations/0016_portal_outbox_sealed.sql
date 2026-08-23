-- Review probe C: the outbox stored the LIVE login token and the plaintext
-- e-mail. A database reader could redeem it and log in as anyone, and the
-- throttle table indexed sha256(plaintext email) - a bare, dictionary-
-- attackable hash, which this project forbids everywhere else.
--
-- The payload is now sealed with the PII KEK through the crypto engine, so
-- a database reader without key access gets nothing, and the throttle key
-- is a keyed HMAC search token like every other identifier index.
DELETE FROM portal_outbox;      -- pending rows carry the old plaintext shape
DELETE FROM portal_email_throttle;

ALTER TABLE portal_outbox DROP COLUMN email;
ALTER TABLE portal_outbox DROP COLUMN token;
ALTER TABLE portal_outbox ADD COLUMN payload BYTEA NOT NULL;
ALTER TABLE portal_outbox ADD COLUMN key_id TEXT NOT NULL;
ALTER TABLE portal_outbox ADD COLUMN alg TEXT NOT NULL DEFAULT 'aes256gcm';
