-- P2.2 short-lived credentials: NULL keeps today's non-expiring behaviour;
-- a set timestamp makes Authenticate reject the credential after it (401
-- credential_expired). Rotate with `sunder client rotate-secret`.
ALTER TABLE clients ADD COLUMN credential_expires_at TIMESTAMPTZ;
