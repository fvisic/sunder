-- N2/N15: the portal mailer becomes an OUTBOX. Start enqueues and returns
-- immediately, so a known and an unknown address cost the same observable
-- work (no enumeration oracle), and a background worker records what was
-- ACTUALLY delivered instead of asserting success up front.
CREATE TABLE portal_outbox (
    id         BIGSERIAL PRIMARY KEY,
    kind       TEXT NOT NULL CHECK (kind IN ('login', 'erase_confirm')),
    email      TEXT NOT NULL,
    token      TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    status     TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'DELIVERED', 'FAILED', 'NO_MAILER')),
    attempts   INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX portal_outbox_pending ON portal_outbox (status, id) WHERE status = 'PENDING';

-- Per-address login throttle (N9): one IP must not be able to mail-bomb a
-- chosen victim, and the limit must survive replica restarts.
CREATE TABLE portal_email_throttle (
    email_token BYTEA PRIMARY KEY,  -- SHA-256 of the normalized address
    window_start TIMESTAMPTZ NOT NULL,
    sends        INT NOT NULL
);
