-- P2.5 self-service privacy portal: one-time login/confirmation tokens and
-- short-lived sessions. Only hashes are stored - a database leak yields
-- nothing usable.
CREATE TABLE portal_tokens (
    token_hash BYTEA PRIMARY KEY,
    person_id  UUID NOT NULL REFERENCES persons(id),
    kind       TEXT NOT NULL CHECK (kind IN ('login', 'erase')),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE portal_sessions (
    session_hash BYTEA PRIMARY KEY,
    person_id    UUID NOT NULL REFERENCES persons(id),
    expires_at   TIMESTAMPTZ NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The portal mailer is a reserved-scope webhook ('_portal'): the org's own
-- sender receives signed {event: portal_login, email, token} payloads and
-- turns them into e-mails. Sunder itself sends no mail.
