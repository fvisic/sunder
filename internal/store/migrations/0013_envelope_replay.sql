-- Review finding (P2.4): consumed external envelopes - one jti, one use.
-- Replaying the same signed envelope to a second CID (or the same one)
-- must fail on this primary key.
CREATE TABLE external_envelopes (
    jti        TEXT PRIMARY KEY CHECK (char_length(jti) BETWEEN 8 AND 128),
    issuer_id  TEXT NOT NULL,
    used_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
