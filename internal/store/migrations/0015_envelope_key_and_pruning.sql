-- N17: jti uniqueness must be PER ISSUER. A global key let issuer A
-- permanently poison a sequential id for issuer B. Sequential jtis are the
-- norm, so this collides in practice, and it is only cheap to change now.
ALTER TABLE external_envelopes DROP CONSTRAINT external_envelopes_pkey;
ALTER TABLE external_envelopes ADD PRIMARY KEY (issuer_id, jti);

-- N16: the replay table must be prunable. Envelopes now carry a bounded
-- lifetime (maxEnvelopeLifetime in internal/service/external.go), so a row
-- is safe to delete once no envelope with that jti can still be valid.
-- expires_at records that horizon explicitly instead of inferring it.
-- Every insert writes expires_at explicitly from maxEnvelopeLifetime in
-- internal/service/external.go; this default only backfills the rows that
-- already existed, so the two cannot drift apart in practice.
ALTER TABLE external_envelopes
    ADD COLUMN expires_at TIMESTAMPTZ NOT NULL DEFAULT now() + interval '24 hours';

CREATE INDEX external_envelopes_expiry ON external_envelopes (expires_at);
