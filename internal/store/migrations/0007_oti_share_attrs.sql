-- OTI attribute sharing: the ISSUER lists which of its attributes the
-- verifier receives (copied into the verifier-scope blob at verification).
-- Default empty: a handoff shares nothing unless explicitly stated.
ALTER TABLE oti ADD COLUMN share_attrs TEXT[] NOT NULL DEFAULT '{}';
