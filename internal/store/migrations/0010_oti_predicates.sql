-- P2.3 selective disclosure: issuer-authorized predicate claims evaluated
-- at verification against the ISSUER's blob. The verifier learns booleans
-- ("age_gte 18: true"), never the underlying value.
ALTER TABLE oti ADD COLUMN share_predicates JSONB NOT NULL DEFAULT '[]';
