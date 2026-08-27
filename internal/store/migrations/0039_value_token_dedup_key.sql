-- CRYPTO-3 / TOKENS-LOOKUP-4. value_tokens.unique_hash - the index that
-- makes `unique:true` mean "tokenizing the same IBAN twice returns the same
-- token instead of breeding aliases" - was keyed by the NEWEST hmac-email
-- version, with no record of which version produced it, no rekey pass and no
-- purge. Two consequences:
--
--   (a) any `keys rotate -kind hmac-email` silently and permanently broke
--       dedup: the next tokenize of the same value hashed under v2, missed
--       every lookup against the v1 hash, and INSERTed a second live token
--       and a second ciphertext for one value.
--   (b) leaking the e-mail SEARCH key handed an attacker an offline
--       dictionary attack over every tokenized card number, IBAN and
--       national id - the exact cross-attribute exposure the
--       separate-key-per-attribute design exists to prevent - and the
--       documented cure (rotate, rekey, retire) did not close it.
--
-- Value tokens get their own key kind, and the row records which version
-- keyed it so matching can span the rotation window and the sweep can
-- converge the backlog.
INSERT INTO keys (key_id, kind, status) VALUES ('hmac-value/v1', 'hmac-value', 'ACTIVE')
    ON CONFLICT (key_id) DO NOTHING;

-- NULL means "keyed by the legacy hmac-email derivation". Those rows keep
-- matching (the dedup probe computes candidates under both derivations)
-- until `keys rekey` re-hashes them.
ALTER TABLE value_tokens ADD COLUMN unique_key_version TEXT;
