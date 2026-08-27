-- CRYPTO-4 and CRYPTO-5: two AEAD bindings that a database-write attacker
-- could sidestep because the associated data did not name what the row is
-- FOR. Both get an AAD version column so pre-existing ciphertext keeps
-- opening under the layout it was sealed with, and `keys rekey
-- -reencrypt-pii` converts the backlog.

-- CRYPTO-4. value_tokens.cid became load-bearing for Article 17 in migration
-- 0032 ("a token minted with a cid is bound to that person and is DELETED by
-- their erasure"), but it was unauthenticated plaintext metadata: the AAD was
-- valtok\0scope\0token and no read path checked the column. One
-- `UPDATE value_tokens SET cid=NULL` made the row invisible to the erasure
-- sweep while the ciphertext still opened, so a completed, audited erasure
-- left the person's IBAN readable through the ordinary API.
--
-- aad_v=1: "valtok\0"   + scope + "\0" + token                (legacy)
-- aad_v=2: "valtok\x01" + scope + "\0" + token + "\0" + cid
ALTER TABLE value_tokens ADD COLUMN aad_v SMALLINT NOT NULL DEFAULT 1;

-- The cheap half of the same defence, independent of the AAD: a cid that
-- does not name a real pseudonym is refused outright.
ALTER TABLE value_tokens ADD CONSTRAINT value_tokens_cid_fk
    FOREIGN KEY (cid) REFERENCES cids(cid) NOT VALID;

-- CRYPTO-5. A version snapshot was the live blob copied byte for byte,
-- together with its own key_id/alg - so for a given cid every historical
-- generation and the current row were AEAD-INTERCHANGEABLE. Writing an old
-- cid_blob_versions.blob (plus its key_id/alg) over cids.pii_encrypted
-- decrypts perfectly, silently rolling an Article 16 rectification back with
-- no cryptographic trace.
--
-- aad_v=1: bound to the cid alone            (legacy, interchangeable)
-- aad_v=2: bound to cid + "\0v" + version_no (a generation cannot be
--          transplanted into the live row, nor into another generation)
ALTER TABLE cid_blob_versions ADD COLUMN aad_v SMALLINT NOT NULL DEFAULT 1;
