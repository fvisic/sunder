-- Review (low): `issuer remove` was a hard DELETE and `issuer add` a plain
-- INSERT, so key rotation was remove-then-add. Stored attributes keep
-- `<claim>@<issuer_id>` forever, so after a re-add every previously stored
-- claim silently read as attested by the NEW key holder.
--
-- Issuers are now retired rather than deleted: the row stays as history,
-- stops being usable for verification, and a re-add under the same id is
-- refused - a new key needs a new id, which keeps provenance truthful.
ALTER TABLE trusted_issuers ADD COLUMN revoked_at TIMESTAMPTZ;
