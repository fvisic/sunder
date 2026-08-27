-- AUTHZ-2: `admin.unlock` on a credential with no expiry turns the strict
-- search posture and the bulk-read second factor into "always allowed with
-- an extra step", forever. auth.ValidateUnlockGrant refuses it at issuance -
-- but only on the paths that call it, and CreateTx (the one `sunder
-- bootstrap` uses, i.e. every deployment's default provisioning) did not.
--
-- NOT VALID deliberately: the constraint governs every future INSERT and
-- UPDATE, and pre-existing rows are left for the operator to fix (serve logs
-- a startup warning naming them). Validating here would refuse to migrate an
-- installed base that the bug itself created.
ALTER TABLE clients ADD CONSTRAINT clients_unlock_needs_expiry
    CHECK (NOT ('admin.unlock' = ANY (allowed_actions)) OR credential_expires_at IS NOT NULL)
    NOT VALID;
