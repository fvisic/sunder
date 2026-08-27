-- AUDIT-CHAIN-4: two audit_anchor rows for one root necessarily share one
-- export filename while their TSA tokens differ (distinct serial, distinct
-- genTime), so VerifyAnchors reported one of them as "file: MISMATCH with
-- database" forever - and audit_anchor is append-only, so the row could never
-- be removed. Anchor() now refuses to re-stamp an unchanged head; this makes
-- the invariant the database's, so no future caller can reintroduce it.
--
-- Deployments that already contain duplicates keep them (a NOT VALID
-- constraint cannot be expressed for an index): create it only if the data
-- allows, and say so if it does not.
DO $$
BEGIN
    CREATE UNIQUE INDEX audit_anchor_root_uq ON audit_anchor (root_hash);
EXCEPTION WHEN unique_violation THEN
    RAISE WARNING 'audit_anchor holds duplicate root_hash rows from before AUDIT-CHAIN-4; the uniqueness index was NOT created. `sunder verify-audit` will keep reporting a file mismatch for the duplicates - the rows are append-only and cannot be removed. New anchors are refused for an already-anchored head regardless.';
END $$;
