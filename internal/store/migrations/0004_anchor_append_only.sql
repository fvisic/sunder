-- audit_anchor gets the same append-only protection as audit: anchors are
-- evidence, and silently deleting or rewriting them is exactly what a
-- privileged attacker rewriting history would do next.
CREATE TRIGGER audit_anchor_no_update BEFORE UPDATE OR DELETE ON audit_anchor
    FOR EACH ROW EXECUTE FUNCTION audit_append_only();
CREATE TRIGGER audit_anchor_no_truncate BEFORE TRUNCATE ON audit_anchor
    FOR EACH STATEMENT EXECUTE FUNCTION audit_append_only();
