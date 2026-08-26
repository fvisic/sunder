-- Phase 3, F7: sub-accounts as person links.
--
-- A link relates two persons within one scope's view (guardian-minor,
-- account-member, owner-device). Both endpoints are cids the linking
-- client can already resolve, so a link never crosses a scope boundary.
-- The link is metadata about a relationship, not a merge: each person
-- keeps its own blob, consents, audit and erasure lifecycle.
--
-- Erasure lists linked persons in the report but NEVER cascades on its
-- own: deleting a child's data because the parent was erased is exactly
-- the accident this design refuses to make silent. A cascade is an
-- explicit per-request opt-in.
CREATE TABLE person_links (
    parent_person UUID NOT NULL REFERENCES persons(id),
    child_person  UUID NOT NULL REFERENCES persons(id),
    scope         TEXT NOT NULL,
    link_type     TEXT NOT NULL, -- guardian | member | owner
    created_by    TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (parent_person, child_person, scope),
    CHECK (parent_person <> child_person)
);
CREATE INDEX person_links_child_idx ON person_links (child_person, scope);
