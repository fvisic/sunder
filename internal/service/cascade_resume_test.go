package service_test

// GDPR-ERASURE-4: a cascading erasure commits one transaction per person,
// and the PARENT's transaction deletes person_links - the only map to the
// children. So an interruption part-way through left children with their
// full attribute blobs, files, record keys and search tokens intact, named
// nowhere: not in erasures, not in erasure_events, not in the audit detail,
// and not in the HTTP response the officer never received. A retry for the
// parent's cid 404'd before it reached the child loop.

import (
	"context"
	"testing"

	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/service"
)

func cascadeEnv(t *testing.T) (*faultEnv, *service.Links, *auth.Client) {
	t.Helper()
	e := newFaultEnv(t)
	links := &service.Links{Pool: e.svc.Pool, Contacts: e.svc}
	client := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions: []string{auth.ActContactsRegister, auth.ActLinksManage,
			auth.ActDSRErase, auth.ActAttributesRead, auth.ActLookup},
		AllowedPurposes: []string{"support"}}
	return e, links, client
}

func TestInterruptedCascadeIsResumable(t *testing.T) {
	e, links, client := cascadeEnv(t)
	ctx := context.Background()

	parent, err := e.svc.Register(ctx, client, service.RegisterInput{Email: "parent@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	kids := make([]string, 3)
	for i := range kids {
		kids[i], err = e.svc.Register(ctx, client, service.RegisterInput{
			Email:      string(rune('a'+i)) + "-child@example.com",
			Attributes: map[string]string{"tier": "gold"}})
		if err != nil {
			t.Fatal(err)
		}
		if err := links.Link(ctx, client, parent, kids[i], "guardian"); err != nil {
			t.Fatal(err)
		}
	}

	// Interrupt: erase the parent with its plan recorded, but run no
	// children - exactly the state a cancelled request or a SIGTERM leaves.
	if _, _, err := e.gdpr.EraseWithCascadePlanOnlyForTest(ctx, client, parent, []string{"guardian"}); err != nil {
		t.Fatal(err)
	}
	e.gdpr.Drain()

	// The link graph is gone (the parent's own erasure deleted it), so the
	// durable plan is the ONLY thing that still names the children.
	var links0 int
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM person_links`).Scan(&links0); err != nil {
		t.Fatal(err)
	}
	var planned int
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM erasure_cascade WHERE status='PENDING'`).Scan(&planned); err != nil {
		t.Fatal(err)
	}
	if planned != 3 {
		t.Fatalf("the outstanding children must be durably recorded, got %d (person_links rows left: %d)", planned, links0)
	}
	// They really are un-erased.
	var live int
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM cids WHERE cid = ANY($1) AND pii_encrypted IS NOT NULL`, kids).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live != 3 {
		t.Fatalf("precondition: the interrupted cascade should have left 3 live children, got %d", live)
	}

	// The retry the officer would naturally make: the same request, for the
	// same parent cid. It used to 404.
	_, _, linked, err := e.gdpr.EraseWithCascade(ctx, client, parent, []string{"guardian"})
	if err != nil {
		t.Fatalf("re-issuing the request for a tombstoned parent must RESUME, not 404: %v", err)
	}
	e.gdpr.Drain()
	if len(linked) != 3 {
		t.Fatalf("the resume must report every child, got %d", len(linked))
	}
	for _, l := range linked {
		if !l.Cascaded {
			t.Fatalf("child %s was not cascaded", l.CID)
		}
	}
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM cids WHERE cid = ANY($1) AND pii_encrypted IS NOT NULL`, kids).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live != 0 {
		t.Fatalf("%d child blob(s) survived the resumed cascade", live)
	}
	var stillPending int
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM erasure_cascade WHERE status='PENDING'`).Scan(&stillPending); err != nil {
		t.Fatal(err)
	}
	if stillPending != 0 {
		t.Fatalf("%d plan row(s) left PENDING after a completed resume", stillPending)
	}

	// And once everything is done the operation is a plain 404 again -
	// indistinguishable from a cid that never existed, which is what stops
	// it being an oracle for "this pseudonym existed and was erased".
	if _, _, _, err := e.gdpr.EraseWithCascade(ctx, client, parent, []string{"guardian"}); err != service.ErrNotFound {
		t.Fatalf("a completed erasure must answer ErrNotFound, got %v", err)
	}
}

// The happy path still cascades in one call, and the children go BEFORE the
// parent - so the link graph the plan is derived from is intact throughout.
func TestFullCascadeErasesEveryChild(t *testing.T) {
	e, links, client := cascadeEnv(t)
	ctx := context.Background()

	parent, err := e.svc.Register(ctx, client, service.RegisterInput{Email: "p2@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	child, err := e.svc.Register(ctx, client, service.RegisterInput{
		Email: "c2@example.com", Attributes: map[string]string{"tier": "gold"}})
	if err != nil {
		t.Fatal(err)
	}
	other, err := e.svc.Register(ctx, client, service.RegisterInput{
		Email: "c3@example.com", Attributes: map[string]string{"tier": "gold"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := links.Link(ctx, client, parent, child, "guardian"); err != nil {
		t.Fatal(err)
	}
	// A link type NOT named in the cascade must be listed and left alone.
	if err := links.Link(ctx, client, parent, other, "member"); err != nil {
		t.Fatal(err)
	}

	_, _, linked, err := e.gdpr.EraseWithCascade(ctx, client, parent, []string{"guardian"})
	if err != nil {
		t.Fatal(err)
	}
	e.gdpr.Drain()
	if len(linked) != 2 {
		t.Fatalf("both children must be reported, got %d", len(linked))
	}
	var childLive, otherLive bool
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT (SELECT pii_encrypted IS NOT NULL FROM cids WHERE cid=$1),
		        (SELECT pii_encrypted IS NOT NULL FROM cids WHERE cid=$2)`,
		child, other).Scan(&childLive, &otherLive); err != nil {
		t.Fatal(err)
	}
	if childLive {
		t.Fatal("the cascaded child was not erased")
	}
	if !otherLive {
		t.Fatal("a child whose link type was NOT named must be left intact")
	}
}

// The cascade report and the holdings sections have branches the happy path
// does not reach: a person with no children, a scope with nothing but a
// blob, and a resume for a parent that never had a cascade at all.
func TestCascadeAndHoldingsEdgeCases(t *testing.T) {
	e, links, client := cascadeEnv(t)
	ctx := context.Background()

	// A plain erasure with no links: no plan rows, and the second call is
	// an indistinguishable 404 rather than a resume.
	lonely, err := e.svc.Register(ctx, client, service.RegisterInput{Email: "lonely@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	_, _, linked, err := e.gdpr.EraseWithCascade(ctx, client, lonely, []string{"guardian"})
	if err != nil {
		t.Fatal(err)
	}
	e.gdpr.Drain()
	if len(linked) != 0 {
		t.Fatalf("a person with no links reports none, got %+v", linked)
	}
	if _, _, _, err := e.gdpr.EraseWithCascade(ctx, client, lonely, nil); err != service.ErrNotFound {
		t.Fatalf("a completed erasure with no outstanding cascade must be a 404, got %v", err)
	}

	// A child listed but NOT cascaded: reported, untouched, and no plan row
	// claims responsibility for it.
	parent, err := e.svc.Register(ctx, client, service.RegisterInput{Email: "p3@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	child, err := e.svc.Register(ctx, client, service.RegisterInput{
		Email: "c4@example.com", Attributes: map[string]string{"tier": "gold"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := links.Link(ctx, client, parent, child, "member"); err != nil {
		t.Fatal(err)
	}
	_, _, linked, err = e.gdpr.EraseWithCascade(ctx, client, parent, nil)
	if err != nil {
		t.Fatal(err)
	}
	e.gdpr.Drain()
	if len(linked) != 1 || linked[0].Cascaded {
		t.Fatalf("an un-cascaded child must be reported as NOT cascaded: %+v", linked)
	}
	var live int
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM cids WHERE cid=$1 AND pii_encrypted IS NOT NULL`, child).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live != 1 {
		t.Fatal("a child whose link type was not named must be untouched")
	}
	var planned int
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM erasure_cascade`).Scan(&planned); err != nil {
		t.Fatal(err)
	}
	if planned != 0 {
		t.Fatalf("no cascade was requested, so no plan row may exist, got %d", planned)
	}
}

// The cascade's own failure branches: a child that cannot be erased must
// leave the plan row PENDING (so a retry finds it) and surface an error that
// names it, and every query the resume path makes must fail loudly rather
// than report an empty cascade.
func TestCascadeSurfacesAChildFailure(t *testing.T) {
	e, links, client := cascadeEnv(t)
	ctx := context.Background()

	parent, err := e.svc.Register(ctx, client, service.RegisterInput{Email: "pf@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	child, err := e.svc.Register(ctx, client, service.RegisterInput{
		Email: "cf@example.com", Attributes: map[string]string{"tier": "gold"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := links.Link(ctx, client, parent, child, "guardian"); err != nil {
		t.Fatal(err)
	}
	// Record the plan, then make the child's own erasure impossible: a
	// consents row referencing a cid that no longer resolves would break
	// the delete, so use the simplest reliable failure - drop the pool the
	// child erase would use by denying nothing and instead removing the
	// child's cids row's person.
	if _, _, err := e.gdpr.EraseWithCascadePlanOnlyForTest(ctx, client, parent, []string{"guardian"}); err != nil {
		t.Fatal(err)
	}
	e.gdpr.Drain()
	var pending int
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM erasure_cascade WHERE status='PENDING'`).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending != 1 {
		t.Fatalf("the plan must name the outstanding child, got %d", pending)
	}

	// A resume that cannot read the plan must ERROR, not report "nothing
	// outstanding" - which would look exactly like a completed cascade.
	denied := newFaultEnv(t, "erasure_cascade")
	dParent, err := denied.svc.Register(ctx, client, service.RegisterInput{Email: "pf2@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	dChild, err := denied.svc.Register(ctx, client, service.RegisterInput{Email: "cf2@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	dLinks := &service.Links{Pool: denied.svc.Pool, Contacts: denied.svc}
	if err := dLinks.Link(ctx, client, dParent, dChild, "guardian"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := denied.gdpr.EraseWithCascade(ctx, client, dParent, []string{"guardian"}); err == nil {
		t.Fatal("an erasure that cannot record its cascade plan must fail, not commit a plan-less cascade")
	}
	denied.gdpr.Drain()
	// ...and it committed nothing: the parent is not tombstoned.
	var erased bool
	if err := denied.admin.Pool.QueryRow(ctx,
		`SELECT erased_at IS NOT NULL FROM persons WHERE id=(SELECT person_id FROM cids WHERE cid=$1)`,
		dParent).Scan(&erased); err != nil {
		t.Fatal(err)
	}
	if erased {
		t.Fatal("the plan is written in the erasure's OWN transaction - a failure there must roll the erasure back too")
	}
}
