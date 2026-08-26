package service_test

import (
	"context"
	"errors"
	"testing"

	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/service"
)

func linksEnv(t *testing.T) (*faultEnv, *service.Links, *auth.Client, string, string) {
	t.Helper()
	e := newFaultEnv(t)
	l := &service.Links{Pool: e.admin.Pool, Contacts: e.svc}
	client := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions:  []string{auth.ActLinksManage, auth.ActContactsRegister, auth.ActDSRErase},
		AllowedPurposes: []string{"support"}}
	ctx := context.Background()
	parent, err := e.svc.Register(ctx, client, service.RegisterInput{Email: "parent@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	child, err := e.svc.Register(ctx, client, service.RegisterInput{Email: "child@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	return e, l, client, parent, child
}

func TestPersonLinkLifecycle(t *testing.T) {
	_, l, client, parent, child := linksEnv(t)
	ctx := context.Background()

	if err := l.Link(ctx, client, parent, child, "guardian"); err != nil {
		t.Fatal(err)
	}
	// Re-link updates the type (idempotent upsert).
	if err := l.Link(ctx, client, parent, child, "owner"); err != nil {
		t.Fatal(err)
	}
	// List from the parent: one child.
	pl, err := l.List(ctx, client, parent)
	if err != nil || len(pl) != 1 || pl[0].CID != child || pl[0].Role != "child" || pl[0].LinkType != "owner" {
		t.Fatalf("parent list: %+v %v", pl, err)
	}
	// List from the child: one parent.
	cl, err := l.List(ctx, client, child)
	if err != nil || len(cl) != 1 || cl[0].CID != parent || cl[0].Role != "parent" {
		t.Fatalf("child list: %+v %v", cl, err)
	}
	// Unlink.
	if err := l.Unlink(ctx, client, parent, child); err != nil {
		t.Fatal(err)
	}
	if err := l.Unlink(ctx, client, parent, child); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("double unlink must be a miss: %v", err)
	}
}

func TestPersonLinkGuards(t *testing.T) {
	e, l, client, parent, child := linksEnv(t)
	ctx := context.Background()
	// Permission.
	noPerm := &auth.Client{ID: "np", Scope: "crm", AllowedPurposes: []string{"support"}}
	if err := l.Link(ctx, noPerm, parent, child, "guardian"); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("link without action: %v", err)
	}
	// Bad link type.
	if err := l.Link(ctx, client, parent, child, "sibling"); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("bad link type: %v", err)
	}
	// Self-link.
	if err := l.Link(ctx, client, parent, parent, "guardian"); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("self link: %v", err)
	}
	// Unknown cid.
	if err := l.Link(ctx, client, parent, "CID-NONE", "guardian"); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("unknown child: %v", err)
	}
	// Foreign-scope endpoint is a miss.
	foreign := &auth.Client{ID: "erp", Scope: "erp", AllowedActions: []string{auth.ActLinksManage}}
	if err := l.Link(ctx, foreign, parent, child, "guardian"); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("foreign scope: %v", err)
	}
	if _, err := l.List(ctx, foreign, parent); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("foreign list: %v", err)
	}
	_ = e
}

func TestPersonLinkFailsClosed(t *testing.T) {
	e := newFaultEnv(t, "person_links")
	l := &service.Links{Pool: e.svc.Pool, Contacts: e.svc}
	client := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions: []string{auth.ActLinksManage}}
	ctx := context.Background()
	parent := e.register(t)
	child, err := e.svc.Register(ctx, e.crm, service.RegisterInput{Email: "c2@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Link(ctx, client, parent, child, "guardian"); err == nil {
		t.Fatal("link must fail when person_links is denied")
	}
	if err := l.Unlink(ctx, client, parent, child); err == nil {
		t.Fatal("unlink must fail when person_links is denied")
	}
	if _, err := l.List(ctx, client, parent); err == nil {
		t.Fatal("list must fail when person_links is denied")
	}
}

func TestErasureListsLinkedNoCascadeByDefault(t *testing.T) {
	e, l, client, parent, child := linksEnv(t)
	ctx := context.Background()
	if err := l.Link(ctx, client, parent, child, "guardian"); err != nil {
		t.Fatal(err)
	}
	// Default erase: child is LISTED but NOT erased.
	_, _, linked, err := e.gdpr.EraseWithCascade(ctx, client, parent, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(linked) != 1 || linked[0].CID != child || linked[0].Cascaded {
		t.Fatalf("default erase must list, not cascade: %+v", linked)
	}
	// The child is still alive.
	var erased bool
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT erased_at IS NOT NULL FROM persons p JOIN cids c ON c.person_id=p.id WHERE c.cid=$1`, child).Scan(&erased); err != nil {
		t.Fatal(err)
	}
	if erased {
		t.Fatal("a default erase must NOT touch the linked child")
	}
}

func TestErasureCascadeOptIn(t *testing.T) {
	e, l, client, parent, child := linksEnv(t)
	ctx := context.Background()
	if err := l.Link(ctx, client, parent, child, "guardian"); err != nil {
		t.Fatal(err)
	}
	// Opt in to cascading guardian links: the child is erased too.
	_, _, linked, err := e.gdpr.EraseWithCascade(ctx, client, parent, []string{"guardian"})
	if err != nil {
		t.Fatal(err)
	}
	if len(linked) != 1 || !linked[0].Cascaded {
		t.Fatalf("cascade must erase the guardian child: %+v", linked)
	}
	var erased bool
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT erased_at IS NOT NULL FROM persons p JOIN cids c ON c.person_id=p.id WHERE c.cid=$1`, child).Scan(&erased); err != nil {
		t.Fatal(err)
	}
	if !erased {
		t.Fatal("an opted-in cascade must erase the child")
	}
}

func TestEraseWithCascadeFaultBranches(t *testing.T) {
	e, l, client, parent, child := linksEnv(t)
	ctx := context.Background()
	if err := l.Link(ctx, client, parent, child, "member"); err != nil {
		t.Fatal(err)
	}
	// Break person_links so the pre-erase child listing query fails.
	if _, err := e.admin.Pool.Exec(ctx, `ALTER TABLE person_links RENAME TO pl_gone`); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := e.gdpr.EraseWithCascade(ctx, client, parent, nil); err == nil {
		t.Fatal("erase must surface the child-listing query error")
	}
	if _, err := e.admin.Pool.Exec(ctx, `ALTER TABLE pl_gone RENAME TO person_links`); err != nil {
		t.Fatal(err)
	}
	// Permission guard on the public cascade entrypoint.
	noPerm := &auth.Client{ID: "np", Scope: "crm"}
	if _, _, _, err := e.gdpr.EraseWithCascade(ctx, noPerm, parent, nil); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("erase without action: %v", err)
	}
	// Unknown cid.
	if _, _, _, err := e.gdpr.EraseWithCascade(ctx, client, "CID-NONE", nil); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("unknown cid: %v", err)
	}
}

// TestCascadeToleratesAlreadyErasedChild: a child erased in a prior request
// is reported as cascaded, not a fatal error.
func TestCascadeToleratesAlreadyErasedChild(t *testing.T) {
	e, l, client, parent, child := linksEnv(t)
	ctx := context.Background()
	if err := l.Link(ctx, client, parent, child, "guardian"); err != nil {
		t.Fatal(err)
	}
	// Erase the child first.
	if _, _, err := e.gdpr.Erase(ctx, client, child); err != nil {
		t.Fatal(err)
	}
	// Now cascade-erase the parent: the already-erased child must not fail.
	_, _, linked, err := e.gdpr.EraseWithCascade(ctx, client, parent, []string{"guardian"})
	if err != nil {
		t.Fatalf("cascade over an already-erased child must not fail: %v", err)
	}
	if len(linked) != 1 || !linked[0].Cascaded {
		t.Fatalf("child should be reported cascaded: %+v", linked)
	}
}
