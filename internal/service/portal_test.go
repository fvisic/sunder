package service_test

// Portal service-level branches the HTTP e2e does not reach: throttled ring
// invalidation, session hygiene, and the erase-confirmation guard.

import (
	"context"
	"testing"

	"github.com/fvisic/sunder/internal/service"
)

func TestPortalConfirmTokenIsPersonBound(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cidA := e.register(t)
	_ = cidA
	cidB, err := e.svc.Register(ctx, e.crm, service.RegisterInput{Email: "second@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	p := &service.Portal{GDPR: e.gdpr, Contacts: e.svc}

	var personA, personB string
	if err := e.admin.Pool.QueryRow(ctx, `SELECT person_id FROM cids WHERE cid=$1`, cidA).Scan(&personA); err != nil {
		t.Fatal(err)
	}
	if err := e.admin.Pool.QueryRow(ctx, `SELECT person_id FROM cids WHERE cid=$1`, cidB).Scan(&personB); err != nil {
		t.Fatal(err)
	}

	// A confirmation token minted for A must not erase B.
	tokenA, err := p.RequestErase(ctx, personA)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.ConfirmErase(ctx, personB, tokenA); err == nil {
		t.Fatal("a confirmation token must only erase the person it was issued for")
	}
	// Crucially, that failed attempt must NOT have consumed the token.
	// It still works for A.
	if _, _, err := p.ConfirmErase(ctx, personA, tokenA); err != nil {
		t.Fatal(err)
	}
	// Garbage confirmation.
	if _, _, err := p.ConfirmErase(ctx, personB, "nope"); err == nil {
		t.Fatal("garbage confirmation token must be rejected")
	}
}

func TestPortalStartUnknownAndSessionErrors(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	p := &service.Portal{GDPR: e.gdpr, Contacts: e.svc}

	// Unknown, malformed and mailer-less starts are all silent successes.
	for _, email := range []string{"ghost@example.com", "not-an-email", ""} {
		if err := p.Start(ctx, email); err != nil {
			t.Fatalf("Start(%q) must not error: %v", email, err)
		}
	}
	// A garbage session resolves to forbidden, never a panic.
	if _, err := p.SessionPerson(ctx, "garbage"); err == nil {
		t.Fatal("garbage session must be rejected")
	}
	if _, err := p.Redeem(ctx, "garbage"); err == nil {
		t.Fatal("garbage login token must be rejected")
	}
}

func TestKeyRingInvalidateThrottled(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	ring := &service.KeyRing{Pool: e.admin.Pool}
	if _, err := ring.Newest(ctx, "hmac-email"); err != nil {
		t.Fatal(err)
	}
	// Two invalidations in a row: the second is throttled, so the ring
	// still answers from cache without a forced reload.
	ring.InvalidateThrottled()
	ring.InvalidateThrottled()
	if _, err := ring.Newest(ctx, "hmac-email"); err != nil {
		t.Fatal(err)
	}
}
