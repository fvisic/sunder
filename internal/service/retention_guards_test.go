package service_test

// TESTS-8: the retention sweep deletes a person's search tokens only when
// FIVE NOT EXISTS guards hold. Two of them had tests; the three added
// defensively at the same time had none, so deleting any of those clauses -
// which only makes the DELETE fire MORE often - left the suite green.
//
// person_tokens are keyed HMACs: once deleted they can only come back by
// re-registering the identifier, so a wrong deletion permanently breaks
// lookup and dedup for a person whose data is still live somewhere.

import (
	"context"
	"testing"

	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/service"
)

func TestRetentionKeepsSearchTokensWhileAnyDatumLives(t *testing.T) {
	for _, tc := range []struct {
		name string
		// create makes the one surviving datum for the person; kill removes
		// or expires it.
		create func(t *testing.T, e *faultEnv, client *auth.Client, cid, otherCID string) any
		kill   func(t *testing.T, e *faultEnv, made any, cid string)
	}{
		{
			name: "standing share",
			create: func(t *testing.T, e *faultEnv, client *auth.Client, cid, _ string) any {
				shares := &service.Shares{Pool: e.admin.Pool, Contacts: e.svc}
				id, _, err := shares.Create(context.Background(), client, service.ShareInput{
					CID: cid, Fields: []string{"tier"}, PartnerLabel: "partner",
					Purpose: "support", TTLSeconds: 7776000})
				if err != nil {
					t.Fatal(err)
				}
				return id
			},
			kill: func(t *testing.T, e *faultEnv, made any, cid string) {
				// Expiry, not deletion: an EXPIRED share must not keep the
				// tokens alive either.
				if _, err := e.admin.Pool.Exec(context.Background(),
					`UPDATE shared_records SET expires_at = now() - interval '1 minute' WHERE uuid=$1`,
					made); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "person link",
			create: func(t *testing.T, e *faultEnv, client *auth.Client, cid, otherCID string) any {
				links := &service.Links{Pool: e.admin.Pool, Contacts: e.svc}
				if err := links.Link(context.Background(), client, otherCID, cid, "guardian"); err != nil {
					t.Fatal(err)
				}
				return nil
			},
			kill: func(t *testing.T, e *faultEnv, _ any, cid string) {
				if _, err := e.admin.Pool.Exec(context.Background(),
					`DELETE FROM person_links`); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "live value token",
			create: func(t *testing.T, e *faultEnv, client *auth.Client, _, otherCID string) any {
				// Bound to the OTHER cid of the same person, so the sweep's
				// `DELETE FROM value_tokens WHERE cid = ANY(wiped)` does not
				// remove it first - which is why the existing test never
				// exercised this guard.
				vt := &service.ValueTokens{Pool: e.admin.Pool, Eng: e.oti.Eng, Ring: e.svc.Ring, Tok: e.svc.Tok}
				tok, err := vt.Tokenize(context.Background(), &auth.Client{
					ID: "erp", Scope: "erp",
					AllowedActions:  []string{auth.ActTokensCreate},
					AllowedPurposes: []string{"support"},
				}, service.TokenizeInput{Type: "string", Value: "HR12", CID: otherCID})
				if err != nil {
					t.Fatal(err)
				}
				return tok
			},
			kill: func(t *testing.T, e *faultEnv, made any, _ string) {
				if _, err := e.admin.Pool.Exec(context.Background(),
					`UPDATE value_tokens SET expires_final = now() - interval '1 minute' WHERE token=$1`,
					made); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newFaultEnv(t)
			ctx := context.Background()
			crm := &auth.Client{ID: "crm", Scope: "crm",
				AllowedActions: []string{auth.ActContactsRegister, auth.ActLookup,
					auth.ActSharesCreate, auth.ActLinksManage, auth.ActAttributesRead,
					auth.ActScopesIssue},
				AllowedPurposes: []string{"support"}}

			cid, err := e.svc.Register(ctx, crm, service.RegisterInput{
				Email: "guarded@example.com", Attributes: map[string]string{"tier": "gold"}})
			if err != nil {
				t.Fatal(err)
			}
			// A second scope's pseudonym, for the datum that must not sit on
			// the wiped cid itself.
			otherCID, err := e.svc.IssueScopedCid(ctx, crm, cid, "erp")
			if err != nil {
				t.Fatal(err)
			}
			// A counterparty for the link case.
			counterparty, err := e.svc.Register(ctx, crm, service.RegisterInput{Email: "counter@example.com"})
			if err != nil {
				t.Fatal(err)
			}
			linkTarget := counterparty
			if tc.name != "person link" {
				linkTarget = otherCID
			}
			made := tc.create(t, e, crm, cid, map[bool]string{true: linkTarget, false: otherCID}[tc.name == "person link"])

			// Age everything out.
			for _, scope := range []string{"crm", "erp"} {
				if _, err := e.admin.Pool.Exec(ctx,
					`INSERT INTO retention_policies (scope, contacts_ttl_days) VALUES ($1,0)
					 ON CONFLICT (scope) DO UPDATE SET contacts_ttl_days=0`, scope); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, err := service.RunRetention(ctx, e.admin.Pool); err != nil {
				t.Fatal(err)
			}

			// The blob is gone, but the person is still resolvable: some
			// scope legitimately holds and serves their data.
			var live int
			if err := e.admin.Pool.QueryRow(ctx,
				`SELECT count(*) FROM cids WHERE cid=$1 AND pii_encrypted IS NOT NULL`, cid).Scan(&live); err != nil {
				t.Fatal(err)
			}
			if live != 0 {
				t.Fatal("precondition: the blob should have been wiped")
			}
			if _, err := e.svc.Lookup(ctx, crm, service.LookupInput{Email: "guarded@example.com"}); err != nil {
				t.Fatalf("a live %s must keep the person resolvable - deleting its NOT EXISTS guard makes them unfindable while their data is still disclosed: %v", tc.name, err)
			}

			// Remove the last datum; the identifier itself now becomes the
			// last datum, and it goes too.
			tc.kill(t, e, made, cid)
			if _, _, err := service.RunRetention(ctx, e.admin.Pool); err != nil {
				t.Fatal(err)
			}
			if _, err := e.svc.Lookup(ctx, crm, service.LookupInput{Email: "guarded@example.com"}); err != service.ErrNotFound {
				t.Fatalf("with nothing live left, the search tokens must go: %v", err)
			}
		})
	}
}

// RunRetention's own branches: nothing to wipe, a policy that matches
// nothing, and the OTI prune - the paths a sweep takes on a healthy,
// steady-state instance, which is most sweeps.
func TestRetentionOnAQuietInstance(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()

	// No policies at all: a no-op that must not error.
	wiped, oti, err := service.RunRetention(ctx, e.admin.Pool)
	if err != nil {
		t.Fatal(err)
	}
	if wiped != 0 || oti != 0 {
		t.Fatalf("a sweep with no policies must do nothing: %d/%d", wiped, oti)
	}

	// A policy whose TTL nothing has reached.
	cid := e.register(t)
	if _, err := e.admin.Pool.Exec(ctx,
		`INSERT INTO retention_policies (scope, contacts_ttl_days) VALUES ('crm', 3650)`); err != nil {
		t.Fatal(err)
	}
	if wiped, _, err = service.RunRetention(ctx, e.admin.Pool); err != nil || wiped != 0 {
		t.Fatalf("a fresh contact must not be wiped under a 10-year TTL: %d %v", wiped, err)
	}
	if _, err := e.svc.Lookup(ctx, e.crm, service.LookupInput{Email: "fault@example.com"}); err != nil {
		t.Fatalf("and it must stay resolvable: %v", err)
	}

	// The OTI prune: rows expired more than 30 days ago go, live ones stay.
	if _, err := e.admin.Pool.Exec(ctx, `
		INSERT INTO oti (jti, cid, purpose, audience, expires_at, status)
		VALUES (gen_random_uuid(), $1, 'support', 'billing', now() - interval '60 days', 'USED'),
		       (gen_random_uuid(), $1, 'support', 'billing', now() + interval '5 minutes', 'VALID')`,
		cid); err != nil {
		t.Fatal(err)
	}
	if _, oti, err = service.RunRetention(ctx, e.admin.Pool); err != nil {
		t.Fatal(err)
	}
	if oti != 1 {
		t.Fatalf("exactly the long-expired OTI must be pruned, got %d", oti)
	}
	var left int
	if err := e.admin.Pool.QueryRow(ctx, `SELECT count(*) FROM oti`).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 1 {
		t.Fatalf("the live OTI must survive the sweep, %d rows left", left)
	}
}
