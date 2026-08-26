package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/service"
)

func TestAttributeAllowlistNarrowsReads(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cid, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
		Email: "ana@example.com", Attributes: map[string]string{"tier": "gold", "iban": "HR12"}})
	if err != nil {
		t.Fatal(err)
	}

	narrowed := &auth.Client{ID: "billing", Scope: "crm",
		AllowedActions:    []string{auth.ActAttributesRead, auth.ActDSRExport, auth.ActDSRAccess},
		AllowedPurposes:   []string{"support"},
		AllowedAttributes: []string{"iban"}}

	// The allowed field reads; anything else is forbidden - and the
	// refusal must not depend on whether the CID exists (no oracle).
	if v, err := e.svc.GetAttribute(ctx, narrowed, cid, "iban", "support"); err != nil || v != "HR12" {
		t.Fatalf("allowlisted attribute must read: %q %v", v, err)
	}
	if _, err := e.svc.GetAttribute(ctx, narrowed, cid, "tier", "support"); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("non-allowlisted attribute must be forbidden: %v", err)
	}
	if _, err := e.svc.GetAttribute(ctx, narrowed, "CID-DOESNOTEXIST", "tier", "support"); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("refusal must be identical for unknown CIDs: %v", err)
	}

	// Export through the narrowed credential carries only allowed fields.
	sd, err := e.gdpr.Export(ctx, narrowed, cid)
	if err != nil {
		t.Fatal(err)
	}
	if _, leaked := sd.Attributes["tier"]; leaked {
		t.Fatal("export must not leak fields outside the allowlist")
	}
	if sd.Attributes["iban"] != "HR12" {
		t.Fatalf("export must keep allowed fields: %+v", sd.Attributes)
	}

	// A nil allowlist keeps the pre-F3 behaviour: everything readable.
	if v, err := e.svc.GetAttribute(ctx, e.crm, cid, "tier", "support"); err != nil || v != "gold" {
		t.Fatalf("nil allowlist must read all: %q %v", v, err)
	}
}

func TestUnlockTokenLifecycle(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	u := &service.Unlock{Pool: e.admin.Pool}
	// Real rows: unlock_tokens carries a foreign key to clients, so
	// fabricated client literals cannot issue.
	admin := &auth.Client{ID: "ops", Name: "Ops", Scope: "crm",
		AllowedActions: []string{auth.ActAdminUnlock}, AllowedPurposes: []string{}, RateLimit: 10}
	if _, err := auth.Create(ctx, e.admin.Pool, *admin); err != nil {
		t.Fatal(err)
	}

	// No permission: forbidden.
	if _, _, err := u.Issue(ctx, e.crm, "search"); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("issue without admin.unlock must be forbidden: %v", err)
	}
	if _, _, err := u.Issue(ctx, admin, ""); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("empty purpose must be rejected: %v", err)
	}

	token, expiresAt, err := u.Issue(ctx, admin, "search")
	if err != nil || token == "" {
		t.Fatalf("issue: %q %v", token, err)
	}
	if until := time.Until(expiresAt); until <= 0 || until > time.Minute+time.Second {
		t.Fatalf("expiry must be about 60s away, got %s", until)
	}

	// Single use: first consume passes, the replay fails.
	if err := u.Consume(ctx, admin, "search", token); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if err := u.Consume(ctx, admin, "search", token); !errors.Is(err, service.ErrUnlockRequired) {
		t.Fatalf("replay must fail: %v", err)
	}

	// Purpose and client binding: a fresh token fails for the wrong ones.
	token2, _, err := u.Issue(ctx, admin, "search")
	if err != nil {
		t.Fatal(err)
	}
	if err := u.Consume(ctx, admin, "bulk-tokens", token2); !errors.Is(err, service.ErrUnlockRequired) {
		t.Fatalf("wrong purpose must fail: %v", err)
	}
	other := &auth.Client{ID: "other", Name: "Other", Scope: "crm",
		AllowedActions: []string{auth.ActAdminUnlock}, AllowedPurposes: []string{}, RateLimit: 10}
	if _, err := auth.Create(ctx, e.admin.Pool, *other); err != nil {
		t.Fatal(err)
	}
	if err := u.Consume(ctx, other, "search", token2); !errors.Is(err, service.ErrUnlockRequired) {
		t.Fatalf("another client must not spend someone else's token: %v", err)
	}
	// Wrong attempts must not have burned it: the owner still can.
	if err := u.Consume(ctx, admin, "search", token2); err != nil {
		t.Fatalf("owner consume after failed probes: %v", err)
	}

	// Expired tokens fail; pruning clears old rows without touching audit.
	token3, _, err := u.Issue(ctx, admin, "search")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.admin.Pool.Exec(ctx,
		`UPDATE unlock_tokens SET expires_at = now() - interval '2 hours' WHERE used_at IS NULL`); err != nil {
		t.Fatal(err)
	}
	if err := u.Consume(ctx, admin, "search", token3); !errors.Is(err, service.ErrUnlockRequired) {
		t.Fatalf("expired token must fail: %v", err)
	}
	n, err := service.PruneUnlockTokens(ctx, e.admin.Pool)
	if err != nil || n == 0 {
		t.Fatalf("prune: %d %v", n, err)
	}
	// Both the issue and the consume are chained audit records.
	var issued, used int64
	if err := e.admin.Pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM audit WHERE action='admin.unlock'),
		(SELECT count(*) FROM audit WHERE action='admin.unlock.use')`).Scan(&issued, &used); err != nil {
		t.Fatal(err)
	}
	if issued != 3 || used != 2 {
		t.Fatalf("audit must carry 3 issues and 2 uses, got %d/%d", issued, used)
	}
}

func TestRolePresets(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()

	cred, err := auth.Create(ctx, e.admin.Pool, auth.Client{
		ID: "ro", Name: "Readonly", Scope: "crm", Role: auth.RoleReadonly,
		AllowedPurposes: []string{"support"}, RateLimit: 10})
	if err != nil {
		t.Fatal(err)
	}
	a := &auth.Authenticator{Pool: e.admin.Pool}
	client, ok, err := a.Authenticate(ctx, "Bearer "+cred)
	if err != nil || !ok {
		t.Fatalf("authenticate: %v", err)
	}
	if client.Role != auth.RoleReadonly {
		t.Fatalf("role must round-trip, got %q", client.Role)
	}
	if !client.Can(auth.ActLookup) || !client.Can(auth.ActAttributesRead) {
		t.Fatal("readonly preset must include lookup and attribute reads")
	}
	if client.Can(auth.ActContactsRegister) || client.Can(auth.ActDSRErase) {
		t.Fatal("readonly preset must not include writes or erasure")
	}
	// The preset actually bites: a register through it is forbidden.
	if _, err := e.svc.Register(ctx, client, service.RegisterInput{Email: "x@example.com"}); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("readonly client must not register: %v", err)
	}
	// Admin preset carries the unlock right.
	if !contains(auth.RoleActions(auth.RoleAdmin), auth.ActAdminUnlock) {
		t.Fatal("admin preset must carry admin.unlock")
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// TestUnlockFailsClosedUnderDeniedTable: the unlock machinery must error
// visibly when its table is unreachable - never issue or accept a token.
func TestUnlockFailsClosedUnderDeniedTable(t *testing.T) {
	e := newFaultEnv(t, "unlock_tokens")
	ctx := context.Background()
	admin := &auth.Client{ID: "ops2", Name: "Ops2", Scope: "crm",
		AllowedActions: []string{auth.ActAdminUnlock}, AllowedPurposes: []string{}, RateLimit: 10}
	if _, err := auth.Create(ctx, e.admin.Pool, *admin); err != nil {
		t.Fatal(err)
	}
	// The restricted-role pool is the one the service uses in this env.
	u := &service.Unlock{Pool: e.svc.Pool}
	if _, _, err := u.Issue(ctx, admin, "search"); err == nil {
		t.Fatal("issue without table rights must error")
	}
	if err := u.Consume(ctx, admin, "search", "SOMETOKEN"); err == nil ||
		errors.Is(err, service.ErrUnlockRequired) {
		t.Fatalf("consume must surface the backend failure, not read as a bad token: %v", err)
	}
	if _, err := service.PruneUnlockTokens(ctx, e.svc.Pool); err == nil {
		t.Fatal("prune without table rights must error")
	}
}

func TestRoleServicePresetAndAccessFilter(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()

	// The service preset exists and sits between readonly and admin.
	svcActs := auth.RoleActions(auth.RoleService)
	if !contains(svcActs, auth.ActOTIIssue) || contains(svcActs, auth.ActDSRErase) {
		t.Fatalf("service preset wrong: %v", svcActs)
	}

	// Access (org-wide) through a narrowed officer credential filters
	// attribute fields in every scope's data.
	cid, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
		Email: "f@example.com", Attributes: map[string]string{"tier": "gold", "iban": "HR99"}})
	if err != nil {
		t.Fatal(err)
	}
	officer := &auth.Client{ID: "dpo", Scope: "crm",
		AllowedActions:    []string{auth.ActDSRAccess},
		AllowedAttributes: []string{"tier"}}
	out, err := e.gdpr.Access(ctx, officer, cid)
	if err != nil {
		t.Fatal(err)
	}
	scopes, _ := out["scopes"].([]service.ScopeData)
	if len(scopes) == 0 {
		t.Fatal("access must return the scope data")
	}
	for _, sd := range scopes {
		if _, leaked := sd.Attributes["iban"]; leaked {
			t.Fatal("org-wide access through a narrowed credential must filter fields")
		}
	}
}
