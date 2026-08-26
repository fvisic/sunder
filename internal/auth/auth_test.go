package auth

import (
	"testing"
	"time"
)

// TestPresetsExcludeExplicitGrantActions (review medium): scopes.issue
// (linkage-capable) and, on the service preset, tokens.delete (destroys the
// only copy of a sealed value) must be EXPLICIT -actions decisions, never
// preset baggage.
func TestPresetsExcludeExplicitGrantActions(t *testing.T) {
	for _, role := range []string{RoleReadonly, RoleService, RoleAdmin} {
		for _, act := range RoleActions(role) {
			if act == ActScopesIssue {
				t.Fatalf("preset %q must not bundle scopes.issue", role)
			}
		}
	}
	for _, act := range RoleActions(RoleService) {
		if act == ActTokensDelete {
			t.Fatal("the service preset must not bundle tokens.delete")
		}
	}
	// admin deliberately keeps tokens.delete - assert so a silent trim is
	// noticed too.
	found := false
	for _, act := range RoleActions(RoleAdmin) {
		if act == ActTokensDelete {
			found = true
		}
	}
	if !found {
		t.Fatal("the admin preset keeps tokens.delete by design")
	}
}

func TestValidateUnlockGrant(t *testing.T) {
	// admin.unlock on a non-expiring credential is refused.
	if err := ValidateUnlockGrant([]string{ActAdminUnlock, ActLookup}, nil); err == nil {
		t.Fatal("admin.unlock without an expiry must be refused")
	}
	// With an expiry it is allowed.
	future := time.Now().Add(time.Hour)
	if err := ValidateUnlockGrant([]string{ActAdminUnlock}, &future); err != nil {
		t.Fatalf("admin.unlock with an expiry must be allowed: %v", err)
	}
	// A credential WITHOUT admin.unlock is unaffected by the expiry rule.
	if err := ValidateUnlockGrant([]string{ActLookup, ActTokensCreate}, nil); err != nil {
		t.Fatalf("no unlock action: %v", err)
	}
}
