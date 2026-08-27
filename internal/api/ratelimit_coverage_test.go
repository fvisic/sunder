package api

// AUTHZ-1: the per-client rate limit was a per-handler call added feature by
// feature, and eleven v1 routes never got it - including the primary PII
// read (GET /v1/contacts/{cid}/attributes/{name}) and the most destructive
// call in the product (POST /v1/dsr/erase). The `rate_limit` column that
// THREAT-MODEL names as the mitigation for a stolen bearer credential was
// silently inoperative on them.
//
// It is enforced in middleware now, so this guard is over the ROUTE TABLE,
// not a handpicked list: a route added tomorrow is covered or this fails.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/config"
	"github.com/fvisic/sunder/internal/testutil"
)

func TestEveryV1RouteIsRateLimited(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewDB(t)
	expiry := testUnlockExpiry()
	cred, err := auth.Create(ctx, st.Pool, auth.Client{
		ID: "rl", Name: "RL", Scope: "crm",
		AllowedActions: []string{auth.ActContactsRegister, auth.ActLookup, auth.ActScopesIssue,
			auth.ActAttributesRead, auth.ActAttributesHistory, auth.ActOTIIssue, auth.ActOTIVerify,
			auth.ActConsentManage, auth.ActDSRAccess, auth.ActDSRErase, auth.ActDSRExport,
			auth.ActTokensCreate, auth.ActTokensRead, auth.ActTokensDelete,
			auth.ActFilesRead, auth.ActFilesWrite, auth.ActLinksManage, auth.ActSharesCreate,
			auth.ActAuditVerify, auth.ActAdminUnlock, auth.ActClaimsExternal},
		AllowedPurposes: []string{"support"}, RateLimit: 1,
		CredentialExpiresAt: expiry})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(config.Config{Keystore: "file", KeyRetireGrace: -1, KeystorePath: t.TempDir(),
		FilesStorage: "local", FilesDir: t.TempDir(), FilesMaxMB: 1}, st)
	if err != nil {
		t.Fatal(err)
	}
	e := &e2eEnv{srv: srv, credCRM: cred}

	// Burn the single allowed request.
	if rec, _ := e.do(t, cred, "POST", "/v1/lookup", map[string]string{"email": "nobody@example.com"}); rec.Code == 429 {
		t.Fatal("precondition: the first request must be allowed")
	}

	var checked int
	for route := range registeredRoutes(t) {
		method, path, _ := strings.Cut(route, " ")
		if !strings.HasPrefix(path, "/v1/") {
			continue // portal and health surfaces have their own limits
		}
		// The credential-less share fetch is limited per IP, not per client
		// (it has no client), and is registered outside the auth guard.
		if path == "/v1/shares/{uuid}" && method == "GET" && srv.Cfg.SharesPublic {
			continue
		}
		// Substitute plausible values for the path variables; the request is
		// expected to be refused before any of them is looked at.
		concrete := path
		for _, v := range []string{"{cid}", "{name}", "{token}", "{id}", "{uuid}", "{version}"} {
			concrete = strings.ReplaceAll(concrete, v, "x")
		}
		rec, _ := e.do(t, cred, method, concrete, map[string]any{})
		if rec.Code != 429 {
			t.Errorf("%s %s is not rate-limited: got %d (every /v1/ route must spend the client's budget)",
				method, concrete, rec.Code)
		}
		checked++
	}
	if checked < 20 {
		t.Fatalf("route discovery covered only %d v1 routes - the guard is vacuous", checked)
	}
}

// AUTHZ-1's other half: probing cids against the primary PII read is
// enumeration too, and it used to be invisible to the detector, which was
// fed only from lookup.
func TestAttributeMissesFeedTheEnumerationDetector(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewDB(t)
	cred, err := auth.Create(ctx, st.Pool, auth.Client{
		ID: "probe", Name: "Probe", Scope: "crm",
		AllowedActions:  []string{auth.ActAttributesRead},
		AllowedPurposes: []string{"support"}, RateLimit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(config.Config{Keystore: "file", KeyRetireGrace: -1, KeystorePath: t.TempDir()}, st)
	if err != nil {
		t.Fatal(err)
	}
	e := &e2eEnv{srv: srv, credCRM: cred}

	before := srv.Detector.Miss("probe")
	// Well-formed cids that do not exist: the shape of an enumeration
	// sweep, not of a malformed request.
	for i := 0; i < 5; i++ {
		rec, _ := e.do(t, cred, "GET",
			"/v1/contacts/CID-AAAAAAAAAAAAAAAAAAAAAAAAA"+string(rune('A'+i))+"/attributes/email?purpose=support", nil)
		if rec.Code != 404 {
			t.Fatalf("probe %d: expected a miss, got %d", i, rec.Code)
		}
	}
	after := srv.Detector.Miss("probe")
	if after-before < 5 {
		t.Fatalf("attribute misses must feed the enumeration detector: counter moved by %d over 5 probes (plus this test's own 2 calls)", after-before)
	}
}

// The middleware's fail-closed branch: no authenticated client means no
// budget to charge, so the request must not proceed.
func TestRateLimitMiddlewareRefusesAnUnauthenticatedRequest(t *testing.T) {
	st := testutil.NewDB(t)
	srv, err := New(config.Config{Keystore: "file", KeyRetireGrace: -1, KeystorePath: t.TempDir()}, st)
	if err != nil {
		t.Fatal(err)
	}
	reached := false
	h := srv.rateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/anything", nil))
	if reached {
		t.Fatal("a request with no authenticated client must not reach the handler")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}
