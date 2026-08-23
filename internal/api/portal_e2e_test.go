package api

// P2.5 portal e2e: magic-link login (via the '_portal' mailer webhook),
// self-access, consent flip that visibly blocks a read, two-step erasure,
// and the no-enumeration guarantee.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/config"
	"github.com/fvisic/sunder/internal/testutil"
)

type portalEnv struct {
	srv     *Server
	credCRM string
	mailer  *httptest.Server
	mu      sync.Mutex
	tokens  []string // login tokens the "mailer" received
}

func newPortalEnv(t *testing.T) *portalEnv {
	t.Helper()
	ctx := context.Background()
	st := testutil.NewDB(t)
	e := &portalEnv{}
	e.mailer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Event string `json:"event"`
			Token string `json:"token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Event == "portal_login" {
			e.mu.Lock()
			e.tokens = append(e.tokens, body.Token)
			e.mu.Unlock()
		}
		w.WriteHeader(200)
	}))
	t.Cleanup(e.mailer.Close)
	if _, err := st.Pool.Exec(ctx,
		`INSERT INTO webhooks (scope, url, secret) VALUES ('_portal', $1, 'mailer-secret')`, e.mailer.URL); err != nil {
		t.Fatal(err)
	}
	cred, err := auth.Create(ctx, st.Pool, auth.Client{
		ID: "crm", Name: "CRM", Scope: "crm",
		AllowedActions:  []string{auth.ActContactsRegister, auth.ActAttributesRead},
		AllowedPurposes: []string{"support"}, RateLimit: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	e.credCRM = cred
	srv, err := New(config.Config{Listen: ":0", Keystore: "file", KeystorePath: t.TempDir()}, st)
	if err != nil {
		t.Fatal(err)
	}
	e.srv = srv
	return e
}

// call performs a portal request carrying the session cookie when set.
func (e *portalEnv) call(t *testing.T, cookie, method, path, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "203.0.113.7:1234"
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: portalSessionCookie, Value: cookie})
	}
	rec := httptest.NewRecorder()
	e.srv.Handler().ServeHTTP(rec, req)
	out := map[string]any{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func (e *portalEnv) register(t *testing.T, email string) string {
	t.Helper()
	req := httptest.NewRequest("POST", "/v1/contacts",
		strings.NewReader(`{"email":"`+email+`","attributes":{"tier":"gold"}}`))
	req.Header.Set("Authorization", "Bearer "+e.credCRM)
	rec := httptest.NewRecorder()
	e.srv.Handler().ServeHTTP(rec, req)
	if rec.Code != 201 {
		t.Fatalf("register: %d %s", rec.Code, rec.Body.String())
	}
	var out map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out["cid"]
}

func (e *portalEnv) login(t *testing.T, email string) string {
	t.Helper()
	rec, _ := e.call(t, "", "POST", "/portal/api/start", `{"email":"`+email+`"}`)
	if rec.Code != 202 {
		t.Fatalf("start: %d", rec.Code)
	}
	e.mu.Lock()
	if len(e.tokens) == 0 {
		e.mu.Unlock()
		t.Fatal("mailer received no login token")
	}
	token := e.tokens[len(e.tokens)-1]
	e.mu.Unlock()
	rec, _ = e.call(t, "", "POST", "/portal/api/session", `{"token":"`+token+`"}`)
	if rec.Code != 200 {
		t.Fatalf("session: %d %s", rec.Code, rec.Body.String())
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == portalSessionCookie {
			return c.Value
		}
	}
	t.Fatal("no session cookie set")
	return ""
}

func TestPortalFullLifecycle(t *testing.T) {
	e := newPortalEnv(t)
	cid := e.register(t, "citizen@example.com")
	session := e.login(t, "Citizen@Example.com") // normalization applies

	// Self-access shows the CRM scope data.
	rec, out := e.call(t, session, "GET", "/portal/api/me", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "gold") {
		t.Fatalf("me: %d %v", rec.Code, out)
	}

	// Withdraw consent for "support": the CRM's read visibly flips to 403.
	rec, _ = e.call(t, session, "POST", "/portal/api/consent",
		`{"cid":"`+cid+`","purpose":"support","granted":false}`)
	if rec.Code != 200 {
		t.Fatalf("consent: %d", rec.Code)
	}
	req := httptest.NewRequest("GET", "/v1/contacts/"+cid+"/attributes/tier?purpose=support", nil)
	req.Header.Set("Authorization", "Bearer "+e.credCRM)
	crmRec := httptest.NewRecorder()
	e.srv.Handler().ServeHTTP(crmRec, req)
	if crmRec.Code != 403 {
		t.Fatalf("withdrawn consent must block the CRM read: %d", crmRec.Code)
	}

	// Erasure is two-step: request returns a confirm token, confirm executes.
	rec, out = e.call(t, session, "POST", "/portal/api/erase", "{}")
	if rec.Code != 200 {
		t.Fatalf("erase request: %d", rec.Code)
	}
	confirm, _ := out["confirm_token"].(string)
	if confirm == "" {
		t.Fatal("no confirm token")
	}
	// Garbage confirmation is rejected; the real one works exactly once.
	if rec, _ = e.call(t, session, "POST", "/portal/api/erase/confirm", `{"confirm_token":"nope"}`); rec.Code == 200 {
		t.Fatal("bad confirm token must be rejected")
	}
	if rec, _ = e.call(t, session, "POST", "/portal/api/erase/confirm", `{"confirm_token":"`+confirm+`"}`); rec.Code != 200 {
		t.Fatalf("confirm: %d", rec.Code)
	}
	if rec, _ = e.call(t, session, "POST", "/portal/api/erase/confirm", `{"confirm_token":"`+confirm+`"}`); rec.Code == 200 {
		t.Fatal("confirm token must be single-use")
	}
	// The erased person's session is dead (tombstoned person).
	if rec, _ = e.call(t, session, "GET", "/portal/api/me", ""); rec.Code != 401 {
		t.Fatalf("session must die with erasure: %d", rec.Code)
	}
}

func TestPortalNoEnumerationAndTokenHygiene(t *testing.T) {
	e := newPortalEnv(t)
	e.register(t, "exists@example.com")

	// Unknown and known addresses return the IDENTICAL response.
	rec1, out1 := e.call(t, "", "POST", "/portal/api/start", `{"email":"exists@example.com"}`)
	rec2, out2 := e.call(t, "", "POST", "/portal/api/start", `{"email":"ghost@example.com"}`)
	if rec1.Code != rec2.Code || out1["status"] != out2["status"] {
		t.Fatalf("enumeration oracle: %d/%v vs %d/%v", rec1.Code, out1, rec2.Code, out2)
	}
	// Garbage email: still the same response.
	rec3, out3 := e.call(t, "", "POST", "/portal/api/start", `{"email":"not-an-email"}`)
	if rec3.Code != rec1.Code || out3["status"] != out1["status"] {
		t.Fatal("invalid email must not change the response")
	}

	// Login tokens are single-use and garbage is rejected.
	e.mu.Lock()
	token := e.tokens[0]
	e.mu.Unlock()
	if rec, _ := e.call(t, "", "POST", "/portal/api/session", `{"token":"`+token+`"}`); rec.Code != 200 {
		t.Fatalf("first redeem: %d", rec.Code)
	}
	if rec, _ := e.call(t, "", "POST", "/portal/api/session", `{"token":"`+token+`"}`); rec.Code == 200 {
		t.Fatal("login token must be single-use")
	}
	if rec, _ := e.call(t, "", "POST", "/portal/api/session", `{"token":"garbage"}`); rec.Code == 200 {
		t.Fatal("garbage token must be rejected")
	}
	// No session cookie: portal data is unreachable.
	if rec, _ := e.call(t, "", "GET", "/portal/api/me", ""); rec.Code != 401 {
		t.Fatal("no cookie must be 401")
	}
	// Only token HASHES are stored.
	var n int
	if err := e.srv.Store.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM portal_tokens WHERE octet_length(token_hash) != 32`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("token storage hygiene: %d %v", n, err)
	}
}

func TestPortalConsentOwnershipAndSPA(t *testing.T) {
	e := newPortalEnv(t)
	e.register(t, "a@example.com")
	other := e.register(t, "b@example.com")
	session := e.login(t, "a@example.com")

	// A session cannot flip consent on someone else's CID.
	rec, _ := e.call(t, session, "POST", "/portal/api/consent",
		`{"cid":"`+other+`","purpose":"support","granted":false}`)
	if rec.Code == 200 {
		t.Fatal("consent on a foreign CID must be rejected")
	}

	// The SPA serves with a locked-down CSP.
	rec, _ = e.call(t, "", "GET", "/portal/", "")
	if rec.Code != 200 || !strings.Contains(rec.Header().Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatalf("SPA: %d CSP=%q", rec.Code, rec.Header().Get("Content-Security-Policy"))
	}
}
