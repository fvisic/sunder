package api

// P2.5 portal e2e: magic-link login (via the '_portal' mailer webhook),
// self-access, consent flip that visibly blocks a read, two-step erasure,
// and the no-enumeration guarantee.

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/config"
	"github.com/fvisic/sunder/internal/testutil"
)

type portalEnv struct {
	srv         *Server
	credCRM     string
	mailer      *httptest.Server
	mu          sync.Mutex
	tokens      []string // login tokens the "mailer" received
	eraseTokens []string // erasure confirmations the "mailer" received
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
		e.mu.Lock()
		switch body.Event {
		case "portal_login":
			e.tokens = append(e.tokens, body.Token)
		case "portal_erase_confirm":
			e.eraseTokens = append(e.eraseTokens, body.Token)
		}
		e.mu.Unlock()
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
	srv, err := New(config.Config{Listen: ":0", Keystore: "file", KeystorePath: t.TempDir(),
		PortalEnabled: true, PortalBaseURL: "https://privacy.example"}, st)
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
	// Mail is queued, not sent inline (that inline send was the
	// enumeration oracle, review N2): drain the outbox like the background
	// worker does.
	if _, err := e.srv.Portal.DeliverPendingMail(context.Background()); err != nil {
		t.Fatal(err)
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
	if rec.Code != 202 {
		t.Fatalf("erase request: %d", rec.Code)
	}
	// The response must NOT carry the token: holding the cookie is not
	// enough to finish an irreversible erasure (review N3).
	if _, leaked := out["confirm_token"]; leaked {
		t.Fatal("the confirmation token must not be returned to the session")
	}
	if _, err := e.srv.Portal.DeliverPendingMail(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	confirm := e.eraseTokens[len(e.eraseTokens)-1]
	e.mu.Unlock()
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

	// Login tokens are single-use and garbage is rejected. Drain the outbox
	// first: nothing is mailed inline any more (review N2).
	if _, err := e.srv.Portal.DeliverPendingMail(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	if len(e.tokens) == 0 {
		e.mu.Unlock()
		t.Fatal("the known address must have produced exactly one queued mail")
	}
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

// N2: the headline property, measured rather than asserted on the body.
// Start must not do an outbound network round-trip on the hit path - that
// difference is what made enumeration practical.
func TestPortalStartDoesNotMailInline(t *testing.T) {
	e := newPortalEnv(t)
	e.register(t, "known@example.com")

	// A deliberately slow mailer: if Start delivered inline, the known
	// address would take at least this long and the unknown one would not.
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(700 * time.Millisecond)
		w.WriteHeader(200)
	}))
	defer slow.Close()
	if _, err := e.srv.Store.Pool.Exec(context.Background(),
		`UPDATE webhooks SET url=$1 WHERE scope='_portal'`, slow.URL); err != nil {
		t.Fatal(err)
	}

	timed := func(email string) time.Duration {
		start := time.Now()
		rec, _ := e.call(t, "", "POST", "/portal/api/start", `{"email":"`+email+`"}`)
		if rec.Code != 202 {
			t.Fatalf("start(%s): %d", email, rec.Code)
		}
		return time.Since(start)
	}
	hit := timed("known@example.com")
	miss := timed("nobody@example.com")
	if hit > 300*time.Millisecond {
		t.Fatalf("known address must not block on the mailer: %s", hit)
	}
	// The remaining difference is one INSERT, not a network round-trip.
	if hit > miss+300*time.Millisecond {
		t.Fatalf("hit/miss timing gap too wide: hit=%s miss=%s", hit, miss)
	}

	// The mail is queued, not lost.
	var pending int
	if err := e.srv.Store.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM portal_outbox WHERE status='PENDING'`).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending != 1 {
		t.Fatalf("expected exactly one queued mail, got %d", pending)
	}
}

// N9: one address cannot be mail-bombed, however many requests arrive.
func TestPortalPerAddressSendThrottle(t *testing.T) {
	e := newPortalEnv(t)
	e.register(t, "victim@example.com")
	// Two independent brakes apply: the per-route IP limit (429) and the
	// per-address send throttle. Either outcome is acceptable per request;
	// what must hold is that no mail bomb reaches the victim.
	for i := 0; i < 8; i++ {
		rec, _ := e.call(t, "", "POST", "/portal/api/start", `{"email":"victim@example.com"}`)
		if rec.Code != 202 && rec.Code != 429 {
			t.Fatalf("start %d: %d", i, rec.Code)
		}
	}
	var queued int
	if err := e.srv.Store.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM portal_outbox WHERE kind='login'`).Scan(&queued); err != nil {
		t.Fatal(err)
	}
	if queued > 3 {
		t.Fatalf("per-address throttle must cap queued login mails, got %d", queued)
	}
}

// Logout, session hygiene and the proxy-header opt-in.
func TestPortalLogoutAndProxyHeader(t *testing.T) {
	e := newPortalEnv(t)
	e.register(t, "logout@example.com")
	session := e.login(t, "logout@example.com")

	if rec, _ := e.call(t, session, "GET", "/portal/api/me", ""); rec.Code != 200 {
		t.Fatal("session must work before logout")
	}
	rec, _ := e.call(t, session, "POST", "/portal/api/logout", "{}")
	if rec.Code != 200 {
		t.Fatalf("logout: %d", rec.Code)
	}
	// The cookie is cleared AND the row is gone: replaying the value fails.
	if rec, _ := e.call(t, session, "GET", "/portal/api/me", ""); rec.Code != 401 {
		t.Fatal("a logged-out session must not be replayable")
	}
	// Logout without a cookie is a no-op success, not a 500.
	if rec, _ := e.call(t, "", "POST", "/portal/api/logout", "{}"); rec.Code != 200 {
		t.Fatal("logout without a session must succeed quietly")
	}

	// Portal responses must never be cacheable (they carry decrypted PII).
	session2 := e.login(t, "logout@example.com")
	rec, _ = e.call(t, session2, "GET", "/portal/api/me", "")
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Fatalf("portal responses must be no-store, got %q", cc)
	}

	// The SPA carries a per-response nonce and no 'unsafe-inline'.
	rec, _ = e.call(t, "", "GET", "/portal/", "")
	csp := rec.Header().Get("Content-Security-Policy")
	if strings.Contains(csp, "unsafe-inline") && !strings.Contains(csp, "style-src 'unsafe-inline'") {
		t.Fatalf("script-src must not allow unsafe-inline: %q", csp)
	}
	for _, want := range []string{"nonce-", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'none'"} {
		if !strings.Contains(csp, want) {
			t.Fatalf("CSP missing %q: %q", want, csp)
		}
	}
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("the erase button must not be framable")
	}
	if strings.Contains(rec.Body.String(), "__NONCE__") {
		t.Fatal("the nonce placeholder must be substituted")
	}
}

// The portal is off unless enabled, and the mailed link is a real link.
func TestPortalDisabledByDefaultAndLinkFormat(t *testing.T) {
	st := testutil.NewDB(t)
	srv, err := New(config.Config{Listen: ":0", Keystore: "file", KeystorePath: t.TempDir()}, st)
	if err != nil {
		t.Fatal(err)
	}
	if srv.Portal != nil {
		t.Fatal("the portal must be nil unless SUNDER_PORTAL_ENABLED")
	}
	req := httptest.NewRequest("GET", "/portal/", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != 404 {
		t.Fatalf("a disabled portal must not be routed: %d", rec.Code)
	}

	// With a base URL configured, the mail payload carries a clickable link
	// whose token rides the FRAGMENT (never sent to a server, never in a
	// Referer header).
	e := newPortalEnv(t)
	e.register(t, "link@example.com")
	var gotLink string
	e.mailer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Link  string `json:"link"`
			Token string `json:"token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotLink = body.Link
		w.WriteHeader(200)
	})
	if rec, _ := e.call(t, "", "POST", "/portal/api/start", `{"email":"link@example.com"}`); rec.Code != 202 {
		t.Fatal("start")
	}
	if _, err := e.srv.Portal.DeliverPendingMail(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(gotLink, "https://privacy.example/portal/#token=") {
		t.Fatalf("the mailed link must carry the token in the fragment: %q", gotLink)
	}
}

// portalClientIP: RemoteAddr by default, the named header only when the
// operator opted in, left-most entry of a comma list, and never a header
// that was not configured.
func TestPortalClientIPResolution(t *testing.T) {
	plain := &Server{}
	req := httptest.NewRequest("POST", "/portal/api/start", nil)
	req.RemoteAddr = "198.51.100.4:5555"
	req.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.1")
	if got := plain.portalClientIP(req); got != "198.51.100.4" {
		t.Fatalf("an unconfigured header must be ignored: %q", got)
	}

	// The RIGHT-most entry is the one our proxy appended; the left-most is
	// caller-supplied, so trusting it hands every requester a fresh bucket
	// (review N9).
	trusting := &Server{Cfg: config.Config{PortalClientIPHeader: "X-Forwarded-For"}}
	if got := trusting.portalClientIP(req); got != "10.0.0.1" {
		t.Fatalf("right-most XFF entry expected: %q", got)
	}
	// With one extra trusted hop, skip one more from the right.
	twoHops := &Server{Cfg: config.Config{
		PortalClientIPHeader: "X-Forwarded-For", PortalTrustedProxyHops: 1}}
	if got := twoHops.portalClientIP(req); got != "203.0.113.9" {
		t.Fatalf("one trusted hop must skip the last entry: %q", got)
	}
	// More hops than entries clamps rather than panicking.
	manyHops := &Server{Cfg: config.Config{
		PortalClientIPHeader: "X-Forwarded-For", PortalTrustedProxyHops: 99}}
	if got := manyHops.portalClientIP(req); got != "203.0.113.9" {
		t.Fatalf("hop count must clamp: %q", got)
	}
	// A spoofed single-entry header from a direct caller yields that entry
	// (the proxy is expected to overwrite it - documented in CONFIG.md).
	spoof := httptest.NewRequest("POST", "/portal/api/start", nil)
	spoof.RemoteAddr = "198.51.100.5:1"
	spoof.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := trusting.portalClientIP(spoof); got != "1.2.3.4" {
		t.Fatalf("single entry: %q", got)
	}
	// Header configured but absent: fall back to RemoteAddr.
	bare := httptest.NewRequest("POST", "/portal/api/start", nil)
	bare.RemoteAddr = "198.51.100.7:1"
	if got := trusting.portalClientIP(bare); got != "198.51.100.7" {
		t.Fatalf("fallback: %q", got)
	}
	// A RemoteAddr with no port (unix socket, some test harnesses).
	odd := httptest.NewRequest("POST", "/portal/api/start", nil)
	odd.RemoteAddr = "not-a-host-port"
	if got := plain.portalClientIP(odd); got != "not-a-host-port" {
		t.Fatalf("malformed RemoteAddr: %q", got)
	}
}

// Error branches on the portal handlers must stay quiet and correct: Start
// never leaks a failure, erase without an address on file is a clean 400.
func TestPortalHandlerErrorBranches(t *testing.T) {
	e := newPortalEnv(t)
	ctx := context.Background()

	// A person with no e-mail attribute in any blob cannot be confirmed
	// against, so erasure request fails validation rather than 500.
	var personID string
	if err := e.srv.Store.Pool.QueryRow(ctx,
		`INSERT INTO persons (id) VALUES (gen_random_uuid()) RETURNING id`).Scan(&personID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.srv.Store.Pool.Exec(ctx,
		`INSERT INTO cids (cid, person_id, scope) VALUES ('CID-NOEMAIL0000000000000000AA', $1, 'crm')`, personID); err != nil {
		t.Fatal(err)
	}
	session, err := mintPortalSession(ctx, e, personID)
	if err != nil {
		t.Fatal(err)
	}
	rec, out := e.call(t, session, "POST", "/portal/api/erase", "{}")
	if rec.Code != 400 {
		t.Fatalf("no address on file must be a clean validation error: %d %v", rec.Code, out)
	}

	// Start on a dead pool must still answer 202 with the same body: the
	// citizen-facing response never depends on backend health.
	e2 := newPortalEnv(t)
	e2.srv.Store.Close()
	rec, out = e2.call(t, "", "POST", "/portal/api/start", `{"email":"anyone@example.com"}`)
	if rec.Code != 202 || out["status"] == "" {
		t.Fatalf("start must not leak backend failures: %d %v", rec.Code, out)
	}
	// /me on a dead pool is a 401 (no resolvable session), never a 500 leak.
	if rec, _ := e2.call(t, "deadsession", "GET", "/portal/api/me", ""); rec.Code != 401 {
		t.Fatalf("me on a dead pool: %d", rec.Code)
	}
}

// mintPortalSession creates a live session row directly, for cases the
// magic-link flow cannot reach (a person with no e-mail on file).
func mintPortalSession(ctx context.Context, e *portalEnv, personID string) (string, error) {
	token := "test-session-" + personID
	sum := sha256.Sum256([]byte(token))
	_, err := e.srv.Store.Pool.Exec(ctx,
		`INSERT INTO portal_sessions (session_hash, person_id, expires_at) VALUES ($1,$2, now() + interval '10 minutes')`,
		sum[:], personID)
	return token, err
}

// The external-claims endpoint is rate-limited: every envelope, accepted or
// rejected, appends to the audit chain under a global lock.
func TestExternalClaimsIsRateLimited(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewDB(t)
	cred, err := auth.Create(ctx, st.Pool, auth.Client{
		ID: "gw", Name: "GW", Scope: "crm",
		AllowedActions: []string{auth.ActClaimsExternal}, AllowedPurposes: []string{"kyc"},
		RateLimit: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(config.Config{Listen: ":0", Keystore: "file", KeystorePath: t.TempDir()}, st)
	if err != nil {
		t.Fatal(err)
	}
	var got429 bool
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("POST", "/v1/claims/external",
			strings.NewReader(`{"cid":"CID-X","envelope":"nope"}`))
		req.Header.Set("Authorization", "Bearer "+cred)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code == 429 {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Fatal("claims.external must be rate-limited: each call appends to the audit chain")
	}
}
