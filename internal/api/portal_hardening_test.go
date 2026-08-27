package api

// Permanent regression tests for three properties that were once
// broken: the outbox must survive a transient mailer failure, it must hold
// nothing usable at rest, and Start must not separate known from unknown
// addresses by timing.

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/service"
)

// A transient mailer failure must not lose the login link.
func TestPortalOutboxRetriesTransientFailure(t *testing.T) {
	e := newPortalEnv(t)
	ctx := context.Background()
	e.register(t, "flaky@example.com")

	failing := true
	flaky := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failing {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(200)
	}))
	defer flaky.Close()
	if _, err := e.srv.Store.Pool.Exec(ctx,
		`UPDATE webhooks SET url=$1 WHERE scope='_portal'`, flaky.URL); err != nil {
		t.Fatal(err)
	}
	if rec, _ := e.call(t, "", "POST", "/portal/api/start", `{"email":"flaky@example.com"}`); rec.Code != 202 {
		t.Fatal("start")
	}

	// First sweep fails; the row must stay PENDING with an attempt counted.
	if n, err := e.srv.Portal.DeliverPendingMail(ctx); err != nil || n != 0 {
		t.Fatalf("failing sweep: %d %v", n, err)
	}
	var status string
	var attempts int
	if err := e.srv.Store.Pool.QueryRow(ctx,
		`SELECT status, attempts FROM portal_outbox ORDER BY id DESC LIMIT 1`).Scan(&status, &attempts); err != nil {
		t.Fatal(err)
	}
	if status != "PENDING" || attempts != 1 {
		t.Fatalf("a transient failure must stay retryable: status=%s attempts=%d", status, attempts)
	}

	// The mailer recovers: the next sweep delivers.
	failing = false
	if n, err := e.srv.Portal.DeliverPendingMail(ctx); err != nil || n != 1 {
		t.Fatalf("recovery sweep: %d %v", n, err)
	}
	if err := e.srv.Store.Pool.QueryRow(ctx,
		`SELECT status FROM portal_outbox ORDER BY id DESC LIMIT 1`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "DELIVERED" {
		t.Fatalf("after recovery the mail must be delivered, got %s", status)
	}
}

// A permanently dead mailer must eventually stop being retried.
func TestPortalOutboxGivesUpAfterCap(t *testing.T) {
	e := newPortalEnv(t)
	ctx := context.Background()
	e.register(t, "dead@example.com")
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer dead.Close()
	if _, err := e.srv.Store.Pool.Exec(ctx,
		`UPDATE webhooks SET url=$1 WHERE scope='_portal'`, dead.URL); err != nil {
		t.Fatal(err)
	}
	if rec, _ := e.call(t, "", "POST", "/portal/api/start", `{"email":"dead@example.com"}`); rec.Code != 202 {
		t.Fatal("start")
	}
	var status string
	for i := 0; i < 10; i++ {
		if _, err := e.srv.Portal.DeliverPendingMail(ctx); err != nil {
			t.Fatal(err)
		}
		if err := e.srv.Store.Pool.QueryRow(ctx,
			`SELECT status FROM portal_outbox ORDER BY id DESC LIMIT 1`).Scan(&status); err != nil {
			t.Fatal(err)
		}
		if status == "FAILED" {
			return
		}
	}
	t.Fatalf("a dead mailer must eventually abandon the row, still %s", status)
}

// Nothing in the outbox or the throttle table is usable by a database
// reader: the token is sealed and the address index is a keyed HMAC.
func TestPortalOutboxHoldsNothingUsableAtRest(t *testing.T) {
	e := newPortalEnv(t)
	ctx := context.Background()
	e.register(t, "atrest@example.com")
	if rec, _ := e.call(t, "", "POST", "/portal/api/start", `{"email":"atrest@example.com"}`); rec.Code != 202 {
		t.Fatal("start")
	}

	// The stored payload is ciphertext: it contains neither the address nor
	// anything redeemable.
	var payload []byte
	var keyID, alg string
	if err := e.srv.Store.Pool.QueryRow(ctx,
		`SELECT payload, key_id, alg FROM portal_outbox ORDER BY id DESC LIMIT 1`).Scan(&payload, &keyID, &alg); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), "atrest@example.com") {
		t.Fatal("the queued address must not be readable in the database")
	}
	if keyID == "" || alg == "" {
		t.Fatal("the sealed payload must record its key version and algorithm")
	}
	// Feeding the raw bytes to the session endpoint cannot log anyone in.
	if rec, _ := e.call(t, "", "POST", "/portal/api/session",
		`{"token":"`+strings.ReplaceAll(string(payload), `"`, "")+`"}`); rec.Code == 200 {
		t.Fatal("a database reader must not be able to redeem the queued token")
	}

	// The throttle key must not be a bare hash of the address: an unkeyed
	// digest would make this table a dictionary-attackable list of
	// registered addresses.
	bare := sha256.Sum256([]byte("atrest@example.com"))
	var matches int
	if err := e.srv.Store.Pool.QueryRow(ctx,
		`SELECT count(*) FROM portal_email_throttle WHERE email_token = $1`, bare[:]).Scan(&matches); err != nil {
		t.Fatal(err)
	}
	if matches != 0 {
		t.Fatal("the throttle index must be a KEYED token, not sha256(address)")
	}
	// ...and a row DOES exist (the throttle is actually recording sends).
	var rows int
	if err := e.srv.Store.Pool.QueryRow(ctx,
		`SELECT count(*) FROM portal_email_throttle`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("the throttle must record the send, found %d rows", rows)
	}
}

// The attacker's real experiment: many distinct addresses, one probe each,
// hits interleaved with misses. Perfect separation would mean single-shot
// enumeration.
func TestPortalStartTimingDoesNotSeparate(t *testing.T) {
	e := newPortalEnv(t)
	const n = 30
	for i := 0; i < n; i++ {
		e.register(t, fmt.Sprintf("known%d@example.com", i))
	}
	call := func(email string, i int) time.Duration {
		req := httptest.NewRequest("POST", "/portal/api/start", strings.NewReader(`{"email":"`+email+`"}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = fmt.Sprintf("203.0.113.%d:1000", i%250+1)
		rec := httptest.NewRecorder()
		start := time.Now()
		e.srv.Handler().ServeHTTP(rec, req)
		d := time.Since(start)
		if rec.Code != 202 {
			t.Fatalf("code %d", rec.Code)
		}
		return d
	}
	for i := 0; i < 30; i++ {
		call("warm@example.com", i) // warm caches and connections
	}
	var hits, misses []time.Duration
	for i := 0; i < n; i++ {
		misses = append(misses, call(fmt.Sprintf("ghost%d@example.com", i), i))
		hits = append(hits, call(fmt.Sprintf("known%d@example.com", i), i))
	}
	// (1) The constant-time FLOOR is real. Nothing asserted this, so
	// deleting the floor did not fail the test as long as both branches
	// sped up together - and the floor is the whole mechanism (TESTS-2).
	floor := service.PortalStartFloor()
	// A small tolerance for timer granularity; the point is that a response
	// cannot come back in single-digit milliseconds.
	tolerance := 3 * time.Millisecond
	for i, d := range append(append([]time.Duration{}, hits...), misses...) {
		if d+tolerance < floor {
			t.Fatalf("sample %d returned in %s, below the %s constant-time floor - the floor is not being applied", i, d, floor)
		}
	}

	sort.Slice(hits, func(i, j int) bool { return hits[i] < hits[j] })
	sort.Slice(misses, func(i, j int) bool { return misses[i] < misses[j] })
	hitMed, missMed := hits[n/2], misses[n/2]
	t.Logf("hit  min=%s median=%s max=%s", hits[0], hitMed, hits[n-1])
	t.Logf("miss min=%s median=%s max=%s", misses[0], missMed, misses[n-1])

	// (2) A LOCATION statistic. The old assertion - "the fastest hit is not
	// slower than the slowest miss" - fails only on complete disjointness,
	// so a handler whose known-address branch was systematically 15ms
	// slower passed unconditionally as long as the noisy tails overlapped.
	// An attacker taking the median of nine probes separates that easily.
	delta := hitMed - missMed
	if delta < 0 {
		delta = -delta
	}
	if delta > 8*time.Millisecond {
		t.Fatalf("median hit %s vs median miss %s (delta %s): the branches separate on a location statistic, which is all an attacker needs",
			hitMed, missMed, delta)
	}

	// (3) The cheap disjointness check, kept.
	if hits[0] > misses[n-1] {
		t.Fatalf("perfect separation: slowest miss %s < fastest hit %s - single-shot enumeration",
			misses[n-1], hits[0])
	}
}

// The remaining portal handler branches: data on a dead pool, logout error
// path, and the SPA served on the dedicated mux.
func TestPortalHandlerRemainingBranches(t *testing.T) {
	e := newPortalEnv(t)
	e.register(t, "branches@example.com")
	session := e.login(t, "branches@example.com")

	// /me after the store dies: a 5xx, never a partial PII response.
	e.srv.Store.Close()
	rec, _ := e.call(t, session, "GET", "/portal/api/me", "")
	if rec.Code == 200 {
		t.Fatal("a dead pool must not yield a successful data response")
	}
	// Logout on a dead pool still clears the cookie and answers 200: the
	// citizen must always be able to drop the session client-side.
	rec, _ = e.call(t, session, "POST", "/portal/api/logout", "{}")
	if rec.Code != 200 {
		t.Fatalf("logout must not fail on a backend error: %d", rec.Code)
	}
	var cleared bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == portalSessionCookie && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("logout must expire the cookie")
	}
	// The SPA still serves (it touches no database).
	rec, _ = e.call(t, "", "GET", "/portal/", "")
	if rec.Code != 200 {
		t.Fatalf("the SPA must not depend on the database: %d", rec.Code)
	}
}

// The remaining Start branches: an unparseable address, and a person whose
// e-mail token is unreadable (denied key material) - both must answer 202.
func TestPortalStartEdgeInputs(t *testing.T) {
	e := newPortalEnv(t)
	// Distinct source addresses: the per-route limit is deliberately strict
	// (5/min), which would otherwise mask these branches.
	start := func(i int, body string) int {
		req := httptest.NewRequest("POST", "/portal/api/start", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = fmt.Sprintf("198.51.100.%d:9000", i+1)
		rec := httptest.NewRecorder()
		e.srv.Handler().ServeHTTP(rec, req)
		return rec.Code
	}
	for i, email := range []string{"", "   ", "@", "no-at-sign", strings.Repeat("a", 400) + "@x.com"} {
		if code := start(i, `{"email":"`+email+`"}`); code != 202 {
			t.Fatalf("start(%q): %d", email, code)
		}
	}
	// A body without the field at all is still accepted (same response).
	if code := start(90, `{}`); code != 202 {
		t.Fatal("a missing email field must not change the response")
	}
	// Nothing was queued for any of them.
	var queued int
	if err := e.srv.Store.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM portal_outbox`).Scan(&queued); err != nil {
		t.Fatal(err)
	}
	if queued != 0 {
		t.Fatalf("malformed addresses must queue nothing, got %d", queued)
	}
}

// The session endpoint's own branches: malformed body, empty token.
func TestPortalSessionEdgeInputs(t *testing.T) {
	e := newPortalEnv(t)
	if rec, _ := e.call(t, "", "POST", "/portal/api/session", `{broken`); rec.Code != 400 {
		t.Fatal("broken JSON must be 400")
	}
	if rec, _ := e.call(t, "", "POST", "/portal/api/session", `{"token":""}`); rec.Code == 200 {
		t.Fatal("an empty token must not create a session")
	}
	if rec, _ := e.call(t, "", "POST", "/portal/api/consent", `{broken`); rec.Code != 401 {
		t.Fatal("consent without a session must be 401 before parsing")
	}
}

// TestDeliveryQueuesDrainConcurrently: a hanging mailer must not starve the
// erasure-webhook queue - an Article 17 delivery path.
//
// This test used to seed only ONE of the two queues it claimed to test in
// parallel: no erasure event was ever queued, so GDPR.DeliverPending's claim
// SELECT returned nothing and finished in microseconds. Replacing the two
// goroutines with two SEQUENTIAL calls left the elapsed time unchanged and
// the test still passed, so it could not distinguish concurrent from
// sequential drain at all (TESTS-1). Both queues carry slow work now, and
// the assertion is on the RENDEZVOUS rather than on wall-clock: it is exact
// under load instead of a threshold that flakes.
func TestDeliveryQueuesDrainConcurrently(t *testing.T) {
	e := newPortalEnv(t)
	ctx := context.Background()
	e.register(t, "concurrent@example.com")

	// Both endpoints block until BOTH have been entered. Sequential drain
	// can never satisfy that (the first would wait for a request the second
	// sweep has not made yet); concurrent drain always does. A rendezvous
	// rather than a wall-clock threshold, so the assertion is exact under
	// CI load instead of flaky.
	mailIn, eraseIn := make(chan struct{}), make(chan struct{})
	var mailOnce, eraseOnce sync.Once
	rendezvous := func(mine chan struct{}, once *sync.Once, other chan struct{}) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			once.Do(func() { close(mine) })
			select {
			case <-other:
			case <-time.After(5 * time.Second):
			}
			w.WriteHeader(200)
		}
	}

	// Seed the ERASURE queue FIRST, while the crm scope still has no
	// webhook: Erase dispatches a detached delivery of its own, and letting
	// that hit the rendezvous handler would consume the erasure side before
	// the test starts.
	victim := e.register(t, "erase-me@example.com")
	officer := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions: []string{auth.ActDSRErase}, AllowedPurposes: []string{"support"}}
	if _, _, _, err := e.srv.GDPR.EraseWithCascade(ctx, officer, victim, nil); err != nil {
		t.Fatal(err)
	}
	e.srv.GDPR.Drain()

	mailer := httptest.NewServer(rendezvous(mailIn, &mailOnce, eraseIn))
	defer mailer.Close()
	if _, err := e.srv.Store.Pool.Exec(ctx,
		`UPDATE webhooks SET url=$1 WHERE scope='_portal'`, mailer.URL); err != nil {
		t.Fatal(err)
	}
	eraseHook := httptest.NewServer(rendezvous(eraseIn, &eraseOnce, mailIn))
	defer eraseHook.Close()
	if _, err := e.srv.Store.Pool.Exec(ctx,
		`INSERT INTO webhooks (scope, url, secret) VALUES ('crm', $1, 's')
		 ON CONFLICT (scope) DO UPDATE SET url=$1`, eraseHook.URL); err != nil {
		t.Fatal(err)
	}
	// The event was settled NO_WEBHOOK a moment ago (no endpoint existed);
	// with one registered it is deliverable again.
	if _, err := e.srv.Store.Pool.Exec(ctx,
		`UPDATE erasure_events SET status='PENDING', attempts=0, claimed_at=NULL`); err != nil {
		t.Fatal(err)
	}

	// Seed the MAIL queue.
	if rec, _ := e.call(t, "", "POST", "/portal/api/start", `{"email":"concurrent@example.com"}`); rec.Code != 202 {
		t.Fatal("start")
	}

	var wg sync.WaitGroup
	wg.Add(2)
	var mailErr, eraseErr error
	var mailed, delivered int
	go func() { defer wg.Done(); mailed, mailErr = e.srv.Portal.DeliverPendingMail(ctx) }()
	go func() { defer wg.Done(); delivered, eraseErr = e.srv.GDPR.DeliverPending(ctx) }()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the two queues did not drain concurrently: each endpoint waits for the other to be entered, so a sequential drain deadlocks until the 5s handler timeout")
	}
	if mailErr != nil || eraseErr != nil {
		t.Fatalf("sweeps: mail=%v erase=%v", mailErr, eraseErr)
	}
	if mailed != 1 || delivered != 1 {
		t.Fatalf("both sweeps must have delivered one item: mail=%d erase=%d", mailed, delivered)
	}
}

// The portal listener's timeout set: the claim the old test's NAME made and
// its body never checked (TESTS-1). The portal is the UNAUTHENTICATED public
// surface, so a slow-loris there is cheaper for an attacker than anywhere
// else - every timeout must be set, and set to the API listener's values.
func TestPortalListenerCarriesTheFullTimeoutSet(t *testing.T) {
	e := newPortalEnv(t)
	e.srv.Cfg.PortalListen = "127.0.0.1:0"
	e.srv.Cfg.Listen = "127.0.0.1:0"

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- e.srv.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-runDone })

	var portal, api *http.Server
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		portal, api = e.srv.ServersForTest()
		if portal != nil && api != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if portal == nil {
		t.Fatal("the portal listener was never constructed")
	}
	for _, tc := range []struct {
		name          string
		portalD, apiD time.Duration
	}{
		{"ReadHeaderTimeout", portal.ReadHeaderTimeout, api.ReadHeaderTimeout},
		{"ReadTimeout", portal.ReadTimeout, api.ReadTimeout},
		{"WriteTimeout", portal.WriteTimeout, api.WriteTimeout},
		{"IdleTimeout", portal.IdleTimeout, api.IdleTimeout},
	} {
		if tc.portalD == 0 {
			t.Errorf("portal listener %s is unset - the unauthenticated surface must not be slow-loris-able", tc.name)
			continue
		}
		// The portal may be STRICTER than the API (it is: a shorter read
		// budget for an unauthenticated surface), never looser.
		if tc.apiD != 0 && tc.portalD > tc.apiD {
			t.Errorf("portal listener %s (%s) is looser than the API listener's (%s)", tc.name, tc.portalD, tc.apiD)
		}
	}
}
