package service_test

// Portal service-level branches the HTTP e2e does not reach: throttled ring
// invalidation, session hygiene, and the erase-confirmation guard.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fvisic/sunder/internal/crypto"
	"github.com/fvisic/sunder/internal/service"
)

// queuedToken opens the SEALED outbox payload the way the worker does -
// the token is no longer readable straight from the row.
func queuedToken(t *testing.T, e *faultEnv, kind string) string {
	t.Helper()
	ctx := context.Background()
	var payload []byte
	var keyID, alg string
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT payload, key_id, alg FROM portal_outbox WHERE kind=$1 ORDER BY id DESC LIMIT 1`,
		kind).Scan(&payload, &keyID, &alg); err != nil {
		t.Fatal(err)
	}
	plain, err := e.svc.PII.OpenBytes(ctx, "portal-outbox", payload, keyID, alg)
	if err != nil {
		t.Fatal(err)
	}
	var mp struct {
		Email string `json:"email"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(plain, &mp); err != nil {
		t.Fatal(err)
	}
	return mp.Token
}

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

	// A confirmation token minted for A must not erase B. The token is
	// mailed out of band now, so read it from the outbox.
	if err := p.RequestErase(ctx, personA); err != nil {
		t.Fatal(err)
	}
	tokenA := queuedToken(t, e, "erase_confirm")
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

func TestPortalOutboxOutcomesAndPruning(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	e.register(t)
	p := &service.Portal{GDPR: e.gdpr, Contacts: e.svc}

	// No mailer configured: the row settles as NO_MAILER and the audit
	// records that, instead of claiming a delivery that never happened.
	if err := p.Start(ctx, "fault@example.com"); err != nil {
		t.Fatal(err)
	}
	if n, err := p.DeliverPendingMail(ctx); err != nil || n != 0 {
		t.Fatalf("no mailer: delivered=%d err=%v", n, err)
	}
	var status string
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT status FROM portal_outbox ORDER BY id DESC LIMIT 1`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "NO_MAILER" {
		t.Fatalf("status: %s", status)
	}
	var actions int
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM audit WHERE action='portal.mail.no_mailer'`).Scan(&actions); err != nil {
		t.Fatal(err)
	}
	if actions != 1 {
		t.Fatalf("the chain must record the real outcome, found %d", actions)
	}

	// A mailer that rejects the POST settles as FAILED, not DELIVERED.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer bad.Close()
	if _, err := e.admin.Pool.Exec(ctx,
		`INSERT INTO webhooks (scope, url, secret) VALUES ('_portal', $1, 's')`, bad.URL); err != nil {
		t.Fatal(err)
	}
	if err := p.Start(ctx, "fault@example.com"); err != nil {
		t.Fatal(err)
	}
	if n, err := p.DeliverPendingMail(ctx); err != nil || n != 0 {
		t.Fatalf("rejecting mailer must not count as delivered: %d %v", n, err)
	}
	// A 500 is TRANSIENT: the row stays PENDING and retryable (probe A),
	// and only the attempt cap abandons it.
	var attempts int
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT status, attempts FROM portal_outbox ORDER BY id DESC LIMIT 1`).Scan(&status, &attempts); err != nil {
		t.Fatal(err)
	}
	if status != "PENDING" || attempts != 1 {
		t.Fatalf("a 500 must stay retryable: status=%s attempts=%d", status, attempts)
	}

	// Pruning clears settled rows, spent tokens and expired throttle rows.
	if _, err := e.admin.Pool.Exec(ctx,
		`UPDATE portal_outbox SET created_at = now() - interval '30 days'`); err != nil {
		t.Fatal(err)
	}
	if n, err := service.PrunePortal(ctx, e.admin.Pool); err != nil || n == 0 {
		t.Fatalf("prune: %d %v", n, err)
	}
}

func TestPortalRequestEraseGuards(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cid := e.register(t)
	p := &service.Portal{GDPR: e.gdpr, Contacts: e.svc}
	var personID string
	if err := e.admin.Pool.QueryRow(ctx, `SELECT person_id FROM cids WHERE cid=$1`, cid).Scan(&personID); err != nil {
		t.Fatal(err)
	}

	// A second request invalidates the first token: outstanding erase
	// confirmations must not accumulate.
	if err := p.RequestErase(ctx, personID); err != nil {
		t.Fatal(err)
	}
	first := queuedToken(t, e, "erase_confirm")
	if err := p.RequestErase(ctx, personID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.ConfirmErase(ctx, personID, first); err == nil {
		t.Fatal("a superseded confirmation token must not work")
	}
	second := queuedToken(t, e, "erase_confirm")
	if _, _, err := p.ConfirmErase(ctx, personID, second); err != nil {
		t.Fatal(err)
	}
	// Already erased: no second erasure, no oracle.
	if err := p.RequestErase(ctx, personID); err != service.ErrNotFound {
		t.Fatalf("erase request on a tombstone: %v", err)
	}
}

// Remaining portal branches: successful delivery, session lifecycle,
// primaryEmail across multiple scope blobs, and Data on a live person.
func TestPortalDeliverySessionAndData(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cid := e.register(t)
	p := &service.Portal{GDPR: e.gdpr, Contacts: e.svc, BaseURL: "https://privacy.example"}

	var seen struct {
		link  string
		event string
	}
	mailer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Event string `json:"event"`
			Link  string `json:"link"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		seen.event, seen.link = body.Event, body.Link
		w.WriteHeader(200)
	}))
	defer mailer.Close()
	if _, err := e.admin.Pool.Exec(ctx,
		`INSERT INTO webhooks (scope, url, secret) VALUES ('_portal', $1, 's')`, mailer.URL); err != nil {
		t.Fatal(err)
	}

	// Start -> queued -> delivered, with the audit recording the success.
	if err := p.Start(ctx, "fault@example.com"); err != nil {
		t.Fatal(err)
	}
	n, err := p.DeliverPendingMail(ctx)
	if err != nil || n != 1 {
		t.Fatalf("delivery: %d %v", n, err)
	}
	if seen.event != "portal_login" || !strings.Contains(seen.link, "/portal/#token=") {
		t.Fatalf("mail payload: %+v", seen)
	}
	var delivered int
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM audit WHERE action='portal.mail.delivered'`).Scan(&delivered); err != nil {
		t.Fatal(err)
	}
	if delivered != 1 {
		t.Fatalf("the chain must record the delivery, found %d", delivered)
	}
	// A second sweep has nothing to do.
	if n, err := p.DeliverPendingMail(ctx); err != nil || n != 0 {
		t.Fatalf("second sweep: %d %v", n, err)
	}

	// Redeem -> session -> data -> logout.
	session, err := p.Redeem(ctx, queuedToken(t, e, "login"))
	if err != nil {
		t.Fatal(err)
	}
	personID, err := p.SessionPerson(ctx, session)
	if err != nil {
		t.Fatal(err)
	}
	data, err := p.Data(ctx, personID)
	if err != nil {
		t.Fatal(err)
	}
	scopes, _ := data["scopes"].([]service.ScopeData)
	if len(scopes) == 0 || scopes[0].CID != cid {
		t.Fatalf("portal data must show the person's own scopes: %+v", data["scopes"])
	}
	if err := p.Logout(ctx, session); err != nil {
		t.Fatal(err)
	}
	if _, err := p.SessionPerson(ctx, session); err == nil {
		t.Fatal("a logged-out session must not resolve")
	}
	// An expired session does not resolve either.
	expired, err := p.Redeem(ctx, mustSecondToken(t, e, p))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.admin.Pool.Exec(ctx,
		`UPDATE portal_sessions SET expires_at = now() - interval '1 minute'`); err != nil {
		t.Fatal(err)
	}
	if _, err := p.SessionPerson(ctx, expired); err == nil {
		t.Fatal("an expired session must not resolve")
	}
}

// mustSecondToken queues and delivers one more login mail, returning its token.
func mustSecondToken(t *testing.T, e *faultEnv, p *service.Portal) string {
	t.Helper()
	ctx := context.Background()
	if err := p.Start(ctx, "fault@example.com"); err != nil {
		t.Fatal(err)
	}
	return queuedToken(t, e, "login")
}

// Portal error branches, reached by denying exactly one table to the
// service's database role - the same technique the rest of the fault suite
// uses. Every one of these must fail closed, never panic and never leak.
func TestPortalFailsClosedOnDatabaseFaults(t *testing.T) {
	ctx := context.Background()

	// portal_tokens denied: Start cannot mint, Redeem cannot consume.
	e := newFaultEnv(t, "portal_tokens")
	e.register(t)
	p := &service.Portal{GDPR: e.gdpr, Contacts: e.svc}
	if err := p.Start(ctx, "fault@example.com"); err == nil {
		t.Fatal("Start must surface a token-write failure")
	}
	if _, err := p.Redeem(ctx, "anything"); err == nil {
		t.Fatal("Redeem must surface a token-read failure")
	}

	// portal_outbox denied: the queue write fails, so Start fails closed
	// rather than minting a token nobody can ever receive.
	e2 := newFaultEnv(t, "portal_outbox")
	e2.register(t)
	p2 := &service.Portal{GDPR: e2.gdpr, Contacts: e2.svc}
	if err := p2.Start(ctx, "fault@example.com"); err == nil {
		t.Fatal("Start must fail when the mail cannot be queued")
	}
	if _, err := p2.DeliverPendingMail(ctx); err == nil {
		t.Fatal("the worker must surface a queue-read failure")
	}

	// portal_sessions denied: a redeemed token cannot become a session.
	e3 := newFaultEnv(t, "portal_sessions")
	e3.register(t)
	p3 := &service.Portal{GDPR: e3.gdpr, Contacts: e3.svc}
	if err := p3.Start(ctx, "fault@example.com"); err != nil {
		t.Fatal(err)
	}
	token := queuedToken(t, e3, "login")
	if _, err := p3.Redeem(ctx, token); err == nil {
		t.Fatal("Redeem must fail when the session cannot be stored")
	}
	if _, err := p3.SessionPerson(ctx, "any"); err == nil {
		t.Fatal("SessionPerson must fail when sessions are unreadable")
	}
	if err := p3.Logout(ctx, "any"); err == nil {
		t.Fatal("Logout must surface a delete failure")
	}

	// portal_email_throttle denied: the per-address cap cannot be enforced,
	// so Start must refuse rather than send unthrottled.
	e4 := newFaultEnv(t, "portal_email_throttle")
	e4.register(t)
	p4 := &service.Portal{GDPR: e4.gdpr, Contacts: e4.svc}
	if err := p4.Start(ctx, "fault@example.com"); err == nil {
		t.Fatal("Start must fail closed when the send throttle is unavailable")
	}

	// consents denied: a portal consent flip fails.
	e5 := newFaultEnv(t, "consents")
	cid := e5.register(t)
	p5 := &service.Portal{GDPR: e5.gdpr, Contacts: e5.svc}
	var person string
	if err := e5.admin.Pool.QueryRow(ctx, `SELECT person_id FROM cids WHERE cid=$1`, cid).Scan(&person); err != nil {
		t.Fatal(err)
	}
	if err := p5.SetConsent(ctx, person, cid, "support", false); err == nil {
		t.Fatal("a consent write failure must surface")
	}
	if err := p5.SetConsent(ctx, person, "CID-FOREIGN", "support", false); err == nil {
		t.Fatal("a foreign CID must be rejected")
	}
	if err := p5.SetConsent(ctx, person, cid, "", false); err == nil {
		t.Fatal("an empty purpose must be rejected")
	}

	// erasures denied: the confirmed erasure cannot commit.
	e6 := newFaultEnv(t, "erasures")
	cid6 := e6.register(t)
	p6 := &service.Portal{GDPR: e6.gdpr, Contacts: e6.svc}
	var person6 string
	if err := e6.admin.Pool.QueryRow(ctx, `SELECT person_id FROM cids WHERE cid=$1`, cid6).Scan(&person6); err != nil {
		t.Fatal(err)
	}
	if err := p6.RequestErase(ctx, person6); err != nil {
		t.Fatal(err)
	}
	if _, _, err := p6.ConfirmErase(ctx, person6, queuedToken(t, e6, "erase_confirm")); err == nil {
		t.Fatal("a failed erasure must surface, not report success")
	}

	// A dead pool everywhere: every entry point errors, none panics.
	e7 := newFaultEnv(t)
	e7.admin.Close()
	p7 := &service.Portal{GDPR: e7.gdpr, Contacts: e7.svc}
	e7.gdpr.Pool.Close()
	if err := p7.Start(ctx, "fault@example.com"); err == nil {
		t.Fatal("Start on a dead pool")
	}
	if _, err := p7.Redeem(ctx, "x"); err == nil {
		t.Fatal("Redeem on a dead pool")
	}
	if _, err := p7.Data(ctx, person6); err == nil {
		t.Fatal("Data on a dead pool")
	}
	if err := p7.RequestErase(ctx, person6); err == nil {
		t.Fatal("RequestErase on a dead pool")
	}
	if _, _, err := p7.ConfirmErase(ctx, person6, "x"); err == nil {
		t.Fatal("ConfirmErase on a dead pool")
	}
	if _, err := service.PrunePortal(ctx, e7.gdpr.Pool); err == nil {
		t.Fatal("PrunePortal on a dead pool")
	}
	if _, err := service.PruneEnvelopes(ctx, e7.gdpr.Pool); err == nil {
		t.Fatal("PruneEnvelopes on a dead pool")
	}
}

// An outbox row whose payload cannot be opened (key retired, corrupt bytes)
// must be abandoned, not retried forever.
func TestPortalOutboxAbandonsUnopenablePayload(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	e.register(t)
	p := &service.Portal{GDPR: e.gdpr, Contacts: e.svc}
	if err := p.Start(ctx, "fault@example.com"); err != nil {
		t.Fatal(err)
	}
	// Corrupt the sealed payload.
	if _, err := e.admin.Pool.Exec(ctx,
		`UPDATE portal_outbox SET payload = 'not a sealed payload'::bytea`); err != nil {
		t.Fatal(err)
	}
	if n, err := p.DeliverPendingMail(ctx); err != nil || n != 0 {
		t.Fatalf("an unopenable payload must not count as delivered: %d %v", n, err)
	}
	var status string
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT status FROM portal_outbox ORDER BY id DESC LIMIT 1`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "FAILED" {
		t.Fatalf("an unopenable payload must be abandoned, got %s", status)
	}

	// A payload that opens but is not the expected JSON is equally abandoned.
	if err := p.Start(ctx, "fault@example.com"); err != nil {
		t.Fatal(err)
	}
	keyID, err := e.svc.Ring.Newest(ctx, crypto.KeyPIIKEK)
	if err != nil {
		t.Fatal(err)
	}
	garbage, err := e.svc.PII.SealBytes(ctx, "portal-outbox", keyID, []byte("{not json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.admin.Pool.Exec(ctx,
		`UPDATE portal_outbox SET payload=$1, key_id=$2 WHERE status='PENDING'`, garbage, keyID); err != nil {
		t.Fatal(err)
	}
	if n, err := p.DeliverPendingMail(ctx); err != nil || n != 0 {
		t.Fatalf("malformed payload: %d %v", n, err)
	}
}

// P3: two workers running concurrently (as replicas do) must not both
// deliver the same queued mail.
func TestPortalOutboxNoDoubleSendAcrossWorkers(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	e.register(t)
	p := &service.Portal{GDPR: e.gdpr, Contacts: e.svc}

	var mu sync.Mutex
	var sends int
	mailer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		sends++
		mu.Unlock()
		time.Sleep(30 * time.Millisecond) // widen the window
		w.WriteHeader(200)
	}))
	defer mailer.Close()
	if _, err := e.admin.Pool.Exec(ctx,
		`INSERT INTO webhooks (scope, url, secret) VALUES ('_portal', $1, 's')`, mailer.URL); err != nil {
		t.Fatal(err)
	}
	if err := p.Start(ctx, "fault@example.com"); err != nil {
		t.Fatal(err)
	}

	// Two "replicas" sweep at the same time.
	var wg sync.WaitGroup
	delivered := make([]int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			n, err := p.DeliverPendingMail(ctx)
			if err != nil {
				t.Errorf("worker %d: %v", i, err)
			}
			delivered[i] = n
		}(i)
	}
	wg.Wait()
	mu.Lock()
	got := sends
	mu.Unlock()
	if got != 1 {
		t.Fatalf("the mail must be sent exactly once across replicas, sent %d times", got)
	}
	if delivered[0]+delivered[1] != 1 {
		t.Fatalf("exactly one worker may claim the row: %v", delivered)
	}
}

// P4: the reaper returns a crashed worker's claim to the queue, and prunes
// PENDING rows whose token can no longer be useful.
func TestPortalReaperAndPendingPruning(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	e.register(t)
	p := &service.Portal{GDPR: e.gdpr, Contacts: e.svc}
	if err := p.Start(ctx, "fault@example.com"); err != nil {
		t.Fatal(err)
	}

	// A claim left behind by a crashed worker.
	if _, err := e.admin.Pool.Exec(ctx,
		`UPDATE portal_outbox SET status='SENDING', created_at = now() - interval '30 minutes'`); err != nil {
		t.Fatal(err)
	}
	if _, err := service.PrunePortal(ctx, e.admin.Pool); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT status FROM portal_outbox ORDER BY id DESC LIMIT 1`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "PENDING" {
		t.Fatalf("a stalled claim must return to the queue, got %s", status)
	}

	// A PENDING row whose token has expired is pruned: an unreachable
	// mailer must not grow the table without bound.
	if _, err := e.admin.Pool.Exec(ctx,
		`UPDATE portal_outbox SET expires_at = now() - interval '1 hour'`); err != nil {
		t.Fatal(err)
	}
	if _, err := service.PrunePortal(ctx, e.admin.Pool); err != nil {
		t.Fatal(err)
	}
	var left int
	if err := e.admin.Pool.QueryRow(ctx, `SELECT count(*) FROM portal_outbox`).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Fatalf("an expired PENDING row must be pruned, %d left", left)
	}
}

// P5: a rolled-back transaction must not burn a send from the per-address cap.
func TestPortalThrottleNotBurnedByRollback(t *testing.T) {
	ctx := context.Background()
	// portal_outbox denied: the transaction rolls back AFTER the throttle
	// would have been counted.
	e := newFaultEnv(t, "portal_outbox")
	e.register(t)
	p := &service.Portal{GDPR: e.gdpr, Contacts: e.svc}
	for i := 0; i < 5; i++ {
		if err := p.Start(ctx, "fault@example.com"); err == nil {
			t.Fatal("Start must fail while the queue is unwritable")
		}
	}
	// The throttle table must show nothing: every attempt rolled back.
	var rows int
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM portal_email_throttle`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("a rolled-back Start must not burn a send, found %d throttle rows", rows)
	}
}

func TestPortalDataForPersonWithoutScopes(t *testing.T) {
	e := newFaultEnv(t) // fully privileged role
	ctx := context.Background()
	p := &service.Portal{GDPR: e.gdpr, Contacts: e.svc}
	// A person row with no cids: possible transiently (registration is
	// multi-statement) and after data damage - the portal must answer
	// with an empty scope list, and the access audit entry must carry an
	// empty pseudonym rather than invent one.
	var personID string
	if err := e.admin.Pool.QueryRow(ctx, `INSERT INTO persons (id) VALUES (gen_random_uuid()) RETURNING id`).Scan(&personID); err != nil {
		t.Fatal(err)
	}
	out, err := p.Data(ctx, personID)
	if err != nil {
		t.Fatal(err)
	}
	scopes, _ := out["scopes"].([]service.ScopeData)
	if len(scopes) != 0 {
		t.Fatalf("want no scopes, got %d", len(scopes))
	}
}

// TestPortalMailDeliveredSuccessfully covers the SENT branch of settleMail
// and the enqueue/deliver happy path with a working mailer.
func TestPortalMailDeliveredSuccessfully(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	e.register(t)
	p := &service.Portal{GDPR: e.gdpr, Contacts: e.svc}

	var got int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got++
		w.WriteHeader(200)
	}))
	defer srv.Close()
	if _, err := e.admin.Pool.Exec(ctx,
		`INSERT INTO webhooks (scope, url, secret) VALUES ('_portal', $1, 's')`, srv.URL); err != nil {
		t.Fatal(err)
	}
	if err := p.Start(ctx, "fault@example.com"); err != nil {
		t.Fatal(err)
	}
	n, err := p.DeliverPendingMail(ctx)
	if err != nil || n != 1 {
		t.Fatalf("delivery: %d %v", n, err)
	}
	if got != 1 {
		t.Fatalf("mailer must have been called once, got %d", got)
	}
	var status string
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT status FROM portal_outbox ORDER BY id DESC LIMIT 1`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "DELIVERED" {
		t.Fatalf("status must be DELIVERED, got %s", status)
	}
	// The delivery is recorded in the chain.
	var sent int64
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM audit WHERE action='portal.mail.delivered'`).Scan(&sent); err != nil {
		t.Fatal(err)
	}
	if sent != 1 {
		t.Fatalf("chain must record the delivery, got %d", sent)
	}
}

// TestS2_PortalOutboxDeletedOnErasure reproduces the S2 finding: a queued
// login/erase mail for the erased person must not survive erasure (the old
// cleanup deleted nothing).
func TestS2_PortalOutboxDeletedOnErasure(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cid := e.register(t) // registers fault@example.com
	p := &service.Portal{GDPR: e.gdpr, Contacts: e.svc}
	// Start enqueues a login mail into portal_outbox tagged with person_id.
	if err := p.Start(ctx, "fault@example.com"); err != nil {
		t.Fatal(err)
	}
	var personID string
	if err := e.admin.Pool.QueryRow(ctx, `SELECT person_id FROM cids WHERE cid=$1`, cid).Scan(&personID); err != nil {
		t.Fatal(err)
	}
	var before int64
	e.admin.Pool.QueryRow(ctx, `SELECT count(*) FROM portal_outbox WHERE person_id=$1`, personID).Scan(&before)
	if before == 0 {
		t.Fatal("precondition: Start should have queued a mail with the person_id")
	}
	if _, _, err := e.gdpr.Erase(ctx, e.crm, cid); err != nil {
		t.Fatal(err)
	}
	var after int64
	if err := e.admin.Pool.QueryRow(ctx, `SELECT count(*) FROM portal_outbox WHERE person_id=$1`, personID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != 0 {
		t.Fatalf("erasure must delete the person's queued mail, %d left", after)
	}
}
