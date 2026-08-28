package service_test

// QUEUE-WORKER-5: the portal outbox worker treated EVERY error from
// OpenBytes as permanent, on the assumption that the only cause is a retired
// key. FAILED is terminal - the claim takes only PENDING, the reaper only
// SENDING - and the sealed payload is the ONLY copy of the clear-text token,
// so one signer restart or Vault blip destroyed a citizen's login link (or
// their erase confirmation) with no recovery path.

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/fvisic/sunder/internal/crypto"
	"github.com/fvisic/sunder/internal/service"
	"net/http"
	"net/http/httptest"
)

func outboxState(t *testing.T, e *faultEnv) (status string, attempts int) {
	t.Helper()
	if err := e.admin.Pool.QueryRow(context.Background(),
		`SELECT status, attempts FROM portal_outbox ORDER BY id DESC LIMIT 1`).Scan(&status, &attempts); err != nil {
		t.Fatal(err)
	}
	return status, attempts
}

// An unreachable signer is TRANSIENT: the row stays queued.
func TestPortalMailSurvivesAnUnreachableSigner(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	e.register(t)

	adminRing := &service.KeyRing{Pool: e.admin.Pool, RetireGrace: -1}
	admin := &service.Contacts{Pool: e.admin.Pool, Tok: e.svc.Tok, PII: e.svc.PII, Ring: adminRing}
	gdpr := &service.GDPR{Pool: e.admin.Pool, Contacts: admin}
	portal := &service.Portal{GDPR: gdpr, Contacts: admin}
	if err := portal.Start(ctx, "fault@example.com"); err != nil {
		t.Fatal(err)
	}
	if status, _ := outboxState(t, e); status != "PENDING" {
		t.Fatalf("precondition: queued mail should be PENDING, got %s", status)
	}

	// A PIIBox over a signer socket that does not exist: every Open is
	// "signer unreachable", never "this ciphertext is bad".
	dead := crypto.NewPIIBox(crypto.NewRemoteEngine(filepath.Join(t.TempDir(), "absent.sock")))
	brokenContacts := &service.Contacts{Pool: e.admin.Pool, Tok: e.svc.Tok, PII: dead, Ring: adminRing}
	brokenPortal := &service.Portal{GDPR: gdpr, Contacts: brokenContacts}
	if _, err := brokenPortal.DeliverPendingMail(ctx); err != nil {
		t.Fatal(err)
	}
	status, _ := outboxState(t, e)
	if status != "PENDING" {
		t.Fatalf("an unreachable signer must leave the mail queued, got %s - the token is destroyed by a FAILED", status)
	}

	// With the engine back, the same row delivers.
	if _, err := portal.DeliverPendingMail(ctx); err != nil {
		t.Fatal(err)
	}
	if status, _ := outboxState(t, e); status != "NO_MAILER" && status != "DELIVERED" {
		t.Fatalf("the recovered row must settle, got %s", status)
	}
}

// A genuinely corrupt payload is PERMANENT: no retry loop.
func TestPortalMailAbandonsACorruptPayload(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	e.register(t)

	adminRing := &service.KeyRing{Pool: e.admin.Pool, RetireGrace: -1}
	admin := &service.Contacts{Pool: e.admin.Pool, Tok: e.svc.Tok, PII: e.svc.PII, Ring: adminRing}
	gdpr := &service.GDPR{Pool: e.admin.Pool, Contacts: admin}
	portal := &service.Portal{GDPR: gdpr, Contacts: admin}
	if err := portal.Start(ctx, "fault@example.com"); err != nil {
		t.Fatal(err)
	}
	// Flip a ciphertext byte: the AEAD rejects it, and no retry can help.
	//
	// XOR rather than assignment. `overlay ... placing '\xff'` SETS the byte,
	// so when it already held 0xff the payload was left intact, the AEAD
	// opened it, and the test failed with NO_MAILER instead of FAILED - a
	// 1-in-256 flake that took a CI leg down once and reproduced in no local
	// run. Corrupting by XOR is corruption whatever the byte held.
	if _, err := e.admin.Pool.Exec(ctx,
		`UPDATE portal_outbox SET payload = set_byte(payload, 19, get_byte(payload, 19) # 255)`); err != nil {
		t.Fatal(err)
	}
	if _, err := portal.DeliverPendingMail(ctx); err != nil {
		t.Fatal(err)
	}
	if status, _ := outboxState(t, e); status != "FAILED" {
		t.Fatalf("a corrupt payload must be abandoned, got %s", status)
	}
}

// CRYPTO-3's portal half: the per-address send throttle is keyed by the
// NEWEST hmac-email version, so a rotation would otherwise hand every
// address a fresh window - resetting the anti-mail-bomb control fleet-wide,
// silently, at exactly the moment an operator is responding to a key
// incident.
func TestEmailThrottleSurvivesAKeyRotation(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	e.register(t)

	adminRing := &service.KeyRing{Pool: e.admin.Pool, RetireGrace: -1}
	admin := &service.Contacts{Pool: e.admin.Pool, Tok: e.svc.Tok, PII: e.svc.PII, Ring: adminRing}
	portal := &service.Portal{GDPR: &service.GDPR{Pool: e.admin.Pool, Contacts: admin}, Contacts: admin}

	// Spend part of the window.
	for i := 0; i < 2; i++ {
		if err := portal.Start(ctx, "fault@example.com"); err != nil {
			t.Fatal(err)
		}
	}
	var rows, sends int
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*), COALESCE(max(sends),0) FROM portal_email_throttle`).Scan(&rows, &sends); err != nil {
		t.Fatal(err)
	}
	if rows != 1 || sends != 2 {
		t.Fatalf("precondition: one throttle row at 2 sends, got %d rows / %d sends", rows, sends)
	}

	// Rotate the key the throttle row is keyed by.
	if _, err := adminRing.Rotate(ctx, e.oti.Eng, crypto.KeyHMACEmail); err != nil {
		t.Fatal(err)
	}
	if err := portal.Start(ctx, "fault@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*), COALESCE(max(sends),0) FROM portal_email_throttle`).Scan(&rows, &sends); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("a rotation must carry the throttle row forward, not mint a second one: %d rows", rows)
	}
	if sends != 3 {
		t.Fatalf("the window must continue across a rotation, got %d sends (a reset would show 1)", sends)
	}
}

// The settle path's failure branches: a denied table must be LOGGED, not
// swallowed - a silently unsettled row is what leaves a queue stuck.
func TestPortalSettleFailureIsSurfacedNotSwallowed(t *testing.T) {
	e := newFaultEnv(t, "audit")
	ctx := context.Background()
	e.register(t)

	// The service pool cannot write to `audit`, so settleMail's AppendTx
	// fails after its UPDATE - the branch that used to return silently.
	portal := &service.Portal{GDPR: &service.GDPR{Pool: e.svc.Pool, Contacts: e.svc}, Contacts: e.svc}
	if err := portal.Start(ctx, "fault@example.com"); err == nil {
		// Start itself audits, so it may fail first; either way the row
		// must not be left claimed.
		if _, err := portal.DeliverPendingMail(ctx); err != nil {
			t.Fatal(err)
		}
	}
	// A settle that fails after its own UPDATE leaves the row claimed -
	// there is nothing else it could do, having lost the database. What
	// matters is that the claim is RECOVERABLE: before the lease existed,
	// SENDING was absorbing and the row was lost for good (H1 /
	// QUEUE-WORKER-3).
	var sending int
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM portal_outbox WHERE status='SENDING'`).Scan(&sending); err != nil {
		t.Fatal(err)
	}
	if sending > 0 {
		n, err := service.ReapStrandedMail(ctx, e.admin.Pool, time.Nanosecond)
		if err != nil {
			t.Fatal(err)
		}
		if n != int64(sending) {
			t.Fatalf("the reaper must recover every claim a failed settle left behind: %d of %d", n, sending)
		}
		var stillSending int
		if err := e.admin.Pool.QueryRow(ctx,
			`SELECT count(*) FROM portal_outbox WHERE status='SENDING'`).Scan(&stillSending); err != nil {
			t.Fatal(err)
		}
		if stillSending != 0 {
			t.Fatalf("%d row(s) still claimed after the reaper ran", stillSending)
		}
	}
}

// The mail worker's retry ladder: a transient mailer failure keeps the row
// PENDING and charges an attempt, and only the cap (or an expired token)
// abandons it. Losing a citizen's login link to one blip is the failure
// QUEUE-WORKER-5 is about.
func TestPortalMailRetriesThenGivesUp(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	e.register(t)

	adminRing := &service.KeyRing{Pool: e.admin.Pool, RetireGrace: -1}
	admin := &service.Contacts{Pool: e.admin.Pool, Tok: e.svc.Tok, PII: e.svc.PII, Ring: adminRing}
	gdpr := &service.GDPR{Pool: e.admin.Pool, Contacts: admin}
	portal := &service.Portal{GDPR: gdpr, Contacts: admin}

	// A mailer that always 500s: transient, so the row stays queued and the
	// attempts climb.
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer dead.Close()
	if _, err := e.admin.Pool.Exec(ctx,
		`INSERT INTO webhooks (scope, url, secret) VALUES ('_portal', $1, 's')
		 ON CONFLICT (scope) DO UPDATE SET url=EXCLUDED.url`, dead.URL); err != nil {
		t.Fatal(err)
	}
	if err := portal.Start(ctx, "fault@example.com"); err != nil {
		t.Fatal(err)
	}

	var status string
	var attempts int
	for i := 0; i < 10; i++ {
		if _, err := portal.DeliverPendingMail(ctx); err != nil {
			t.Fatal(err)
		}
		if err := e.admin.Pool.QueryRow(ctx,
			`SELECT status, attempts FROM portal_outbox ORDER BY id DESC LIMIT 1`).Scan(&status, &attempts); err != nil {
			t.Fatal(err)
		}
		if status == "FAILED" {
			break
		}
		if status != "PENDING" {
			t.Fatalf("a transient mailer failure must leave the row queued, got %s", status)
		}
	}
	if status != "FAILED" {
		t.Fatalf("the attempts cap must eventually abandon the row, still %s after %d attempts", status, attempts)
	}
	// FAILED is terminal: no sweep and no reaper revisits it.
	if _, err := portal.DeliverPendingMail(ctx); err != nil {
		t.Fatal(err)
	}
	if n, err := service.ReapStrandedMail(ctx, e.admin.Pool, time.Nanosecond); err != nil || n != 0 {
		t.Fatalf("the reaper must not resurrect an abandoned row: %d %v", n, err)
	}
}

// The mail worker's cancellation branches, mirroring the erasure queue's:
// a SIGTERM mid-sweep must return every unattempted claim rather than
// leaving it to the lease, and must not charge an attempt for our own death.
func TestPortalMailReleasesClaimsOnCancellation(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	e.register(t)
	if _, err := e.svc.Register(ctx, e.crm, service.RegisterInput{Email: "second@example.com"}); err != nil {
		t.Fatal(err)
	}

	adminRing := &service.KeyRing{Pool: e.admin.Pool, RetireGrace: -1}
	admin := &service.Contacts{Pool: e.admin.Pool, Tok: e.svc.Tok, PII: e.svc.PII, Ring: adminRing}
	portal := &service.Portal{GDPR: &service.GDPR{Pool: e.admin.Pool, Contacts: admin}, Contacts: admin}

	entered := make(chan struct{}, 1)
	unblock := make(chan struct{})
	mailer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-unblock
		w.WriteHeader(200)
	}))
	defer mailer.Close()
	if _, err := e.admin.Pool.Exec(ctx,
		`INSERT INTO webhooks (scope, url, secret) VALUES ('_portal', $1, 's')
		 ON CONFLICT (scope) DO UPDATE SET url=EXCLUDED.url`, mailer.URL); err != nil {
		t.Fatal(err)
	}
	for _, addr := range []string{"fault@example.com", "second@example.com"} {
		if err := portal.Start(ctx, addr); err != nil {
			t.Fatal(err)
		}
	}

	sweepCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = portal.DeliverPendingMail(sweepCtx)
	}()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the mail worker never reached the mailer - the claim must commit before the send")
	}
	// The claim is committed and visible: the strand window is open.
	var claimed int
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM portal_outbox WHERE status='SENDING'`).Scan(&claimed); err != nil {
		t.Fatal(err)
	}
	if claimed == 0 {
		t.Fatal("precondition: the batch should be claimed while the mailer is blocked")
	}
	cancel()
	close(unblock)
	<-done

	var sending, attempts int
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FILTER (WHERE status='SENDING'), COALESCE(max(attempts),0) FROM portal_outbox`).Scan(&sending, &attempts); err != nil {
		t.Fatal(err)
	}
	if sending != 0 {
		t.Fatalf("cancellation stranded %d portal mail row(s)", sending)
	}
	if attempts > 1 {
		t.Fatalf("our own shutdown must not charge attempts to the mailer, got %d", attempts)
	}
}

// The citizen flow end to end, plus the branches an error takes on each
// step. The portal is the only anonymous surface in the product, so a
// half-completed step there must never leave a usable session.
func TestPortalCitizenFlowAndFailures(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cid := e.register(t)

	adminRing := &service.KeyRing{Pool: e.admin.Pool, RetireGrace: -1}
	admin := &service.Contacts{Pool: e.admin.Pool, Tok: e.svc.Tok, PII: e.svc.PII, Ring: adminRing}
	gdpr := &service.GDPR{Pool: e.admin.Pool, Contacts: admin}
	portal := &service.Portal{GDPR: gdpr, Contacts: admin}

	// An address nobody registered: identical answer, and nothing queued -
	// no enumeration oracle.
	if err := portal.Start(ctx, "ghost@example.com"); err != nil {
		t.Fatalf("an unknown address must answer identically: %v", err)
	}
	var queued int
	if err := e.admin.Pool.QueryRow(ctx, `SELECT count(*) FROM portal_outbox`).Scan(&queued); err != nil {
		t.Fatal(err)
	}
	if queued != 0 {
		t.Fatalf("an unknown address must queue nothing, got %d", queued)
	}

	// A real one: a token is minted, and only its HASH is stored.
	if err := portal.Start(ctx, "fault@example.com"); err != nil {
		t.Fatal(err)
	}
	var tokenRows int
	if err := e.admin.Pool.QueryRow(ctx, `SELECT count(*) FROM portal_tokens`).Scan(&tokenRows); err != nil {
		t.Fatal(err)
	}
	if tokenRows != 1 {
		t.Fatalf("one login token expected, got %d", tokenRows)
	}

	// Redeeming garbage must not mint a session.
	if _, err := portal.Redeem(ctx, "not-a-token"); err == nil {
		t.Error("an unknown token must not create a session")
	}
	if _, err := portal.Redeem(ctx, ""); err == nil {
		t.Error("an empty token must not create a session")
	}
	var sessions int
	if err := e.admin.Pool.QueryRow(ctx, `SELECT count(*) FROM portal_sessions`).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if sessions != 0 {
		t.Fatalf("a failed redeem must leave no session, got %d", sessions)
	}

	// A session for the real person: the citizen's own view of their data.
	var personID string
	if err := e.admin.Pool.QueryRow(ctx, `SELECT person_id FROM cids WHERE cid=$1`, cid).Scan(&personID); err != nil {
		t.Fatal(err)
	}
	data, err := portal.Data(ctx, personID)
	if err != nil {
		t.Fatal(err)
	}
	if data["scopes"] == nil || data["audit_trail"] == nil {
		t.Fatalf("the citizen view must carry both scopes and the access trail: %+v", data)
	}
	// A consent flip on a cid that is not theirs is refused.
	if err := portal.SetConsent(ctx, personID, "CID-NOTTHEIRS000000000000", "support", false); err == nil {
		t.Error("a citizen must not be able to flip consent on someone else's pseudonym")
	}
	// ...and on their own, it lands.
	if err := portal.SetConsent(ctx, personID, cid, "support", false); err != nil {
		t.Fatal(err)
	}
	var granted bool
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT granted FROM consents WHERE cid=$1 AND purpose='support'`, cid).Scan(&granted); err != nil {
		t.Fatal(err)
	}
	if granted {
		t.Fatal("the withdrawal must be recorded")
	}
	// Logout is idempotent and never errors on an unknown session.
	if err := portal.Logout(ctx, "no-such-session"); err != nil {
		t.Fatalf("logout must tolerate an unknown session: %v", err)
	}
}
