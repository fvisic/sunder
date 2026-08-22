package api

// A realistic delayed-notification flow: a support ticket escalates hours
// after creation, and a separate notifier service must email the customer.
//
// The point this test pins: an OTI lives five minutes, so a delayed send
// can NEVER be "an OTI saved for later". The correct shape is:
//
//	t0  CRM opens the ticket, issues an OTI (purpose escalation_notify,
//	    audience notifier); the notifier verifies it immediately and stores
//	    ONLY its own scoped CID next to the ticket id - no email, no name.
//	t+N escalation fires: the notifier fetches the email attribute
//	    just-in-time (purpose-checked, consent-checked, audited), sends,
//	    and still stores nothing.
//
// A notifier database leak therefore contains ticket ids and CIDs - zero
// PII - and the person can kill escalation emails at any moment by
// withdrawing consent for that one purpose, without touching the CRM.

import (
	"context"
	"testing"

	"github.com/fvisic/sunder/internal/auth"
)

func TestDelayedEscalationEmailFlow(t *testing.T) {
	e := newE2E(t)
	ctx := context.Background()

	// CRM may register contacts, manage consent, and hand off to the notifier.
	if _, err := e.srv.Store.Pool.Exec(ctx,
		`UPDATE clients SET allowed_actions = allowed_actions || '{oti.issue,consent.manage}',
		                    allowed_purposes = allowed_purposes || '{escalation_notify}'
		 WHERE client_id='crm'`); err != nil {
		t.Fatal(err)
	}
	// The notifier can verify handoffs and read attributes for exactly one
	// purpose. It cannot look anyone up and cannot register anyone.
	credNotifier, err := auth.Create(ctx, e.srv.Store.Pool, auth.Client{
		ID: "notifier", Name: "Escalation Notifier", Scope: "notifier",
		AllowedActions:  []string{auth.ActOTIVerify, auth.ActAttributesRead},
		AllowedPurposes: []string{"escalation_notify"}, RateLimit: 100,
	})
	if err != nil {
		t.Fatal(err)
	}

	// t0: the customer registers a ticket in the CRM. The handoff explicitly
	// shares ONLY the email attribute - a handoff shares nothing by default.
	crmCID := registerFilip(t, e)
	rec, out := e.do(t, e.credCRM, "POST", "/v1/oti", map[string]any{
		"cid": crmCID, "purpose": "escalation_notify", "audience": "notifier",
		"share_attributes": []string{"email"}})
	if rec.Code != 201 {
		t.Fatalf("oti issue: %d %s", rec.Code, rec.Body.String())
	}
	// The notifier consumes the handoff NOW (within the 5-minute window)
	// and stores only its own pseudonym next to the ticket.
	rec, out = e.do(t, credNotifier, "POST", "/v1/oti/verify", map[string]string{
		"token": out["token"], "purpose": "escalation_notify", "audience": "notifier"})
	if rec.Code != 200 {
		t.Fatalf("oti verify: %d %s", rec.Code, rec.Body.String())
	}
	notifierCID := out["cid"]
	if notifierCID == crmCID {
		t.Fatal("notifier must receive its own scoped CID")
	}

	// t+N hours: escalation fires. Just-in-time attribute fetch - the email
	// exists in the notifier scope ONLY because the issuer shared it.
	rec, out = e.do(t, credNotifier, "GET",
		"/v1/contacts/"+notifierCID+"/attributes/email?purpose=escalation_notify", nil)
	if rec.Code != 200 || out["value"] != "filip@example.com" {
		t.Fatalf("just-in-time email fetch: %d %s", rec.Code, rec.Body.String())
	}
	// Attributes the issuer did NOT share are absent from the notifier scope.
	rec, _ = e.do(t, credNotifier, "GET",
		"/v1/contacts/"+notifierCID+"/attributes/phone?purpose=escalation_notify", nil)
	if rec.Code != 404 {
		t.Fatalf("unshared attribute must be absent: %d", rec.Code)
	}
	// The notifier's grant is purpose-capped: any other purpose is refused,
	// so the escalation credential cannot be repurposed for marketing.
	rec, out = e.do(t, credNotifier, "GET",
		"/v1/contacts/"+notifierCID+"/attributes/email?purpose=newsletter", nil)
	if rec.Code != 403 || out["error"] != "purpose_not_allowed" {
		t.Fatalf("purpose cap: %d %s", rec.Code, rec.Body.String())
	}

	// The customer opts out of escalation emails (one purpose, org-wide
	// effect): the CRM records the withdrawal on ITS CID...
	rec, _ = e.do(t, e.credCRM, "POST", "/v1/consent", map[string]any{
		"cid": crmCID, "purpose": "escalation_notify", "granted": false})
	if rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	// ...but consent decisions are per-CID, and the notifier holds a
	// different CID: pin the ACTUAL semantics - the notifier-side consent
	// must be recorded on the notifier CID to block its sends.
	rec, _ = e.do(t, credNotifier, "GET",
		"/v1/contacts/"+notifierCID+"/attributes/email?purpose=escalation_notify", nil)
	if rec.Code != 200 {
		t.Fatalf("consent on the CRM CID does not govern the notifier CID: got %d", rec.Code)
	}
	// The notifier records the withdrawal it received (e.g. via the
	// unsubscribe link IT sent) on its own CID - and is now blocked.
	if _, err := e.srv.Store.Pool.Exec(ctx,
		`UPDATE clients SET allowed_actions = allowed_actions || '{consent.manage}' WHERE client_id='notifier'`); err != nil {
		t.Fatal(err)
	}
	rec, _ = e.do(t, credNotifier, "POST", "/v1/consent", map[string]any{
		"cid": notifierCID, "purpose": "escalation_notify", "granted": false})
	if rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	rec, out = e.do(t, credNotifier, "GET",
		"/v1/contacts/"+notifierCID+"/attributes/email?purpose=escalation_notify", nil)
	if rec.Code != 403 || out["error"] != "consent_denied" {
		t.Fatalf("withdrawn consent must block the delayed send: %d %s", rec.Code, rec.Body.String())
	}
}
