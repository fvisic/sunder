package sunder

// The routes beyond the core handoff surface. Each test asserts the wire
// contract - method, path, body, headers - and the properties the API
// documents that a client can get wrong: an empty cascade must not be sent
// as an opt-in, bulk routes must carry the unlock token, and the calls that
// destroy or consume something must never be blind-retried.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSetAndGetConsent(t *testing.T) {
	c, m := newMock(t, reply{200, `{"cid":"CID1","purpose":"billing","granted":true}`})
	got, err := c.SetConsent(context.Background(), "CID1", "billing", true)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Granted || got.Purpose != "billing" {
		t.Fatalf("consent round-trip lost fields: %+v", got)
	}
	r := m.only()
	if r.Method != http.MethodPost || r.Path != "/v1/consent" {
		t.Fatalf("wrong route: %s %s", r.Method, r.Path)
	}
	if r.Body["granted"] != true {
		t.Fatalf("granted must reach the server as a boolean, got %#v", r.Body["granted"])
	}

	c2, m2 := newMock(t, reply{200, `{"consents":[{"purpose":"billing","granted":false,"updated_at":"2026-01-01T00:00:00Z"}]}`})
	list, err := c2.GetConsent(context.Background(), "CID1")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Granted {
		t.Fatalf("consent list not decoded: %+v", list)
	}
	if m2.only().Path != "/v1/consent/CID1" {
		t.Fatalf("wrong path: %s", m2.only().Path)
	}
}

func TestDSRAccessCarriesHoldingsBeyondTheBlob(t *testing.T) {
	// Article 15 has to answer for what does NOT live in the attribute
	// blob: tokens, files, the RECIPIENTS of shares, and links.
	c, m := newMock(t, reply{200, `{
		"scopes":[{"scope":"crm","cid":"CID1","attributes":{"email":"a@b.c"},
			"value_tokens":[{"token":"tok_1","type":"card"}],
			"files":[{"id":"f1","name":"scan.pdf","size_bytes":12}],
			"shares":[{"uuid":"u1","partner_label":"partner-bank","fields":["email"]}],
			"links":[{"cid":"CID2","link_type":"guardian","role":"parent"}]}],
		"audit_trail":[{"ts":"2026-01-01T00:00:00Z","client_id":"crm","user_id":"agent-7","action":"lookup","count":3}]}`})
	got, err := c.DSRAccess(context.Background(), "CID1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Scopes) != 1 {
		t.Fatalf("expected one scope, got %d", len(got.Scopes))
	}
	s := got.Scopes[0]
	if len(s.ValueTokens) != 1 || len(s.Files) != 1 || len(s.Shares) != 1 || len(s.Links) != 1 {
		t.Fatalf("a holdings section was dropped in decoding: %+v", s)
	}
	if s.Shares[0].PartnerLabel != "partner-bank" {
		t.Fatal("the share's recipient label is the Article 15 answer - it must survive decoding")
	}
	if len(got.AuditTrail) != 1 || got.AuditTrail[0].Count != 3 {
		t.Fatalf("bucketed read entry lost its count: %+v", got.AuditTrail)
	}
	if m.only().Path != "/v1/dsr/access?cid=CID1" {
		t.Fatalf("wrong path: %s", m.only().Path)
	}
}

func TestDSRExportIsCallerScopeOnly(t *testing.T) {
	c, m := newMock(t, reply{200, `{"scope":"crm","cid":"CID1","attributes":{"email":"a@b.c"}}`})
	got, err := c.DSRExport(context.Background(), "CID1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Scope != "crm" || got.Attributes["email"] != "a@b.c" {
		t.Fatalf("export not decoded: %+v", got)
	}
	if m.only().Path != "/v1/dsr/export?cid=CID1" {
		t.Fatalf("wrong path: %s", m.only().Path)
	}
}

func TestEraseDoesNotCascadeUnlessAsked(t *testing.T) {
	// The absence of a cascade key is the whole safety property: a
	// serialized empty list would be indistinguishable from "cascade
	// nothing", but it must not be sent at all.
	c, m := newMock(t, reply{200, `{"erasure_id":7,"scopes":2,"linked":[{"cid":"CID2","link_type":"guardian","cascaded":false}]}`})
	got, err := c.DSRErase(context.Background(), "CID1")
	if err != nil {
		t.Fatal(err)
	}
	if got.ErasureID != 7 || got.Scopes != 2 {
		t.Fatalf("erase result not decoded: %+v", got)
	}
	if len(got.Linked) != 1 || got.Linked[0].Cascaded {
		t.Fatal("a linked child reported as cascaded when it was not")
	}
	if _, present := m.only().Body["cascade"]; present {
		t.Fatal("no cascade was requested, so the key must be absent from the body")
	}

	c2, m2 := newMock(t, reply{200, `{"erasure_id":8,"scopes":1,"linked":[{"cid":"CID2","link_type":"guardian","cascaded":true}]}`})
	if _, err := c2.DSRErase(context.Background(), "CID1", "guardian"); err != nil {
		t.Fatal(err)
	}
	casc, ok := m2.only().Body["cascade"].([]any)
	if !ok || len(casc) != 1 || casc[0] != "guardian" {
		t.Fatalf("named link types must reach the server verbatim: %#v", m2.only().Body["cascade"])
	}
}

func TestEraseIsNeverRetried(t *testing.T) {
	// Erasure is destructive and resuming an interrupted cascade is an
	// explicit decision. One 5xx, one attempt.
	c, m := newMock(t, reply{503, `{"error":"service_unavailable"}`})
	if _, err := c.DSRErase(context.Background(), "CID1"); err == nil {
		t.Fatal("a 503 must surface, not be swallowed")
	}
	if n := len(m.requests()); n != 1 {
		t.Fatalf("erase must be attempted exactly once, saw %d attempts", n)
	}
}

func TestTokenizeAndDetokenize(t *testing.T) {
	c, m := newMock(t, reply{201, `{"token":"tok_abc"}`})
	tok, err := c.Tokenize(context.Background(), TokenizeInput{
		Value: "4111111111111111", Type: "card", CID: "CID1", Unique: true})
	if err != nil {
		t.Fatal(err)
	}
	if tok != "tok_abc" {
		t.Fatalf("token not returned: %q", tok)
	}
	r := m.only()
	if r.Body["cid"] != "CID1" {
		t.Fatal("the cid binding is what makes erasure destroy the token - it must be sent")
	}
	if r.Body["unique"] != true {
		t.Fatalf("unique not sent: %#v", r.Body["unique"])
	}

	c2, m2 := newMock(t, reply{200, `{"value":"4111111111111111"}`})
	v, err := c2.Detokenize(context.Background(), "tok_abc")
	if err != nil || v != "4111111111111111" {
		t.Fatalf("detokenize failed: %v %q", err, v)
	}
	if m2.only().Path != "/v1/tokens/tok_abc" {
		t.Fatalf("wrong path: %s", m2.only().Path)
	}
}

func TestTokenizeOmitsAnUnsetCID(t *testing.T) {
	// An unattributed token survives the person's erasure, so binding one
	// by accident is not the risk here - sending an empty cid that the
	// server would reject as a foreign CID is.
	c, m := newMock(t, reply{201, `{"token":"tok_1"}`})
	if _, err := c.Tokenize(context.Background(), TokenizeInput{Value: "x"}); err != nil {
		t.Fatal(err)
	}
	if _, present := m.only().Body["cid"]; present {
		t.Fatal("an unset cid must be omitted, not sent empty")
	}
}

func TestDeleteTokenIsNotRetried(t *testing.T) {
	c, m := newMock(t, reply{503, `{"error":"service_unavailable"}`})
	if err := c.DeleteToken(context.Background(), "tok_1"); err == nil {
		t.Fatal("expected the 503 to surface")
	}
	if n := len(m.requests()); n != 1 {
		t.Fatalf("a destructive call must not be retried, saw %d attempts", n)
	}
}

func TestBulkRoutesCarryTheUnlockTokenAndAreNotRetried(t *testing.T) {
	c, m := newMock(t, reply{201, `{"tokens":["t1","t2"]}`})
	toks, err := c.TokenizeBulk(context.Background(), "unlock_xyz",
		[]TokenizeInput{{Value: "a"}, {Value: "b"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(toks) != 2 {
		t.Fatalf("expected two tokens, got %v", toks)
	}
	if got := m.only().Header.Get("X-Sunder-Unlock"); got != "unlock_xyz" {
		t.Fatalf("bulk routes always require an unlock token; header was %q", got)
	}

	// Spent by the first attempt: a retry would come back already-used and
	// leave the caller unable to tell whether the batch landed.
	c2, m2 := newMock(t, reply{503, `{"error":"service_unavailable"}`})
	if _, err := c2.DetokenizeBulk(context.Background(), "unlock_xyz", []string{"t1"}); err == nil {
		t.Fatal("expected the 503 to surface")
	}
	if n := len(m2.requests()); n != 1 {
		t.Fatalf("an unlock-spending call must not be retried, saw %d attempts", n)
	}
}

func TestUploadFileSendsMultipartAndExpiry(t *testing.T) {
	c, m := newMock(t, reply{201, `{"id":"f1","name":"scan.pdf","size_bytes":3,"sha256":"deadbeef"}`})
	deadline := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	meta, err := c.UploadFile(context.Background(), "CID1", "scan.pdf", "application/pdf",
		strings.NewReader("abc"), deadline)
	if err != nil {
		t.Fatal(err)
	}
	if meta.ID != "f1" || meta.SHA256 != "deadbeef" {
		t.Fatalf("file metadata not decoded: %+v", meta)
	}
	r := m.only()
	if r.Path != "/v1/contacts/CID1/files" {
		t.Fatalf("wrong path: %s", r.Path)
	}
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "multipart/form-data") {
		t.Fatalf("upload must be multipart, got %q", ct)
	}
	if got := r.Header.Get("X-Sunder-File-Expiry"); got != "2030-01-02T03:04:05Z" {
		t.Fatalf("expiry header wrong: %q", got)
	}
	if !bytes.Contains(r.Raw, []byte(`filename="scan.pdf"`)) || !bytes.Contains(r.Raw, []byte("abc")) {
		t.Fatal("the multipart body must carry the filename and the content")
	}
}

func TestUploadFileOmitsExpiryWhenZero(t *testing.T) {
	c, m := newMock(t, reply{201, `{"id":"f1"}`})
	if _, err := c.UploadFile(context.Background(), "CID1", "a.txt", "", strings.NewReader("x"), time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, present := m.only().Header["X-Sunder-File-Expiry"]; present {
		t.Fatal("a zero expiry must not send the header at all")
	}
}

func TestListAndDownloadFile(t *testing.T) {
	c, m := newMock(t, reply{200, `{"files":[{"id":"f1","name":"scan.pdf"}]}`})
	files, err := c.ListFiles(context.Background(), "CID1", "support")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].ID != "f1" {
		t.Fatalf("file list not decoded: %+v", files)
	}
	if m.only().Path != "/v1/contacts/CID1/files?purpose=support" {
		t.Fatalf("purpose must be sent as a query parameter: %s", m.only().Path)
	}

	c2, m2 := newMock(t, reply{200, `raw-bytes`})
	body, err := c2.DownloadFile(context.Background(), "f1", "support")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(body)
	_ = body.Close()
	if string(got) != "raw-bytes" {
		t.Fatalf("download returned %q", got)
	}
	if m2.only().Path != "/v1/files/f1?purpose=support" {
		t.Fatalf("wrong path: %s", m2.only().Path)
	}
}

func TestDownloadFileMapsErrorsInsteadOfReturningABody(t *testing.T) {
	// A 404 must not reach the caller as an io.Reader over an error page.
	c, _ := newMock(t, reply{404, `{"error":"not_found"}`})
	if _, err := c.DownloadFile(context.Background(), "missing", "support"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestSharesRoundTrip(t *testing.T) {
	c, m := newMock(t, reply{201, `{"uuid":"u1","expires_at":"2026-01-01T00:00:00Z"}`})
	sh, err := c.CreateShare(context.Background(), ShareInput{
		CID: "CID1", Fields: []string{"email"}, PartnerLabel: "partner-bank",
		Purpose: "kyc", TTLSeconds: 3600})
	if err != nil {
		t.Fatal(err)
	}
	if sh.UUID != "u1" {
		t.Fatalf("share uuid missing: %+v", sh)
	}
	if m.only().Body["partner_label"] != "partner-bank" {
		t.Fatal("the partner label is what the Article 15 answer reports - it must be sent")
	}

	c2, m2 := newMock(t, reply{200, `{"fields":{"email":"a@b.c"}}`})
	fields, err := c2.FetchShare(context.Background(), "u1")
	if err != nil {
		t.Fatal(err)
	}
	if fields["email"] != "a@b.c" {
		t.Fatalf("share fields not decoded: %v", fields)
	}
	if m2.only().Path != "/v1/shares/u1" {
		t.Fatalf("wrong path: %s", m2.only().Path)
	}

	c3, m3 := newMock(t, reply{200, `{"status":"revoked"}`})
	if err := c3.RevokeShare(context.Background(), "u1"); err != nil {
		t.Fatal(err)
	}
	if m3.only().Method != http.MethodDelete {
		t.Fatalf("revoke must be a DELETE, got %s", m3.only().Method)
	}
}

func TestLinksRoundTrip(t *testing.T) {
	c, m := newMock(t, reply{201, `{"status":"linked"}`})
	if err := c.Link(context.Background(), "PARENT", "CHILD", "guardian"); err != nil {
		t.Fatal(err)
	}
	r := m.only()
	if r.Body["parent_cid"] != "PARENT" || r.Body["link_type"] != "guardian" {
		t.Fatalf("link body wrong: %#v", r.Body)
	}

	c2, m2 := newMock(t, reply{200, `{"links":[{"cid":"CHILD","link_type":"guardian","role":"parent"}]}`})
	links, err := c2.ListLinks(context.Background(), "PARENT")
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 1 || links[0].Role != "parent" {
		t.Fatalf("links not decoded: %+v", links)
	}
	if m2.only().Path != "/v1/contacts/PARENT/links" {
		t.Fatalf("wrong path: %s", m2.only().Path)
	}

	c3, m3 := newMock(t, reply{200, `{"status":"unlinked"}`})
	if err := c3.Unlink(context.Background(), "PARENT", "CHILD"); err != nil {
		t.Fatal(err)
	}
	if m3.only().Method != http.MethodDelete || m3.only().Body["child_cid"] != "CHILD" {
		t.Fatalf("unlink wrong: %s %#v", m3.only().Method, m3.only().Body)
	}
}

func TestVersionHistory(t *testing.T) {
	c, m := newMock(t, reply{200, `{"versions":[{"version_no":2,"written_by":"crm","written_at":"2026-01-01T00:00:00Z"}]}`})
	vs, err := c.ListVersions(context.Background(), "CID1")
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 1 || vs[0].VersionNo != 2 {
		t.Fatalf("versions not decoded: %+v", vs)
	}
	if m.only().Path != "/v1/contacts/CID1/versions" {
		t.Fatalf("wrong path: %s", m.only().Path)
	}

	c2, m2 := newMock(t, reply{200, `{"value":"old@example.com"}`})
	v, err := c2.GetVersionAttribute(context.Background(), "CID1", 2, "email", "support")
	if err != nil || v != "old@example.com" {
		t.Fatalf("historical read failed: %v %q", err, v)
	}
	// An old value is not a lesser secret: the purpose must still be sent.
	if m2.only().Path != "/v1/contacts/CID1/versions/2/attributes/email?purpose=support" {
		t.Fatalf("wrong path: %s", m2.only().Path)
	}
}

func TestExternalClaimReportsStoredNames(t *testing.T) {
	c, m := newMock(t, reply{200, `{"stored":["verified_age@gov-id"]}`})
	stored, err := c.StoreExternalClaim(context.Background(), "CID1", "eyJ...envelope")
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 || !strings.Contains(stored[0], "@") {
		t.Fatalf("issuer provenance must survive in the stored name: %v", stored)
	}
	if m.only().Body["envelope"] != "eyJ...envelope" {
		t.Fatal("the envelope must be forwarded unmodified")
	}
}

func TestUnlockMintsASingleUseToken(t *testing.T) {
	c, m := newMock(t, reply{201, `{"unlock_token":"unlock_xyz","expires_at":"2026-01-01T00:01:00Z"}`})
	u, err := c.Unlock(context.Background(), "tokens")
	if err != nil {
		t.Fatal(err)
	}
	if u.Token != "unlock_xyz" {
		t.Fatalf("unlock token missing: %+v", u)
	}
	if m.only().Body["purpose"] != "tokens" {
		t.Fatalf("purpose not sent: %#v", m.only().Body)
	}
}

func TestUnlockRefusesAResponseWithNoToken(t *testing.T) {
	// A 201 with an empty token would otherwise be spent as a valid unlock
	// on the next bulk call and fail there, far from the cause.
	c, _ := newMock(t, reply{201, `{"expires_at":"2026-01-01T00:01:00Z"}`})
	if _, err := c.Unlock(context.Background(), "tokens"); !errors.Is(err, ErrBadResponse) {
		t.Fatalf("expected ErrBadResponse, got %v", err)
	}
}

func TestWithUserIDIsSentOnEveryCall(t *testing.T) {
	c, m := newMock(t, reply{200, `{"value":"x"}`})
	c.userID = "agent-7" // WithUserID, applied post-construction by the mock helper
	if _, err := c.GetAttribute(context.Background(), "CID1", "email", "support"); err != nil {
		t.Fatal(err)
	}
	if got := m.only().Header.Get("X-Sunder-User-Id"); got != "agent-7" {
		t.Fatalf("operator attribution header missing: %q", got)
	}
}

func TestWithUserIDOptionSetsTheField(t *testing.T) {
	c, err := New("https://sunder.internal", "crm.secret", WithUserID("agent-9"))
	if err != nil {
		t.Fatal(err)
	}
	if c.userID != "agent-9" {
		t.Fatalf("WithUserID did not apply: %q", c.userID)
	}
}

func TestReadyProbe(t *testing.T) {
	c, m := newMock(t, reply{200, `ok`})
	got, err := c.Ready(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got != "ok" {
		t.Fatalf("readiness returned %q", got)
	}
	if m.only().Path != "/readyz" {
		t.Fatalf("wrong path: %s", m.only().Path)
	}
}
