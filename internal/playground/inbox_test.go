package playground

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fvisic/sunder/internal/crypto"
)

func sign(secret, body string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	return hex.EncodeToString(mac.Sum(nil))
}

func postWebhook(t *testing.T, base, body, signature string) int {
	t.Helper()
	req, err := http.NewRequest("POST", base+"/hooks/erasure", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if signature != "" {
		req.Header.Set("X-Sunder-Signature", signature)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestWebhookInbox(t *testing.T) {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	pg, err := NewServer(Config{BaseURL: "http://127.0.0.1:1", Scenarios: embedded(t),
		WebhookSecret: "s3cret", RatePerMin: 1000, Log: quiet})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(pg.Handler())
	defer srv.Close()
	call := newClient(t, srv.URL)

	// The visitor's own CID: taken from their session so the inbox can be
	// scoped to them.
	// A CID-shaped value: the inbox scopes on pseudonyms, so no session
	// CONSTANT (demo_name, unique, ...) can be a delivery target (GAP-5).
	_, out := call("GET", "/api/scenarios", nil)
	vars, _ := out["vars"].(map[string]any)
	_ = vars
	// RFC 4648 base32, the alphabet crypto.NewCID emits: A-Z and 2-7. The
	// old fixture used a 9, which no real pseudonym can contain.
	const mine = "CID-GF2A7VXTNP"
	for _, sess := range pg.SessionsForTest().AllForTest() {
		sess.Do(func(v map[string]string) { v["crm_cid"] = mine })
	}

	body := fmt.Sprintf(`{"event":"erase","scope":"crm","cid":%q,"erasure_id":7,"ts":"2026-08-26T10:00:00Z"}`, mine)
	if code := postWebhook(t, srv.URL, body, sign("s3cret", body)); code != 200 {
		t.Fatalf("a correctly signed delivery must be accepted, got %d", code)
	}
	// A forged delivery is rejected with a 401 - what a real receiver does.
	if code := postWebhook(t, srv.URL, body, sign("wrong-secret", body)); code != 401 {
		t.Fatalf("a bad signature must be refused, got %d", code)
	}
	if code := postWebhook(t, srv.URL, "not json", sign("s3cret", "not json")); code != 400 {
		t.Fatalf("a non-JSON body must be a 400, got %d", code)
	}

	_, out = call("GET", "/api/inbox", nil)
	raw, _ := json.Marshal(out["deliveries"])
	var deliveries []Delivery
	if err := json.Unmarshal(raw, &deliveries); err != nil {
		t.Fatal(err)
	}
	if len(deliveries) != 2 {
		t.Fatalf("expected the visitor's two deliveries, got %d", len(deliveries))
	}
	// Newest first, and the verdicts must be distinguishable.
	if deliveries[0].Signature != "invalid" || deliveries[1].Signature != "valid" {
		t.Fatalf("signature verdicts: %q, %q", deliveries[0].Signature, deliveries[1].Signature)
	}
	if deliveries[1].ErasureID != 7 || deliveries[1].Scope != "crm" || deliveries[1].Event != "erase" {
		t.Fatalf("payload was not parsed: %+v", deliveries[1])
	}

	// Another visitor's delivery must not show up in this inbox.
	other := `{"event":"erase","scope":"crm","cid":"CID-ZZZZZZZZZZ","erasure_id":8}`
	if code := postWebhook(t, srv.URL, other, sign("s3cret", other)); code != 200 {
		t.Fatalf("delivery for another session: %d", code)
	}
	_, out = call("GET", "/api/inbox", nil)
	raw, _ = json.Marshal(out["deliveries"])
	deliveries = nil
	_ = json.Unmarshal(raw, &deliveries)
	if len(deliveries) != 2 {
		t.Fatalf("the inbox must stay scoped to the visitor, got %d entries", len(deliveries))
	}
}

func TestInboxUnverifiedWithoutSecretAndCap(t *testing.T) {
	i := newInbox("")
	if got := i.verify([]byte("body"), []byte("whatever")); got != "unverified" {
		t.Fatalf("without a secret the verdict must be 'unverified', got %q", got)
	}
	i = newInbox("k")
	for n := 0; n < inboxCap+10; n++ {
		i.add(Delivery{CID: "CID-AAAAAAAAAA"})
	}
	if len(i.items) != inboxCap {
		t.Fatalf("inbox must stay bounded, got %d", len(i.items))
	}
	if i.dropped == 0 {
		t.Fatal("expected dropped deliveries to be counted")
	}
	if got := len(i.list(map[string]string{"crm_cid": "CID-AAAAAAAAAA"})); got != inboxCap {
		t.Fatalf("list by cid: %d", got)
	}
}

// GAP-5: `demo_name: "Ana Horvat"` is seeded into EVERY session, and the
// inbox matched every VALUE in the session map - so an unauthenticated
// delivery with that cid landed in every visitor's panel, and repeating it
// evicted the genuine deliveries from the bounded ring.
func TestInboxIsScopedToPseudonymsNotSessionConstants(t *testing.T) {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	pg, err := NewServer(Config{BaseURL: "http://127.0.0.1:1", Scenarios: embedded(t),
		WebhookSecret: "s3cret", RatePerMin: 1000, Log: quiet})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(pg.Handler())
	defer srv.Close()
	call := newClient(t, srv.URL)
	call("GET", "/api/scenarios", nil) // establish a session

	// The constant every visitor shares must be refused at ingest.
	body := `{"event":"erase","scope":"crm","cid":"Ana Horvat","erasure_id":1}`
	if code := postWebhook(t, srv.URL, body, sign("s3cret", body)); code != 400 {
		t.Fatalf("a delivery whose cid is not a pseudonym must be refused, got %d", code)
	}
	// ...and it must not be scoped to anyone even if it somehow got in.
	for _, sess := range pg.SessionsForTest().AllForTest() {
		vars := sess.Vars()
		if vars["demo_name"] == "" {
			t.Fatal("precondition: the shared constant should be in the session")
		}
		if got := len(pg.inbox.list(vars)); got != 0 {
			t.Fatalf("the session's constants matched %d deliveries", got)
		}
	}
	i := newInbox("")
	i.add(Delivery{CID: "Ana Horvat"})
	if got := len(i.list(map[string]string{"demo_name": "Ana Horvat"})); got != 0 {
		t.Fatal("a non-pseudonym value must never scope the inbox")
	}
}

// TestLooksLikeCIDMatchesTheVaultsAlphabet pins the inbox filter to the shape
// crypto.NewCID actually emits: "CID-" plus RFC 4648 base32 (A-Z, 2-7).
//
// This regressed for real. The filter checked a CROCKFORD alphabet - digits
// 0-9 present, letter U absent - so any pseudonym containing a U was refused
// as "not a pseudonym" and its signed erasure callback never reached the
// inbox. At 26 characters that is roughly 56% of all pseudonyms, which made
// the playground's erasure walkthrough fail on about every second run and
// pass on the others.
func TestLooksLikeCIDMatchesTheVaultsAlphabet(t *testing.T) {
	for _, tc := range []struct {
		cid  string
		want bool
		why  string
	}{
		{"CID-ZCM2CFJFK7AHGIGKIP5GDS27UM", true, "a real pseudonym containing U - the exact shape that used to be refused"},
		{"CID-AAAAAAAAAAAAAAAAAAAAAAAAAA", true, "all-letter pseudonym"},
		{"CID-234567234567234567234567AB", true, "the digit range base32 actually uses"},
		{"CID-ABCDEF0GHIJKLMNOPQRSTUVWXY", false, "0 is not in RFC 4648 base32"},
		{"CID-ABCDEF1GHIJKLMNOPQRSTUVWXY", false, "1 is not in RFC 4648 base32"},
		{"CID-ABCDEF8GHIJKLMNOPQRSTUVWXY", false, "8 is not in RFC 4648 base32"},
		{"CID-abcdefghijklmnopqrstuvwxyz", false, "lowercase is not the emitted shape"},
		{"CID-", false, "too short to be a pseudonym"},
		{"NOTACID-ABCDEF", false, "wrong prefix"},
		{"CID-ABC DEF", false, "a space is not base32"},
	} {
		if got := looksLikeCID(tc.cid); got != tc.want {
			t.Errorf("looksLikeCID(%q) = %v, want %v - %s", tc.cid, got, tc.want, tc.why)
		}
	}
}

// TestEveryGeneratedCIDPassesTheInboxFilter closes the loop between the two
// packages: whatever the vault mints, the inbox must accept. A per-character
// alphabet mismatch shows up here as a flake, so the sample is large enough
// that a 1-in-32 miss is a certainty rather than a coin flip.
func TestEveryGeneratedCIDPassesTheInboxFilter(t *testing.T) {
	for i := 0; i < 500; i++ {
		cid, err := crypto.NewCID()
		if err != nil {
			t.Fatal(err)
		}
		if !looksLikeCID(cid) {
			t.Fatalf("the vault minted %q and the inbox refuses it as not a pseudonym", cid)
		}
	}
}
