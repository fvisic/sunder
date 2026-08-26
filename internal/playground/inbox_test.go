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
	_, out := call("GET", "/api/scenarios", nil)
	vars, _ := out["vars"].(map[string]any)
	mine := fmt.Sprint(vars["unique"])

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
	other := fmt.Sprintf(`{"event":"erase","scope":"crm","cid":"someone-else","erasure_id":8}`)
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
		i.add(Delivery{CID: "c"})
	}
	if len(i.items) != inboxCap {
		t.Fatalf("inbox must stay bounded, got %d", len(i.items))
	}
	if i.dropped == 0 {
		t.Fatal("expected dropped deliveries to be counted")
	}
	if got := len(i.list(map[string]string{"x": "c"})); got != inboxCap {
		t.Fatalf("list by cid: %d", got)
	}
}
