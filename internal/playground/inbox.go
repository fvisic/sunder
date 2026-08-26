package playground

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"
)

// The erasure-webhook inbox. Sunder's erasure flow tells every scope that
// holds the person to forget them, over a signed HTTP callback; the demo
// needs somewhere for that callback to land so the panel can show it
// arriving - and, more importantly, show that the signature verifies. A
// webhook receiver that does not check the signature is a hole, and the
// demo should not teach one.

const inboxCap = 50

// Delivery is one received erasure webhook, as the panel shows it.
type Delivery struct {
	ReceivedAt time.Time `json:"received_at"`
	Event      string    `json:"event"`
	Scope      string    `json:"scope"`
	CID        string    `json:"cid"`
	ErasureID  int64     `json:"erasure_id"`
	// Signature is "valid", "invalid" or "unverified" (no secret
	// configured) - never a boolean, because "we did not check" and "it
	// failed" must not render the same.
	Signature string `json:"signature"`
	Body      string `json:"body"`
}

type inbox struct {
	mu      sync.Mutex
	items   []Delivery
	secret  string
	dropped int
}

func newInbox(secret string) *inbox { return &inbox{secret: secret} }

func (i *inbox) add(d Delivery) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.items = append(i.items, d)
	if len(i.items) > inboxCap {
		i.items = i.items[len(i.items)-inboxCap:]
		i.dropped++
	}
}

// list returns the deliveries whose CID belongs to this visitor, newest
// first. Scoping by CID keeps one visitor's inbox out of another's panel on
// a shared demo - the payloads are fake, but showing strangers' records is
// precisely the habit this product exists to break.
func (i *inbox) list(vars map[string]string) []Delivery {
	mine := map[string]bool{}
	for _, v := range vars {
		mine[v] = true
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	out := make([]Delivery, 0, len(i.items))
	for n := len(i.items) - 1; n >= 0; n-- {
		if mine[i.items[n].CID] {
			out = append(out, i.items[n])
		}
	}
	return out
}

func (i *inbox) verify(body, sig []byte) string {
	if i.secret == "" {
		return "unverified"
	}
	mac := hmac.New(sha256.New, []byte(i.secret))
	mac.Write(body)
	want := make([]byte, hex.EncodedLen(sha256.Size))
	hex.Encode(want, mac.Sum(nil))
	if hmac.Equal(want, sig) {
		return "valid"
	}
	return "invalid"
}

func (s *Server) handleWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unreadable"})
		return
	}
	d := Delivery{
		ReceivedAt: time.Now().UTC(),
		Signature:  s.inbox.verify(body, []byte(r.Header.Get("X-Sunder-Signature"))),
		Body:       prettyJSON(body),
	}
	var payload struct {
		Event     string `json:"event"`
		Scope     string `json:"scope"`
		CID       string `json:"cid"`
		ErasureID int64  `json:"erasure_id"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_json"})
		return
	}
	d.Event, d.Scope, d.CID, d.ErasureID = payload.Event, payload.Scope, payload.CID, payload.ErasureID
	if d.Signature == "invalid" {
		// Record it (the panel should be able to show a forged delivery)
		// but answer with a failure, so Sunder's delivery queue reports
		// what a real receiver would report.
		s.inbox.add(d)
		s.log.Warn("erasure webhook with a bad signature", "scope", d.Scope)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "bad_signature"})
		return
	}
	s.inbox.add(d)
	writeJSON(w, http.StatusOK, map[string]string{"status": "received"})
}

func (s *Server) handleInbox(w http.ResponseWriter, r *http.Request) {
	sess := s.session(w, r)
	writeJSON(w, http.StatusOK, map[string]any{"deliveries": s.inbox.list(sess.Vars())})
}
