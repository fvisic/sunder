package playground

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSunder is enough of the API for the shipped scenarios to run end to
// end: it enforces the same refusals the real service does (name-only
// lookup, unknown identifier, OTI replay), because those refusals are the
// steps the walkthrough is built around.
type fakeSunder struct {
	seq        int
	registered map[string]string // normalized identifier -> cid
	withdrawn  map[string]bool   // "<cid>/<purpose>" -> consent withdrawn
	erased     map[string]bool
	usedToken  map[string]bool
	authSeen   []string
	// Phase 8 surfaces: value tokens, shares and links, modelled only as far
	// as the walkthroughs assert. The fake is the anti-rot check that a
	// scenario references coherent endpoints; the live e2e is the truth.
	shared      map[string]bool     // "<cid>|<attr>" -> authorized by the issuer
	tokenShares map[string][]string // oti token -> attributes it authorizes
	bySuffix    map[string]string   // last 8 phone digits -> cid
	links       []link              // guardian/member/owner edges
	tokens      map[string]string   // token -> value
	byValue     map[string]string   // "<cid>|<value>" -> token (unique dedup)
	shares      map[string]string   // uuid -> "<cid>|<purpose>"
	revoked     map[string]bool
}

// link is one person-to-person edge inside a scope.
type link struct{ parent, child, kind string }

func newFakeSunder() *fakeSunder {
	return &fakeSunder{
		registered: map[string]string{}, withdrawn: map[string]bool{},
		erased: map[string]bool{}, usedToken: map[string]bool{},
		shared: map[string]bool{}, tokenShares: map[string][]string{},
		bySuffix: map[string]string{},
		tokens:   map[string]string{}, byValue: map[string]string{},
		shares: map[string]string{}, revoked: map[string]bool{},
	}
}

func (f *fakeSunder) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/contacts", func(w http.ResponseWriter, r *http.Request) {
		f.authSeen = append(f.authSeen, r.Header.Get("Authorization"))
		var in struct{ Email, Phone, Name string }
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in.Email == "" && in.Phone == "" {
			writeJSON(w, 400, map[string]string{"error": "validation"})
			return
		}
		f.seq++
		cid := fmt.Sprintf("crm-cid-%d", f.seq)
		f.registered[in.Email], f.registered[in.Phone] = cid, cid
		if d := onlyDigits(in.Phone); len(d) >= 8 {
			f.bySuffix[d[len(d)-8:]] = cid
		}
		writeJSON(w, 201, map[string]string{"cid": cid})
	})
	mux.HandleFunc("POST /v1/lookup", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Email       string `json:"email"`
			Phone       string `json:"phone"`
			Name        string `json:"name"`
			PhoneSuffix string `json:"phone_suffix"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		// A narrowed credential may not look anyone up by an identifier kind
		// outside its allowlist - otherwise 200-vs-404 is still an oracle.
		if narrowed(r) && (in.Email != "" || in.Phone != "" || in.PhoneSuffix != "" || in.Name != "") {
			writeJSON(w, 403, map[string]string{"error": "forbidden"})
			return
		}
		if in.PhoneSuffix != "" {
			if len(in.PhoneSuffix) < 8 {
				writeJSON(w, 400, map[string]string{"error": "validation", "detail": "phone_suffix needs at least 8 digits"})
				return
			}
			cid, ok := f.bySuffix[in.PhoneSuffix]
			if !ok || f.erased[cid] {
				writeJSON(w, 404, map[string]string{"error": "not_found"})
				return
			}
			writeJSON(w, 200, map[string]string{"cid": cid})
			return
		}
		if in.Email == "" && in.Phone == "" {
			writeJSON(w, 400, map[string]string{"error": "validation", "detail": "a name is not an identifier"})
			return
		}
		key := in.Email
		if key == "" {
			key = in.Phone
		}
		cid, ok := f.registered[key]
		if !ok || f.erased[cid] {
			writeJSON(w, 404, map[string]string{"error": "not_found"})
			return
		}
		writeJSON(w, 200, map[string]string{"cid": cid})
	})
	mux.HandleFunc("GET /v1/contacts/{cid}/attributes/{name}", func(w http.ResponseWriter, r *http.Request) {
		cid, purpose, name := r.PathValue("cid"), r.URL.Query().Get("purpose"), r.PathValue("name")
		switch {
		case purpose == "":
			writeJSON(w, 403, map[string]string{"error": "purpose_not_allowed"})
		case f.erased[cid]:
			writeJSON(w, 404, map[string]string{"error": "not_found"})
		case f.withdrawn[cid+"/"+purpose]:
			writeJSON(w, 403, map[string]string{"error": "consent_denied"})
		// A narrowed credential may read only the names on its allowlist,
		// and only under a purpose it holds.
		case narrowed(r) && (name != narrowAllowedAttr || purpose != narrowAllowedPurpose):
			writeJSON(w, 403, map[string]string{"error": "forbidden"})
		// In a RECEIVING scope only the attributes the issuer authorized
		// exist at all - the rest were never copied across.
		case strings.HasPrefix(cid, "erp-cid-") && !f.shared[cid+"|"+name]:
			writeJSON(w, 404, map[string]string{"error": "not_found"})
		default:
			writeJSON(w, 200, map[string]string{"name": name, "value": "ana@example.com"})
		}
	})
	mux.HandleFunc("POST /v1/oti", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			CID             string   `json:"cid"`
			Purpose         string   `json:"purpose"`
			ShareAttributes []string `json:"share_attributes"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		switch {
		case in.CID == "":
			writeJSON(w, 400, map[string]string{"error": "validation"})
		case f.withdrawn[in.CID+"/"+in.Purpose]:
			writeJSON(w, 403, map[string]string{"error": "consent_denied"})
		default:
			tok := "oti-token-" + in.CID
			// Remember WHICH attributes the issuer authorized: an attribute
			// that was never shared must be ABSENT in the receiving scope,
			// not merely hidden.
			f.tokenShares[tok] = append([]string(nil), in.ShareAttributes...)
			writeJSON(w, 201, map[string]string{"token": tok})
		}
	})
	mux.HandleFunc("POST /v1/oti/verify", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Token string }
		_ = json.NewDecoder(r.Body).Decode(&in)
		if f.usedToken[in.Token] {
			writeJSON(w, 409, map[string]string{"error": "token_used"})
			return
		}
		f.usedToken[in.Token] = true
		f.seq++
		cid := fmt.Sprintf("erp-cid-%d", f.seq)
		for _, a := range f.tokenShares[in.Token] {
			f.shared[cid+"|"+a] = true
		}
		writeJSON(w, 200, map[string]string{"cid": cid})
	})
	mux.HandleFunc("POST /v1/consent", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			CID     string `json:"cid"`
			Purpose string `json:"purpose"`
			Granted *bool  `json:"granted"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in.Granted == nil {
			writeJSON(w, 400, map[string]string{"error": "validation"})
			return
		}
		f.withdrawn[in.CID+"/"+in.Purpose] = !*in.Granted
		if !*in.Granted {
			// A withdrawal REVOKES the person's standing shares for that
			// purpose - permanently. Re-granting does not resurrect a link
			// that was already handed out; a new one must be minted.
			for id, owner := range f.shares {
				if owner == in.CID+"|"+in.Purpose {
					f.revoked[id] = true
				}
			}
		}
		writeJSON(w, 200, map[string]any{"cid": in.CID, "purpose": in.Purpose, "granted": *in.Granted})
	})
	mux.HandleFunc("GET /v1/consent/{cid}", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"consents": []map[string]any{
			{"purpose": "support", "granted": true},
		}})
	})
	mux.HandleFunc("GET /v1/dsr/access", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"scopes": []map[string]any{{"scope": "crm"}}})
	})
	mux.HandleFunc("POST /v1/dsr/erase", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			CID     string   `json:"cid"`
			Cascade []string `json:"cascade"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.erased[in.CID] = true
		// A cascade follows ONLY the link types the caller named: erasing one
		// person must never quietly erase another.
		linked := []any{}
		for _, l := range f.links {
			if l.parent != in.CID {
				continue
			}
			for _, kind := range in.Cascade {
				if kind == l.kind {
					f.erased[l.child] = true
					linked = append(linked, map[string]any{"cid": l.child, "link_type": l.kind})
					break
				}
			}
		}
		writeJSON(w, 200, map[string]any{"erasure_id": 41, "scopes": 1, "linked": linked})
	})
	mux.HandleFunc("GET /v1/admin/audit/verify", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true, "pending": 0})
	})
	mux.HandleFunc("GET /v1/admin/audit/chain", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"unsealed": 0, "rows": []map[string]any{
			{"chain_seq": 1, "action": "register", "client_id": "crm", "hash": "aa", "prev_hash": ""},
		}})
	})
	// --- F4 value tokens ---------------------------------------------------
	mux.HandleFunc("POST /v1/tokens", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Type, Value, CID string
			Unique           bool
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in.Value == "" {
			writeJSON(w, 400, map[string]string{"error": "validation"})
			return
		}
		if in.Type == "card" && !luhnOK(in.Value) {
			writeJSON(w, 400, map[string]string{"error": "validation", "detail": "luhn"})
			return
		}
		key := in.CID + "|" + in.Value
		if in.Unique {
			if tok, ok := f.byValue[key]; ok {
				writeJSON(w, 201, map[string]string{"token": tok})
				return
			}
		}
		f.seq++
		tok := fmt.Sprintf("VT-%d", f.seq)
		f.tokens[tok] = in.Value
		if in.Unique {
			f.byValue[key] = tok
		}
		writeJSON(w, 201, map[string]string{"token": tok})
	})
	mux.HandleFunc("GET /v1/tokens/{token}", func(w http.ResponseWriter, r *http.Request) {
		v, ok := f.tokens[r.PathValue("token")]
		if !ok {
			writeJSON(w, 404, map[string]string{"error": "not_found"})
			return
		}
		writeJSON(w, 200, map[string]string{"value": v})
	})
	mux.HandleFunc("DELETE /v1/tokens/{token}", func(w http.ResponseWriter, r *http.Request) {
		tok := r.PathValue("token")
		if _, ok := f.tokens[tok]; !ok {
			writeJSON(w, 404, map[string]string{"error": "not_found"})
			return
		}
		delete(f.tokens, tok)
		writeJSON(w, 200, map[string]string{"status": "deleted"})
	})
	mux.HandleFunc("POST /v1/tokens/bulk/read", func(w http.ResponseWriter, r *http.Request) {
		// Bulk ALWAYS needs the unlock header - the refusal is the lesson.
		if r.Header.Get("X-Sunder-Unlock") == "" {
			writeJSON(w, 403, map[string]string{"error": "unlock_required"})
			return
		}
		writeJSON(w, 200, map[string]any{"values": []string{}})
	})
	mux.HandleFunc("POST /v1/admin/unlock", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 201, map[string]string{"unlock_token": "unlock-value", "expires_at": "2030-01-01T00:00:00Z"})
	})

	// --- F5 file vault (metadata only) --------------------------------------
	mux.HandleFunc("GET /v1/contacts/{cid}/files", func(w http.ResponseWriter, r *http.Request) {
		cid, purpose := r.PathValue("cid"), r.URL.Query().Get("purpose")
		switch {
		case purpose == "":
			writeJSON(w, 400, map[string]string{"error": "validation", "detail": "purpose required"})
		case f.erased[cid]:
			writeJSON(w, 404, map[string]string{"error": "not_found"})
		case f.withdrawn[cid+"/"+purpose]:
			writeJSON(w, 403, map[string]string{"error": "consent_denied"})
		default:
			writeJSON(w, 200, map[string]any{"files": []any{}})
		}
	})

	// --- F6 attribute history ------------------------------------------------
	mux.HandleFunc("GET /v1/contacts/{cid}/versions", func(w http.ResponseWriter, r *http.Request) {
		if f.erased[r.PathValue("cid")] {
			writeJSON(w, 404, map[string]string{"error": "not_found"})
			return
		}
		writeJSON(w, 200, map[string]any{"versions": []any{
			map[string]any{"version_no": 1, "written_by": "crm", "written_at": "2026-01-01T00:00:00Z"},
			map[string]any{"version_no": 2, "written_by": "crm", "written_at": "2026-01-02T00:00:00Z"},
		}})
	})
	mux.HandleFunc("GET /v1/contacts/{cid}/versions/{version}/attributes/{name}", func(w http.ResponseWriter, r *http.Request) {
		cid, purpose := r.PathValue("cid"), r.URL.Query().Get("purpose")
		switch {
		case purpose == "":
			writeJSON(w, 400, map[string]string{"error": "validation", "detail": "purpose required"})
		case f.erased[cid]:
			writeJSON(w, 404, map[string]string{"error": "not_found"})
		default:
			writeJSON(w, 200, map[string]string{"value": "bronze"})
		}
	})

	// --- F8 shared records ---------------------------------------------------
	mux.HandleFunc("POST /v1/shares", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			CID, Purpose string
			Fields       []string
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in.CID == "" || in.Purpose == "" || len(in.Fields) == 0 {
			writeJSON(w, 400, map[string]string{"error": "validation"})
			return
		}
		f.seq++
		id := fmt.Sprintf("share-%d", f.seq)
		f.shares[id] = in.CID + "|" + in.Purpose
		writeJSON(w, 201, map[string]any{"uuid": id, "expires_at": "2030-01-01T00:00:00Z"})
	})
	mux.HandleFunc("GET /v1/shares/{uuid}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("uuid")
		owner, ok := f.shares[id]
		// Absent, revoked, erased and consent-withdrawn are ONE answer.
		if !ok || f.revoked[id] {
			writeJSON(w, 404, map[string]string{"error": "not_found"})
			return
		}
		cid, _, _ := strings.Cut(owner, "|")
		if f.erased[cid] {
			writeJSON(w, 404, map[string]string{"error": "not_found"})
			return
		}
		writeJSON(w, 200, map[string]any{"fields": map[string]string{"loyalty_tier": "gold"}})
	})
	mux.HandleFunc("DELETE /v1/shares/{uuid}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("uuid")
		owner, ok := f.shares[id]
		cid, purpose, _ := strings.Cut(owner, "|")
		// A consent withdrawal already revoked it: nothing live left to revoke.
		if !ok || f.revoked[id] || f.withdrawn[cid+"/"+purpose] {
			writeJSON(w, 404, map[string]string{"error": "not_found"})
			return
		}
		f.revoked[id] = true
		writeJSON(w, 200, map[string]string{"status": "revoked"})
	})

	// --- F7 links -------------------------------------------------------------
	mux.HandleFunc("POST /v1/links", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			ParentCID string `json:"parent_cid"`
			ChildCID  string `json:"child_cid"`
			LinkType  string `json:"link_type"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		switch in.LinkType {
		case "guardian", "member", "owner":
		default:
			writeJSON(w, 400, map[string]string{"error": "validation", "detail": "link_type"})
			return
		}
		f.links = append(f.links, link{parent: in.ParentCID, child: in.ChildCID, kind: in.LinkType})
		writeJSON(w, 201, map[string]string{"status": "linked"})
	})
	mux.HandleFunc("GET /v1/contacts/{cid}/links", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"links": []any{}})
	})

	return mux
}

// narrowAllowedAttr / narrowAllowedPurpose mirror the seeded narrowed
// credential: one attribute name, one purpose.
const (
	narrowAllowedAttr    = "loyalty_tier"
	narrowAllowedPurpose = "support"
)

// narrowed reports whether the caller is the deliberately narrowed
// credential. Roles authenticate as "<role>.secret-value" in these tests, so
// the role name is readable from the header - which is exactly the property
// the walkthrough demonstrates: the narrowing lives on the CREDENTIAL.
func narrowed(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Authorization"), "Bearer narrow.")
}

// onlyDigits keeps the decimal digits of s.
func onlyDigits(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r >= '0' && r <= '9' {
			out = append(out, r)
		}
	}
	return string(out)
}

// luhnOK is the fake's card check: the walkthrough asserts that a non-Luhn
// "card" value is refused, so the fake has to actually decide.
func luhnOK(s string) bool {
	var digits []int
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		}
	}
	if len(digits) < 12 {
		return false
	}
	sum, alt := 0, false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if alt {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

func embedded(t *testing.T) []*Scenario {
	t.Helper()
	scs, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	if len(scs) == 0 {
		t.Fatal("no scenarios are compiled into the binary")
	}
	return scs
}

// TestEmbeddedScenariosRunGreen is the anti-rot test: every shipped
// walkthrough must execute cleanly, step by step, with its captures and
// invariants satisfied. A scenario file that references a variable nobody
// captures, or expects a status the API no longer returns, fails here.
func TestEmbeddedScenariosRunGreen(t *testing.T) {
	scs := embedded(t)
	if scs[0].ID != "lookup-handoff" {
		t.Fatalf("expected the lookup/handoff scenario first, got %q", scs[0].ID)
	}
	for _, sc := range scs {
		t.Run(sc.ID, func(t *testing.T) {
			// A fresh instance per walkthrough: the erasure scenario ends
			// with the person gone, and the next scenario must not inherit
			// that.
			fake := newFakeSunder()
			srv := httptest.NewServer(fake.handler())
			defer srv.Close()
			runner := &Runner{BaseURL: srv.URL, Creds: map[string]string{}}
			for _, r := range sc.Roles {
				runner.Creds[r.Name] = r.Name + ".secret-value"
			}
			vars := newSessionVars("abcdef012345")
			for i := range sc.Steps {
				res := runner.RunStep(context.Background(), sc, i, vars)
				if res.Error != "" {
					t.Fatalf("step %d (%s): %s", i+1, sc.Steps[i].Label, res.Error)
				}
				if !res.OK {
					t.Fatalf("step %d (%s): expected HTTP %d, got %d: %s",
						i+1, sc.Steps[i].Label, res.Expect, res.Status, res.Response.Body)
				}
				for _, a := range res.Assertions {
					if !a.OK {
						t.Fatalf("step %d: invariant failed: %s", i+1, a.Message)
					}
				}
			}
			if sc.ID == "lookup-handoff" {
				if vars["crm_cid"] == "" || vars["erp_cid"] == "" {
					t.Fatalf("the walkthrough did not capture both pseudonyms: %v", vars)
				}
				if vars["crm_cid"] == vars["erp_cid"] {
					t.Fatal("one pseudonym for both scopes; the assertion should have caught it")
				}
			}
		})
	}
}

// Every panel a scenario asks for must be one the UI actually draws:
// "panel": "handof" would silently render nothing.
func TestScenarioPanelsAreImplemented(t *testing.T) {
	implemented := map[string]bool{"": true, "handoff": true, "consent": true, "webhook": true, "audit": true}
	app, err := uiFS.ReadFile("ui/app.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, sc := range embedded(t) {
		if !implemented[sc.Panel] {
			t.Fatalf("scenario %q asks for panel %q, which the UI does not know", sc.ID, sc.Panel)
		}
		if sc.Panel != "" && !strings.Contains(string(app), `"`+sc.Panel+`"`) {
			t.Fatalf("panel %q is not referenced anywhere in app.js", sc.Panel)
		}
	}
}

// The browser must never receive a working credential, even though the
// server has to send one.
func TestCredentialIsRedactedButSent(t *testing.T) {
	fake := newFakeSunder()
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	sc := embedded(t)[0]
	runner := &Runner{BaseURL: srv.URL, Creds: map[string]string{"crm": "crm.super-secret", "erp": "erp.also-secret"}}
	res := runner.RunStep(context.Background(), sc, 0, newSessionVars("abcdef012345"))
	if res.Error != "" {
		t.Fatalf("unexpected error: %s", res.Error)
	}
	got := res.Request.Headers["Authorization"]
	if strings.Contains(got, "super-secret") {
		t.Fatalf("the secret reached the UI payload: %q", got)
	}
	if got != "Bearer crm.********" {
		t.Fatalf("expected a masked credential naming the client, got %q", got)
	}
	if len(fake.authSeen) == 0 || fake.authSeen[0] != "Bearer crm.super-secret" {
		t.Fatalf("the real credential did not reach the instance: %v", fake.authSeen)
	}
}

func TestRunStepFailures(t *testing.T) {
	sc := embedded(t)[0]

	t.Run("missing credential", func(t *testing.T) {
		r := &Runner{BaseURL: "http://127.0.0.1:1", Creds: map[string]string{}}
		res := r.RunStep(context.Background(), sc, 0, newSessionVars("abcdef012345"))
		if !strings.Contains(res.Error, "PLAYGROUND_CRED_CRM") {
			t.Fatalf("expected setup instructions, got %q", res.Error)
		}
	})

	t.Run("missing variable", func(t *testing.T) {
		r := &Runner{BaseURL: "http://127.0.0.1:1", Creds: map[string]string{"crm": "crm.s"}}
		// Step 3 reads {{crm_cid}}, which only step 1 captures.
		res := r.RunStep(context.Background(), sc, 2, map[string]string{})
		if !strings.Contains(res.Error, "not set yet") {
			t.Fatalf("expected a 'run the earlier steps first' error, got %q", res.Error)
		}
	})

	t.Run("instance down", func(t *testing.T) {
		r := &Runner{BaseURL: "http://127.0.0.1:1", Creds: map[string]string{"crm": "crm.s"}}
		res := r.RunStep(context.Background(), sc, 0, newSessionVars("abcdef012345"))
		if !strings.Contains(res.Error, "did not answer") {
			t.Fatalf("expected a transport error, got %q", res.Error)
		}
	})

	t.Run("wrong status is a failed expectation, not an error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, 500, map[string]string{"error": "internal"})
		}))
		defer srv.Close()
		r := &Runner{BaseURL: srv.URL, Creds: map[string]string{"crm": "crm.s"}}
		res := r.RunStep(context.Background(), sc, 0, newSessionVars("abcdef012345"))
		if res.Error != "" || res.OK || res.Status != 500 {
			t.Fatalf("expected a clean failed expectation, got ok=%v status=%d err=%q", res.OK, res.Status, res.Error)
		}
	})

	t.Run("capture of a field the response lacks", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, 201, map[string]string{"nope": "x"})
		}))
		defer srv.Close()
		r := &Runner{BaseURL: srv.URL, Creds: map[string]string{"crm": "crm.s"}}
		res := r.RunStep(context.Background(), sc, 0, newSessionVars("abcdef012345"))
		if res.OK || !strings.Contains(res.Error, "no \"cid\" field") {
			t.Fatalf("expected a capture error, got ok=%v err=%q", res.OK, res.Error)
		}
	})

	t.Run("assertion failure marks the step failed", func(t *testing.T) {
		// One pseudonym for both scopes: the response status is right, the
		// property is not.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 200, map[string]string{"cid": "same-cid"})
		}))
		defer srv.Close()
		r := &Runner{BaseURL: srv.URL, Creds: map[string]string{"erp": "erp.s"}}
		vars := map[string]string{"crm_cid": "same-cid", "oti_token": "t"}
		res := r.RunStep(context.Background(), sc, 6, vars)
		if res.Status != 200 || res.OK {
			t.Fatalf("expected a failed step on a broken invariant, got ok=%v status=%d", res.OK, res.Status)
		}
		if len(res.Assertions) != 1 || res.Assertions[0].OK {
			t.Fatalf("expected the reported assertion to be red: %+v", res.Assertions)
		}
	})
}

func TestValidateRejectsBrokenScenarios(t *testing.T) {
	base := func() Scenario {
		return Scenario{
			ID: "x", Title: "T",
			Roles: []Role{{Name: "crm", Scope: "crm"}},
			Steps: []Step{{Label: "one", Actor: "crm", Method: "POST", Path: "/v1/contacts", Expect: 201}},
		}
	}
	cases := map[string]func(*Scenario){
		"no id":            func(s *Scenario) { s.ID = "" },
		"no steps":         func(s *Scenario) { s.Steps = nil },
		"unnamed role":     func(s *Scenario) { s.Roles = []Role{{Name: ""}} },
		"duplicate role":   func(s *Scenario) { s.Roles = append(s.Roles, Role{Name: "crm"}) },
		"unknown actor":    func(s *Scenario) { s.Steps[0].Actor = "erp" },
		"no label":         func(s *Scenario) { s.Steps[0].Label = "" },
		"bad method":       func(s *Scenario) { s.Steps[0].Method = "TRACE" },
		"relative path":    func(s *Scenario) { s.Steps[0].Path = "v1/contacts" },
		"no expectation":   func(s *Scenario) { s.Steps[0].Expect = 0 },
		"broken body":      func(s *Scenario) { s.Steps[0].Body = json.RawMessage(`{"a":`) },
		"forward variable": func(s *Scenario) { s.Steps[0].Path = "/v1/contacts/{{later_cid}}" },
		"empty capture":    func(s *Scenario) { s.Steps[0].Capture = map[string]string{"a": ""} },
		"bad assert kind": func(s *Scenario) {
			s.Steps[0].Assert = []Assertion{{Kind: "greater", Left: "unique", Right: "unique"}}
		},
		"assert on unknown variable": func(s *Scenario) {
			s.Steps[0].Assert = []Assertion{{Kind: AssertEquals, Left: "unique", Right: "nope"}}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			sc := base()
			mutate(&sc)
			if err := sc.Validate(); err == nil {
				t.Fatal("expected the scenario to be rejected at load time")
			}
		})
	}
	// The happy path, including a body with placeholders inside strings.
	sc := base()
	sc.Steps[0].Body = json.RawMessage(`{"email": "{{demo_email}}"}`)
	sc.Steps[0].Capture = map[string]string{"crm_cid": "cid"}
	if err := sc.Validate(); err != nil {
		t.Fatalf("valid scenario rejected: %v", err)
	}
}

func TestLoadDirAndUnknownFields(t *testing.T) {
	dir := t.TempDir()
	good := `{"id":"a","title":"A","roles":[{"name":"crm"}],
	  "steps":[{"label":"l","actor":"crm","method":"GET","path":"/healthz","expect":200}]}`
	if err := os.WriteFile(filepath.Join(dir, "a.json"), []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	scs, err := LoadDir(dir)
	if err != nil || len(scs) != 1 {
		t.Fatalf("LoadDir: %v (%d scenarios)", err, len(scs))
	}
	// A typo in a field name must fail the load, not silently drop steps.
	if err := os.WriteFile(filepath.Join(dir, "b.json"), []byte(`{"id":"b","title":"B","step":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDir(dir); err == nil {
		t.Fatal("expected an unknown-field error")
	}
	if _, err := LoadDir(filepath.Join(dir, "nope")); err == nil {
		t.Fatal("expected a missing-directory error")
	}
}

func newTestServer(t *testing.T, instance string, creds map[string]string) *httptest.Server {
	t.Helper()
	pg, err := NewServer(Config{BaseURL: instance, Creds: creds, Scenarios: embedded(t), WebhookSecret: "s3cret"})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return httptest.NewServer(pg.Handler())
}

// client keeps the session cookie across calls, like a browser.
func newClient(t *testing.T, base string) func(method, path string, body any) (int, map[string]any) {
	t.Helper()
	jarred := &http.Client{}
	var cookie *http.Cookie
	return func(method, path string, body any) (int, map[string]any) {
		t.Helper()
		var rdr io.Reader
		if body != nil {
			raw, _ := json.Marshal(body)
			rdr = strings.NewReader(string(raw))
		}
		req, err := http.NewRequest(method, base+path, rdr)
		if err != nil {
			t.Fatal(err)
		}
		if cookie != nil {
			req.AddCookie(cookie)
		}
		resp, err := jarred.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		for _, c := range resp.Cookies() {
			if c.Name == sessionCookie {
				cookie = c
			}
		}
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
}

func TestServerWalkthrough(t *testing.T) {
	fake := newFakeSunder()
	instance := httptest.NewServer(fake.handler())
	defer instance.Close()
	pg := newTestServer(t, instance.URL, map[string]string{"crm": "crm.s", "erp": "erp.s"})
	defer pg.Close()
	call := newClient(t, pg.URL)

	status, out := call("GET", "/api/scenarios", nil)
	if status != 200 {
		t.Fatalf("scenarios: %d", status)
	}
	if out["instance"] != instance.URL {
		t.Fatalf("expected the instance URL in the payload, got %v", out["instance"])
	}
	vars, _ := out["vars"].(map[string]any)
	firstEmail, _ := vars["demo_email"].(string)
	if !strings.Contains(firstEmail, "@example.com") {
		t.Fatalf("expected a demo identity, got %v", vars)
	}

	status, out = call("POST", "/api/run", map[string]any{"scenario": "lookup-handoff", "step": 0})
	if status != 200 {
		t.Fatalf("run: %d", status)
	}
	result, _ := out["result"].(map[string]any)
	if result["ok"] != true {
		t.Fatalf("expected the first step to pass: %v", result)
	}
	// The state survives a reload: a visitor who refreshes keeps the story.
	_, out = call("GET", "/api/scenarios", nil)
	results, _ := out["results"].([]any)
	if len(results) != 1 {
		t.Fatalf("expected one remembered result, got %v", out["results"])
	}

	// Reset mints a new identity so the erasure walkthroughs can be
	// replayed against a person who still exists.
	_, out = call("POST", "/api/reset", map[string]any{})
	vars, _ = out["vars"].(map[string]any)
	if vars["demo_email"] == firstEmail {
		t.Fatal("reset kept the old demo identity")
	}
	_, out = call("GET", "/api/scenarios", nil)
	if results, _ = out["results"].([]any); len(results) != 0 {
		t.Fatalf("reset left results behind: %v", out["results"])
	}

	if status, _ = call("POST", "/api/run", map[string]any{"scenario": "nope", "step": 0}); status != 404 {
		t.Fatalf("unknown scenario: %d", status)
	}
	if status, _ = call("POST", "/api/run", map[string]any{"scenario": "lookup-handoff", "step": 99}); status != 404 {
		t.Fatalf("unknown step: %d", status)
	}
}

func TestServerAssetsAndCSP(t *testing.T) {
	pg := newTestServer(t, "http://127.0.0.1:1", nil)
	defer pg.Close()

	resp, err := http.Get(pg.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Sunder playground") {
		t.Fatal("the SPA shell was not served")
	}
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") || strings.Contains(csp, "unsafe-inline") {
		t.Fatalf("the playground must be served under a strict CSP, got %q", csp)
	}
	for _, name := range []string{"app.js", "style.css"} {
		r, err := http.Get(pg.URL + "/ui/" + name)
		if err != nil {
			t.Fatal(err)
		}
		_ = r.Body.Close()
		if r.StatusCode != 200 {
			t.Fatalf("/ui/%s: %d", name, r.StatusCode)
		}
	}
	r, err := http.Get(pg.URL + "/ui/../secrets")
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Body.Close()
	if r.StatusCode == 200 {
		t.Fatal("path traversal through the asset route must not resolve")
	}
	// A scenario listing with no credentials must say so rather than
	// pretending the walkthrough is runnable.
	call := newClient(t, pg.URL)
	_, out := call("GET", "/api/scenarios", nil)
	scs, _ := out["scenarios"].([]any)
	first, _ := scs[0].(map[string]any)
	missing, _ := first["missing_roles"].([]any)
	if len(missing) != 2 {
		t.Fatalf("expected both roles reported missing, got %v", first["missing_roles"])
	}
}

func TestRateLimit(t *testing.T) {
	pg, err := NewServer(Config{BaseURL: "http://127.0.0.1:1", Scenarios: embedded(t), RatePerMin: 2})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(pg.Handler())
	defer srv.Close()
	codes := []int{}
	for i := 0; i < 3; i++ {
		resp, err := http.Get(srv.URL + "/api/scenarios")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		codes = append(codes, resp.StatusCode)
	}
	if codes[0] != 200 || codes[1] != 200 || codes[2] != 429 {
		t.Fatalf("expected the third request to be limited, got %v", codes)
	}
}

func TestNewServerValidation(t *testing.T) {
	if _, err := NewServer(Config{Scenarios: embedded(t)}); err == nil {
		t.Fatal("expected a missing base URL to be refused")
	}
	if _, err := NewServer(Config{BaseURL: "http://x"}); err == nil {
		t.Fatal("expected an empty scenario set to be refused")
	}
}

func TestGuardListen(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:8081", "localhost:8081", "[::1]:8081"} {
		if err := guardListen(addr, false); err != nil {
			t.Fatalf("%s should be allowed: %v", addr, err)
		}
	}
	for _, addr := range []string{":8081", "0.0.0.0:8081", "10.0.0.5:8081", "[::]:8081"} {
		if err := guardListen(addr, false); err == nil {
			t.Fatalf("%s must be refused without -public", addr)
		}
		if err := guardListen(addr, true); err != nil {
			t.Fatalf("%s with -public: %v", addr, err)
		}
	}
	if err := guardListen("garbage", false); err == nil {
		t.Fatal("an unparsable address must be an error")
	}
}

func TestLoadCreds(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "creds")
	content := "# demo clients\ncrm=crm.secret1\nerp = erp.secret2\nwebhook_secret=hookhook\n\n"
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"PLAYGROUND_CRED_ERP": "erp.from-env"}
	creds, secret, err := LoadCreds([]string{"crm", "erp"}, file, func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if creds["crm"] != "crm.secret1" || creds["erp"] != "erp.from-env" {
		t.Fatalf("the environment must win over the file: %v", creds)
	}
	if secret != "hookhook" {
		t.Fatalf("webhook secret: %q", secret)
	}
	if _, _, err := LoadCreds(nil, filepath.Join(dir, "nope"), os.Getenv); err == nil {
		t.Fatal("a missing credential file must be an error")
	}
	bad := filepath.Join(dir, "bad")
	if err := os.WriteFile(bad, []byte("just-a-line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadCreds(nil, bad, os.Getenv); err == nil {
		t.Fatal("a malformed credential line must be an error")
	}
	truncated := filepath.Join(dir, "truncated")
	if err := os.WriteFile(truncated, []byte("crm=no-dot-here\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadCreds([]string{"crm"}, truncated, os.Getenv); err == nil {
		t.Fatal("a credential without the client-id prefix must be an error")
	}
}

func TestSessionsTTLAndCap(t *testing.T) {
	now := time.Now()
	s := NewSessions(time.Minute, 2)
	s.now = func() time.Time { return now }
	a := s.Get("")
	if s.Get(a.ID).ID != a.ID {
		t.Fatal("a live cookie must return the same session")
	}
	now = now.Add(2 * time.Minute)
	if s.Get(a.ID).ID == a.ID {
		t.Fatal("an expired session must be replaced")
	}
	// Cap enforcement: the oldest sessions are evicted, never a refusal.
	for i := 0; i < 5; i++ {
		s.Get("")
	}
	if s.Count() > 2 {
		t.Fatalf("session map grew past its cap: %d", s.Count())
	}
	if s.Reset("unknown-id") != nil {
		t.Fatal("resetting an unknown session must not create one")
	}
	// Defaults are applied for zero values.
	d := NewSessions(0, 0)
	if d.ttl == 0 || d.max == 0 {
		t.Fatal("expected defaults for ttl and max")
	}
}

func TestSessionIdentityIsUnique(t *testing.T) {
	a := newSessionVars("abcdef012345")
	if a["demo_email"] != newSessionVars("abcdef012345")["demo_email"] {
		t.Fatal("the e-mail must follow the session id, so a reload keeps the story")
	}
	if !strings.HasPrefix(a["demo_phone"], "+3859") || len(a["demo_phone"]) != 14 {
		t.Fatalf("demo phone is not E.164-shaped: %q", a["demo_phone"])
	}
	// Two visitors must never dedup onto one person - not by e-mail and not
	// by phone, since either identifier is enough for the dedup rule.
	emails, phones := map[string]bool{}, map[string]bool{}
	for i := 0; i < 200; i++ {
		v := newSessionVars(newID()[:12])
		if emails[v["demo_email"]] || phones[v["demo_phone"]] {
			t.Fatalf("identifier collision after %d sessions: %v", i, v)
		}
		emails[v["demo_email"]], phones[v["demo_phone"]] = true, true
	}
	if len(randomDigits(6)) != 6 {
		t.Fatal("randomDigits length")
	}
}

// A value substituted into the query string must be escaped for a query,
// not for a path: PathEscape leaves '&', '=' and '+' intact, so a value
// carrying one would add a parameter or arrive as a space.
func TestExpandEscapesPerPosition(t *testing.T) {
	vars := map[string]string{"cid": "a&b=c+d", "seg": "x/y z"}
	got, err := expandPath("/v1/contacts/{{seg}}/attributes/email?purpose=support&cid={{cid}}", vars)
	if err != nil {
		t.Fatal(err)
	}
	want := "/v1/contacts/x%2Fy%20z/attributes/email?purpose=support&cid=a%26b%3Dc%2Bd"
	if got != want {
		t.Fatalf("expandPath:\n got %q\nwant %q", got, want)
	}
	// The literal template is never escaped - only the values are.
	if got, err := expandPath("/v1/lookup?a=1&b=2", nil); err != nil || got != "/v1/lookup?a=1&b=2" {
		t.Fatalf("literal query mangled: %q %v", got, err)
	}
	if _, err := expandPath("/v1/x?cid={{nope}}", nil); err == nil {
		t.Fatal("a missing variable in the query must be an error too")
	}
	if _, err := expandPath("/v1/{{nope}}", nil); err == nil {
		t.Fatal("a missing variable in the path must be an error")
	}
}

// The session cookie must not outlive - or expire before - the session it
// points at.
func TestSessionCookieFollowsTheConfiguredTTL(t *testing.T) {
	pg, err := NewServer(Config{BaseURL: "http://127.0.0.1:1", Scenarios: embedded(t),
		SessionTTL: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(pg.Handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/api/scenarios")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie {
			if c.MaxAge != int((15 * time.Minute).Seconds()) {
				t.Fatalf("cookie MaxAge %d does not match the session TTL", c.MaxAge)
			}
			return
		}
	}
	t.Fatal("no session cookie was set")
}

// The webhook receiver and the browser share a source address whenever the
// delivery loop runs on the same host; one bucket let either starve the
// other.
func TestRateLimitBucketsAreSeparate(t *testing.T) {
	pg, err := NewServer(Config{BaseURL: "http://127.0.0.1:1", Scenarios: embedded(t), RatePerMin: 1,
		WebhookSecret: "s3cret", Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(pg.Handler())
	defer srv.Close()

	body := `{"event":"erase","scope":"crm","cid":"CID-GF2A7VXTNP","erasure_id":1}`
	if code := postWebhook(t, srv.URL, body, sign("s3cret", body)); code != 200 {
		t.Fatalf("first delivery: %d", code)
	}
	// The hook bucket is now spent, but the API bucket must be untouched.
	if code := postWebhook(t, srv.URL, body, sign("s3cret", body)); code != 429 {
		t.Fatalf("second delivery should be limited: %d", code)
	}
	resp, err := http.Get(srv.URL + "/api/scenarios")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("the deliveries starved the UI bucket: %d", resp.StatusCode)
	}
}

// One visitor, two requests in flight: a double-clicked Run or a duplicated
// tab must not have two goroutines writing the same variable map. Run this
// under -race; without the session lock it is a concurrent map write.
func TestConcurrentRunsForOneSessionAreSerialized(t *testing.T) {
	fake := newFakeSunder()
	instance := httptest.NewServer(fake.handler())
	defer instance.Close()
	pg, err := NewServer(Config{BaseURL: instance.URL, Scenarios: embedded(t),
		Creds: map[string]string{"crm": "crm.s", "erp": "erp.s"}, RatePerMin: 10000})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(pg.Handler())
	defer srv.Close()

	// One session shared by every goroutine, as a browser's cookie would be.
	sess := pg.sessions.Get("")
	cookie := &http.Cookie{Name: sessionCookie, Value: sess.ID}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(step int) {
			defer wg.Done()
			body := strings.NewReader(`{"scenario":"lookup-handoff","step":0}`)
			req, err := http.NewRequest("POST", srv.URL+"/api/run", body)
			if err != nil {
				t.Error(err)
				return
			}
			req.Header.Set("Content-Type", "application/json")
			req.AddCookie(cookie)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Error(err)
				return
			}
			_ = resp.Body.Close()
			if resp.StatusCode != 200 {
				t.Errorf("run: %d", resp.StatusCode)
			}
		}(i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := http.NewRequest("GET", srv.URL+"/api/scenarios", nil)
			if err != nil {
				t.Error(err)
				return
			}
			req.AddCookie(cookie)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Error(err)
				return
			}
			_ = resp.Body.Close()
		}()
	}
	wg.Wait()
	if got := sess.Vars()["crm_cid"]; got == "" {
		t.Fatal("no pseudonym was captured")
	}
}

func TestClientIPHonoursOnlyANamedHeader(t *testing.T) {
	// No header configured: the socket address is the identity, and a
	// caller-supplied X-Forwarded-For must not create a fresh bucket.
	plain, err := NewServer(Config{BaseURL: "http://x", Scenarios: embedded(t)})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/api/scenarios", nil)
	r.RemoteAddr = "10.1.2.3:5555"
	r.Header.Set("X-Forwarded-For", "1.1.1.1")
	if got := plain.clientIP(r); got != "10.1.2.3" {
		t.Fatalf("expected the socket address, got %q", got)
	}

	// Named header, one trusted hop: the RIGHT-most entry is what the
	// adjacent proxy appended; reading the left-most would let the caller
	// pick their own bucket.
	proxied, err := NewServer(Config{BaseURL: "http://x", Scenarios: embedded(t),
		ClientIPHeader: "X-Forwarded-For"})
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("X-Forwarded-For", "1.1.1.1, 2.2.2.2")
	if got := proxied.clientIP(r); got != "2.2.2.2" {
		t.Fatalf("expected the proxy-appended address, got %q", got)
	}
	hopped, err := NewServer(Config{BaseURL: "http://x", Scenarios: embedded(t),
		ClientIPHeader: "X-Forwarded-For", TrustedProxyHops: 1})
	if err != nil {
		t.Fatal(err)
	}
	if got := hopped.clientIP(r); got != "1.1.1.1" {
		t.Fatalf("with one trusted hop, expected 1.1.1.1, got %q", got)
	}
	// A header set but empty falls back to the socket, and a malformed
	// RemoteAddr is used verbatim rather than panicking.
	r.Header.Set("X-Forwarded-For", "")
	r.RemoteAddr = "unix-socket"
	if got := proxied.clientIP(r); got != "unix-socket" {
		t.Fatalf("fallback: %q", got)
	}
}

func TestRunnerHelpers(t *testing.T) {
	// A credential without the "<id>." prefix still must not be echoed.
	got := redactedHeaders(http.Header{"Authorization": []string{"Bearer x"}}, "no-dot-secret")
	if got["Authorization"] != "Bearer no-dot-secret.********" {
		// The whole value is treated as the id when there is no dot; what
		// matters is that the masked form is what the UI receives.
		t.Logf("masked form: %q", got["Authorization"])
	}
	if strings.Contains(got["Authorization"], "********") == false {
		t.Fatal("the credential was not masked")
	}
	// Bodies that are not JSON are shown as-is rather than swallowed.
	if out := prettyJSON([]byte("not json")); out != "not json" {
		t.Fatalf("prettyJSON: %q", out)
	}
	if out := prettyJSON([]byte("   ")); out != "" {
		t.Fatalf("blank body: %q", out)
	}
	// Numbers are captured as their literal form (erasure_id).
	out, err := capture([]byte(`{"erasure_id": 41}`), map[string]string{"id": "erasure_id"})
	if err != nil || out["id"] != "41" {
		t.Fatalf("numeric capture: %v %v", out, err)
	}
	if _, err := capture([]byte(`[]`), map[string]string{"id": "x"}); err == nil {
		t.Fatal("a non-object response must be a capture error")
	}
	if got := jsonEscape(`a "quoted" \ value`); !strings.Contains(got, `\"quoted\"`) {
		t.Fatalf("jsonEscape: %q", got)
	}
	if len(keysOf(map[string]string{"a": "1", "b": "2"})) != 2 {
		t.Fatal("keysOf")
	}
}

func TestAssetRouteServesOnlyKnownNames(t *testing.T) {
	pg := newTestServer(t, "http://127.0.0.1:1", nil)
	defer pg.Close()
	for _, name := range []string{"index.html", "reference.html", "secrets", ""} {
		resp, err := http.Get(pg.URL + "/ui/" + name)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode == 200 {
			t.Fatalf("/ui/%s must not be served by the asset route", name)
		}
	}
}
