package api

// Edge-case floor for the thin routes (house rule: every endpoint carries at
// least one happy-path test and two edge tests - malformed input, oversized
// input, unknown targets). These top up the routes the rest of the suite
// exercises only once or twice; TestEveryRouteIsExercised enforces the floor
// mechanically.

import (
	"bytes"
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	apispec "github.com/fvisic/sunder/api"
	"github.com/fvisic/sunder/internal/config"
	"github.com/fvisic/sunder/internal/testutil"
)

// GET /readyz: edge - the database is unreachable, readiness must say so.
func TestReadyzReportsDeadDatabase(t *testing.T) {
	st := testutil.NewDB(t)
	srv, err := New(config.Config{Keystore: "file", KeyRetireGrace: -1, KeystorePath: t.TempDir()}, st)
	if err != nil {
		t.Fatal(err)
	}
	// Happy first.
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
	if rec.Code != 200 {
		t.Fatalf("ready with a live database: %d", rec.Code)
	}
	// Kill the pool: readiness must fail, not lie.
	st.Pool.Close()
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
	if rec.Code != 503 {
		t.Fatalf("readyz over a dead pool must be 503, got %d", rec.Code)
	}
}

// GET /readyz: edge - a write method on a GET route is a 405 from the mux,
// and the GET itself still answers around it.
func TestReadyzRejectsWrongMethod(t *testing.T) {
	st := testutil.NewDB(t)
	srv, err := New(config.Config{Keystore: "file", KeyRetireGrace: -1, KeystorePath: t.TempDir()}, st)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/readyz", nil))
	if rec.Code != 405 {
		t.Fatalf("POST /readyz must be 405, got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
	if rec.Code != 200 {
		t.Fatalf("GET /readyz after the 405 must still be 200, got %d", rec.Code)
	}
}

// GET /healthz edges: wrong method is 405, and liveness stays 200 even with
// the database gone - liveness is NOT readiness.
func TestHealthzEdges(t *testing.T) {
	st := testutil.NewDB(t)
	srv, err := New(config.Config{Keystore: "file", KeyRetireGrace: -1, KeystorePath: t.TempDir()}, st)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("PUT", "/healthz", nil))
	if rec.Code != 405 {
		t.Fatalf("PUT /healthz must be 405, got %d", rec.Code)
	}
	st.Pool.Close()
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != 200 {
		t.Fatalf("liveness must not depend on the database: %d", rec.Code)
	}
}

// GET /openapi.yaml edges: the served contract is the embedded spec (yaml
// content type, non-trivial, carries the paths), and a write method is 405.
func TestOpenAPISpecServed(t *testing.T) {
	st := testutil.NewDB(t)
	srv, err := New(config.Config{Keystore: "file", KeyRetireGrace: -1, KeystorePath: t.TempDir()}, st)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/openapi.yaml", nil))
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "application/yaml" {
		t.Fatalf("spec must be served as yaml: %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	body := rec.Body.String()
	if len(body) < 10000 || !strings.Contains(body, "paths:") || !strings.Contains(body, "/v1/tokens") {
		t.Fatalf("served spec looks wrong: %d bytes", len(body))
	}
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/openapi.yaml", nil))
	if rec.Code != 405 {
		t.Fatalf("POST /openapi.yaml must be 405, got %d", rec.Code)
	}
}

// GET /openapi.yaml: the served bytes ARE the repo contract - byte-identical
// to the embedded file, so a stale copy cannot be served.
func TestOpenAPISpecMatchesEmbedded(t *testing.T) {
	st := testutil.NewDB(t)
	srv, err := New(config.Config{Keystore: "file", KeyRetireGrace: -1, KeystorePath: t.TempDir()}, st)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/openapi.yaml", nil))
	if !bytes.Equal(rec.Body.Bytes(), apispec.OpenAPI) {
		t.Fatal("served spec must be byte-identical to the embedded contract")
	}
}

// POST+DELETE /v1/links edges: garbage link_type, self-link, unknown pair,
// malformed body.
func TestLinkEndpointEdges(t *testing.T) {
	e := newE2E(t)
	if _, err := e.srv.Store.Pool.Exec(context.Background(),
		`UPDATE clients SET allowed_actions = allowed_actions || '{links.manage}' WHERE client_id='crm'`); err != nil {
		t.Fatal(err)
	}
	_, out := e.do(t, e.credCRM, "POST", "/v1/contacts", map[string]any{"email": "l1@example.com"})
	cid1 := out["cid"]
	_, out = e.do(t, e.credCRM, "POST", "/v1/contacts", map[string]any{"email": "l2@example.com"})
	cid2 := out["cid"]

	if rec, _ := e.do(t, e.credCRM, "POST", "/v1/links", map[string]string{
		"parent_cid": cid1, "child_cid": cid2, "link_type": "overlord"}); rec.Code != 400 {
		t.Fatalf("garbage link_type must be 400, got %d", rec.Code)
	}
	if rec, _ := e.do(t, e.credCRM, "POST", "/v1/links", map[string]string{
		"parent_cid": cid1, "child_cid": cid1, "link_type": "guardian"}); rec.Code == 201 {
		t.Fatal("a self-link must be refused")
	}
	if rec, _ := e.do(t, e.credCRM, "DELETE", "/v1/links", map[string]string{
		"parent_cid": cid1, "child_cid": cid2}); rec.Code != 404 {
		t.Fatalf("unlinking a pair that was never linked must be 404, got %d", rec.Code)
	}
	if rec, _ := e.do(t, e.credCRM, "DELETE", "/v1/links", map[string]string{
		"parent_cid": ""}); rec.Code != 400 && rec.Code != 404 {
		t.Fatalf("a malformed unlink must be refused, got %d", rec.Code)
	}
}

// GET /v1/consent/{cid} edges: no consent.manage action; a cid stuffed with
// garbage; both must refuse without an oracle.
func TestConsentListEdges(t *testing.T) {
	e := newE2E(t)
	ctx := context.Background()
	if _, err := e.srv.Store.Pool.Exec(ctx,
		`UPDATE clients SET allowed_actions = allowed_actions || '{consent.manage}' WHERE client_id='crm'`); err != nil {
		t.Fatal(err)
	}
	_, out := e.do(t, e.credCRM, "POST", "/v1/contacts", map[string]any{"email": "c1@example.com"})
	cid := out["cid"]
	if rec, _ := e.do(t, e.credCRM, "GET", "/v1/consent/"+cid, nil); rec.Code != 200 {
		t.Fatalf("consent list happy path: %d", rec.Code)
	}
	if rec, _ := e.do(t, e.credDWH, "GET", "/v1/consent/"+cid, nil); rec.Code != 403 && rec.Code != 404 {
		t.Fatalf("foreign client without the action must be refused, got %d", rec.Code)
	}
	if rec, _ := e.do(t, e.credCRM, "GET", "/v1/consent/%00%ff-not-a-cid", nil); rec.Code != 404 && rec.Code != 400 {
		t.Fatalf("garbage cid must be a clean miss, got %d", rec.Code)
	}
}

// GET /v1/dsr/access edges: missing cid parameter and an unknown cid.
func TestDSRAccessEdges(t *testing.T) {
	e, credDPO := gdprEnv(t)
	if rec, _ := e.do(t, credDPO, "GET", "/v1/dsr/access", nil); rec.Code != 400 && rec.Code != 404 {
		t.Fatalf("dsr/access without cid must be refused, got %d", rec.Code)
	}
	if rec, _ := e.do(t, credDPO, "GET", "/v1/dsr/access?cid=CID-DOESNOTEXIST00000000000", nil); rec.Code != 404 {
		t.Fatalf("dsr/access for an unknown cid must be 404, got %d", rec.Code)
	}
}

// GET /v1/contacts/{cid}/versions/{version}/attributes/{name} edges: a
// non-numeric version and a version that never existed.
func TestVersionAttributeEdges(t *testing.T) {
	e := newE2E(t)
	ctx := context.Background()
	if _, err := e.srv.Store.Pool.Exec(ctx,
		`UPDATE clients SET allowed_actions = allowed_actions || '{attributes.history}' WHERE client_id='crm'`); err != nil {
		t.Fatal(err)
	}
	_, out := e.do(t, e.credCRM, "POST", "/v1/contacts", map[string]any{"email": "v1@example.com"})
	cid := out["cid"]
	if rec, _ := e.do(t, e.credCRM, "GET", "/v1/contacts/"+cid+"/versions/banana/attributes/email?purpose=newsletter", nil); rec.Code != 400 {
		t.Fatalf("non-numeric version must be 400, got %d", rec.Code)
	}
	if rec, _ := e.do(t, e.credCRM, "GET", "/v1/contacts/"+cid+"/versions/999/attributes/email?purpose=newsletter", nil); rec.Code != 404 {
		t.Fatalf("a version that never existed must be 404, got %d", rec.Code)
	}
}

// POST /portal/api/logout and /portal/api/erase/confirm edges: no session
// cookie, and a forged confirmation token.
func TestPortalLogoutAndConfirmEdges(t *testing.T) {
	p := newPortalEnv(t)
	rec := httptest.NewRecorder()
	p.srv.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/portal/api/logout", nil))
	if rec.Code != 200 && rec.Code != 401 {
		t.Fatalf("logout without a session must be a clean no-op or 401, got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/portal/api/erase/confirm?token=forged-token-000", nil)
	p.srv.Handler().ServeHTTP(rec, req)
	if rec.Code == 200 {
		t.Fatal("a forged erase confirmation must never succeed")
	}
}

// GET /v1/contacts/{cid}/attributes/{name}: the hottest read endpoint was
// the ONE cid surface bypassing the shared shape guard - a NUL byte in the
// path used to 500 it (review N1). It must miss cleanly like the other
// eleven cid-addressed routes.
func TestAttributeGetGarbageCid(t *testing.T) {
	e := newE2E(t)
	for _, cid := range []string{"CID-%00EVIL", "CID-%FF%FE", "CID-" + strings.Repeat("A", 400)} {
		rec, _ := e.do(t, e.credCRM, "GET", "/v1/contacts/"+cid+"/attributes/email?purpose=newsletter", nil)
		if rec.Code != 404 {
			t.Fatalf("garbage cid %q must be a clean 404, got %d", cid[:12], rec.Code)
		}
	}
}
