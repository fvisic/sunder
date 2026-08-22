package audit

// Offline anchor tests: testdata/freetsa-sample.tsr is a real FreeTSA token
// over the digest 0123..ef (fetched once), so token parsing and verification
// run without network. Signature verification uses the vendored CA.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

const (
	fixtureTSR    = "testdata/freetsa-sample.tsr"
	fixtureDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	vendoredCA    = "../../deploy/freetsa/cacert.pem"
)

func fixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(fixtureTSR)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func fakeTSA(t *testing.T, status int, body []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/timestamp-query" {
			t.Errorf("wrong content type: %s", r.Header.Get("Content-Type"))
		}
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestPostReturnsTokenAndMapsErrors(t *testing.T) {
	needsOpenSSL(t)
	tok := fixture(t)
	srv := fakeTSA(t, 200, tok)
	got, err := Post(context.Background(), srv.URL, []byte("query"))
	if err != nil || len(got) != len(tok) {
		t.Fatalf("post: %v (%d bytes)", err, len(got))
	}
	bad := fakeTSA(t, 500, []byte("boom"))
	if _, err := Post(context.Background(), bad.URL, []byte("query")); err == nil {
		t.Fatal("500 from TSA must error")
	}
	if _, err := Post(context.Background(), "http://127.0.0.1:1/tsr", []byte("q")); err == nil {
		t.Fatal("unreachable TSA must error")
	}
}

func TestTokenTimeParsesFixture(t *testing.T) {
	needsOpenSSL(t)
	when, err := TokenTime(fixture(t))
	if err != nil || when == "" {
		t.Fatalf("token time: %q %v", when, err)
	}
	if _, err := TokenTime([]byte("not a token")); err == nil {
		t.Fatal("garbage token must error")
	}
}

func TestVerifyTokenOfflineAgainstVendoredCA(t *testing.T) {
	needsOpenSSL(t)
	ok, err := VerifyToken(fixture(t), fixtureDigest, vendoredCA)
	if err != nil || !ok {
		t.Fatalf("fixture must verify: ok=%v err=%v", ok, err)
	}
	// Wrong digest: a clean verification FAILURE (false, nil), not an error.
	wrong := "ffff" + fixtureDigest[4:]
	ok, err = VerifyToken(fixture(t), wrong, vendoredCA)
	if err != nil || ok {
		t.Fatalf("wrong digest must fail verification cleanly: ok=%v err=%v", ok, err)
	}
}

func TestAnchorFullFlowWithFakeTSA(t *testing.T) {
	needsOpenSSL(t)
	s := testPool(t)
	ctx := context.Background()
	if err := Append(ctx, s.Pool, Entry{ClientID: "crm", Action: "lookup"}); err != nil {
		t.Fatal(err)
	}
	srv := fakeTSA(t, 200, fixture(t))
	outDir := t.TempDir()

	// Without a CA the token is stored and exported as-is.
	root, stampedAt, err := Anchor(ctx, s.Pool, srv.URL, "", outDir)
	if err != nil || root == "" || stampedAt == "" {
		t.Fatalf("anchor: root=%q at=%q err=%v", root, stampedAt, err)
	}
	if _, err := os.Stat(filepath.Join(outDir, root+".tsr")); err != nil {
		t.Fatalf("export missing: %v", err)
	}
	// With a CA, a token that does not cover the actual chain head must be
	// rejected BEFORE persisting (fixture covers a different digest).
	if _, _, err := Anchor(ctx, s.Pool, srv.URL, vendoredCA, outDir); err == nil {
		t.Fatal("mismatched token must not be stored when a CA is available")
	}

	// Cross-check: DB and export agree; token verification against the
	// wrong-root fixture reports INVALID (not an error).
	results, err := VerifyAnchors(ctx, s.Pool, vendoredCA, outDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].FileState != "ok" || !results[0].InChain {
		t.Fatalf("unexpected results: %+v", results)
	}
	if results[0].TokenOK {
		t.Fatal("fixture token cannot verify over the real chain head")
	}
}

func TestBuildQueryRejectsBadRoot(t *testing.T) {
	for _, bad := range []string{"", "zz", fixtureDigest[:63], fixtureDigest + "0", "ABCDEF" + fixtureDigest[6:]} {
		if _, err := BuildQuery(bad); err == nil {
			t.Errorf("BuildQuery(%q): expected error", bad)
		}
	}
}
