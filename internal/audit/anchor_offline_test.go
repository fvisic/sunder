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
	sealAll(t, s) // anchoring stamps the SEALED head; in async mode that needs a seal pass
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

func TestAnchorErrorBranches(t *testing.T) {
	needsOpenSSL(t)
	s := testPool(t)
	ctx := context.Background()
	if err := Append(ctx, s.Pool, Entry{ClientID: "crm", Action: "seed"}); err != nil {
		t.Fatal(err)
	}
	sealAll(t, s) // anchoring stamps the SEALED head; in async mode that needs a seal pass
	// TSA returns garbage: TokenTime fails, nothing is stored.
	garbage := fakeTSA(t, 200, []byte("this is not a DER token"))
	if _, _, err := Anchor(ctx, s.Pool, garbage.URL, "", t.TempDir()); err == nil {
		t.Fatal("garbage TSA reply must not be stored")
	}
	// Unreachable TSA.
	if _, _, err := Anchor(ctx, s.Pool, "http://127.0.0.1:1/tsr", "", ""); err == nil {
		t.Fatal("unreachable TSA must error")
	}
	var n int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_anchor`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("failed anchor attempts must store nothing, found %d rows", n)
	}
}

func TestVerifyAnchorsMalformedRootRow(t *testing.T) {
	needsOpenSSL(t)
	s := testPool(t)
	ctx := context.Background()
	// A row whose root is not a sha256 digest: with a CA the token check
	// must surface an error (environment/validation), not a silent verdict.
	if _, err := s.Pool.Exec(ctx,
		`INSERT INTO audit_anchor (root_hash, tsa_url, stamped_at, tsr) VALUES ('XYZ','t','',''::bytea)`); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAnchors(ctx, s.Pool, vendoredCA, ""); err == nil {
		t.Fatal("malformed stored root must error under token verification")
	}
	// Without a CA it is only reported as not-in-chain.
	res, err := VerifyAnchors(ctx, s.Pool, "", "")
	if err != nil || len(res) != 1 || res[0].InChain {
		t.Fatalf("expected one not-in-chain row: %+v %v", res, err)
	}
}

func TestVerifyTokenWithoutOpenSSL(t *testing.T) {
	withoutOpenSSL(t) // no PATH surgery: the binary path is injectable
	if _, err := VerifyToken([]byte("x"), fixtureDigest, vendoredCA); err == nil {
		t.Fatal("missing openssl must be an environment error")
	}
}

func TestAppendOnDeadPool(t *testing.T) {
	s := testPool(t)
	s.Close()
	if err := Append(context.Background(), s.Pool, Entry{ClientID: "x", Action: "y"}); err == nil {
		t.Fatal("append on dead pool must error")
	}
	if _, _, _, err := Verify(context.Background(), s.Pool); err == nil {
		t.Fatal("verify on dead pool must error")
	}
	if _, err := Head(context.Background(), s.Pool); err == nil {
		t.Fatal("head on dead pool must error")
	}
	if _, err := VerifyAnchors(context.Background(), s.Pool, "", ""); err == nil {
		t.Fatal("verify-anchors on dead pool must error")
	}
	if _, _, err := Anchor(context.Background(), s.Pool, "http://x", "", ""); err == nil {
		t.Fatal("anchor on dead pool must error")
	}
}

func TestVerifyAnchorsFileStates(t *testing.T) {
	s := testPool(t)
	ctx := context.Background()
	if err := Append(ctx, s.Pool, Entry{ClientID: "crm", Action: "seed"}); err != nil {
		t.Fatal(err)
	}
	sealAll(t, s) // anchoring stamps the SEALED head; in async mode that needs a seal pass
	head, err := Head(ctx, s.Pool)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx,
		`INSERT INTO audit_anchor (root_hash, tsa_url, stamped_at, tsr) VALUES ($1,'t','','dbbytes'::bytea)`, head); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	// missing: no exported file for the DB anchor.
	res, err := VerifyAnchors(ctx, s.Pool, "", dir)
	if err != nil || len(res) != 1 || res[0].FileState != "missing" {
		t.Fatalf("want missing, got %+v %v", res, err)
	}
	// mismatch: exported bytes differ from the DB token.
	if err := os.WriteFile(dir+"/"+head+".tsr", []byte("otherbytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err = VerifyAnchors(ctx, s.Pool, "", dir)
	if err != nil || res[0].FileState != "mismatch" {
		t.Fatalf("want mismatch, got %+v %v", res, err)
	}
	// ok: bytes agree.
	if err := os.WriteFile(dir+"/"+head+".tsr", []byte("dbbytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err = VerifyAnchors(ctx, s.Pool, "", dir)
	if err != nil || res[0].FileState != "ok" {
		t.Fatalf("want ok, got %+v %v", res, err)
	}
}

func TestVerifyAnchorsOrphanWithCA(t *testing.T) {
	needsOpenSSL(t)
	s := testPool(t)
	ctx := context.Background()
	dir := t.TempDir()
	// An orphan export whose root is the fixture digest: not in the chain,
	// not in the DB, but the TSA token verifies - deletion evidence with a
	// cryptographically valid receipt.
	if err := os.WriteFile(dir+"/"+fixtureDigest+".tsr", fixture(t), 0o444); err != nil {
		t.Fatal(err)
	}
	res, err := VerifyAnchors(ctx, s.Pool, vendoredCA, dir)
	if err != nil || len(res) != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if res[0].InDB || res[0].InChain || !res[0].TokenOK {
		t.Fatalf("orphan with valid token expected: %+v", res[0])
	}
}

func TestBuildQueryWithoutOpenSSL(t *testing.T) {
	withoutOpenSSL(t)
	if _, err := BuildQuery(fixtureDigest); err == nil {
		t.Fatal("BuildQuery without openssl must error")
	}
	if _, err := TokenTime([]byte("x")); err == nil {
		t.Fatal("TokenTime without openssl must error")
	}
}

// stubOpenSSL puts a fake openssl on PATH whose behaviour is scripted per
// subcommand, unlocking the CA-success paths without a live TSA.
func stubOpenSSL(t *testing.T, script string) {
	t.Helper()
	dir := t.TempDir()
	stub := filepath.Join(dir, "openssl")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	useOpenSSL(t, stub)
}

// useOpenSSL points the package at a specific binary for one test and
// restores the previous value afterwards - no process-global state.
func useOpenSSL(t *testing.T, path string) {
	t.Helper()
	prev := opensslBin
	opensslBin = path
	t.Cleanup(func() { opensslBin = prev })
}

// withoutOpenSSL simulates a host with no timestamping helper.
func withoutOpenSSL(t *testing.T) {
	t.Helper()
	useOpenSSL(t, filepath.Join(t.TempDir(), "definitely-not-openssl"))
}

func TestAnchorSuccessWithCA(t *testing.T) {
	s := testPool(t)
	ctx := context.Background()
	if err := Append(ctx, s.Pool, Entry{ClientID: "crm", Action: "seed"}); err != nil {
		t.Fatal(err)
	}
	sealAll(t, s) // anchoring stamps the SEALED head; in async mode that needs a seal pass
	stubOpenSSL(t, `case "$*" in
*-query*) printf 'QUERYBYTES' ;;
*-reply*) echo 'Time stamp: Aug 22 10:00:00 2026 GMT' ;;
*-verify*) echo 'Verification: OK' ;;
esac
exit 0`)
	srv := fakeTSA(t, 200, []byte("TOKENBYTES"))
	outDir := t.TempDir()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, []byte("pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, stampedAt, err := Anchor(ctx, s.Pool, srv.URL, ca, outDir)
	if err != nil || root == "" || stampedAt == "" {
		t.Fatalf("anchor with verifying CA: %q %q %v", root, stampedAt, err)
	}
	// Full cross-check succeeds end to end.
	res, err := VerifyAnchors(ctx, s.Pool, ca, outDir)
	if err != nil || len(res) != 1 || !res[0].TokenOK || !res[0].InChain || res[0].FileState != "ok" {
		t.Fatalf("verify-anchors: %+v %v", res, err)
	}
}

func TestTokenTimeWithoutStampLine(t *testing.T) {
	stubOpenSSL(t, `echo 'no stamp here'; exit 0`)
	if _, err := TokenTime([]byte("x")); err == nil {
		t.Fatal("reply without a Time stamp line must error")
	}
}

func TestVerifyTokenOpenSSLGarbageOutput(t *testing.T) {
	stubOpenSSL(t, `echo 'something else'; exit 0`)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, []byte("pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyToken([]byte("x"), fixtureDigest, ca)
	if err != nil || ok {
		t.Fatalf("exit-0 without Verification: OK must be a clean failure: %v %v", ok, err)
	}
}

// Anchor/verify error branches: unreadable CA, unreadable export directory,
// and a TSA reply that is not a token.
func TestAnchorEnvironmentErrors(t *testing.T) {
	needsOpenSSL(t)
	s := testPool(t)
	ctx := context.Background()
	if err := Append(ctx, s.Pool, Entry{ClientID: "crm", Action: "seed"}); err != nil {
		t.Fatal(err)
	}
	sealAll(t, s) // anchoring stamps the SEALED head; in async mode that needs a seal pass
	srv := fakeTSA(t, 200, fixture(t))

	// A CA path that does not exist is an ENVIRONMENT error, never a
	// verification verdict.
	if _, _, err := Anchor(ctx, s.Pool, srv.URL, "/nope/ca.pem", t.TempDir()); err == nil {
		t.Fatal("a missing CA bundle must error")
	}
	if _, err := VerifyToken(fixture(t), fixtureDigest, "/nope/ca.pem"); err == nil {
		t.Fatal("VerifyToken with a missing CA must be an environment error")
	}
	// An unwritable export directory fails the anchor rather than storing a
	// token with no off-host copy.
	if _, _, err := Anchor(ctx, s.Pool, srv.URL, "", "/definitely/not/writable"); err == nil {
		t.Fatal("an unwritable export directory must fail the anchor")
	}
	// A missing export directory is not an error: it means no exports have
	// been synced yet, and the DB-side check must still run (the orphan
	// detection is what would flag a deleted export).
	if _, err := VerifyAnchors(ctx, s.Pool, "", "/definitely/not/a/dir"); err != nil {
		t.Fatalf("a missing export directory must not fail the chain check: %v", err)
	}
}
