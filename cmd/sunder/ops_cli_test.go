package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/fvisic/sunder/internal/audit"
	"github.com/fvisic/sunder/internal/config"
	"github.com/fvisic/sunder/internal/testutil"
)

func testCfg(t *testing.T) config.Config {
	t.Helper()
	return config.Config{Keystore: "file", KeystorePath: t.TempDir()}
}

func TestKeysCmdLifecycle(t *testing.T) {
	st := testutil.NewDB(t)
	ctx := context.Background()
	cfg := testCfg(t)

	if err := keysCmd(ctx, cfg, st, []string{"list"}); err != nil {
		t.Fatal(err)
	}
	if err := keysCmd(ctx, cfg, st, []string{"rotate", "-kind", "hmac-email"}); err != nil {
		t.Fatal(err)
	}
	if err := keysCmd(ctx, cfg, st, []string{"rekey", "-batch", "10"}); err != nil {
		t.Fatal(err)
	}
	if err := keysCmd(ctx, cfg, st, []string{"retire", "-kind", "hmac-email", "-version", "v1"}); err != nil {
		t.Fatal(err)
	}
	// Guard rails.
	if err := keysCmd(ctx, cfg, st, []string{"rotate", "-kind", "bogus"}); err == nil {
		t.Fatal("unknown kind must error")
	}
	if err := keysCmd(ctx, cfg, st, []string{"rotate"}); err == nil {
		t.Fatal("missing -kind must error")
	}
	if err := keysCmd(ctx, cfg, st, []string{"retire", "-kind", "hmac-email"}); err == nil {
		t.Fatal("missing -version must error")
	}
	if err := keysCmd(ctx, cfg, st, []string{"nonsense"}); err == nil {
		t.Fatal("unknown subcommand must error")
	}
	if err := keysCmd(ctx, cfg, st, nil); err == nil {
		t.Fatal("no subcommand must error")
	}
}

func TestWebhookCmdValidationAndList(t *testing.T) {
	st := testutil.NewDB(t)
	ctx := context.Background()
	if err := webhookCmd(ctx, st, []string{"set", "-scope", "crm", "-url", "https://hooks.internal/erase"}); err != nil {
		t.Fatal(err)
	}
	if err := webhookCmd(ctx, st, []string{"set", "-scope", "dev", "-url", "http://localhost:9999/x"}); err != nil {
		t.Fatal(err)
	}
	if err := webhookCmd(ctx, st, []string{"set", "-scope", "bad", "-url", "http://prod.example.com/x"}); err == nil {
		t.Fatal("plain http to a non-loopback host must be rejected")
	}
	if err := webhookCmd(ctx, st, []string{"set", "-scope", "x"}); err == nil {
		t.Fatal("missing -url must error")
	}
	if err := webhookCmd(ctx, st, []string{"list"}); err != nil {
		t.Fatal(err)
	}
	if err := webhookCmd(ctx, st, []string{"nope"}); err == nil {
		t.Fatal("unknown subcommand must error")
	}
}

func TestRetentionAndDSRCmds(t *testing.T) {
	st := testutil.NewDB(t)
	ctx := context.Background()
	if err := retentionCmd(ctx, st, []string{"set", "-scope", "crm", "-days", "30"}); err != nil {
		t.Fatal(err)
	}
	if err := retentionCmd(ctx, st, []string{"run"}); err != nil {
		t.Fatal(err)
	}
	if err := retentionCmd(ctx, st, []string{"set", "-scope", "crm"}); err == nil {
		t.Fatal("missing -days must error")
	}
	if err := retentionCmd(ctx, st, []string{"huh"}); err == nil {
		t.Fatal("unknown subcommand must error")
	}
	if err := dsrCmd(ctx, config.Config{}, st, []string{"deliver"}); err != nil {
		t.Fatal(err)
	}
	if err := dsrCmd(ctx, config.Config{}, st, []string{"events"}); err != nil {
		t.Fatal(err)
	}
	if err := dsrCmd(ctx, config.Config{}, st, []string{"wat"}); err == nil {
		t.Fatal("unknown subcommand must error")
	}
}

func TestAnchorAndVerifyAuditCmds(t *testing.T) {
	st := testutil.NewDB(t)
	ctx := context.Background()

	// Empty log: anchor is a no-op, verify reports an intact (empty) chain.
	cfg := config.Config{TSAURL: "http://tsa.invalid/never-called"}
	if err := anchorCmd(ctx, cfg, st, nil); err != nil {
		t.Fatal(err)
	}
	if err := verifyAuditCmd(ctx, cfg, st, nil); err != nil {
		t.Fatal(err)
	}

	// Put one record in the chain and anchor it at a fake TSA that returns a
	// real (but foreign-digest) token; no CA is resolvable from this cwd, so
	// the fresh token is stored unverified.
	if err := audit.Append(ctx, st.Pool, audit.Entry{ClientID: "test", Action: "seed"}); err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile("../../internal/audit/testdata/freetsa-sample.tsr")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()
	out := t.TempDir()
	cfg = config.Config{TSAURL: srv.URL, AnchorDir: out}
	if err := anchorCmd(ctx, cfg, st, nil); err != nil {
		t.Fatal(err)
	}

	// Anchors exist but no CA is available: refusing to report success.
	err = verifyAuditCmd(ctx, config.Config{}, st, nil)
	if err == nil || !strings.Contains(err.Error(), "CA bundle") {
		t.Fatalf("verify without CA must refuse success: %v", err)
	}
	// With the vendored CA the foreign-digest token is INVALID -> failure.
	err = verifyAuditCmd(ctx, config.Config{AnchorDir: out}, st,
		[]string{"-ca", "../../deploy/freetsa/cacert.pem"})
	if err == nil || !strings.Contains(err.Error(), "anchor check") {
		t.Fatalf("mismatched token must fail verification: %v", err)
	}
}

func TestCLIBranchSweep(t *testing.T) {
	st := testutil.NewDB(t)
	ctx := context.Background()
	cfg := testCfg(t)

	// Flag-parse error branches.
	if err := webhookCmd(ctx, st, []string{"set", "-bogus"}); err == nil {
		t.Fatal("webhook bad flag")
	}
	if err := retentionCmd(ctx, st, []string{"set", "-bogus"}); err == nil {
		t.Fatal("retention bad flag")
	}
	if err := keysCmd(ctx, cfg, st, []string{"retire", "-bogus"}); err == nil {
		t.Fatal("retire bad flag")
	}
	if err := keysCmd(ctx, cfg, st, []string{"rekey", "-bogus"}); err == nil {
		t.Fatal("rekey bad flag")
	}
	if err := verifyAuditCmd(ctx, config.Config{}, st, []string{"-bogus"}); err == nil {
		t.Fatal("verify bad flag")
	}
	if err := anchorCmd(ctx, config.Config{}, st, []string{"-bogus"}); err == nil {
		t.Fatal("anchor bad flag")
	}
	if err := clientCmd(ctx, st, nil); err == nil {
		t.Fatal("client no args")
	}
	if err := clientCmd(ctx, st, []string{"create", "-bogus"}); err == nil {
		t.Fatal("client bad flag")
	}
	// Duplicate client id -> DB unique violation surfaces.
	if err := clientCmd(ctx, st, []string{"create", "-id", "dup", "-name", "D", "-scope", "s"}); err != nil {
		t.Fatal(err)
	}
	if err := clientCmd(ctx, st, []string{"create", "-id", "dup", "-name", "D", "-scope", "s"}); err == nil {
		t.Fatal("duplicate client id must error")
	}
	// dsr deliver with a live webhook: covers the delivery success path from
	// the CLI side.
	if _, err := st.Pool.Exec(ctx,
		`INSERT INTO erasures (person_id, requested_by) VALUES (gen_random_uuid(), 'test')`); err != nil {
		t.Fatal(err)
	}
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer hook.Close()
	if _, err := st.Pool.Exec(ctx, `INSERT INTO webhooks (scope, url, secret) VALUES ('crm', $1, 's')`, hook.URL); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx,
		`INSERT INTO erasure_events (erasure_id, scope, cid) SELECT id, 'crm', 'CID-X' FROM erasures LIMIT 1`); err != nil {
		t.Fatal(err)
	}
	if err := dsrCmd(ctx, config.Config{}, st, []string{"deliver"}); err != nil {
		t.Fatal(err)
	}
	if err := dsrCmd(ctx, config.Config{}, st, []string{"events"}); err != nil {
		t.Fatal(err)
	}
}

func TestResolveCABranches(t *testing.T) {
	if got := resolveCA("/explicit.pem", config.Config{TSACA: "/env.pem"}); got != "/explicit.pem" {
		t.Fatalf("flag must win: %s", got)
	}
	if got := resolveCA("", config.Config{TSACA: "/env.pem"}); got != "/env.pem" {
		t.Fatalf("env must win over vendored: %s", got)
	}
	// Vendored fallback: create the well-known relative path in a temp cwd.
	dir := t.TempDir()
	old, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(old) }()
	if got := resolveCA("", config.Config{}); got != "" {
		t.Fatalf("no CA anywhere must resolve empty: %s", got)
	}
	if err := os.MkdirAll("deploy/freetsa", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vendoredCA, []byte("pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := resolveCA("", config.Config{}); got != vendoredCA {
		t.Fatalf("vendored fallback: %s", got)
	}
}

func TestOpsCmdsOnDeadPool(t *testing.T) {
	st := testutil.NewDB(t)
	ctx := context.Background()
	cfg := testCfg(t)
	st.Close()

	if err := webhookCmd(ctx, st, []string{"list"}); err == nil {
		t.Fatal("webhook list on dead pool")
	}
	if err := webhookCmd(ctx, st, []string{"set", "-scope", "s", "-url", "https://x/y"}); err == nil {
		t.Fatal("webhook set on dead pool")
	}
	if err := retentionCmd(ctx, st, []string{"run"}); err == nil {
		t.Fatal("retention run on dead pool")
	}
	if err := retentionCmd(ctx, st, []string{"set", "-scope", "s", "-days", "1"}); err == nil {
		t.Fatal("retention set on dead pool")
	}
	if err := dsrCmd(ctx, config.Config{}, st, []string{"deliver"}); err == nil {
		t.Fatal("dsr deliver on dead pool")
	}
	if err := dsrCmd(ctx, config.Config{}, st, []string{"events"}); err == nil {
		t.Fatal("dsr events on dead pool")
	}
	if err := anchorCmd(ctx, config.Config{TSAURL: "http://x"}, st, nil); err == nil {
		t.Fatal("anchor on dead pool")
	}
	if err := verifyAuditCmd(ctx, config.Config{}, st, nil); err == nil {
		t.Fatal("verify-audit on dead pool")
	}
	if err := keysCmd(ctx, cfg, st, []string{"list"}); err == nil {
		t.Fatal("keys list on dead pool")
	}
	if err := clientCmd(ctx, st, []string{"create", "-id", "c", "-name", "n", "-scope", "s"}); err == nil {
		t.Fatal("client create on dead pool")
	}
}

func TestVerifyAuditCmdFullSuccessWithStub(t *testing.T) {
	st := testutil.NewDB(t)
	ctx := context.Background()
	if err := audit.Append(ctx, st.Pool, audit.Entry{ClientID: "test", Action: "seed"}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/openssl", []byte(`#!/bin/sh
case "$*" in
*-query*) printf 'Q' ;;
*-reply*) echo 'Time stamp: Aug 22 10:00:00 2026 GMT' ;;
*-verify*) echo 'Verification: OK' ;;
esac
exit 0`), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("TOKEN"))
	}))
	defer srv.Close()
	out := t.TempDir()
	ca := dir + "/ca.pem"
	if err := os.WriteFile(ca, []byte("pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{TSAURL: srv.URL, TSACA: ca, AnchorDir: out}
	if err := anchorCmd(ctx, cfg, st, nil); err != nil {
		t.Fatal(err)
	}
	// Chain + anchors + exports all verify: the success report prints.
	if err := verifyAuditCmd(ctx, cfg, st, nil); err != nil {
		t.Fatal(err)
	}
}

func TestClientRotateSecretCLIAndTTL(t *testing.T) {
	st := testutil.NewDB(t)
	ctx := context.Background()
	if err := clientCmd(ctx, st, []string{"create", "-id", "rot", "-name", "R", "-scope", "s", "-ttl", "90d"}); err != nil {
		t.Fatal(err)
	}
	if err := clientCmd(ctx, st, []string{"rotate-secret", "-id", "rot", "-ttl", "720h"}); err != nil {
		t.Fatal(err)
	}
	if err := clientCmd(ctx, st, []string{"rotate-secret", "-id", "rot"}); err != nil {
		t.Fatal(err)
	}
	if err := clientCmd(ctx, st, []string{"rotate-secret"}); err == nil {
		t.Fatal("missing -id must error")
	}
	if err := clientCmd(ctx, st, []string{"rotate-secret", "-id", "ghost"}); err == nil {
		t.Fatal("unknown client must error")
	}
	if err := clientCmd(ctx, st, []string{"create", "-id", "bad", "-name", "B", "-scope", "s", "-ttl", "yesterday"}); err == nil {
		t.Fatal("bad ttl must error")
	}
	if err := clientCmd(ctx, st, []string{"create", "-id", "bad2", "-name", "B", "-scope", "s", "-ttl", "0d"}); err == nil {
		t.Fatal("zero-day ttl must error")
	}
	// Rotation is audited.
	var n int
	if err := st.Pool.QueryRow(ctx,
		`SELECT count(*) FROM audit WHERE action='client.rotate_secret'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("rotations must be audited, found %d records", n)
	}
}

func TestIssuerCLI(t *testing.T) {
	st := testutil.NewDB(t)
	ctx := context.Background()
	pub := strings.Repeat("ab", 32)
	if err := issuerCmd(ctx, st, []string{"add", "-id", "gov.wallet", "-pubkey", pub, "-claims", "age_gte_18"}); err != nil {
		t.Fatal(err)
	}
	if err := issuerCmd(ctx, st, []string{"list"}); err != nil {
		t.Fatal(err)
	}
	if err := issuerCmd(ctx, st, []string{"add", "-id", "gov.wallet", "-pubkey", pub}); err == nil {
		t.Fatal("duplicate issuer must error")
	}
	if err := issuerCmd(ctx, st, []string{"add", "-id", "x", "-pubkey", "zz"}); err == nil {
		t.Fatal("bad pubkey must error")
	}
	if err := issuerCmd(ctx, st, []string{"remove", "-id", "gov.wallet"}); err != nil {
		t.Fatal(err)
	}
	if err := issuerCmd(ctx, st, []string{"remove", "-id", "gov.wallet"}); err == nil {
		t.Fatal("removing an absent issuer must error")
	}
	if err := issuerCmd(ctx, st, []string{"wat"}); err == nil {
		t.Fatal("unknown subcommand must error")
	}
	if err := issuerCmd(ctx, st, nil); err == nil {
		t.Fatal("no subcommand must error")
	}
}
