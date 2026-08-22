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
	if err := dsrCmd(ctx, st, []string{"deliver"}); err != nil {
		t.Fatal(err)
	}
	if err := dsrCmd(ctx, st, []string{"events"}); err != nil {
		t.Fatal(err)
	}
	if err := dsrCmd(ctx, st, []string{"wat"}); err == nil {
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
