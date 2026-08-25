package main

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fvisic/sunder/internal/audit"
	"github.com/fvisic/sunder/internal/config"
	"github.com/fvisic/sunder/internal/crypto"
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
	// Anchoring stamps the SEALED head; in async mode the fresh row must be
	// sealed first or there is nothing to anchor.
	if _, err := audit.Drain(ctx, st.Pool, 100); err != nil {
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
	if _, err := audit.Drain(ctx, st.Pool, 100); err != nil { // anchor needs a sealed head
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
	t.Cleanup(audit.SetOpenSSLForTest(dir + "/openssl"))

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

func TestBootstrapCmd(t *testing.T) {
	st := testutil.NewDB(t)
	ctx := context.Background()
	cfg := testCfg(t)

	// Interactive: prints the credential; idempotent on rerun.
	if err := bootstrapCmd(ctx, cfg, st, nil); err != nil {
		t.Fatal(err)
	}
	if err := bootstrapCmd(ctx, cfg, st, nil); err != nil {
		t.Fatalf("rerun must be a no-op success: %v", err)
	}
	var n int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM clients WHERE client_id='admin'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("exactly one admin client expected: %d %v", n, err)
	}

	// Unattended: credential written 0600 to the given file.
	st2 := testutil.NewDB(t)
	credFile := t.TempDir() + "/cred"
	if err := bootstrapCmd(ctx, cfg, st2, []string{
		"-unattended", "-id", "provisioner", "-credential-file", credFile, "-ttl", "90d",
	}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(credFile)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("credential file must be 0600, got %o", fi.Mode().Perm())
	}
	b, _ := os.ReadFile(credFile)
	if !strings.HasPrefix(string(b), "provisioner.") {
		t.Fatalf("credential file content: %q", b)
	}
	// The written credential authenticates (TTL applied, not expired).
	var expires *time.Time
	if err := st2.Pool.QueryRow(ctx,
		`SELECT credential_expires_at FROM clients WHERE client_id='provisioner'`).Scan(&expires); err != nil || expires == nil {
		t.Fatalf("ttl must be stored: %v %v", expires, err)
	}
	// Unattended without a file is an explicit error.
	st3 := testutil.NewDB(t)
	if err := bootstrapCmd(ctx, cfg, st3, []string{"-unattended"}); err == nil {
		t.Fatal("unattended without a credential file must error")
	}
}

func TestBootstrapGuardsAndAtomicity(t *testing.T) {
	ctx := context.Background()
	cfg := testCfg(t)

	// A stream target would put the credential in a container log.
	st := testutil.NewDB(t)
	if err := bootstrapCmd(ctx, cfg, st, []string{"-unattended", "-credential-file", "/dev/stdout"}); err == nil {
		t.Fatal("a /dev/ credential target must be rejected")
	}
	// Nothing was created by the rejected run.
	var n int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM clients`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("a rejected bootstrap must create no client, found %d", n)
	}

	// Unattended with no file at all: same guarantee.
	st2 := testutil.NewDB(t)
	if err := bootstrapCmd(ctx, cfg, st2, []string{"-unattended"}); err == nil {
		t.Fatal("unattended without a file must be rejected")
	}
	if err := st2.Pool.QueryRow(ctx, `SELECT count(*) FROM clients`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("no client may exist after the guard fired, found %d", n)
	}

	// An unwritable credential path must roll the client back entirely.
	st3 := testutil.NewDB(t)
	if err := bootstrapCmd(ctx, cfg, st3, []string{
		"-unattended", "-credential-file", "/definitely/not/a/dir/cred"}); err == nil {
		t.Fatal("an unwritable credential file must fail the bootstrap")
	}
	if err := st3.Pool.QueryRow(ctx, `SELECT count(*) FROM clients`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("the admin row must roll back with the failed write, found %d", n)
	}

	// A bad TTL is rejected before anything is created.
	if err := bootstrapCmd(ctx, cfg, st3, []string{"-ttl", "eventually"}); err == nil {
		t.Fatal("a malformed ttl must be rejected")
	}

	// The happy path grants usable purposes (an admin with none is useless).
	st4 := testutil.NewDB(t)
	if err := bootstrapCmd(ctx, cfg, st4, []string{"-id", "ops", "-purposes", "support,billing"}); err != nil {
		t.Fatal(err)
	}
	var purposes []string
	if err := st4.Pool.QueryRow(ctx,
		`SELECT allowed_purposes FROM clients WHERE client_id='ops'`).Scan(&purposes); err != nil {
		t.Fatal(err)
	}
	if len(purposes) != 2 {
		t.Fatalf("purposes must be applied: %v", purposes)
	}
	// The default is a real purpose, not an empty (deny-all) list.
	st5 := testutil.NewDB(t)
	if err := bootstrapCmd(ctx, cfg, st5, nil); err != nil {
		t.Fatal(err)
	}
	if err := st5.Pool.QueryRow(ctx,
		`SELECT allowed_purposes FROM clients WHERE client_id='admin'`).Scan(&purposes); err != nil {
		t.Fatal(err)
	}
	if len(purposes) == 0 {
		t.Fatal("the default admin must have at least one usable purpose")
	}
}

// Remaining CLI branches: retention prunes the new tables, issuer listing
// with a wildcard grant, rotate-secret flag combinations.
func TestCLIRemainingBranches(t *testing.T) {
	st := testutil.NewDB(t)
	ctx := context.Background()

	// retention run now also prunes envelopes and portal rows.
	if err := retentionCmd(ctx, st, []string{"run"}); err != nil {
		t.Fatal(err)
	}
	// A wildcard issuer grant is explicit, and listing renders it.
	pub := strings.Repeat("cd", 32)
	if err := issuerCmd(ctx, st, []string{"add", "-id", "gw.any", "-pubkey", pub, "-claims", "*"}); err != nil {
		t.Fatal(err)
	}
	if err := issuerCmd(ctx, st, []string{"list"}); err != nil {
		t.Fatal(err)
	}
	// rotate-secret: -ttl and -no-expiry are mutually exclusive.
	if err := clientCmd(ctx, st, []string{"create", "-id", "rotme", "-name", "R", "-scope", "s"}); err != nil {
		t.Fatal(err)
	}
	if err := clientCmd(ctx, st, []string{"rotate-secret", "-id", "rotme", "-ttl", "30d", "-no-expiry"}); err == nil {
		t.Fatal("-ttl with -no-expiry must be rejected")
	}
	// -no-expiry clears a previously set expiry.
	if err := clientCmd(ctx, st, []string{"rotate-secret", "-id", "rotme", "-ttl", "30d"}); err != nil {
		t.Fatal(err)
	}
	if err := clientCmd(ctx, st, []string{"rotate-secret", "-id", "rotme", "-no-expiry"}); err != nil {
		t.Fatal(err)
	}
	var expires *time.Time
	if err := st.Pool.QueryRow(ctx,
		`SELECT credential_expires_at FROM clients WHERE client_id='rotme'`).Scan(&expires); err != nil {
		t.Fatal(err)
	}
	if expires != nil {
		t.Fatal("-no-expiry must clear the stored expiry")
	}
	// A plain rotation PRESERVES the policy rather than silently clearing it.
	if err := clientCmd(ctx, st, []string{"rotate-secret", "-id", "rotme", "-ttl", "30d"}); err != nil {
		t.Fatal(err)
	}
	if err := clientCmd(ctx, st, []string{"rotate-secret", "-id", "rotme"}); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx,
		`SELECT credential_expires_at FROM clients WHERE client_id='rotme'`).Scan(&expires); err != nil {
		t.Fatal(err)
	}
	if expires == nil {
		t.Fatal("a plain rotation must preserve the expiry policy")
	}
}

// CLI error branches on a dead pool: every ops command must surface the
// failure rather than reporting success.
func TestNewCommandsFailClosedOnDeadPool(t *testing.T) {
	st := testutil.NewDB(t)
	ctx := context.Background()
	cfg := testCfg(t)
	st.Close()

	if err := bootstrapCmd(ctx, cfg, st, nil); err == nil {
		t.Fatal("bootstrap on a dead pool")
	}
	if err := issuerCmd(ctx, st, []string{"list"}); err == nil {
		t.Fatal("issuer list on a dead pool")
	}
	if err := issuerCmd(ctx, st, []string{"add", "-id", "x", "-pubkey", strings.Repeat("ab", 32)}); err == nil {
		t.Fatal("issuer add on a dead pool")
	}
	if err := issuerCmd(ctx, st, []string{"remove", "-id", "x"}); err == nil {
		t.Fatal("issuer remove on a dead pool")
	}
	if err := issuerCmd(ctx, st, []string{"add", "-bogus"}); err == nil {
		t.Fatal("issuer add bad flag")
	}
	if err := issuerCmd(ctx, st, []string{"remove", "-bogus"}); err == nil {
		t.Fatal("issuer remove bad flag")
	}
	if err := issuerCmd(ctx, st, []string{"remove"}); err == nil {
		t.Fatal("issuer remove without -id")
	}
	if err := clientCmd(ctx, st, []string{"rotate-secret", "-id", "x"}); err == nil {
		t.Fatal("rotate-secret on a dead pool")
	}
	if err := clientCmd(ctx, st, []string{"rotate-secret", "-bogus"}); err == nil {
		t.Fatal("rotate-secret bad flag")
	}
	if err := retentionCmd(ctx, st, []string{"run"}); err == nil {
		t.Fatal("retention run on a dead pool")
	}
}

// An operator must not be able to register a forgeable key.
func TestIssuerAddRejectsSmallOrderKeys(t *testing.T) {
	st := testutil.NewDB(t)
	ctx := context.Background()
	for _, bad := range []string{
		"0100000000000000000000000000000000000000000000000000000000000000", // identity: forges everything
		"0000000000000000000000000000000000000000000000000000000000000000",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	} {
		if err := issuerCmd(ctx, st, []string{"add", "-id", "bad", "-pubkey", bad}); err == nil {
			t.Fatalf("issuer add accepted a small-order key: %s", bad)
		}
	}
	// A genuine key is accepted.
	_, pub, err := crypto.Ed25519FromSeed(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := issuerCmd(ctx, st, []string{"add", "-id", "good", "-pubkey", hex.EncodeToString(pub)}); err != nil {
		t.Fatal(err)
	}
}

// Webhook URL validation must parse, not prefix-match.
func TestWebhookURLValidation(t *testing.T) {
	for _, ok := range []string{
		"https://hooks.internal/erase",
		"http://localhost:9999/x",
		"http://127.0.0.1/x",
		"http://[::1]:8080/x",
	} {
		if err := validWebhookURL(ok); err != nil {
			t.Errorf("%s must be accepted: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"http://localhost.attacker.example/", // the prefix-check bypass
		"http://127.0.0.1.attacker.example/", // same trick on the IP form
		"http://prod.example.com/x",
		"ftp://example.com/x",
		"not-a-url-at-all",
		"https://",
	} {
		if err := validWebhookURL(bad); err == nil {
			t.Errorf("%s must be rejected", bad)
		}
	}
}

func TestSealerCmd(t *testing.T) {
	st := testutil.NewDB(t)
	ctx := context.Background()
	cfg := testCfg(t)
	cfg.AuditSealing = audit.ModeAsync
	cfg.AuditSealBatch = 100
	cfg.AuditSealInterval = 50 * time.Millisecond
	cfg.AuditSealDelay = 100 * time.Millisecond

	old := audit.Mode()
	audit.SetMode(audit.ModeAsync)
	t.Cleanup(func() { audit.SetMode(old) })

	for i := 0; i < 3; i++ {
		if err := audit.Append(ctx, st.Pool, audit.Entry{ClientID: "crm", Action: "lookup"}); err != nil {
			t.Fatal(err)
		}
	}
	// -once drains the backlog and exits: the cron / pre-switch shape.
	if err := sealerCmd(ctx, cfg, st, []string{"-once"}); err != nil {
		t.Fatal(err)
	}
	if n, err := audit.UnsealedCount(ctx, st.Pool); err != nil || n != 0 {
		t.Fatalf("sealer -once left %d unsealed (err=%v)", n, err)
	}

	// A sealer under sync mode is a misconfiguration, not a silent no-op:
	// someone believes sealing is delegated while sync seals inline.
	cfg.AuditSealing = audit.ModeSync
	if err := sealerCmd(ctx, cfg, st, []string{"-once"}); err == nil {
		t.Fatal("sealer with SUNDER_AUDIT_SEALING=sync must refuse")
	}

	// The loop form: runs until cancelled, seals as rows appear.
	cfg.AuditSealing = audit.ModeAsync
	loopCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- sealerCmd(loopCtx, cfg, st, nil) }()
	if err := audit.Append(ctx, st.Pool, audit.Entry{ClientID: "crm", Action: "lookup"}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		n, err := audit.UnsealedCount(ctx, st.Pool)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("sealer loop did not seal: %d pending", n)
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("cancelled sealer loop must exit clean: %v", err)
	}
}

func TestSealerCmdGuards(t *testing.T) {
	st := testutil.NewDB(t)
	cfg := testCfg(t)
	cfg.AuditSealing = audit.ModeAsync
	cfg.AuditSealBatch = 100
	if err := sealerCmd(context.Background(), cfg, st, []string{"-bogus"}); err == nil {
		t.Fatal("unknown flag must error")
	}
	// A dead pool during -once must surface, not report success.
	st.Close()
	if err := sealerCmd(context.Background(), cfg, st, []string{"-once"}); err == nil {
		t.Fatal("sealer -once on a dead pool must error")
	}
}
