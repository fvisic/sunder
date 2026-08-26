package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fvisic/sunder/internal/audit"
	"github.com/fvisic/sunder/internal/crypto"
	"github.com/fvisic/sunder/internal/testutil"
)

// Exercises run() end to end for the non-serving commands: env config,
// store connection, migration and dispatch.
func TestRunMigrateAndClientViaEnv(t *testing.T) {
	st := testutil.NewDB(t)
	url := st.Pool.Config().ConnString()
	st.Close() // run() opens its own pool

	t.Setenv("SUNDER_DB_URL", url)
	t.Setenv("SUNDER_KEYSTORE_PATH", t.TempDir())

	if err := run("migrate", nil); err != nil {
		t.Fatal(err)
	}
	if err := run("client", []string{"create", "-id", "envtest", "-name", "T", "-scope", "crm",
		"-actions", "lookup"}); err != nil {
		t.Fatal(err)
	}
	if err := run("keys", []string{"list"}); err != nil {
		t.Fatal(err)
	}
	// Config errors surface before any DB work.
	t.Setenv("SUNDER_DB_URL", "")
	if err := run("migrate", nil); err == nil || !strings.Contains(err.Error(), "SUNDER_DB_URL") {
		t.Fatalf("missing DB URL must fail config validation: %v", err)
	}
	// Connection errors surface cleanly.
	t.Setenv("SUNDER_DB_URL", "postgres://nouser@127.0.0.1:1/none")
	if err := run("migrate", nil); err == nil {
		t.Fatal("unreachable database must error")
	}
}

// The serve path end to end: boots, answers healthz, shuts down on ctx cancel.
func TestRunServe(t *testing.T) {
	st := testutil.NewDB(t)
	url := st.Pool.Config().ConnString()
	st.Close()
	t.Setenv("SUNDER_DB_URL", url)
	t.Setenv("SUNDER_KEYSTORE_PATH", t.TempDir())
	// A concrete free port (not :0) so the readiness poll below has an
	// address to dial.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen := probe.Addr().String()
	_ = probe.Close()
	t.Setenv("SUNDER_LISTEN", listen)

	ctx, cancel := context.WithCancel(context.Background())
	old := signalContext
	signalContext = func() (context.Context, context.CancelFunc) { return ctx, func() {} }
	defer func() { signalContext = old }()

	done := make(chan error, 1)
	go func() { done <- run("serve", nil) }()
	// Poll for the listener instead of a fixed sleep: migrate + keystore
	// bootstrap + listen is slower on loaded CI.
	deadline := time.Now().Add(20 * time.Second)
	for {
		if c, err := net.DialTimeout("tcp", listen, 100*time.Millisecond); err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("serve never bound its port")
		}
		select {
		case err := <-done:
			t.Fatalf("serve exited before binding: %v", err)
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve must shut down cleanly: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not stop")
	}

	// serve with a broken keystore config: api.New fails at bootstrap.
	t.Setenv("SUNDER_KEYSTORE", "vault")
	t.Setenv("SUNDER_VAULT_ADDR", "http://127.0.0.1:1")
	t.Setenv("SUNDER_VAULT_TOKEN", "t")
	signalContext = func() (context.Context, context.CancelFunc) {
		return context.Background(), func() {}
	}
	if err := run("serve", nil); err == nil {
		t.Fatal("unreachable vault keystore must fail serve startup")
	}
}

// run() dispatch lines for the ops commands (each command's own logic is
// covered by its dedicated tests; this pins the wiring).
func TestRunDispatchesOpsCommands(t *testing.T) {
	st := testutil.NewDB(t)
	url := st.Pool.Config().ConnString()
	st.Close()
	t.Setenv("SUNDER_DB_URL", url)
	t.Setenv("SUNDER_KEYSTORE_PATH", t.TempDir())

	if err := run("webhook", []string{"list"}); err != nil {
		t.Fatal(err)
	}
	if err := run("retention", []string{"run"}); err != nil {
		t.Fatal(err)
	}
	if err := run("dsr", []string{"events"}); err != nil {
		t.Fatal(err)
	}
	if err := run("verify-audit", nil); err != nil {
		t.Fatal(err)
	}
	// anchor on an empty log is a no-op regardless of the TSA URL.
	t.Setenv("SUNDER_TSA_URL", "http://tsa.invalid/x")
	if err := run("anchor", nil); err != nil {
		t.Fatal(err)
	}
	// The Phase 3 additions dispatch through run() too. The sealer refuses
	// under sync sealing (it seals inline), so only exercise it in async.
	if audit.Mode() == audit.ModeAsync {
		if err := run("sealer", []string{"-once"}); err != nil {
			t.Fatal(err)
		}
	} else if err := run("sealer", []string{"-once"}); err == nil {
		t.Fatal("sealer must refuse under sync sealing")
	}
	if err := run("client", []string{"create", "-id", "grantme", "-name", "G", "-scope", "crm", "-actions", "lookup", "-purposes", "support"}); err != nil {
		t.Fatal(err)
	}
	if err := run("client", []string{"grant", "-id", "grantme", "-add-actions", "admin.unlock"}); err != nil {
		t.Fatal(err)
	}
	// import from a small JSONL file via the dispatcher.
	dir := t.TempDir()
	jf := dir + "/c.jsonl"
	if err := os.WriteFile(jf, []byte(`{"email":"run@example.com"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run("import", []string{"-file", jf, "-scope", "crm"}); err != nil {
		t.Fatal(err)
	}
	// An unknown command is rejected without touching the database.
	if err := run("nonsense-cmd", nil); err == nil {
		t.Fatal("unknown command must error")
	}
}

// The signer subcommand needs the keystore, never the database.
func TestRunSignerWithoutDB(t *testing.T) {
	t.Setenv("SUNDER_DB_URL", "")
	t.Setenv("SUNDER_KEYSTORE_PATH", t.TempDir())

	// Missing socket: specific error, not a DB complaint.
	if err := run("signer", nil); err == nil || !strings.Contains(err.Error(), "socket") {
		t.Fatalf("signer without a socket must say so: %v", err)
	}

	// With a socket it serves until the signal context is cancelled.
	dir, err := os.MkdirTemp("", "sgn")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := dir + "/s.sock"
	ctx, cancel := context.WithCancel(context.Background())
	old := signalContext
	signalContext = func() (context.Context, context.CancelFunc) { return ctx, cancel }
	t.Cleanup(func() { signalContext = old })
	done := make(chan error, 1)
	go func() { done <- run("signer", []string{"-socket", sock}) }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("signer socket never appeared")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// It answers over the wire.
	eng := crypto.NewRemoteEngine(sock)
	if err := eng.Ensure(ctx, "hmac-email/v1"); err != nil {
		t.Fatal(err)
	}
	if sum, err := eng.MAC(ctx, "hmac-email/v1", []byte("x")); err != nil || len(sum) != 32 {
		t.Fatalf("mac over CLI-started signer: %d %v", len(sum), err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("signer shutdown must be clean: %v", err)
	}
}

func TestGetenvDefaultFallsBackOnEmpty(t *testing.T) {
	const key = "SUNDER_TEST_GETENV_DEFAULT"
	t.Setenv(key, "")
	if got := getenvDefault(key, "fallback"); got != "fallback" {
		t.Fatalf("empty env must fall back, got %q", got)
	}
	t.Setenv(key, "set")
	if got := getenvDefault(key, "fallback"); got != "set" {
		t.Fatalf("set env must win, got %q", got)
	}
}

func TestCLIExitCodes(t *testing.T) {
	if code := cli([]string{"sunder", "definitely-not-a-command"}); code != 1 {
		t.Fatalf("unknown command must exit 1, got %d", code)
	}
	// No args defaults to serve, which without SUNDER_DB_URL fails config
	// validation - exit 1, never a panic.
	t.Setenv("SUNDER_DB_URL", "")
	if code := cli([]string{"sunder"}); code != 1 {
		t.Fatalf("serve without a database must exit 1, got %d", code)
	}
}

// TestRunKeysRekeyReencrypt drives the keys rekey command with -reencrypt
// through run(), covering the CLI rekey path and the vault-rewrap output.
func TestRunKeysRekeyReencrypt(t *testing.T) {
	st := testutil.NewDB(t)
	url := st.Pool.Config().ConnString()
	st.Close()
	t.Setenv("SUNDER_DB_URL", url)
	t.Setenv("SUNDER_KEYSTORE_PATH", t.TempDir())
	if err := run("client", []string{"create", "-id", "crm", "-name", "C", "-scope", "crm", "-actions", "contacts.register", "-purposes", "support"}); err != nil {
		t.Fatal(err)
	}
	// Import a person with attributes so the rekey actually re-encrypts a
	// blob and prints its summary (BlobsReenc > 0).
	dir := t.TempDir()
	jf := dir + "/c.jsonl"
	if err := os.WriteFile(jf, []byte(`{"email":"rk@example.com","attributes":{"tier":"gold"}}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run("import", []string{"-file", jf, "-scope", "crm"}); err != nil {
		t.Fatal(err)
	}
	// Rotate then rekey so there is stale-kek data to move.
	if err := run("keys", []string{"rotate", "-kind", "pii-kek"}); err != nil {
		t.Fatal(err)
	}
	if err := run("keys", []string{"rekey", "-reencrypt-pii"}); err != nil {
		t.Fatalf("keys rekey -reencrypt: %v", err)
	}
}

// TestShamirRecoveryCycle runs the real F9 CLI flow: bootstrap keys,
// shamir-init to issue shares, wipe the keystore, then shamir-recover from a
// threshold of shares and confirm the keys are byte-identical.
func TestShamirRecoveryCycle(t *testing.T) {
	st := testutil.NewDB(t)
	url := st.Pool.Config().ConnString()
	st.Close()
	ksDir := t.TempDir()
	t.Setenv("SUNDER_DB_URL", url)
	t.Setenv("SUNDER_KEYSTORE_PATH", ksDir)

	// Bootstrap creates the keystore keys.
	if err := run("bootstrap", []string{"-id", "admin", "-scope", "admin"}); err != nil {
		t.Fatal(err)
	}
	before := readKeystore(t, ksDir)
	if len(before) == 0 {
		t.Fatal("bootstrap must create keys")
	}

	// shamir-init: capture the printed shares.
	out := captureStdout(t, func() {
		if err := run("keys", []string{"shamir-init", "-n", "5", "-k", "3"}); err != nil {
			t.Fatal(err)
		}
	})
	shares := parseSharesFromOutput(out)
	if len(shares) != 5 {
		t.Fatalf("want 5 shares printed, got %d\n%s", len(shares), out)
	}

	// Simulate a keystore loss: delete every .key file (the bundle stays).
	entries, _ := os.ReadDir(ksDir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".key") {
			os.Remove(filepath.Join(ksDir, e.Name()))
		}
	}
	if len(readKeystore(t, ksDir)) != 0 {
		t.Fatal("keystore should be wiped")
	}

	// Recover from shares 1, 3, 5 (a valid 3-of-5 subset).
	if err := run("keys", []string{"shamir-recover", "-shares", shares[0] + "," + shares[2] + "," + shares[4]}); err != nil {
		t.Fatalf("recover: %v", err)
	}
	after := readKeystore(t, ksDir)
	if len(after) != len(before) {
		t.Fatalf("recovered %d keys, had %d", len(after), len(before))
	}
	for name, key := range before {
		if string(after[name]) != string(key) {
			t.Fatalf("key %q did not round-trip through recovery", name)
		}
	}

	// Too few shares must fail cleanly.
	entries, _ = os.ReadDir(ksDir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".key") {
			os.Remove(filepath.Join(ksDir, e.Name()))
		}
	}
	if err := run("keys", []string{"shamir-recover", "-shares", shares[0] + "," + shares[1]}); err == nil {
		t.Fatal("2 of 3 shares must fail recovery")
	}
}

func readKeystore(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".key") {
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			out[e.Name()] = b
		}
	}
	return out
}

func parseSharesFromOutput(out string) []string {
	var shares []string
	for _, line := range strings.Split(out, "\n") {
		if i := strings.Index(line, ": "); i >= 0 && strings.Contains(line, "share ") {
			shares = append(shares, strings.TrimSpace(line[i+2:]))
		}
	}
	return shares
}

// captureStdout runs fn with os.Stdout redirected to a pipe and returns what
// it printed. Used to grab the once-only shamir shares.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var buf strings.Builder
		b := make([]byte, 4096)
		for {
			n, err := r.Read(b)
			if n > 0 {
				buf.Write(b[:n])
			}
			if err != nil {
				break
			}
		}
		done <- buf.String()
	}()
	fn()
	w.Close()
	os.Stdout = old
	return <-done
}

// TestShamirRotateAndGuards covers shamir-rotate (re-seal under the same
// shares) and the error/guard branches.
func TestShamirRotateAndGuards(t *testing.T) {
	st := testutil.NewDB(t)
	url := st.Pool.Config().ConnString()
	st.Close()
	ksDir := t.TempDir()
	t.Setenv("SUNDER_DB_URL", url)
	t.Setenv("SUNDER_KEYSTORE_PATH", ksDir)
	if err := run("bootstrap", []string{"-id", "admin", "-scope", "admin"}); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		if err := run("keys", []string{"shamir-init"}); err != nil {
			t.Fatal(err)
		}
	})
	shares := parseSharesFromOutput(out)
	// Rotate re-seals the bundle over the SAME shares.
	if err := run("keys", []string{"shamir-rotate", "-shares", shares[0] + "," + shares[1] + "," + shares[2]}); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	// The old shares still recover after a rotate (a key added meanwhile is
	// picked up). Add a key by rotating a kind, then re-rotate the bundle.
	if err := run("keys", []string{"rotate", "-kind", "pii-kek"}); err != nil {
		t.Fatal(err)
	}
	if err := run("keys", []string{"shamir-rotate", "-shares", shares[0] + "," + shares[3] + "," + shares[4]}); err != nil {
		t.Fatalf("rotate after key add: %v", err)
	}
	// Guards: no shares, non-hex share, unknown subcommand.
	if err := run("keys", []string{"shamir-recover", "-shares", ""}); err == nil {
		t.Fatal("empty shares must error")
	}
	if err := run("keys", []string{"shamir-recover", "-shares", "zzzz"}); err == nil {
		t.Fatal("non-hex share must error")
	}
	// Vault driver refuses shamir.
	t.Setenv("SUNDER_KEYSTORE", "vault")
	if err := run("keys", []string{"shamir-init"}); err == nil {
		t.Fatal("shamir must refuse the vault driver")
	}
	t.Setenv("SUNDER_KEYSTORE", "file")
}

// TestShamirCLIErrorPaths covers the shamir subcommands' error branches.
func TestShamirCLIErrorPaths(t *testing.T) {
	st := testutil.NewDB(t)
	url := st.Pool.Config().ConnString()
	st.Close()
	t.Setenv("SUNDER_DB_URL", url)

	// shamir-init before any keys exist: AllKeys fails.
	emptyKS := t.TempDir()
	t.Setenv("SUNDER_KEYSTORE_PATH", emptyKS)
	if err := run("keys", []string{"shamir-init"}); err == nil {
		t.Fatal("shamir-init with no keys must error")
	}

	// Bootstrap, then shamir-recover with a valid-looking but wrong share:
	// CombineWithChecksum fails.
	ksDir := t.TempDir()
	t.Setenv("SUNDER_KEYSTORE_PATH", ksDir)
	if err := run("bootstrap", []string{"-id", "admin", "-scope", "admin"}); err != nil {
		t.Fatal(err)
	}
	// Recover before shamir-init: no bundle file.
	out := captureStdout(t, func() {
		if err := run("keys", []string{"shamir-init"}); err != nil {
			t.Fatal(err)
		}
	})
	shares := parseSharesFromOutput(out)
	// Delete the bundle, then recover: ReadRecoveryBundle fails.
	os.Remove(filepath.Join(ksDir, "recovery.bundle"))
	if err := run("keys", []string{"shamir-recover", "-shares", shares[0] + "," + shares[1] + "," + shares[2]}); err == nil {
		t.Fatal("recover without a bundle must error")
	}
	// A short (odd-length) hex share fails hex decode; a wrong share set
	// fails the checksum. Rewrite a fresh bundle first.
	out = captureStdout(t, func() {
		if err := run("keys", []string{"shamir-init"}); err != nil {
			t.Fatal(err)
		}
	})
	shares = parseSharesFromOutput(out)
	// Three shares that do not all belong together: corrupt one hex nibble.
	bad := shares[0][:len(shares[0])-1] + "0"
	if err := run("keys", []string{"shamir-recover", "-shares", bad + "," + shares[1] + "," + shares[2]}); err == nil {
		t.Fatal("a corrupted share set must fail the checksum")
	}
	// Unknown keys subcommand.
	if err := run("keys", []string{"bogus"}); err == nil {
		t.Fatal("unknown keys subcommand must error")
	}
}

// TestShamirRecoverInteractiveStdin covers readShares' interactive branch:
// shares are fed on stdin, one hex per line, blank line to end.
func TestShamirRecoverInteractiveStdin(t *testing.T) {
	st := testutil.NewDB(t)
	url := st.Pool.Config().ConnString()
	st.Close()
	ksDir := t.TempDir()
	t.Setenv("SUNDER_DB_URL", url)
	t.Setenv("SUNDER_KEYSTORE_PATH", ksDir)
	if err := run("bootstrap", []string{"-id", "admin", "-scope", "admin"}); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		if err := run("keys", []string{"shamir-init"}); err != nil {
			t.Fatal(err)
		}
	})
	shares := parseSharesFromOutput(out)
	// Wipe the key files (bundle stays).
	entries, _ := os.ReadDir(ksDir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".key") {
			os.Remove(filepath.Join(ksDir, e.Name()))
		}
	}
	// Feed three shares on stdin, blank line to finish.
	stdin := shares[0] + "\n" + shares[1] + "\n" + shares[2] + "\n\n"
	withStdin(t, stdin, func() {
		if err := run("keys", []string{"shamir-recover"}); err != nil {
			t.Fatalf("interactive recover: %v", err)
		}
	})
	if len(readKeystore(t, ksDir)) == 0 {
		t.Fatal("interactive recovery restored no keys")
	}
}

func withStdin(t *testing.T, input string, fn func()) {
	t.Helper()
	old := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = r
	go func() {
		_, _ = w.WriteString(input)
		w.Close()
	}()
	defer func() { os.Stdin = old }()
	fn()
}

// TestShamirWriteFailures covers the bundle-write and key-restore failure
// branches by making the keystore directory unwritable, and the bad-n/k
// branch of SplitWithChecksum.
func TestShamirWriteFailures(t *testing.T) {
	st := testutil.NewDB(t)
	url := st.Pool.Config().ConnString()
	st.Close()
	ksDir := t.TempDir()
	t.Setenv("SUNDER_DB_URL", url)
	t.Setenv("SUNDER_KEYSTORE_PATH", ksDir)
	if err := run("bootstrap", []string{"-id", "admin", "-scope", "admin"}); err != nil {
		t.Fatal(err)
	}
	// Bad -n/-k: SplitWithChecksum rejects k > n.
	if err := run("keys", []string{"shamir-init", "-n", "2", "-k", "5"}); err == nil {
		t.Fatal("k > n must be rejected")
	}
	// Issue real shares first (dir still writable).
	out := captureStdout(t, func() {
		if err := run("keys", []string{"shamir-init"}); err != nil {
			t.Fatal(err)
		}
	})
	shares := parseSharesFromOutput(out)

	// Make the keystore directory read-only: WriteRecoveryBundle (rotate)
	// and RestoreKeys (recover) must surface the failure.
	if err := os.Chmod(ksDir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(ksDir, 0o700)
	rotErr := run("keys", []string{"shamir-rotate", "-shares", shares[0] + "," + shares[1] + "," + shares[2]})
	recErr := run("keys", []string{"shamir-recover", "-shares", shares[0] + "," + shares[1] + "," + shares[2]})
	if rotErr == nil && recErr == nil {
		t.Fatal("a read-only keystore must fail at least one of rotate/recover")
	}
}

// TestShamirFlagAndDriverGuards covers the fs.Parse error branch and the
// vault-driver refusal on all three shamir subcommands.
func TestShamirFlagAndDriverGuards(t *testing.T) {
	st := testutil.NewDB(t)
	url := st.Pool.Config().ConnString()
	st.Close()
	t.Setenv("SUNDER_DB_URL", url)
	t.Setenv("SUNDER_KEYSTORE_PATH", t.TempDir())
	for _, sub := range []string{"shamir-init", "shamir-recover", "shamir-rotate"} {
		// A bad flag fails fs.Parse.
		if err := run("keys", []string{sub, "-nope"}); err == nil {
			t.Fatalf("%s with a bad flag must error", sub)
		}
	}
	// The vault driver refuses every shamir subcommand.
	t.Setenv("SUNDER_KEYSTORE", "vault")
	for _, sub := range []string{"shamir-init", "shamir-recover", "shamir-rotate"} {
		if err := run("keys", []string{sub, "-shares", "00"}); err == nil {
			t.Fatalf("%s must refuse the vault driver", sub)
		}
	}
}
