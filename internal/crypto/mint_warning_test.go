package crypto

// OPS-CLI-CONFIG-1: the file keystore minted fresh material with no log
// line, no metric and no non-zero exit. The DR runbook's restore step 3
// ("if it mints a key that should have existed, you restored the wrong
// keystore: stop") had no observable condition under this driver.

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"
)

func captureWarnings(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

func TestFileKeystoreWarnsOnMint(t *testing.T) {
	buf := captureWarnings(t)
	ks := &FileKeystore{Dir: t.TempDir()}
	ctx := context.Background()

	before := MintedKeys()
	if err := ks.Ensure(ctx, "pii-kek/v1"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "MINTING NEW key material") {
		t.Fatalf("a mint must be loud; log was %q", out)
	}
	if strings.Count(out, "MINTING NEW key material") != 1 {
		t.Fatalf("expected exactly one warning, got %q", out)
	}
	if MintedKeys() != before+1 {
		t.Fatal("the mint counter did not move")
	}

	// A second Ensure with the material present must be silent.
	buf.Reset()
	if err := ks.Ensure(ctx, "pii-kek/v1"); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Fatalf("an existing key must not warn: %q", buf.String())
	}
}

// The stale-lock-reclaim branch is the second entry into writeKey and must
// warn too - it was the only branch that ever did, before the warning was
// deleted without a replacement.
func TestFileKeystoreWarnsOnStaleLockReclaim(t *testing.T) {
	buf := captureWarnings(t)
	dir := t.TempDir()
	ks := &FileKeystore{Dir: dir}
	ctx := context.Background()

	p := ks.path("hmac-email/v1")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p+".lock", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	stale := time.Now().Add(-60 * time.Second)
	if err := os.Chtimes(p+".lock", stale, stale); err != nil {
		t.Fatal(err)
	}
	if err := ks.Ensure(ctx, "hmac-email/v1"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "MINTING NEW key material") {
		t.Fatalf("the stale-lock reclaim path must warn too; log was %q", buf.String())
	}
}
