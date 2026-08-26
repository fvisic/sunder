package playground

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunServesAndShutsDown(t *testing.T) {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	ready := make(chan string, 1)
	go func() {
		done <- Run(ctx, RunConfig{
			Listen: "127.0.0.1:0", BaseURL: "http://127.0.0.1:1",
			Getenv: func(string) string { return "" }, Log: quiet,
			Ready: func(addr string) { ready <- addr },
		})
	}()
	var addr string
	select {
	case addr = <-ready:
	case err := <-done:
		t.Fatalf("playground exited before serving: %v", err)
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("playground never came up")
	}
	resp, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		cancel()
		t.Fatalf("healthz: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		cancel()
		t.Fatalf("healthz: %d", resp.StatusCode)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("shutdown returned %v", err)
	}
}

func TestRunRefusesBadConfig(t *testing.T) {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	noEnv := func(string) string { return "" }

	if err := Run(context.Background(), RunConfig{Listen: "0.0.0.0:18098", BaseURL: "http://x", Log: quiet, Getenv: noEnv}); err == nil {
		t.Fatal("a public bind without -public must be refused")
	}
	if err := Run(context.Background(), RunConfig{Listen: "127.0.0.1:0", BaseURL: "", Log: quiet, Getenv: noEnv}); err == nil {
		t.Fatal("an empty instance URL must be refused")
	}
	if err := Run(context.Background(), RunConfig{
		Listen: "127.0.0.1:0", BaseURL: "http://x", ScenarioDir: filepath.Join(t.TempDir(), "nope"),
		Log: quiet, Getenv: noEnv,
	}); err == nil {
		t.Fatal("an unreadable scenario directory must be refused")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.json"), []byte(`{"id":"a"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), RunConfig{
		Listen: "127.0.0.1:0", BaseURL: "http://x", ScenarioDir: dir, Log: quiet, Getenv: noEnv,
	}); err == nil || !strings.Contains(err.Error(), "bad.json") {
		t.Fatalf("a broken scenario must name its file: %v", err)
	}
	credFile := filepath.Join(dir, "creds")
	if err := os.WriteFile(credFile, []byte("crm=nodot\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), RunConfig{
		Listen: "127.0.0.1:0", BaseURL: "http://x", CredFile: credFile, Log: quiet, Getenv: noEnv,
	}); err == nil {
		t.Fatal("a malformed credential must be refused at startup")
	}
}
