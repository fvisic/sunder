// Command sunder-playground serves the interactive demo: every guide
// scenario as a clickable walkthrough against a running Sunder instance,
// with the HTTP request and response shown for each step.
//
// It is a demo tool, not part of the service: it holds client credentials
// and therefore never ships inside the runtime image that serves traffic.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/fvisic/sunder/internal/playground"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "sunder-playground: "+err.Error())
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("sunder-playground", flag.ContinueOnError)
	listen := fs.String("listen", env("PLAYGROUND_LISTEN", "127.0.0.1:8081"), "address to serve the playground on")
	base := fs.String("sunder", env("SUNDER_URL", "http://localhost:8080"), "base URL of the Sunder instance")
	scenarios := fs.String("scenarios", os.Getenv("PLAYGROUND_SCENARIOS"), "directory of scenario JSON files (default: the ones built into the binary)")
	credFile := fs.String("credential-file", os.Getenv("PLAYGROUND_CREDENTIAL_FILE"), "file of \"role=<client_id>.<secret>\" lines")
	public := fs.Bool("public", os.Getenv("PLAYGROUND_PUBLIC") == "1", "allow binding a non-loopback address (the playground holds working credentials)")
	rate := fs.Int("rate", envInt("PLAYGROUND_RATE", 120), "requests per minute per source IP")
	cookieSecure := fs.Bool("cookie-secure", os.Getenv("PLAYGROUND_COOKIE_SECURE") == "1", "mark the session cookie Secure (serve over TLS)")
	ipHeader := fs.String("client-ip-header", os.Getenv("PLAYGROUND_CLIENT_IP_HEADER"), "header naming the client IP behind a proxy (empty: use the socket address)")
	hops := fs.Int("trusted-proxy-hops", envInt("PLAYGROUND_TRUSTED_PROXY_HOPS", 0), "trusted proxy hops when -client-ip-header is set")
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	return playground.Run(ctx, playground.RunConfig{
		Listen: *listen, BaseURL: *base, ScenarioDir: *scenarios, CredFile: *credFile,
		Public: *public, RatePerMin: *rate, CookieSecure: *cookieSecure,
		ClientIPHdr: *ipHeader, ProxyHops: *hops,
	})
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
