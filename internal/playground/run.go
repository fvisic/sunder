package playground

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// RunConfig is what the `sunder-playground` binary is given.
type RunConfig struct {
	Listen  string
	BaseURL string
	// ScenarioDir overrides the embedded walkthroughs (authoring loop).
	ScenarioDir string
	// CredFile holds "role=<client_id>.<secret>" lines - how the compose
	// seeder hands over what `sunder client create` printed, mirroring
	// `sunder bootstrap -credential-file`.
	CredFile string
	// Public must be set explicitly before the playground binds anything
	// other than loopback. It holds working credentials for a real
	// instance, so being reachable is a decision, never a default.
	Public        bool
	RatePerMin    int
	CookieSecure  bool
	WebhookSecret string
	ClientIPHdr   string
	ProxyHops     int
	// Ready is called with the bound address once the listener is up. It
	// exists so a caller (and the tests) can find the port when Listen
	// asks for :0 instead of racing a retry loop.
	Ready  func(addr string)
	Getenv func(string) string
	Log    *slog.Logger
}

// Run loads the scenarios, resolves credentials and serves until ctx is
// cancelled.
func Run(ctx context.Context, cfg RunConfig) error {
	if cfg.Getenv == nil {
		cfg.Getenv = os.Getenv
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.NewJSONHandler(os.Stderr, nil))
	}
	if err := guardListen(cfg.Listen, cfg.Public); err != nil {
		return err
	}
	scenarios, err := loadScenarios(cfg.ScenarioDir)
	if err != nil {
		return err
	}
	creds, fileSecret, err := LoadCreds(roleNames(scenarios), cfg.CredFile, cfg.Getenv)
	if err != nil {
		return err
	}
	secret := cfg.WebhookSecret
	if secret == "" {
		secret = fileSecret
	}
	srv, err := NewServer(Config{
		BaseURL: cfg.BaseURL, Creds: creds, Scenarios: scenarios,
		RatePerMin: cfg.RatePerMin, CookieSecure: cfg.CookieSecure,
		ClientIPHeader: cfg.ClientIPHdr, TrustedProxyHops: cfg.ProxyHops,
		WebhookSecret: secret, Log: cfg.Log,
	})
	if err != nil {
		return err
	}
	missing := missingRoles(scenarios, creds)
	if len(missing) > 0 {
		// Not fatal: a stack without the file vault has no F5 credential,
		// and the other walkthroughs must still run. The UI marks those
		// scenarios instead of failing at click time.
		cfg.Log.Warn("scenarios with no credential will be shown as unavailable", "roles", strings.Join(missing, ","))
	}
	if secret == "" {
		cfg.Log.Warn("no webhook secret configured: erasure deliveries land in the inbox marked 'unverified'")
	}

	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	errCh := make(chan error, 1)
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	go func() { errCh <- httpSrv.Serve(ln) }()
	cfg.Log.Info("playground listening", "addr", ln.Addr().String(), "instance", cfg.BaseURL,
		"scenarios", len(scenarios), "public", cfg.Public)
	if cfg.Ready != nil {
		cfg.Ready(ln.Addr().String())
	}

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return httpSrv.Shutdown(shutdownCtx)
	}
}

// guardListen refuses a non-loopback bind unless the operator asked for it.
// The playground can register, read and erase records on the instance it
// points at; exposing that by forgetting a flag default must be impossible.
func guardListen(addr string, public bool) error {
	if public {
		return nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("listen address %q: %w", addr, err)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		return fmt.Errorf("refusing to listen on %q without -public: the playground holds working credentials for %s",
			addr, "the instance it demonstrates")
	}
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("refusing to listen on %q without -public: not a loopback address", addr)
	}
	return nil
}

func loadScenarios(dir string) ([]*Scenario, error) {
	if dir == "" {
		return LoadEmbedded()
	}
	return LoadDir(dir)
}

func roleNames(scenarios []*Scenario) []string {
	seen := map[string]bool{}
	for _, sc := range scenarios {
		for _, r := range sc.Roles {
			seen[r.Name] = true
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func missingRoles(scenarios []*Scenario, creds map[string]string) []string {
	var out []string
	for _, name := range roleNames(scenarios) {
		if creds[name] == "" {
			out = append(out, name)
		}
	}
	return out
}

// LoadCreds resolves each role's credential from the environment
// (PLAYGROUND_CRED_<ROLE>) and, when given, from a credential file whose
// lines are "role=<client_id>.<secret>". The environment wins: it is what a
// developer overrides by hand.
func LoadCreds(roles []string, file string, getenv func(string) string) (map[string]string, string, error) {
	creds := map[string]string{}
	var secret string
	if file != "" {
		raw, err := os.ReadFile(file)
		if err != nil {
			return nil, "", fmt.Errorf("credential file: %w", err)
		}
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			name, value, ok := strings.Cut(line, "=")
			if !ok {
				return nil, "", fmt.Errorf("credential file: %q is not role=credential", line)
			}
			name, value = strings.TrimSpace(name), strings.TrimSpace(value)
			if name == "webhook_secret" {
				secret = value
				continue
			}
			creds[name] = value
		}
	}
	for _, role := range roles {
		if v := getenv("PLAYGROUND_CRED_" + strings.ToUpper(strings.ReplaceAll(role, "-", "_"))); v != "" {
			creds[role] = v
		}
	}
	for role, v := range creds {
		// A credential is "<client_id>.<secret>"; a value missing the dot
		// is almost always a truncated copy-paste, and it would fail as a
		// puzzling 401 on the first click instead of at startup.
		if v != "" && !strings.Contains(v, ".") {
			return nil, "", fmt.Errorf("credential for role %q is not in <client_id>.<secret> form", role)
		}
	}
	if v := getenv("PLAYGROUND_WEBHOOK_SECRET"); v != "" {
		secret = v
	}
	return creds, secret, nil
}
