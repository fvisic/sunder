// Command sunder runs the Sunder identity-decoupling service.
//
// Subcommands:
//
//	serve    start the HTTP service (default)
//	migrate  apply database migrations and exit
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/fvisic/sunder/internal/api"
	"github.com/fvisic/sunder/internal/audit"
	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/config"
	"github.com/fvisic/sunder/internal/service"
	"github.com/fvisic/sunder/internal/store"
)

func main() {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	if err := run(cmd, os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "sunder:", err)
		os.Exit(1)
	}
}

func run(cmd string, args []string) error {
	switch cmd {
	case "serve", "migrate", "client", "keys", "anchor", "verify-audit":
	default:
		// Fail on typos before requiring config or a live database.
		return fmt.Errorf("unknown command %q (available: serve, migrate, client, keys, anchor, verify-audit)", cmd)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	st, err := store.New(ctx, cfg.DBURL)
	if err != nil {
		return err
	}
	defer st.Close()

	switch cmd {
	case "serve":
		if err := st.Migrate(ctx); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
		srv, err := api.New(cfg, st)
		if err != nil {
			return err
		}
		return srv.Run(ctx)
	case "migrate":
		return st.Migrate(ctx)
	case "keys":
		return keysCmd(ctx, cfg, st, args)
	case "anchor":
		return anchorCmd(ctx, cfg, st)
	case "verify-audit":
		return verifyAuditCmd(ctx, st, args)
	default:
		return clientCmd(ctx, st, args)
	}
}

// anchorCmd stamps the current audit-chain head at the configured TSA.
// Run it from cron (daily); only a 32-byte digest leaves the system.
func anchorCmd(ctx context.Context, cfg config.Config, st *store.Store) error {
	if err := st.Migrate(ctx); err != nil {
		return err
	}
	root, stampedAt, err := audit.Anchor(ctx, st.Pool, cfg.TSAURL)
	if err != nil {
		return err
	}
	if root == "" {
		fmt.Println("audit log is empty - nothing to anchor")
		return nil
	}
	fmt.Printf("anchored chain head %s...\n  TSA: %s\n  stamped at: %s\n", root[:16], cfg.TSAURL, stampedAt)
	return nil
}

// verifyAuditCmd recomputes the whole hash chain and, with -ca, verifies
// every stored TSA token offline. Non-zero exit on any failure.
func verifyAuditCmd(ctx context.Context, st *store.Store, args []string) error {
	fs := flag.NewFlagSet("verify-audit", flag.ContinueOnError)
	caFile := fs.String("ca", "", "TSA root CA bundle for offline token verification (optional)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := st.Migrate(ctx); err != nil {
		return err
	}
	broken, reason, err := audit.Verify(ctx, st.Pool)
	if err != nil {
		return err
	}
	if broken != 0 {
		return fmt.Errorf("audit chain BROKEN at seq %d: %s", broken, reason)
	}
	fmt.Println("audit chain: intact")

	anchors, err := audit.VerifyAnchors(ctx, st.Pool, *caFile)
	if err != nil {
		return err
	}
	bad := 0
	for _, a := range anchors {
		status := "in-chain"
		if !a.InChain {
			status, bad = "ROOT NOT IN CHAIN (history rewritten?)", bad+1
		}
		token := "token: not checked (pass -ca)"
		if *caFile != "" {
			if a.TokenOK {
				token = "token: OK"
			} else {
				token, bad = "token: INVALID", bad+1
			}
		}
		fmt.Printf("anchor #%d %s... (%s) %s; %s\n", a.ID, a.Root[:16], a.StampedAt, status, token)
	}
	if bad > 0 {
		return fmt.Errorf("%d anchor check(s) failed", bad)
	}
	if len(anchors) == 0 {
		fmt.Println("no anchors stored yet - schedule `sunder anchor` in cron")
	}
	return nil
}

// keysCmd implements `sunder keys rotate -kind <kind>` and `sunder keys list`.
func keysCmd(ctx context.Context, cfg config.Config, st *store.Store, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: sunder keys rotate -kind <kind> | keys retire -kind <kind> -version <v> | keys list")
	}
	if err := st.Migrate(ctx); err != nil {
		return err
	}
	ring := &service.KeyRing{Pool: st.Pool}
	switch args[0] {
	case "rotate":
		fs := flag.NewFlagSet("keys rotate", flag.ContinueOnError)
		kind := fs.String("kind", "", "key kind (e.g. hmac-email)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *kind == "" {
			return fmt.Errorf("-kind is required")
		}
		version, err := ring.Rotate(ctx, api.OpenKeystore(cfg), *kind)
		if err != nil {
			return err
		}
		note := map[string]string{
			"hmac-email": "old tokens keep matching, rows re-key on touch",
			"hmac-phone": "old tokens keep matching, rows re-key on touch",
			"hmac-name":  "old tokens keep matching, rows re-key on touch",
			"pii-kek":    "old blobs stay decryptable via stored pii_key_id, re-encrypt on touch",
			"oti-sign":   "tokens signed by previous versions keep verifying until you `keys retire` them",
		}[*kind]
		fmt.Printf("rotated %s to %s (previous versions RETIRING; %s)\n", *kind, version, note)
		fmt.Println("running servers pick up the change within 30s (keyring cache TTL)")
		return nil
	case "retire":
		fs := flag.NewFlagSet("keys retire", flag.ContinueOnError)
		kind := fs.String("kind", "", "key kind")
		version := fs.String("version", "", "version to retire (e.g. v1)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *kind == "" || *version == "" {
			return fmt.Errorf("-kind and -version are required")
		}
		if err := ring.Retire(ctx, *kind, *version); err != nil {
			return err
		}
		fmt.Printf("retired %s/%s - it no longer matches lookups nor verifies tokens\n", *kind, *version)
		fmt.Println("(for hmac kinds: rows still stored under this version stop matching; re-key first)")
		return nil
	case "list":
		rows, err := st.Pool.Query(ctx, `SELECT key_id, status, created_at FROM keys ORDER BY kind, created_at`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id, status string
			var created time.Time
			if err := rows.Scan(&id, &status, &created); err != nil {
				return err
			}
			fmt.Printf("%-24s %-9s %s\n", id, status, created.Format(time.RFC3339))
		}
		return rows.Err()
	default:
		return fmt.Errorf("unknown keys subcommand %q", args[0])
	}
}

// clientCmd implements `sunder client create ...`. The credential is printed
// exactly once; only its hash is stored.
func clientCmd(ctx context.Context, st *store.Store, args []string) error {
	if len(args) < 1 || args[0] != "create" {
		return fmt.Errorf("usage: sunder client create -id <id> -name <name> -scope <scope> [-actions a,b] [-purposes p,q] [-rate n]")
	}
	fs := flag.NewFlagSet("client create", flag.ContinueOnError)
	id := fs.String("id", "", "client id (required)")
	name := fs.String("name", "", "display name (required)")
	scope := fs.String("scope", "", "CID scope this client belongs to (required)")
	actions := fs.String("actions", "", "comma-separated allowed actions")
	purposes := fs.String("purposes", "", "comma-separated allowed purposes")
	rate := fs.Int("rate", 60, "lookup rate limit per minute")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *id == "" || *name == "" || *scope == "" {
		return fmt.Errorf("-id, -name and -scope are required")
	}
	// Reject typo'd actions up front: a dead grant would surface much later
	// as a confusing 403 in some integration.
	known := map[string]bool{
		auth.ActContactsRegister: true, auth.ActScopesIssue: true, auth.ActLookup: true,
		auth.ActAttributesRead: true, auth.ActOTIIssue: true, auth.ActOTIVerify: true,
	}
	acts := splitCSV(*actions)
	for _, a := range acts {
		if !known[a] {
			return fmt.Errorf("unknown action %q", a)
		}
	}
	if err := st.Migrate(ctx); err != nil {
		return err
	}
	cred, err := auth.Create(ctx, st.Pool, auth.Client{
		ID: *id, Name: *name, Scope: *scope,
		AllowedActions:  acts,
		AllowedPurposes: splitCSV(*purposes),
		RateLimit:       *rate,
	})
	if err != nil {
		return err
	}
	fmt.Println("credential (shown once, store it now):")
	fmt.Println(cred)
	return nil
}

func splitCSV(s string) []string {
	if s == "" {
		return []string{}
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
