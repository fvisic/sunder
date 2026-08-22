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
	case "serve", "migrate", "client", "keys":
	default:
		// Fail on typos before requiring config or a live database.
		return fmt.Errorf("unknown command %q (available: serve, migrate, client, keys)", cmd)
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
	default:
		return clientCmd(ctx, st, args)
	}
}

// keysCmd implements `sunder keys rotate -kind <kind>` and `sunder keys list`.
func keysCmd(ctx context.Context, cfg config.Config, st *store.Store, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: sunder keys rotate -kind <kind> | sunder keys list")
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
		fmt.Printf("rotated %s to %s (previous versions RETIRING; old tokens keep matching, re-key happens on touch)\n", *kind, version)
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
