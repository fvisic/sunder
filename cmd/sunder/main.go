// Command sunder runs the Sunder identity-decoupling service.
//
// Subcommands:
//
//	serve    start the HTTP service (default)
//	migrate  apply database migrations and exit
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/fvisic/sunder/internal/api"
	"github.com/fvisic/sunder/internal/config"
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
		return api.New(cfg, st).Run(ctx)
	case "migrate":
		return st.Migrate(ctx)
	default:
		return dispatch(ctx, cfg, st, cmd, args)
	}
}

// dispatch routes milestone-added subcommands (client, keys, verify-audit,
// anchor); they register themselves in later packages.
func dispatch(_ context.Context, _ config.Config, _ *store.Store, cmd string, _ []string) error {
	return fmt.Errorf("unknown command %q (available: serve, migrate)", cmd)
}
