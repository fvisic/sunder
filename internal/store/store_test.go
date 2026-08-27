package store_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/fvisic/sunder/internal/store"
	"github.com/fvisic/sunder/internal/testutil"
)

// TestMigrate runs against a real PostgreSQL when SUNDER_TEST_DB_URL is set
// (CI provides one; locally: deploy/docker-compose.yml). Skipped otherwise.
func TestMigrate(t *testing.T) {
	if os.Getenv("SUNDER_TEST_DB_URL") == "" {
		t.Skip("SUNDER_TEST_DB_URL not set")
	}
	ctx := context.Background()
	// An ISOLATED database: migrating the shared server's database would
	// leave permanent schema pollution behind.
	s := testutil.NewDB(t)
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	// Idempotency: a second run must be a no-op.
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	var n int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatalf("expected at least 1 applied migration, got %d", n)
	}
	// The direct constructor still rejects a bad URL.
	if _, err := store.New(ctx, "not-a-url://"); err == nil {
		t.Fatal("invalid URL must error")
	}
}

// TestConcurrentMigrateOnAnEmptyDatabase is the deployment this lock exists
// for: two replicas starting at once against a database with no schema at
// all. `CREATE TABLE IF NOT EXISTS` is NOT atomic - the existence check and
// the creation are separate steps - so a bookkeeping table created outside
// the advisory lock lets both racers pass the check and the loser die with
// "duplicate key value violates unique constraint pg_type_typname_nsp_index"
// (a table creates its row type too). That was a crash loop on a two-replica
// cold boot: the playground stack's `deliver` worker and the API server
// racing each other on a fresh volume.
func TestConcurrentMigrateOnAnEmptyDatabase(t *testing.T) {
	base := os.Getenv("SUNDER_TEST_DB_URL")
	if base == "" {
		t.Skip("SUNDER_TEST_DB_URL not set")
	}
	ctx := context.Background()

	// testutil.NewDB migrates on the way out, so this test creates its own
	// database and leaves it EMPTY - an already-migrated database would make
	// both racers no-ops and prove nothing.
	var suffix [6]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatal(err)
	}
	name := "sunder_migrace_" + hex.EncodeToString(suffix[:])
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		_ = admin.Close(ctx)
		t.Fatalf("create test db: %v", err)
	}
	_ = admin.Close(ctx)
	t.Cleanup(func() {
		a, err := pgx.Connect(context.Background(), base)
		if err != nil {
			return
		}
		defer a.Close(context.Background())
		_, _ = a.Exec(context.Background(), fmt.Sprintf("DROP DATABASE %s WITH (FORCE)", name))
	})

	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	dsn := u.String()

	const racers = 2
	stores := make([]*store.Store, racers)
	for i := range stores {
		s, err := store.New(ctx, dsn)
		if err != nil {
			t.Fatalf("pool %d: %v", i, err)
		}
		t.Cleanup(s.Close)
		stores[i] = s
	}

	errs := make(chan error, racers)
	start := make(chan struct{})
	for _, s := range stores {
		go func(s *store.Store) {
			<-start // rendezvous, so both are inside Migrate at once
			errs <- s.Migrate(ctx)
		}(s)
	}
	close(start)
	for i := 0; i < racers; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent migrate on an empty database failed: %v", err)
		}
	}

	// Exactly one row per migration: the loser must not re-apply anything.
	var n, distinct int
	if err := stores[0].Pool.QueryRow(ctx,
		`SELECT count(*), count(DISTINCT version) FROM schema_migrations`).Scan(&n, &distinct); err != nil {
		t.Fatal(err)
	}
	if n < 1 || n != distinct {
		t.Fatalf("schema_migrations holds %d rows for %d distinct versions", n, distinct)
	}
}
