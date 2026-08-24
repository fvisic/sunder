package store_test

import (
	"context"
	"os"
	"testing"

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
