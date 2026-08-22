package store

import (
	"context"
	"os"
	"testing"
)

// TestMigrate runs against a real PostgreSQL when SUNDER_TEST_DB_URL is set
// (CI provides one; locally: deploy/docker-compose.yml). Skipped otherwise.
func TestMigrate(t *testing.T) {
	dbURL := os.Getenv("SUNDER_TEST_DB_URL")
	if dbURL == "" {
		t.Skip("SUNDER_TEST_DB_URL not set")
	}
	ctx := context.Background()
	s, err := New(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
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
}
