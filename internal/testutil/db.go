// Package testutil provides integration-test helpers.
package testutil

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
)

// NewDB creates a uniquely-named database for this test (packages run in
// parallel; sharing one database makes audit-chain tests interfere), runs
// migrations, and drops the database on cleanup. Skips when
// SUNDER_TEST_DB_URL is unset.
func NewDB(t *testing.T) *store.Store {
	t.Helper()
	base := os.Getenv("SUNDER_TEST_DB_URL")
	if base == "" {
		t.Skip("SUNDER_TEST_DB_URL not set")
	}
	ctx := context.Background()

	var suffix [6]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatal(err)
	}
	name := "sunder_t_" + hex.EncodeToString(suffix[:])

	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		_ = admin.Close(ctx)
		t.Fatalf("create test db: %v", err)
	}
	_ = admin.Close(ctx)

	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	s, err := store.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.Close()
		admin, err := pgx.Connect(context.Background(), base)
		if err != nil {
			return
		}
		defer admin.Close(context.Background())
		_, _ = admin.Exec(context.Background(), fmt.Sprintf("DROP DATABASE %s WITH (FORCE)", name))
	})
	return s
}
