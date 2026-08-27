package audit

// DOCS-1: four documents told the operator to grant the external sealer
// `UPDATE (prev_hash, hash, chain_seq)` on `audit`. Since migration 0033 the
// sealing statement also writes hash_v, and the same process closes
// read-bucket hours - which UPDATEs audit_read_buckets and INSERTs the
// hourly digest into audit. Following the documented grant made every seal
// cycle fail with "permission denied for column hash_v" while
// `verify-audit` kept reporting the chain intact.
//
// The grants below are copied from
// docs-site/docs/admin/audit-operations.md. If the sealing code grows a
// column, this test fails and the document has to be corrected with it.

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

var sealerRoleSeq int

func TestDocumentedSealerGrantIsSufficient(t *testing.T) {
	// The grant is for the EXTERNAL sealer, which exists only under async
	// sealing (`sunder sealer` refuses to start otherwise).
	setMode(t, ModeAsync)
	setReads(t, ReadsBucketed)
	s := testPool(t)
	ctx := context.Background()

	sealerRoleSeq++
	role := fmt.Sprintf("sunder_sealer_t_%d_%d", os.Getpid(), sealerRoleSeq)
	// EXACTLY the documented grants, nothing more.
	for _, stmt := range []string{
		`DROP ROLE IF EXISTS ` + role,
		`CREATE ROLE ` + role + ` LOGIN PASSWORD 'sealer-test-only'`,
		`GRANT USAGE ON SCHEMA public TO ` + role,
		`GRANT SELECT, UPDATE (prev_hash, hash, chain_seq, hash_v) ON audit TO ` + role,
		`GRANT INSERT ON audit TO ` + role,
		`GRANT SELECT, UPDATE (sealed_at) ON audit_read_buckets TO ` + role,
		`GRANT USAGE, SELECT ON SEQUENCE audit_seq_seq TO ` + role,
	} {
		if _, err := s.Pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	t.Cleanup(func() {
		_, _ = s.Pool.Exec(context.Background(), `DROP OWNED BY `+role)
		_, _ = s.Pool.Exec(context.Background(), `DROP ROLE IF EXISTS `+role)
	})

	cfg := s.Pool.Config().ConnConfig
	url := fmt.Sprintf("postgres://%s:sealer-test-only@%s:%d/%s", role, cfg.Host, cfg.Port, cfg.Database)
	sealer, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer sealer.Close()

	// Work for both halves of the sealer's job.
	for i := 0; i < 3; i++ {
		if err := Append(ctx, s.Pool, Entry{ClientID: "crm", Action: "lookup"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Pool.Exec(ctx, `
		INSERT INTO audit_read_buckets (client_id, user_id, cid, action, bucket_start, count, first_seen, last_seen)
		VALUES ('crm','op1','CID-A','attributes.read', date_trunc('hour', now()-interval '2 hours'), 5, now(), now())`); err != nil {
		t.Fatal(err)
	}

	// The chain half.
	n, err := SealOnce(ctx, sealer, 100, 0)
	if err != nil {
		t.Fatalf("sealing under the documented grant failed: %v", err)
	}
	if n == 0 {
		t.Fatal("the sealer sealed nothing")
	}
	// The read-bucket half (an UPDATE on audit_read_buckets plus an INSERT
	// into audit for the digest).
	hours, err := CloseReadBuckets(ctx, sealer)
	if err != nil {
		t.Fatalf("closing read buckets under the documented grant failed: %v", err)
	}
	if hours != 1 {
		t.Fatalf("expected one closed hour, got %d", hours)
	}
	// Its digest row needs sealing too.
	if _, err := SealOnce(ctx, sealer, 100, 0); err != nil {
		t.Fatal(err)
	}
	if pending, err := UnsealedCount(ctx, s.Pool); err != nil || pending != 0 {
		t.Fatalf("the documented grant must drain the backlog: pending=%d err=%v", pending, err)
	}
	if bad, why, _, err := VerifyReadBuckets(ctx, s.Pool); err != nil || bad != "" {
		t.Fatalf("read buckets must verify after a sealer-role close: %q %s %v", bad, why, err)
	}
}
