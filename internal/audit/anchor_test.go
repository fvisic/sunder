package audit

import (
	"context"
	"os"
	"os/exec"
	"testing"
)

func lookupEnv(k string) (string, bool) { return os.LookupEnv(k) }

func needsOpenSSL(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not available")
	}
}

func TestBuildQueryShape(t *testing.T) {
	needsOpenSSL(t)
	root := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	tsq, err := BuildQuery(root)
	if err != nil {
		t.Fatal(err)
	}
	// DER SEQUENCE header + the digest must be embedded.
	if len(tsq) < 40 || tsq[0] != 0x30 {
		t.Fatalf("does not look like a DER TimeStampReq (%d bytes)", len(tsq))
	}
	if _, err := BuildQuery("tooshort"); err == nil {
		t.Fatal("non-sha256 root accepted")
	}
}

func TestAnchorSkipsEmptyLog(t *testing.T) {
	s := testPool(t)
	root, _, err := Anchor(context.Background(), s.Pool, "http://tsa.invalid/never-called")
	if err != nil || root != "" {
		t.Fatalf("empty log must be a no-op: root=%q err=%v", root, err)
	}
}

func TestVerifyAnchorsDetectsRewrittenHistory(t *testing.T) {
	s := testPool(t)
	ctx := context.Background()
	if err := Append(ctx, s.Pool, Entry{ClientID: "crm", Action: "lookup"}); err != nil {
		t.Fatal(err)
	}
	// Simulate an anchor whose root no longer exists in the chain — exactly
	// what a full-chain rewrite leaves behind.
	orphan := "beef000000000000000000000000000000000000000000000000000000000000"
	if _, err := s.Pool.Exec(ctx,
		`INSERT INTO audit_anchor (root_hash, tsa_url, stamped_at, tsr) VALUES ($1,'test','',''::bytea)`,
		orphan); err != nil {
		t.Fatal(err)
	}
	head, err := Head(ctx, s.Pool)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx,
		`INSERT INTO audit_anchor (root_hash, tsa_url, stamped_at, tsr) VALUES ($1,'test','',''::bytea)`,
		head); err != nil {
		t.Fatal(err)
	}

	results, err := VerifyAnchors(ctx, s.Pool, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 anchors, got %d", len(results))
	}
	if results[0].InChain {
		t.Fatal("orphaned anchor reported as in-chain")
	}
	if !results[1].InChain {
		t.Fatal("valid head anchor reported as orphaned")
	}
}

// TestAnchorAgainstRealTSA exercises the full network + openssl path against
// freetsa.org. Off by default (network): enable with SUNDER_TEST_TSA=1.
func TestAnchorAgainstRealTSA(t *testing.T) {
	needsOpenSSL(t)
	s := testPool(t)
	ctx := context.Background()
	if err := Append(ctx, s.Pool, Entry{ClientID: "crm", Action: "lookup"}); err != nil {
		t.Fatal(err)
	}
	if testing.Short() {
		t.Skip("short mode")
	}
	if v, ok := lookupEnv("SUNDER_TEST_TSA"); !ok || v != "1" {
		t.Skip("SUNDER_TEST_TSA not set")
	}
	root, stampedAt, err := Anchor(ctx, s.Pool, "https://freetsa.org/tsr")
	if err != nil {
		t.Fatal(err)
	}
	if root == "" || stampedAt == "" {
		t.Fatalf("anchor incomplete: %q %q", root, stampedAt)
	}
}
