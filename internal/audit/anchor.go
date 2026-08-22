package audit

// RFC 3161 trusted timestamping of the audit-chain head (PLAN section 8.2).
//
// A bare hash chain proves internal consistency but not existence-at-a-time:
// an attacker with full DB access can rewrite the whole chain consistently.
// Anchoring defeats that: the chain head is signed by an external Time Stamp
// Authority, so rewriting history would require forging every previously
// issued TSA token as well. Only the 32-byte digest ever leaves the system —
// no audit content, no PII.
//
// Implementation shells out to the openssl `ts` CLI (zero Go dependencies;
// requires openssl on the host/image that runs `sunder anchor` — typically a
// cron job, not the API service).

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// BuildQuery produces an RFC 3161 request over the chain-head digest.
func BuildQuery(rootHex string) ([]byte, error) {
	if len(rootHex) != 64 {
		return nil, fmt.Errorf("anchor: root must be a sha256 hex digest")
	}
	out, err := exec.Command("openssl", "ts", "-query", "-digest", rootHex, "-sha256", "-cert", "-no_nonce").Output()
	if err != nil {
		return nil, fmt.Errorf("anchor: openssl ts -query: %w", err)
	}
	return out, nil
}

// Post sends the query to the TSA and returns the raw token (.tsr).
func Post(ctx context.Context, tsaURL string, tsq []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", tsaURL, strings.NewReader(string(tsq)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/timestamp-query")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("anchor: TSA returned status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

var stampTimeRe = regexp.MustCompile(`(?m)^Time stamp:\s*(.+)$`)

// TokenTime extracts the TSA's asserted signing time from a token.
func TokenTime(tsr []byte) (string, error) {
	f, err := os.CreateTemp("", "sunder-*.tsr")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(tsr); err != nil {
		return "", err
	}
	_ = f.Close()
	out, err := exec.Command("openssl", "ts", "-reply", "-in", f.Name(), "-text").Output()
	if err != nil {
		return "", fmt.Errorf("anchor: openssl ts -reply: %w", err)
	}
	m := stampTimeRe.FindStringSubmatch(string(out))
	if m == nil {
		return "", fmt.Errorf("anchor: no timestamp in token")
	}
	return strings.TrimSpace(m[1]), nil
}

// VerifyToken reports whether tsr is a valid TSA signature over exactly
// rootHex under the given CA bundle — fully offline (works in front of an
// auditor or court).
func VerifyToken(tsr []byte, rootHex, caFile string) (bool, error) {
	f, err := os.CreateTemp("", "sunder-*.tsr")
	if err != nil {
		return false, err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(tsr); err != nil {
		return false, err
	}
	_ = f.Close()
	out, err := exec.Command("openssl", "ts", "-verify", "-digest", rootHex, "-in", f.Name(), "-CAfile", caFile).CombinedOutput()
	if err != nil {
		return false, nil // openssl exits non-zero on verification failure
	}
	return strings.Contains(string(out), "Verification: OK"), nil
}

// Anchor stamps the current chain head at the TSA and stores the token.
// A no-op on an empty log.
func Anchor(ctx context.Context, pool *pgxpool.Pool, tsaURL string) (root string, stampedAt string, err error) {
	root, err = Head(ctx, pool)
	if err != nil {
		return "", "", err
	}
	if root == "" {
		return "", "", nil
	}
	tsq, err := BuildQuery(root)
	if err != nil {
		return "", "", err
	}
	tsr, err := Post(ctx, tsaURL, tsq)
	if err != nil {
		return "", "", err
	}
	stampedAt, err = TokenTime(tsr)
	if err != nil {
		return "", "", err
	}
	_, err = pool.Exec(ctx,
		`INSERT INTO audit_anchor (root_hash, tsa_url, stamped_at, tsr) VALUES ($1,$2,$3,$4)`,
		root, tsaURL, stampedAt, tsr)
	if err != nil {
		return "", "", err
	}
	return root, stampedAt, nil
}

// AnchorResult is one anchor's verification outcome.
type AnchorResult struct {
	ID        int64
	Root      string
	StampedAt string
	InChain   bool // the anchored root exists in the current chain
	TokenOK   bool // TSA signature verifies offline (only checked with a CA)
}

// VerifyAnchors checks every stored anchor: the anchored root must still be
// present in the chain (a full-chain rewrite leaves orphaned anchors), and,
// when caFile is given, the TSA token must verify offline.
func VerifyAnchors(ctx context.Context, pool *pgxpool.Pool, caFile string) ([]AnchorResult, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, root_hash, COALESCE(stamped_at,''), tsr FROM audit_anchor ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AnchorResult
	for rows.Next() {
		var r AnchorResult
		var tsr []byte
		if err := rows.Scan(&r.ID, &r.Root, &r.StampedAt, &tsr); err != nil {
			return nil, err
		}
		if err := pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM audit WHERE hash=$1)`, r.Root).Scan(&r.InChain); err != nil {
			return nil, err
		}
		if caFile != "" {
			ok, err := VerifyToken(tsr, r.Root, caFile)
			if err != nil {
				return nil, err
			}
			r.TokenOK = ok
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
