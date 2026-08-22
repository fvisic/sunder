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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

var hexRoot = regexp.MustCompile(`^[0-9a-f]{64}$`)

// BuildQuery produces an RFC 3161 request over the chain-head digest.
func BuildQuery(rootHex string) ([]byte, error) {
	if !hexRoot.MatchString(rootHex) {
		return nil, fmt.Errorf("anchor: root must be a lowercase sha256 hex digest")
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
//
// A verification failure returns (false, nil); an ENVIRONMENT failure
// (openssl missing, unreadable CA file, malformed root) returns an error —
// an auditor must never read "openssl is not installed" as "tampered".
func VerifyToken(tsr []byte, rootHex, caFile string) (bool, error) {
	if !hexRoot.MatchString(rootHex) {
		return false, fmt.Errorf("anchor: stored root is not a sha256 hex digest")
	}
	if _, err := exec.LookPath("openssl"); err != nil {
		return false, fmt.Errorf("anchor: openssl not available: %w", err)
	}
	if _, err := os.Stat(caFile); err != nil {
		return false, fmt.Errorf("anchor: CA bundle unreadable: %w", err)
	}
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
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return false, nil // openssl ran and rejected: genuine verification failure
		}
		return false, fmt.Errorf("anchor: openssl execution failed: %w", err)
	}
	return strings.Contains(string(out), "Verification: OK"), nil
}

// Anchor stamps the current chain head at the TSA and stores the token.
// A no-op on an empty log.
//
// When caFile is given, the fresh token is verified BEFORE persisting — a
// misconfigured or hostile TSA endpoint must not plant a worthless anchor.
// When outDir is given, the token is also exported as a .tsr file: exporting
// anchors OFF the database host (write-once storage, another machine) is
// what makes them evidence against a privileged database attacker — tokens
// living only in the same database are circular.
func Anchor(ctx context.Context, pool *pgxpool.Pool, tsaURL, caFile, outDir string) (root string, stampedAt string, err error) {
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
	if caFile != "" {
		ok, err := VerifyToken(tsr, root, caFile)
		if err != nil {
			return "", "", err
		}
		if !ok {
			return "", "", fmt.Errorf("anchor: TSA %s returned a token that does not verify over the chain head — not stored", tsaURL)
		}
	}
	stampedAt, err = TokenTime(tsr)
	if err != nil {
		return "", "", err
	}
	if _, err = pool.Exec(ctx,
		`INSERT INTO audit_anchor (root_hash, tsa_url, stamped_at, tsr) VALUES ($1,$2,$3,$4)`,
		root, tsaURL, stampedAt, tsr); err != nil {
		return "", "", err
	}
	if outDir != "" {
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			return "", "", err
		}
		if err := os.WriteFile(filepath.Join(outDir, root+".tsr"), tsr, 0o444); err != nil {
			return "", "", err
		}
	}
	return root, stampedAt, nil
}

// AnchorResult is one anchor's verification outcome.
type AnchorResult struct {
	ID        int64
	Root      string
	StampedAt string
	InChain   bool   // the anchored root exists in the current chain
	TokenOK   bool   // TSA signature verifies offline (only checked with a CA)
	FileState string // with anchorsDir: "ok", "missing", "mismatch"; "" otherwise
	InDB      bool   // false for a .tsr file whose anchor row is gone (deletion evidence)
}

// VerifyAnchors checks every stored anchor: the anchored root must still be
// present in the chain (a full-chain rewrite leaves orphaned anchors); when
// caFile is given, the TSA token must verify offline; when anchorsDir is
// given, each DB anchor is cross-checked against its exported .tsr file AND
// exported files with no matching DB row are reported (InDB=false) — that is
// the check a database-level attacker cannot silence, because the export
// lives outside their reach.
func VerifyAnchors(ctx context.Context, pool *pgxpool.Pool, caFile, anchorsDir string) ([]AnchorResult, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, root_hash, COALESCE(stamped_at,''), tsr FROM audit_anchor ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AnchorResult
	dbRoots := map[string]bool{}
	for rows.Next() {
		r := AnchorResult{InDB: true}
		var tsr []byte
		if err := rows.Scan(&r.ID, &r.Root, &r.StampedAt, &tsr); err != nil {
			return nil, err
		}
		dbRoots[r.Root] = true
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
		if anchorsDir != "" {
			fileTsr, err := os.ReadFile(filepath.Join(anchorsDir, r.Root+".tsr"))
			switch {
			case err != nil:
				r.FileState = "missing"
			case !bytes.Equal(fileTsr, tsr):
				r.FileState = "mismatch"
			default:
				r.FileState = "ok"
			}
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if anchorsDir != "" {
		files, err := filepath.Glob(filepath.Join(anchorsDir, "*.tsr"))
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			root := strings.TrimSuffix(filepath.Base(f), ".tsr")
			if !dbRoots[root] {
				r := AnchorResult{Root: root, InDB: false, FileState: "ok"}
				if err := pool.QueryRow(ctx,
					`SELECT EXISTS(SELECT 1 FROM audit WHERE hash=$1)`, root).Scan(&r.InChain); err != nil {
					return nil, err
				}
				if caFile != "" && hexRoot.MatchString(root) {
					tsr, rerr := os.ReadFile(f)
					if rerr == nil {
						if ok, verr := VerifyToken(tsr, root, caFile); verr == nil {
							r.TokenOK = ok
						}
					}
				}
				out = append(out, r)
			}
		}
	}
	return out, nil
}
