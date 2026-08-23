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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fvisic/sunder/internal/api"
	"github.com/fvisic/sunder/internal/audit"
	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/config"
	"github.com/fvisic/sunder/internal/crypto"
	"github.com/fvisic/sunder/internal/service"
	"github.com/fvisic/sunder/internal/store"
)

// signalContext is a seam for tests (which cannot deliver real signals).
var signalContext = func() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
}

func main() {
	cmd := "serve"
	var rest []string
	if len(os.Args) > 1 {
		cmd = os.Args[1]
		rest = os.Args[2:]
	}
	if err := run(cmd, rest); err != nil {
		fmt.Fprintln(os.Stderr, "sunder:", err)
		os.Exit(1)
	}
}

func run(cmd string, args []string) error {
	switch cmd {
	case "serve", "migrate", "client", "keys", "anchor", "verify-audit", "webhook", "retention", "dsr", "signer":
	default:
		// Fail on typos before requiring config or a live database.
		return fmt.Errorf("unknown command %q (available: serve, migrate, client, keys, anchor, verify-audit, webhook, retention, dsr, signer)", cmd)
	}

	ctx, stop := signalContext()
	defer stop()

	// The signer needs the keystore, never the database: it is the sole
	// key-material holder in split mode and exposes six operations over a
	// local Unix socket (P2.1).
	if cmd == "signer" {
		cfg, err := config.FromEnvNoDB()
		if err != nil {
			return err
		}
		return signerCmd(ctx, cfg, args)
	}
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
	case "anchor":
		return anchorCmd(ctx, cfg, st, args)
	case "verify-audit":
		return verifyAuditCmd(ctx, cfg, st, args)
	case "webhook":
		return webhookCmd(ctx, st, args)
	case "retention":
		return retentionCmd(ctx, st, args)
	case "dsr":
		return dsrCmd(ctx, cfg, st, args)
	default:
		return clientCmd(ctx, st, args)
	}
}

// webhookCmd manages per-scope erasure webhooks. The signing secret is
// printed exactly once; receivers verify X-Sunder-Signature =
// hex(HMAC-SHA256(secret, body)).
func webhookCmd(ctx context.Context, st *store.Store, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: sunder webhook set -scope <s> -url <u> | webhook list")
	}
	if err := st.Migrate(ctx); err != nil {
		return err
	}
	switch args[0] {
	case "set":
		fs := flag.NewFlagSet("webhook set", flag.ContinueOnError)
		scope := fs.String("scope", "", "scope whose erasure events go to this URL")
		url := fs.String("url", "", "HTTPS endpoint")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *scope == "" || *url == "" {
			return fmt.Errorf("-scope and -url are required")
		}
		// HTTPS only (loopback exempt for local development): erasure events
		// carry pseudonyms and must not travel plaintext.
		if !strings.HasPrefix(*url, "https://") &&
			!strings.HasPrefix(*url, "http://localhost") &&
			!strings.HasPrefix(*url, "http://127.0.0.1") {
			return fmt.Errorf("webhook URL must be https:// (http:// allowed for localhost only)")
		}
		secret, err := crypto.NewClientSecret()
		if err != nil {
			return err
		}
		if _, err := st.Pool.Exec(ctx,
			`INSERT INTO webhooks (scope, url, secret) VALUES ($1,$2,$3)
			 ON CONFLICT (scope) DO UPDATE SET url=EXCLUDED.url, secret=EXCLUDED.secret, created_at=now()`,
			*scope, *url, secret); err != nil {
			return err
		}
		fmt.Println("webhook signing secret (shown once, configure the receiver now):")
		fmt.Println(secret)
		return nil
	case "list":
		rows, err := st.Pool.Query(ctx, `SELECT scope, url, created_at FROM webhooks ORDER BY scope`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var scope, url string
			var created time.Time
			if err := rows.Scan(&scope, &url, &created); err != nil {
				return err
			}
			fmt.Printf("%-16s %s (%s)\n", scope, url, created.Format(time.RFC3339))
		}
		return rows.Err()
	default:
		return fmt.Errorf("unknown webhook subcommand %q", args[0])
	}
}

// retentionCmd manages per-scope contact TTLs and runs the sweep.
func retentionCmd(ctx context.Context, st *store.Store, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: sunder retention set -scope <s> -days <n> | retention run")
	}
	if err := st.Migrate(ctx); err != nil {
		return err
	}
	switch args[0] {
	case "set":
		fs := flag.NewFlagSet("retention set", flag.ContinueOnError)
		scope := fs.String("scope", "", "scope")
		days := fs.Int("days", -1, "contact blob TTL in days")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *scope == "" || *days < 0 {
			return fmt.Errorf("-scope and -days are required")
		}
		if _, err := st.Pool.Exec(ctx,
			`INSERT INTO retention_policies (scope, contacts_ttl_days) VALUES ($1,$2)
			 ON CONFLICT (scope) DO UPDATE SET contacts_ttl_days=EXCLUDED.contacts_ttl_days`,
			*scope, *days); err != nil {
			return err
		}
		fmt.Printf("retention for scope %s: blobs older than %d day(s) are wiped by `sunder retention run`\n", *scope, *days)
		return nil
	case "run":
		wiped, otiPruned, err := service.RunRetention(ctx, st.Pool)
		if err != nil {
			return err
		}
		fmt.Printf("retention sweep: %d blob(s) wiped, %d expired OTI row(s) pruned\n", wiped, otiPruned)
		fmt.Println("(audit rows are never pruned - the chain and its anchors are the tamper evidence)")
		return nil
	default:
		return fmt.Errorf("unknown retention subcommand %q", args[0])
	}
}

// dsrCmd operates the erasure delivery queue.
func dsrCmd(ctx context.Context, cfg config.Config, st *store.Store, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: sunder dsr deliver | dsr events")
	}
	if err := st.Migrate(ctx); err != nil {
		return err
	}
	switch args[0] {
	case "deliver":
		g := &service.GDPR{Pool: st.Pool, HTTPTimeout: cfg.WebhookTimeout, MaxAttempts: cfg.WebhookMaxAttempts}
		n, err := g.DeliverPending(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("delivered %d erasure event(s)\n", n)
		return nil
	case "events":
		rows, err := st.Pool.Query(ctx,
			`SELECT id, erasure_id, scope, cid, status, attempts, COALESCE(delivered_at::text,'')
			 FROM erasure_events ORDER BY id DESC LIMIT 50`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id, erasureID int64
			var scope, cid, status, deliveredAt string
			var attempts int
			if err := rows.Scan(&id, &erasureID, &scope, &cid, &status, &attempts, &deliveredAt); err != nil {
				return err
			}
			fmt.Printf("#%d erasure=%d scope=%-12s cid=%s %s attempts=%d %s\n",
				id, erasureID, scope, cid, status, attempts, deliveredAt)
		}
		return rows.Err()
	default:
		return fmt.Errorf("unknown dsr subcommand %q", args[0])
	}
}

// vendoredCA is the fallback TSA root bundle shipped in the repo.
const vendoredCA = "deploy/freetsa/cacert.pem"

// resolveCA picks the TSA CA bundle: explicit flag > SUNDER_TSA_CACERT >
// vendored file (when present).
func resolveCA(flagVal string, cfg config.Config) string {
	if flagVal != "" {
		return flagVal
	}
	if cfg.TSACA != "" {
		return cfg.TSACA
	}
	if _, err := os.Stat(vendoredCA); err == nil {
		return vendoredCA
	}
	return ""
}

// anchorCmd stamps the current audit-chain head at the configured TSA.
// Run it from cron (daily); only a 32-byte digest leaves the system.
func anchorCmd(ctx context.Context, cfg config.Config, st *store.Store, args []string) error {
	fs := flag.NewFlagSet("anchor", flag.ContinueOnError)
	out := fs.String("out", cfg.AnchorDir, "directory to export the .tsr token to (sync it to write-once storage OFF this host)")
	ca := fs.String("ca", "", "TSA root CA bundle to verify the fresh token before storing (default: SUNDER_TSA_CACERT or the vendored FreeTSA CA)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := st.Migrate(ctx); err != nil {
		return err
	}
	caFile := resolveCA(*ca, cfg)
	root, stampedAt, err := audit.Anchor(ctx, st.Pool, cfg.TSAURL, caFile, *out)
	if err != nil {
		return err
	}
	if root == "" {
		fmt.Println("audit log is empty - nothing to anchor")
		return nil
	}
	fmt.Printf("anchored chain head %s...\n  TSA: %s\n  stamped at: %s\n", root[:16], cfg.TSAURL, stampedAt)
	if caFile == "" {
		fmt.Println("WARNING: fresh token NOT verified (no CA bundle available)")
	}
	if *out == "" {
		fmt.Println("WARNING: token stored only in the database - a database-level attacker can delete it.")
		fmt.Println("         Pass -out (or set SUNDER_ANCHOR_DIR) and sync that directory to write-once storage.")
	} else {
		fmt.Printf("  exported: %s\n", *out+"/"+root+".tsr")
	}
	return nil
}

// verifyAuditCmd recomputes the whole hash chain, verifies every stored TSA
// token offline, and cross-checks exported .tsr files when -anchors is
// given. Non-zero exit on any failure, and on anchors that exist but cannot
// be cryptographically verified - success must mean something.
func verifyAuditCmd(ctx context.Context, cfg config.Config, st *store.Store, args []string) error {
	fs := flag.NewFlagSet("verify-audit", flag.ContinueOnError)
	caFlag := fs.String("ca", "", "TSA root CA bundle (default: SUNDER_TSA_CACERT or the vendored FreeTSA CA)")
	anchorsDir := fs.String("anchors", "", "directory of exported .tsr files to cross-check against the database")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := st.Migrate(ctx); err != nil {
		return err
	}
	broken, reason, err := audit.Verify(ctx, st.Pool)
	if err != nil {
		return err
	}
	if broken != 0 {
		return fmt.Errorf("audit chain BROKEN at seq %d: %s", broken, reason)
	}
	fmt.Println("audit chain: intact")

	caFile := resolveCA(*caFlag, cfg)
	if *anchorsDir == "" && cfg.AnchorDir != "" {
		*anchorsDir = cfg.AnchorDir
	}
	anchors, err := audit.VerifyAnchors(ctx, st.Pool, caFile, *anchorsDir)
	if err != nil {
		return err
	}
	if len(anchors) == 0 {
		fmt.Println("no anchors stored yet - schedule `sunder anchor` in cron")
		return nil
	}
	if caFile == "" {
		return fmt.Errorf("%d anchor(s) exist but no TSA CA bundle is available - pass -ca (or set SUNDER_TSA_CACERT); refusing to report success without cryptographic verification", len(anchors))
	}
	bad := 0
	for _, a := range anchors {
		var parts []string
		if !a.InDB {
			parts, bad = append(parts, "MISSING FROM DATABASE (anchor row deleted?)"), bad+1
		}
		if a.InChain {
			parts = append(parts, "in-chain")
		} else {
			parts, bad = append(parts, "ROOT NOT IN CHAIN (history rewritten?)"), bad+1
		}
		if a.TokenOK {
			parts = append(parts, "token: OK")
		} else {
			parts, bad = append(parts, "token: INVALID"), bad+1
		}
		if *anchorsDir != "" && a.InDB {
			switch a.FileState {
			case "ok":
				parts = append(parts, "file: OK")
			case "missing":
				parts, bad = append(parts, "file: MISSING from export dir"), bad+1
			case "mismatch":
				parts, bad = append(parts, "file: MISMATCH with database"), bad+1
			}
		}
		fmt.Printf("anchor #%d %s... (%s) %s\n", a.ID, a.Root[:16], a.StampedAt, strings.Join(parts, "; "))
	}
	if bad > 0 {
		return fmt.Errorf("%d anchor check(s) failed", bad)
	}
	return nil
}

// keysCmd implements `sunder keys rotate -kind <kind>` and `sunder keys list`.
func keysCmd(ctx context.Context, cfg config.Config, st *store.Store, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: sunder keys rotate -kind <kind> | keys rekey [-reencrypt-pii] | keys retire -kind <kind> -version <v> | keys list")
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
		version, err := ring.Rotate(ctx, api.OpenEngine(cfg), *kind)
		if err != nil {
			return err
		}
		note := map[string]string{
			"hmac-email": "old tokens keep matching, rows re-key on touch",
			"hmac-phone": "old tokens keep matching, rows re-key on touch",
			"hmac-name":  "old tokens keep matching, rows re-key on touch",
			"pii-kek":    "old blobs stay decryptable via stored pii_key_id, re-encrypt on touch",
			"oti-sign":   "tokens signed by previous versions keep verifying until you `keys retire` them",
		}[*kind]
		fmt.Printf("rotated %s to %s (previous versions RETIRING; %s)\n", *kind, version, note)
		fmt.Println("running servers pick up the change within 30s (keyring cache TTL)")
		return nil
	case "retire":
		fs := flag.NewFlagSet("keys retire", flag.ContinueOnError)
		kind := fs.String("kind", "", "key kind")
		version := fs.String("version", "", "version to retire (e.g. v1)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *kind == "" || *version == "" {
			return fmt.Errorf("-kind and -version are required")
		}
		if err := ring.Retire(ctx, *kind, *version); err != nil {
			return err
		}
		fmt.Printf("retired %s/%s - it no longer matches lookups nor verifies tokens\n", *kind, *version)
		fmt.Println("(for hmac kinds: rows still stored under this version stop matching; re-key first)")
		return nil
	case "rekey":
		fs := flag.NewFlagSet("keys rekey", flag.ContinueOnError)
		reenc := fs.Bool("reencrypt-pii", true, "also re-encrypt attribute blobs under the newest pii-kek")
		batch := fs.Int("batch", 500, "persons per page")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		eng := api.OpenEngine(cfg)
		ring := &service.KeyRing{Pool: st.Pool}
		if err := ring.EnsureAll(ctx, eng); err != nil {
			return err
		}
		pii := crypto.NewPIIBox(eng)
		pii.Alg = cfg.PIIAlg
		contacts := &service.Contacts{Pool: st.Pool, Tok: crypto.NewTokenizer(eng), PII: pii, Ring: ring}
		stats, err := contacts.Rekey(ctx, *reenc, *batch)
		if err != nil {
			return err
		}
		fmt.Printf("rekey sweep: %d person(s), %d token(s) written, %d blob(s) re-encrypted, %d blob(s) undecryptable\n",
			stats.Persons, stats.TokensInserted, stats.BlobsReenc, stats.Skipped)
		fmt.Println("old versions can now be retired: sunder keys retire -kind <kind> -version <v>")
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
	if len(args) >= 1 && args[0] == "rotate-secret" {
		return clientRotateCmd(ctx, st, args[1:])
	}
	if len(args) < 1 || args[0] != "create" {
		return fmt.Errorf("usage: sunder client create -id <id> -name <name> -scope <scope> [-actions a,b] [-purposes p,q] [-rate n] [-ttl 90d] | client rotate-secret -id <id> [-ttl 90d]")
	}
	fs := flag.NewFlagSet("client create", flag.ContinueOnError)
	id := fs.String("id", "", "client id (required)")
	name := fs.String("name", "", "display name (required)")
	scope := fs.String("scope", "", "CID scope this client belongs to (required)")
	actions := fs.String("actions", "", "comma-separated allowed actions")
	purposes := fs.String("purposes", "", "comma-separated allowed purposes")
	rate := fs.Int("rate", 60, "lookup rate limit per minute")
	ttl := fs.String("ttl", "", "credential lifetime (e.g. 90d, 720h); empty = non-expiring")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *id == "" || *name == "" || *scope == "" {
		return fmt.Errorf("-id, -name and -scope are required")
	}
	expiresAt, err := parseTTL(*ttl)
	if err != nil {
		return err
	}
	// Reject typo'd actions up front: a dead grant would surface much later
	// as a confusing 403 in some integration.
	known := map[string]bool{
		auth.ActContactsRegister: true, auth.ActScopesIssue: true, auth.ActLookup: true,
		auth.ActAttributesRead: true, auth.ActOTIIssue: true, auth.ActOTIVerify: true,
		auth.ActConsentManage: true, auth.ActDSRAccess: true, auth.ActDSRErase: true,
		auth.ActDSRExport: true,
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
		AllowedActions:      acts,
		AllowedPurposes:     splitCSV(*purposes),
		RateLimit:           *rate,
		CredentialExpiresAt: expiresAt,
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

// signerCmd runs the key-holding signer process (P2.1 split). It serves the
// six-operation engine protocol on a local Unix socket; the main process
// (started with SUNDER_SIGNER_SOCKET pointing here) then never holds keys.
func signerCmd(ctx context.Context, cfg config.Config, args []string) error {
	fs := flag.NewFlagSet("signer", flag.ContinueOnError)
	socket := fs.String("socket", cfg.SignerSocket, "unix socket path to serve on")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *socket == "" {
		return fmt.Errorf("signer: -socket or SUNDER_SIGNER_SOCKET required")
	}
	eng := crypto.NewLocalEngine(api.OpenKeystore(cfg))
	fmt.Printf("sunder signer: serving %s (keystore: %s)\n", *socket, cfg.Keystore)
	return crypto.ServeSigner(ctx, *socket, eng)
}

// parseTTL turns "90d" / "720h" / "" into an absolute expiry (nil = never).
// Days are accepted because credential lifetimes are quoted in days far
// more often than in Go duration units.
func parseTTL(ttl string) (*time.Time, error) {
	if ttl == "" {
		return nil, nil
	}
	var d time.Duration
	if n, ok := strings.CutSuffix(ttl, "d"); ok {
		days, err := strconv.Atoi(n)
		if err != nil || days < 1 {
			return nil, fmt.Errorf("-ttl: %q is not a day count (e.g. 90d)", ttl)
		}
		d = time.Duration(days) * 24 * time.Hour
	} else {
		var err error
		if d, err = time.ParseDuration(ttl); err != nil || d < time.Minute {
			return nil, fmt.Errorf("-ttl: %q must be a duration >= 1m or a day count like 90d", ttl)
		}
	}
	t := time.Now().Add(d)
	return &t, nil
}

// clientRotateCmd implements `sunder client rotate-secret`: a new secret
// (and optionally a new expiry) printed exactly once; the old secret stops
// working immediately.
func clientRotateCmd(ctx context.Context, st *store.Store, args []string) error {
	fs := flag.NewFlagSet("client rotate-secret", flag.ContinueOnError)
	id := fs.String("id", "", "client id (required)")
	ttl := fs.String("ttl", "", "new credential lifetime (e.g. 90d); empty = non-expiring")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		return fmt.Errorf("-id is required")
	}
	expiresAt, err := parseTTL(*ttl)
	if err != nil {
		return err
	}
	if err := st.Migrate(ctx); err != nil {
		return err
	}
	cred, err := auth.RotateSecret(ctx, st.Pool, *id, expiresAt)
	if err != nil {
		return err
	}
	if err := audit.Append(ctx, st.Pool, audit.Entry{
		ClientID: "operator", Action: "client.rotate_secret",
		Detail: map[string]any{"client_id": *id, "expires": *ttl != ""},
	}); err != nil {
		return err
	}
	fmt.Println("new credential (shown once, store it now):")
	fmt.Println(cred)
	if expiresAt != nil {
		fmt.Printf("expires: %s\n", expiresAt.UTC().Format(time.RFC3339))
	}
	return nil
}
