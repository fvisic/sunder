// Command sunder runs the Sunder identity-decoupling service.
//
// Subcommands:
//
//	serve start the HTTP service (default)
//	migrate apply database migrations and exit
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	neturl "net/url"
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
	case "serve", "migrate", "client", "keys", "anchor", "verify-audit", "webhook", "retention", "dsr", "signer", "issuer", "bootstrap", "sealer", "import":
	default:
		// Fail on typos before requiring config or a live database.
		return fmt.Errorf("unknown command %q (available: serve, migrate, client, keys, anchor, verify-audit, webhook, retention, dsr, signer, issuer, bootstrap, sealer, import)", cmd)
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
	// One authority for the write modes: the parsed (validated) config, not
	// the raw environment the audit package fell back to at init.
	audit.SetMode(cfg.AuditSealing)
	audit.SetReadsMode(cfg.AuditReads)
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
	case "sealer":
		return sealerCmd(ctx, cfg, st, args)
	case "import":
		return importCmd(ctx, cfg, st, args)
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
	case "issuer":
		return issuerCmd(ctx, st, args)
	case "bootstrap":
		return bootstrapCmd(ctx, cfg, st, args)
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
		// carry pseudonyms and must not travel plaintext. Parsed, not
		// prefix-matched: "http://localhost.attacker.example/" satisfies a
		// prefix check on "http://localhost".
		if err := validWebhookURL(*url); err != nil {
			return err
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
		envelopes, err := service.PruneEnvelopes(ctx, st.Pool)
		if err != nil {
			return err
		}
		portalRows, err := service.PrunePortal(ctx, st.Pool)
		if err != nil {
			return err
		}
		fmt.Printf("retention sweep: %d blob(s) wiped, %d expired OTI row(s) pruned, %d consumed envelope(s) pruned, %d portal row(s) pruned\n",
			wiped, otiPruned, envelopes, portalRows)
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
	broken, reason, pending, err := audit.Verify(ctx, st.Pool)
	if err != nil {
		return err
	}
	if broken != 0 {
		return fmt.Errorf("audit chain BROKEN at chain position %d: %s", broken, reason)
	}
	// The sealing window must never be discoverable only by reading code:
	// the mode and the pending count are printed on every verification.
	// Pending rows are information, not a break - they are protected by the
	// append-only trigger and enter the chain on the sealer's next pass.
	fmt.Printf("audit chain: intact (sealing mode %s, %d unsealed rows pending)\n",
		audit.Mode(), pending)
	// Read buckets (P4.2): every sealed hour's digest is recomputed from
	// the stored buckets and checked against its chained hourly row.
	badHour, bucketReason, pendingHours, err := audit.VerifyReadBuckets(ctx, st.Pool)
	if err != nil {
		return err
	}
	if badHour != "" {
		return fmt.Errorf("read buckets BROKEN for hour %s: %s", badHour, bucketReason)
	}
	fmt.Printf("read buckets: intact (read mode %s, %d finished hours awaiting close)\n",
		audit.ReadsMode(), pendingHours)
	// Under sync mode, though, pending rows cannot be in-flight work: sync
	// seals at insert and the server drains before serving. A backlog here
	// means rows stranded outside the chain - fail visibly, with the fix.
	if audit.Mode() == audit.ModeSync && pending > 0 {
		return fmt.Errorf("%d unsealed rows under sync sealing: these are outside the chain and will not seal on their own; run `sunder sealer -once` with SUNDER_AUDIT_SEALING=async to drain them", pending)
	}

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
		contacts := &service.Contacts{Pool: st.Pool, Tok: crypto.NewTokenizer(eng), PII: pii, Ring: ring,
			FuzzyName: cfg.SearchFuzzyName, PhoneSuffix: cfg.SearchPhoneSuffix}
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
		auth.ActDSRExport: true, auth.ActClaimsExternal: true,
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
	ttl := fs.String("ttl", "", "new credential lifetime (e.g. 90d); empty = keep the current expiry policy")
	noExpiry := fs.Bool("no-expiry", false, "explicitly clear any credential expiry")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		return fmt.Errorf("-id is required")
	}
	if *ttl != "" && *noExpiry {
		return fmt.Errorf("-ttl and -no-expiry are mutually exclusive")
	}
	expiresAt, err := parseTTL(*ttl)
	if err != nil {
		return err
	}
	if err := st.Migrate(ctx); err != nil {
		return err
	}
	cred, err := auth.RotateSecret(ctx, st.Pool, *id, expiresAt, *ttl != "" || *noExpiry)
	if err != nil {
		return err
	}
	// Print FIRST: the old secret is already dead, so a failure past this
	// point must never leave the operator without the new credential.
	fmt.Println("new credential (shown once, store it now):")
	fmt.Println(cred)
	if expiresAt != nil {
		fmt.Printf("expires: %s\n", expiresAt.UTC().Format(time.RFC3339))
	}
	if err := audit.Append(ctx, st.Pool, audit.Entry{
		ClientID: "operator", Action: "client.rotate_secret",
		Detail: map[string]any{"client_id": *id, "expires": *ttl != "", "cleared": *noExpiry},
	}); err != nil {
		return fmt.Errorf("credential rotated and printed above, but the audit append failed: %w", err)
	}
	return nil
}

// issuerCmd manages the P2.4 external-issuer trust registry.
func issuerCmd(ctx context.Context, st *store.Store, args []string) error {
	if err := st.Migrate(ctx); err != nil {
		return err
	}
	if len(args) < 1 {
		return fmt.Errorf("usage: sunder issuer add -id <id> -pubkey <hex32> [-claims a,b] | issuer list | issuer remove -id <id>")
	}
	switch args[0] {
	case "add":
		fs := flag.NewFlagSet("issuer add", flag.ContinueOnError)
		id := fs.String("id", "", "issuer id (required)")
		pub := fs.String("pubkey", "", "hex-encoded 32-byte Ed25519 public key (required)")
		claims := fs.String("claims", "", "comma-separated claim names this issuer may assert; '*' = any; empty = NONE (deny by default)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		key, err := hex.DecodeString(*pub)
		if err != nil || *id == "" {
			return fmt.Errorf("-id and a 64-hex-char -pubkey are required")
		}
		// Registration is where unusable key material must be stopped: a
		// small-order point accepts forged signatures for every payload
		//.
		if err := crypto.ValidEd25519PublicKey(key); err != nil {
			return fmt.Errorf("refusing to register issuer %q: %w", *id, err)
		}
		if _, err := st.Pool.Exec(ctx,
			`INSERT INTO trusted_issuers (issuer_id, public_key, allowed_claims, added_by) VALUES ($1,$2,$3,'operator')`,
			*id, key, splitCSV(*claims)); err != nil {
			return err
		}
		if err := audit.Append(ctx, st.Pool, audit.Entry{
			ClientID: "operator", Action: "issuer.add",
			Detail: map[string]any{"issuer": *id, "claims": splitCSV(*claims)},
		}); err != nil {
			return err
		}
		fmt.Printf("issuer %s registered\n", *id)
		return nil
	case "list":
		rows, err := st.Pool.Query(ctx,
			`SELECT issuer_id, encode(public_key,'hex'), allowed_claims, created_at, revoked_at
			 FROM trusted_issuers ORDER BY issuer_id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id, pub string
			var claims []string
			var created time.Time
			var revoked *time.Time
			if err := rows.Scan(&id, &pub, &claims, &created, &revoked); err != nil {
				return err
			}
			state := "active"
			if revoked != nil {
				state = "retired " + revoked.Format("2006-01-02")
			}
			fmt.Printf("%-24s %s claims=%v added=%s %s\n",
				id, pub[:16]+"...", claims, created.Format("2006-01-02"), state)
		}
		return rows.Err()
	case "remove":
		fs := flag.NewFlagSet("issuer remove", flag.ContinueOnError)
		id := fs.String("id", "", "issuer id (required)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *id == "" {
			return fmt.Errorf("-id is required")
		}
		// RETIRE rather than delete: the row is history, and re-adding the
		// same id under a new key would silently re-attribute every stored
		// `<claim>@<id>` attribute to the new key holder.
		tag, err := st.Pool.Exec(ctx,
			`UPDATE trusted_issuers SET revoked_at=now() WHERE issuer_id=$1 AND revoked_at IS NULL`, *id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("issuer %q not found or already retired", *id)
		}
		if err := audit.Append(ctx, st.Pool, audit.Entry{
			ClientID: "operator", Action: "issuer.remove", Detail: map[string]any{"issuer": *id},
		}); err != nil {
			return err
		}
		fmt.Printf("issuer %s retired (its id stays reserved so stored claims keep their provenance)\n", *id)
		return nil
	default:
		return fmt.Errorf("unknown issuer subcommand %q", args[0])
	}
}

// bootstrapCmd performs first-run setup in one command: migrations, key
// material, and the first admin client whose credential is printed (or, in
// unattended mode, written to a file) exactly once. Idempotent: rerunning
// against an initialized instance is a no-op success, so compose/Helm
// hooks and provisioning scripts can call it unconditionally.
func bootstrapCmd(ctx context.Context, cfg config.Config, st *store.Store, args []string) error {
	fs := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	unattended := fs.Bool("unattended", false, "write the credential to -credential-file instead of stdout")
	id := fs.String("id", getenvDefault("SUNDER_BOOTSTRAP_CLIENT_ID", "admin"), "admin client id")
	scope := fs.String("scope", getenvDefault("SUNDER_BOOTSTRAP_SCOPE", "admin"), "admin client scope")
	// An admin with no purposes cannot read a single attribute or issue an
	// OTI (CanUse is deny-all), which made provisioning produce a useless
	// credential. Default to a real, usable purpose.
	purposes := fs.String("purposes", getenvDefault("SUNDER_BOOTSTRAP_PURPOSES", "admin"),
		"comma-separated purposes for the admin client")
	credFile := fs.String("credential-file", os.Getenv("SUNDER_BOOTSTRAP_CREDENTIAL_FILE"),
		"unattended mode: file the credential is written to (created 0600; must not be a stream)")
	ttl := fs.String("ttl", os.Getenv("SUNDER_BOOTSTRAP_TTL"), "credential lifetime (e.g. 90d); empty = non-expiring")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Validate BEFORE anything is created: a rejected flag combination must
	// never leave a committed admin behind.
	if *unattended && *credFile == "" {
		return fmt.Errorf("bootstrap -unattended requires -credential-file or SUNDER_BOOTSTRAP_CREDENTIAL_FILE")
	}
	if *credFile != "" {
		// A stream target cannot be 0600 and would land in container logs,
		// where any log shipper forwards it.
		if strings.HasPrefix(*credFile, "/dev/") || strings.HasPrefix(*credFile, "/proc/") {
			return fmt.Errorf("-credential-file must be a real file, not %s: the credential would be written to a log stream", *credFile)
		}
	}
	expiresAt, err := parseTTL(*ttl)
	if err != nil {
		return err
	}
	if err := st.Migrate(ctx); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	eng := api.OpenEngine(cfg)
	ring := &service.KeyRing{Pool: st.Pool}
	if err := ring.EnsureAll(ctx, eng); err != nil {
		return fmt.Errorf("key bootstrap: %w", err)
	}

	// One transaction for the row, the persisted credential and the audit
	// record: any failure rolls all three back, so a rerun can repair
	// instead of reporting "already exists" over an unusable admin.
	tx, err := st.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Advisory lock + in-transaction check: two concurrent bootstraps must
	// not race past the existence check.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(0x53554E4442)`); err != nil {
		return err
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM clients WHERE client_id=$1`, *id).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		fmt.Printf("bootstrap: client %q already exists - nothing to do\n", *id)
		return nil
	}
	cred, err := auth.CreateTx(ctx, tx, auth.Client{
		ID: *id, Name: "Bootstrap admin", Scope: *scope,
		AllowedActions: []string{auth.ActContactsRegister, auth.ActScopesIssue, auth.ActLookup,
			auth.ActAttributesRead, auth.ActOTIIssue, auth.ActOTIVerify, auth.ActConsentManage,
			auth.ActDSRAccess, auth.ActDSRErase, auth.ActDSRExport, auth.ActClaimsExternal},
		AllowedPurposes:     splitCSV(*purposes),
		RateLimit:           600,
		CredentialExpiresAt: expiresAt,
	})
	if err != nil {
		return err
	}
	if err := audit.AppendTx(ctx, tx, audit.Entry{
		ClientID: "operator", Action: "bootstrap",
		Detail: map[string]any{"client_id": *id, "scope": *scope, "unattended": *unattended},
	}); err != nil {
		return err
	}
	if *unattended {
		// Written before the commit: if this fails, the client is never
		// created, so the credential can never be lost with a row behind it.
		f, err := os.OpenFile(*credFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		if _, err := f.WriteString(cred + "\n"); err != nil {
			_ = f.Close()
			return err
		}
		// O_CREATE does not tighten a pre-existing file's mode.
		if err := f.Chmod(0o600); err != nil {
			_ = f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			_ = os.Remove(*credFile)
			return err
		}
		fmt.Printf("bootstrap: credential for %q written to %s (0600 - move it to your secret store)\n", *id, *credFile)
		fmt.Printf("purposes: %s\n", *purposes)
		return nil
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	fmt.Println("bootstrap complete. Admin credential (shown once, store it now):")
	fmt.Println(cred)
	fmt.Printf("purposes: %s (set SUNDER_BOOTSTRAP_PURPOSES or -purposes for your own)\n", *purposes)
	return nil
}

func getenvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// validWebhookURL accepts https:// anywhere, and http:// only for a genuine
// loopback HOST (not merely a hostname that starts with one).
func validWebhookURL(raw string) error {
	u, err := neturl.Parse(raw)
	if err != nil {
		return fmt.Errorf("webhook URL is not a URL: %w", err)
	}
	switch u.Scheme {
	case "https":
		if u.Host == "" {
			return fmt.Errorf("webhook URL has no host")
		}
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return nil
		}
		return fmt.Errorf("plain http webhook URLs are allowed for loopback only, got host %q", host)
	default:
		return fmt.Errorf("webhook URL must be https:// (http:// allowed for loopback only)")
	}
}

// sealerCmd runs the audit sealer as its own process
// (SUNDER_AUDIT_SEAL_EXTERNAL=true on the API side). The point of the
// split is privilege separation, same pattern as the P2.1 signer: give
// this process a DB role that may UPDATE only prev_hash/hash/chain_seq on
// audit, and the API a role with INSERT but no UPDATE - then a
// compromised API cannot forge hashes over its own rows.
func sealerCmd(ctx context.Context, cfg config.Config, st *store.Store, args []string) error {
	fs := flag.NewFlagSet("sealer", flag.ContinueOnError)
	once := fs.Bool("once", false, "drain the backlog and exit (for cron or a pre-switch drain)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if cfg.AuditSealing == audit.ModeSync {
		return fmt.Errorf("SUNDER_AUDIT_SEALING=sync seals at insert; a sealer process has nothing to do")
	}
	// No Migrate here: the sealer's restricted role may lack DDL rights,
	// and a sealer must never be the thing that alters the schema.

	if *once {
		n, err := audit.Drain(ctx, st.Pool, cfg.AuditSealBatch)
		if err != nil {
			return err
		}
		hours, err := audit.CloseReadBuckets(ctx, st.Pool)
		if err != nil {
			return err
		}
		fmt.Printf("sealed %d row(s), closed %d finished bucket hour(s)\n", n, hours)
		return nil
	}

	fmt.Printf("sealer: interval %s, delay %s, batch %d, reads %s\n",
		cfg.AuditSealInterval, cfg.AuditSealDelay, cfg.AuditSealBatch, audit.ReadsMode())
	ticker := time.NewTicker(cfg.AuditSealInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if _, err := audit.SealOnce(ctx, st.Pool, cfg.AuditSealBatch, cfg.AuditSealDelay); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				// Log and keep going: a transient DB error must not kill
				// the one process whose absence silently grows the
				// unsealed window.
				fmt.Fprintln(os.Stderr, "sealer:", err)
				continue
			}
			// The external sealer owns bucket closing too (with
			// SUNDER_AUDIT_SEAL_EXTERNAL=true the server runs neither
			// loop). Closing an already-closed backlog is a cheap
			// try-locked no-op, so sharing the sealing cadence is fine.
			if _, err := audit.CloseReadBuckets(ctx, st.Pool); err != nil && ctx.Err() == nil {
				fmt.Fprintln(os.Stderr, "sealer (bucket close):", err)
			}
		}
	}
}
