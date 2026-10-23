// Command sunder runs the Sunder identity-decoupling service.
//
// Subcommands:
//
//	serve start the HTTP service (default)
//	migrate apply database migrations and exit
package main

import (
	"bufio"
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	neturl "net/url"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/fvisic/sunder/internal/api"
	"github.com/fvisic/sunder/internal/audit"
	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/config"
	"github.com/fvisic/sunder/internal/crypto"
	"github.com/fvisic/sunder/internal/service"
	"github.com/fvisic/sunder/internal/storage"
	"github.com/fvisic/sunder/internal/store"
)

// signalContext is a seam for tests (which cannot deliver real signals).
var signalContext = func() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
}

func main() { os.Exit(cli(os.Args)) }

// cli is main minus os.Exit, so the argv handling is testable.
func cli(argv []string) int {
	cmd := "serve"
	var rest []string
	if len(argv) > 1 {
		cmd = argv[1]
		rest = argv[2:]
	}
	if err := run(cmd, rest); err != nil {
		fmt.Fprintln(os.Stderr, "sunder:", err)
		return 1
	}
	return 0
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
	audit.SetStaleUnsealedBound(cfg.AuditStaleUnsealed)
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
		return retentionCmd(ctx, cfg, st, args)
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
		// Audited: repointing a scope's erasure webhook redirects every
		// future notification (scope + CID) and mints a new signing secret.
		// The URL is recorded, the secret never is.
		if err := auditOperator(ctx, st.Pool, "webhook.set",
			map[string]any{"scope": *scope, "url": *url}, func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx,
					`INSERT INTO webhooks (scope, url, secret) VALUES ($1,$2,$3)
					 ON CONFLICT (scope) DO UPDATE SET url=EXCLUDED.url, secret=EXCLUDED.secret, created_at=now()`,
					*scope, *url, secret)
				return err
			}); err != nil {
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

// clientGrantCmd adjusts an existing client's actions, attribute allowlist
// or role - the supported path to enable strict search posture (grant
// admin.unlock) or F3 narrowing on a live client without editing SQL.
// checkUnlockAgainstExpiry refuses to put admin.unlock on a credential that
// has no expiry (L10). It reads the client's CURRENT expiry, so it is the
// single guard every grant path funnels through.
func checkUnlockAgainstExpiry(ctx context.Context, st *store.Store, id string, actions []string) error {
	if !slices.Contains(actions, auth.ActAdminUnlock) {
		return nil
	}
	var hasExpiry bool
	if err := st.Pool.QueryRow(ctx,
		`SELECT credential_expires_at IS NOT NULL FROM clients WHERE client_id=$1`, id).Scan(&hasExpiry); err != nil {
		return err
	}
	if !hasExpiry {
		return fmt.Errorf("admin.unlock must not be granted to a non-expiring credential (L10): a standing unlock grant defeats the strict search posture; give it a -ttl first")
	}
	return nil
}

func clientGrantCmd(ctx context.Context, st *store.Store, args []string) error {
	fs := flag.NewFlagSet("client grant", flag.ContinueOnError)
	id := fs.String("id", "", "client id (required)")
	role := fs.String("role", "", "replace actions with a preset: readonly|service|admin|privacy-officer")
	addActions := fs.String("add-actions", "", "comma-separated actions to ADD to the current set")
	attributes := fs.String("attributes", "", "replace the attribute allowlist (comma-separated); empty is IGNORED - use -clear-attributes to read all")
	clearAttrs := fs.Bool("clear-attributes", false, "remove the attribute allowlist (read all)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		return fmt.Errorf("-id is required")
	}
	if err := st.Migrate(ctx); err != nil {
		return err
	}
	known := knownActions()
	if *role != "" && *addActions != "" {
		return fmt.Errorf("-role and -add-actions are mutually exclusive")
	}
	var preset []string
	if *role != "" {
		if preset = auth.RoleActions(*role); preset == nil {
			return fmt.Errorf("unknown role %q", *role)
		}
		// L10: a preset that includes admin.unlock (admin does) must not land
		// on a non-expiring credential - same rule as create and -add-actions.
		if err := checkUnlockAgainstExpiry(ctx, st, *id, preset); err != nil {
			return err
		}
	}
	var add []string
	if *addActions != "" {
		add = splitCSV(*addActions)
		for _, a := range add {
			if !known[a] {
				return fmt.Errorf("unknown action %q", a)
			}
		}
		// L10: adding admin.unlock to a non-expiring credential is refused,
		// same rule as at creation.
		if err := checkUnlockAgainstExpiry(ctx, st, *id, add); err != nil {
			return err
		}
	}
	var attrs []string
	if !*clearAttrs && *attributes != "" {
		if attrs = splitCSV(*attributes); len(attrs) == 0 {
			return fmt.Errorf("-attributes given but empty after parsing; use -clear-attributes to allow all")
		}
	}

	// ONE transaction for every UPDATE plus the audit row. It used to be up
	// to three independent autocommit statements with an unconditional
	// success print: a failure between them left a half-applied grant
	// reported as success, and a typo'd client id reported success while
	// changing nothing (OPS-CLI-CONFIG-10). Escalating a credential is also
	// exactly the mutation the chain must carry - THREAT-MODEL calls
	// reviewing grants a human duty, and a review needs something
	// tamper-evident to review (OPS-CLI-CONFIG-3).
	tx, err := st.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Existence is checked under a row lock, so the audit row cannot
	// describe a client that vanished mid-command.
	var found int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM (SELECT 1 FROM clients WHERE client_id=$1 FOR UPDATE) x`, *id).Scan(&found); err != nil {
		return err
	}
	if found == 0 {
		return fmt.Errorf("no such client %q", *id)
	}

	detail := map[string]any{"client_id": *id}
	if preset != nil {
		if _, err := tx.Exec(ctx,
			`UPDATE clients SET role=$2, allowed_actions=$3 WHERE client_id=$1`,
			*id, *role, preset); err != nil {
			return err
		}
		detail["role"], detail["allowed_actions"] = *role, preset
	}
	if add != nil {
		// Union the added actions into the current set; role becomes custom.
		if _, err := tx.Exec(ctx, `
			UPDATE clients
			   SET allowed_actions = (SELECT array_agg(DISTINCT a) FROM unnest(allowed_actions || $2::text[]) a),
			       role = 'custom'
			 WHERE client_id = $1`, *id, add); err != nil {
			return err
		}
		detail["added_actions"], detail["role"] = add, "custom"
	}
	if *clearAttrs {
		if _, err := tx.Exec(ctx, `UPDATE clients SET allowed_attributes=NULL WHERE client_id=$1`, *id); err != nil {
			return err
		}
		detail["allowed_attributes"] = nil
	} else if attrs != nil {
		if _, err := tx.Exec(ctx, `UPDATE clients SET allowed_attributes=$2 WHERE client_id=$1`,
			*id, attrs); err != nil {
			return err
		}
		detail["allowed_attributes"] = attrs
	}
	if err := audit.AppendTx(ctx, tx, audit.Entry{
		ClientID: "operator", Action: "client.grant", Detail: detail,
	}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	fmt.Printf("client %q updated\n", *id)
	return nil
}

// auditOperator writes one chained record for a privileged operator
// mutation, inside the transaction that performs it.
//
// Auditing used to be added per command as each was written - rotate-secret,
// issuer add/remove and bootstrap had it; creating a credential with an
// arbitrary action set, escalating one, repointing a scope's erasure webhook,
// retiring a key version (which DELETEs person_tokens) and setting a
// retention TTL that wipes blobs en masse did not. `verify-audit` then
// reported an intact chain across a period in which the whole authorisation
// model was rewritten (OPS-CLI-CONFIG-3). Detail carries configuration
// metadata only - never a secret, never personal data.
func auditOperator(ctx context.Context, pool *pgxpool.Pool, action string, detail map[string]any, mutate func(pgx.Tx) error) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := mutate(tx); err != nil {
		return err
	}
	if err := audit.AppendTx(ctx, tx, audit.Entry{
		ClientID: "operator", Action: action, Detail: detail,
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// knownActions is the authoritative action allowlist for CLI validation.
func knownActions() map[string]bool {
	return map[string]bool{
		auth.ActContactsRegister: true, auth.ActScopesIssue: true, auth.ActLookup: true,
		auth.ActAttributesRead: true, auth.ActOTIIssue: true, auth.ActOTIVerify: true,
		auth.ActConsentManage: true, auth.ActDSRAccess: true, auth.ActDSRErase: true,
		auth.ActDSRExport: true, auth.ActClaimsExternal: true, auth.ActAdminUnlock: true,
		auth.ActTokensCreate: true, auth.ActTokensRead: true, auth.ActTokensDelete: true,
		auth.ActFilesWrite: true, auth.ActFilesRead: true, auth.ActLinksManage: true, auth.ActSharesCreate: true,
		auth.ActAttributesHistory: true, auth.ActAuditVerify: true,
	}
}

// retentionCmd manages per-scope contact TTLs and runs the sweep.
func retentionCmd(ctx context.Context, cfg config.Config, st *store.Store, args []string) error {
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
		// Audited: a TTL change is the instruction that makes the next
		// sweep wipe blobs en masse.
		if err := auditOperator(ctx, st.Pool, "retention.set",
			map[string]any{"scope": *scope, "contacts_ttl_days": *days}, func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx,
					`INSERT INTO retention_policies (scope, contacts_ttl_days) VALUES ($1,$2)
					 ON CONFLICT (scope) DO UPDATE SET contacts_ttl_days=EXCLUDED.contacts_ttl_days`,
					*scope, *days)
				return err
			}); err != nil {
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
		// Claims abandoned by a worker that died mid-send. The workers reap
		// on every sweep too; this is the operator-driven path and the one
		// that recovers rows stranded before the reaper existed (H1).
		strandedEvents, err := service.ReapStrandedErasureEvents(ctx, st.Pool, cfg.WorkerClaimTTL)
		if err != nil {
			return err
		}
		strandedMail, err := service.ReapStrandedMail(ctx, st.Pool, cfg.WorkerClaimTTL)
		if err != nil {
			return err
		}
		unlockRows, err := service.PruneUnlockTokens(ctx, st.Pool)
		if err != nil {
			return err
		}
		valueRows, err := service.PruneValueTokens(ctx, st.Pool)
		if err != nil {
			return err
		}
		versionRows, err := service.PruneBlobVersions(ctx, st.Pool, cfg.VersionsTTL)
		if err != nil {
			return err
		}
		shareRows, err := service.PruneShares(ctx, st.Pool)
		if err != nil {
			return err
		}
		var filesReaped int64
		if cfg.FilesStorage != "" {
			drv, err := storage.Open(storage.Config{Kind: cfg.FilesStorage, Dir: cfg.FilesDir,
				S3Endpoint: cfg.FilesS3Endpoint, S3Bucket: cfg.FilesS3Bucket, S3Region: cfg.FilesS3Region,
				S3AccessKey: cfg.FilesS3AccessKey, S3SecretKey: cfg.FilesS3SecretKey, S3PathStyle: cfg.FilesS3PathStyle})
			if err != nil {
				return err
			}
			if filesReaped, err = service.RunFileGC(ctx, st.Pool, drv); err != nil {
				return err
			}
		}
		fmt.Printf("retention sweep: %d blob(s) wiped, %d expired OTI row(s) pruned, %d consumed envelope(s) pruned, %d portal row(s) pruned, %d unlock token(s) pruned, %d value token(s) pruned, %d version(s) pruned, %d share(s) pruned, %d file(s) garbage-collected\n",
			wiped, otiPruned, envelopes, portalRows, unlockRows, valueRows, versionRows, shareRows, filesReaped)
		fmt.Printf("stranded worker claims requeued: %d erasure event(s), %d portal mail row(s)\n",
			strandedEvents, strandedMail)
		fmt.Println("(audit rows are never pruned - the chain and its anchors are the tamper evidence)")
		return nil
	default:
		return fmt.Errorf("unknown retention subcommand %q", args[0])
	}
}

// dsrCmd operates the erasure delivery queue.
func dsrCmd(ctx context.Context, cfg config.Config, st *store.Store, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: sunder dsr deliver | dsr events | dsr requeue | dsr cascade-status")
	}
	if err := st.Migrate(ctx); err != nil {
		return err
	}
	switch args[0] {
	case "deliver":
		g := &service.GDPR{Pool: st.Pool, HTTPTimeout: cfg.WebhookTimeout,
			MaxAttempts: cfg.WebhookMaxAttempts, ClaimTTL: cfg.WorkerClaimTTL,
			MaxCascadeChildren: cfg.MaxCascadeChildren}
		n, err := g.DeliverPending(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("delivered %d erasure event(s)\n", n)
		return nil
	case "requeue":
		// Operator recovery for a claim stranded by a worker that died
		// between the committed claim and the settle. `-all` ignores the
		// grace period, for the case where the operator KNOWS no worker is
		// running (e.g. after a crash loop).
		fs := flag.NewFlagSet("dsr requeue", flag.ContinueOnError)
		all := fs.Bool("all", false, "requeue every SENDING row regardless of claim age")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		ttl := cfg.WorkerClaimTTL
		if *all {
			ttl = time.Nanosecond
		}
		n, err := service.ReapStrandedErasureEvents(ctx, st.Pool, ttl)
		if err != nil {
			return err
		}
		m, err := service.ReapStrandedMail(ctx, st.Pool, ttl)
		if err != nil {
			return err
		}
		fmt.Printf("requeued %d erasure event(s) and %d portal mail row(s) stranded in SENDING\n", n, m)
		return nil
	case "cascade-status":
		// What an interrupted cascade left outstanding. Before the durable
		// plan existed this was unanswerable: the parent's erasure deleted
		// person_links, so nothing named the children (GDPR-ERASURE-4).
		rows, err := st.Pool.Query(ctx, `
			SELECT ec.erasure_id, ec.child_cid, ec.link_type, ec.status,
			       COALESCE(ec.done_at::text,'')
			  FROM erasure_cascade ec
			 ORDER BY ec.status, ec.erasure_id DESC, ec.child_cid LIMIT 200`)
		if err != nil {
			return err
		}
		defer rows.Close()
		pending := 0
		for rows.Next() {
			var erasureID int64
			var childCID, linkType, status, doneAt string
			if err := rows.Scan(&erasureID, &childCID, &linkType, &status, &doneAt); err != nil {
				return err
			}
			if status == "PENDING" {
				pending++
			}
			fmt.Printf("erasure=%d child=%s type=%-9s %s %s\n", erasureID, childCID, linkType, status, doneAt)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if pending > 0 {
			fmt.Printf("\n%d child erasure(s) OUTSTANDING - re-issue POST /v1/dsr/erase for the parent cid to resume\n", pending)
		}
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
	if errors.Is(err, audit.ErrAlreadyAnchored) {
		// Not a failure: the head has not moved since the last run, so
		// there is nothing new to attest. Re-stamping it would write a
		// second anchor row whose export can never match the first
		// (AUDIT-CHAIN-4), which is why this is a no-op rather than a
		// duplicate.
		fmt.Printf("chain head %s... is already anchored - nothing new to stamp\n", root[:16])
		return nil
	}
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
	// The same verdict function the HTTP endpoint uses, so the two surfaces
	// cannot answer differently for the same database (AUDIT-CHAIN-3).
	rep, err := audit.VerifyAll(ctx, st.Pool)
	if err != nil {
		return err
	}
	if !rep.OK {
		switch {
		case rep.BrokenChainSeq != 0:
			return fmt.Errorf("audit chain BROKEN at chain position %d: %s", rep.BrokenChainSeq, rep.Reason)
		case rep.BadHour != "":
			return fmt.Errorf("read buckets BROKEN for hour %s: %s", rep.BadHour, rep.Reason)
		default:
			return fmt.Errorf("%s", rep.Reason)
		}
	}
	// The sealing window must never be discoverable only by reading code:
	// the mode and the pending count are printed on every verification.
	// Pending rows are information, not a break - they are protected by the
	// append-only trigger and enter the chain on the sealer's next pass.
	fmt.Printf("audit chain: intact (sealing mode %s, %d unsealed rows pending, oldest %.0fs)\n",
		rep.Sealing, rep.Pending, rep.OldestPendingSeconds)
	fmt.Printf("read buckets: intact (read mode %s, %d finished hours awaiting close)\n",
		rep.Reads, rep.PendingHours)

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
		return fmt.Errorf("usage: sunder keys rotate|rekey|retire|list | keys shamir-init -n 5 -k 3 | keys shamir-recover | keys shamir-rotate")
	}
	if err := st.Migrate(ctx); err != nil {
		return err
	}
	ring := &service.KeyRing{Pool: st.Pool, RetireGrace: cfg.KeyRetireGrace}
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
		force := fs.Bool("force", false, "retire a pii-kek version still referenced by sealed data (that data becomes UNREADABLE)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *kind == "" || *version == "" {
			return fmt.Errorf("-kind and -version are required")
		}
		if err := ring.RetireWithForce(ctx, *kind, *version, *force); err != nil {
			return err
		}
		fmt.Printf("retired %s/%s\n", *kind, *version)
		// The propagation bound, as `rotate` already prints. Invalidate() is
		// process-local, so a RUNNING replica keeps accepting the retired
		// version until its ring cache expires - and for a retirement (an
		// incident response, not routine rotation latency) that window is
		// the thing the operator needs to know (DOCS-12).
		fmt.Println("running servers stop accepting this version within 30s (keyring cache TTL) - restart the fleet to cut it off immediately")
		fmt.Println("(for hmac kinds: rows still stored under this version stop matching; re-key first)")
		return nil
	case "rekey":
		fs := flag.NewFlagSet("keys rekey", flag.ContinueOnError)
		reenc := fs.Bool("reencrypt-pii", true, "also re-encrypt attribute blobs under the newest pii-kek")
		// The flag overrides the configured default, so an operator can slow
		// a sweep down on a loaded database without redeploying.
		batch := fs.Int("batch", cfg.RekeyBatch, "persons per page, and per token INSERT (SUNDER_REKEY_BATCH)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		eng := api.OpenEngine(cfg)
		ring := &service.KeyRing{Pool: st.Pool, RetireGrace: cfg.KeyRetireGrace}
		if err := ring.EnsureAll(ctx, eng); err != nil {
			return err
		}
		pii := crypto.NewPIIBox(eng)
		pii.Alg = cfg.PIIAlg
		contacts := &service.Contacts{Pool: st.Pool, Tok: crypto.NewTokenizer(eng), PII: pii, Ring: ring,
			FuzzyName: cfg.SearchFuzzyName, PhoneSuffix: cfg.SearchPhoneSuffix,
			SplitLookupActions: cfg.AuditLookupActions == "split",
			VersionsKeep:       cfg.VersionsKeep,
			// The sweep runs for hours on a large dataset; without this the
			// operator watches a silent terminal and cannot tell a working
			// sweep from a hung one.
			Log: slog.Default()}
		stats, err := contacts.Rekey(ctx, *reenc, *batch)
		if err != nil {
			return err
		}
		if stats.Resumed {
			// Without this line "500 persons" after a resume reads as a sweep
			// that has barely started, when it is actually near the end.
			fmt.Printf("resumed from a previous run's position: %d person(s) were already covered\n",
				stats.PersonsSkipped)
		}
		fmt.Printf("rekey sweep: %d person(s) this run, %d token(s) written, %d blob(s) re-encrypted, %d blob(s) undecryptable\n",
			stats.Persons, stats.TokensInserted, stats.BlobsReenc, stats.Skipped)
		if stats.Resumed {
			fmt.Printf("  %d person(s) covered in total across runs\n", stats.PersonsSkipped+stats.Persons)
		}
		if stats.Raced > 0 {
			// NOT a warning to be ignored: these rows were written by a
			// concurrent request between this sweep's read and its write, so
			// they are still on the old key/algorithm (TOKENS-LOOKUP-2).
			fmt.Printf("  %d blob(s) were modified concurrently and NOT converted - re-run the sweep to pick them up\n",
				stats.Raced)
		}
		fmt.Printf("  vaults re-wrapped: %d value token(s), %d record key(s), %d version blob(s), %d portal outbox row(s)\n",
			stats.ValueTokensRewrapped, stats.RecordKeysRewrapped, stats.VersionsRewrapped, stats.OutboxRewrapped)
		// Not a promise that retirement is safe - `keys retire` decides that
		// for itself by refusing while any store still references the
		// version (GAP-1).
		fmt.Println("retire an old version with: sunder keys retire -kind <kind> -version <v>")
		return nil
	case "shamir-init":
		fs := flag.NewFlagSet("keys shamir-init", flag.ContinueOnError)
		n := fs.Int("n", 5, "total number of shares to issue")
		k := fs.Int("k", 3, "shares required to recover")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		ks, err := fileKeystore(cfg)
		if err != nil {
			return err
		}
		return shamirInit(ks, *n, *k, os.Stdout)

	case "shamir-recover":
		fs := flag.NewFlagSet("keys shamir-recover", flag.ContinueOnError)
		sharesFlag := fs.String("shares", "", "comma-separated hex shares (omit to read interactively, one per line)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		ks, err := fileKeystore(cfg)
		if err != nil {
			return err
		}
		shares, err := readShares(*sharesFlag)
		if err != nil {
			return err
		}
		return shamirRecover(ks, shares, os.Stdout)

	case "shamir-rotate":
		fs := flag.NewFlagSet("keys shamir-rotate", flag.ContinueOnError)
		sharesFlag := fs.String("shares", "", "comma-separated hex shares (omit to read interactively)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		ks, err := fileKeystore(cfg)
		if err != nil {
			return err
		}
		shares, err := readShares(*sharesFlag)
		if err != nil {
			return err
		}
		return shamirRotate(ks, shares, os.Stdout)

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

// fileKeystore returns the file-driver keystore for F9 recovery, refusing
// the Vault driver (which delegates recovery to Vault's own unseal).
var randRead = cryptorand.Read

func fileKeystore(cfg config.Config) (*crypto.FileKeystore, error) {
	if cfg.Keystore != "" && cfg.Keystore != "file" {
		return nil, fmt.Errorf("shamir recovery is for the file keystore only (SUNDER_KEYSTORE=%q delegates recovery to its own mechanism)", cfg.Keystore)
	}
	return &crypto.FileKeystore{Dir: cfg.KeystorePath}, nil
}

// readShares parses comma-separated hex shares from the flag, or reads them
// interactively (one hex share per line, blank line to end) when empty.
func readShares(flagVal string) ([][]byte, error) {
	var raw []string
	if flagVal != "" {
		raw = strings.Split(flagVal, ",")
	} else {
		fmt.Fprintln(os.Stderr, "Enter recovery shares, one hex share per line, blank line to finish:")
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				break
			}
			raw = append(raw, line)
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	var out [][]byte
	for _, r := range raw {
		b, err := hex.DecodeString(strings.TrimSpace(r))
		if err != nil {
			return nil, fmt.Errorf("share %q is not valid hex: %w", r, err)
		}
		out = append(out, b)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no shares provided")
	}
	return out, nil
}

// clientCmd implements `sunder client create ...`. The credential is printed
// exactly once; only its hash is stored.
func clientCmd(ctx context.Context, st *store.Store, args []string) error {
	if len(args) >= 1 && args[0] == "rotate-secret" {
		return clientRotateCmd(ctx, st, args[1:])
	}
	if len(args) >= 1 && args[0] == "grant" {
		return clientGrantCmd(ctx, st, args[1:])
	}
	if len(args) < 1 || args[0] != "create" {
		return fmt.Errorf("usage: sunder client create -id <id> -name <name> -scope <scope> [-actions a,b] [-purposes p,q] [-rate n] [-ttl 90d] | client rotate-secret -id <id> [-ttl 90d]")
	}
	fs := flag.NewFlagSet("client create", flag.ContinueOnError)
	id := fs.String("id", "", "client id (required)")
	name := fs.String("name", "", "display name (required)")
	scope := fs.String("scope", "", "CID scope this client belongs to (required)")
	actions := fs.String("actions", "", "comma-separated allowed actions (implies -role custom)")
	role := fs.String("role", "", "preset: readonly | service | admin (replaces -actions)")
	attributes := fs.String("attributes", "", "comma-separated attribute allowlist; empty = all attributes (F3)")
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
	known := knownActions()
	acts := splitCSV(*actions)
	for _, a := range acts {
		if !known[a] {
			return fmt.Errorf("unknown action %q", a)
		}
	}
	// A role preset and explicit actions are mutually exclusive: mixing
	// them would make the role label a lie about what the client can do.
	if *role != "" {
		if len(acts) > 0 {
			return fmt.Errorf("-role and -actions are mutually exclusive: a preset defines the action set")
		}
		if auth.RoleActions(*role) == nil {
			return fmt.Errorf("unknown role %q (readonly | service | admin)", *role)
		}
	}
	var allowedAttrs []string
	if *attributes != "" {
		allowedAttrs = splitCSV(*attributes)
		if len(allowedAttrs) == 0 {
			return fmt.Errorf("-attributes given but empty after parsing (a stray comma?); omit it to allow all")
		}
	}
	if err := st.Migrate(ctx); err != nil {
		return err
	}
	// Creating a credential with an arbitrary action set is the mutation
	// that decides who may read personal data; the chain has to carry it
	// (OPS-CLI-CONFIG-3). The client row and its record commit together.
	var cred string
	expires := ""
	if expiresAt != nil {
		expires = expiresAt.UTC().Format(time.RFC3339)
	}
	if err := auditOperator(ctx, st.Pool, "client.create", map[string]any{
		"client_id": *id, "scope": *scope, "role": *role,
		"allowed_actions": acts, "allowed_purposes": splitCSV(*purposes),
		"allowed_attributes": allowedAttrs, "rate_limit": *rate, "expires_at": expires,
	}, func(tx pgx.Tx) error {
		var cerr error
		cred, cerr = auth.CreateTx(ctx, tx, auth.Client{
			ID: *id, Name: *name, Scope: *scope,
			AllowedActions:      acts,
			Role:                *role,
			AllowedAttributes:   allowedAttrs,
			AllowedPurposes:     splitCSV(*purposes),
			RateLimit:           *rate,
			CredentialExpiresAt: expiresAt,
		})
		return cerr
	}); err != nil {
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
	// The bootstrap admin holds admin.unlock, and a NON-EXPIRING credential
	// holding admin.unlock is the exact state every other grant path refuses
	// by name - it makes the bulk-read second factor a permanent
	// self-service dump and removes any forced rotation of the omnipotent
	// credential (AUTHZ-2). A concrete default is what makes the promise
	// true on the default provisioning path; an operator who explicitly
	// passes an empty -ttl now gets a loud refusal rather than that state.
	ttl := fs.String("ttl", getenvDefault("SUNDER_BOOTSTRAP_TTL", "90d"),
		"credential lifetime (e.g. 90d); empty = non-expiring, which admin.unlock forbids")
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
	// `bootstrap` is the explicit "create this vault" act, so it is the one
	// command allowed to mint. The mint itself still logs a WARN naming the
	// key, which is what the DR runbook's restore step 3 tells the operator
	// to watch for (OPS-CLI-CONFIG-1).
	if err := ring.EnsureAllAllowingMint(ctx, eng); err != nil {
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
			auth.ActDSRAccess, auth.ActDSRErase, auth.ActDSRExport, auth.ActClaimsExternal,
			auth.ActAdminUnlock, auth.ActTokensCreate, auth.ActTokensRead,
			auth.ActFilesWrite, auth.ActFilesRead},
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

	// Liveness. The sealer deliberately logs and CONTINUES on error, so a
	// process that can no longer reach the database (or that lost UPDATE on
	// `audit`) stays Running and Ready forever while the unsealed window
	// grows without bound - the one component whose absence silently
	// disables tamper evidence shipped with no probe at all
	// (OPS-CLI-CONFIG-8). /healthz answers 200 only while the last
	// SUCCESSFUL pass is recent, so a wedged sealer is restarted.
	//
	// An HTTP endpoint rather than a heartbeat file: the runtime image is
	// distroless, so an exec probe has no shell to run.
	var lastOK atomic.Int64
	lastOK.Store(time.Now().UnixNano())
	staleAfter := cfg.AuditSealInterval * 20
	if staleAfter < time.Minute {
		staleAfter = time.Minute
	}
	if addr := getenvDefault("SUNDER_SEALER_HEALTH_ADDR", ""); addr != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
			age := time.Since(time.Unix(0, lastOK.Load()))
			if age > staleAfter {
				http.Error(w, fmt.Sprintf("no successful seal pass for %s", age.Truncate(time.Second)),
					http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write([]byte("ok\n"))
		})
		hs := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		go func() {
			if err := hs.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				fmt.Fprintln(os.Stderr, "sealer health listener:", err)
			}
		}()
		defer func() {
			shCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = hs.Shutdown(shCtx)
		}()
		fmt.Printf("sealer: health endpoint on %s (stale after %s)\n", addr, staleAfter)
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
			lastOK.Store(time.Now().UnixNano())
		}
	}
}
