package service_test

// The erasure-invariant guard. Four of the six severest findings of the
// Phase 3 review were "a new table survives Article 17": each new feature
// added person-linked rows and nothing forced its author to decide what
// erasure does to them. This test closes that class structurally:
//
//  1. it DISCOVERS every table carrying a person-linked column
//     (person_id / parent_person / child_person / cid) from
//     information_schema - so a future migration cannot add one silently;
//  2. every discovered table MUST appear in the decision map below, either
//     ERASED (no rows referencing the person survive erasePerson) or KEPT
//     with a written reason and its own predicate;
//  3. an unknown table fails the test with instructions, forcing the next
//     feature to state its erasure story before it can merge.
//
// The per-table deletes also have dedicated regression tests (TestS1-S5,
// TestFullDataErasure, ...); this sweep is the completeness gate, not a
// replacement for them.

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/service"
	"github.com/fvisic/sunder/internal/storage"
)

// linkedCol is one person-linked column: its table, name, and whether it
// references persons (match by person id) or cids (match by pseudonym).
type linkedCol struct{ table, col, target string }

// erasureDecision is one table's story under Article 17.
type erasureDecision struct {
	// erased: the generic check applies - zero rows referencing the erased
	// person (by any of the table's person-linked columns) may survive.
	erased bool
	// keptWhy documents WHY rows may survive; check must then prove the
	// surviving rows are in their post-erasure state.
	keptWhy string
	check   func(ctx context.Context, t *testing.T, q *pgxpool.Pool, pid string, cids []string)
}

// notPersonal is every base table that holds NO data about a data subject,
// each with the reason. Adding here is an explicit decision, reviewed like
// code - the whole point of the gate is that "this one is fine" has to be
// written down and defended rather than assumed.
var notPersonal = map[string]string{
	"schema_migrations":  "applied migration versions",
	"keys":               "key metadata (kind, version, status) - no subject reference",
	"clients":            "API credentials: the CLIENT organisation, never a data subject",
	"webhooks":           "per-scope endpoint configuration",
	"retention_policies": "per-scope TTL configuration",
	"trusted_issuers":    "federation issuer public keys and their revocation state - the ISSUING organisation, never a data subject",
	"audit":              "the append-only chain: NEVER pruned, it is the tamper evidence. Its cid column is a tombstoned pseudonym, which is the accountability record erasure is proven by",
	"audit_anchor":       "RFC 3161 timestamps over chain heads - a digest, no subject data",
	"audit_read_buckets": "hourly read aggregates keyed by the (tombstoned) pseudonym; append-only by trigger, like `audit`, for the same reason",
	"unlock_tokens":      "single-use operator intent declarations, keyed by client and purpose",
	// A single row holding "the sweep has reached this uuid", not a fact
	// about the person. The uuid itself is NOT disclosed by keeping it:
	// erasure tombstones a person rather than deleting the row, so
	// persons.id survives erasure permanently and by design - client-side
	// CID references must not break. The row is also transient (deleted the
	// moment a sweep finishes) and there is at most one. Deleting it during
	// erasure would slow every erasure to protect nothing.
	"rekey_progress":        "one row recording how far `keys rekey` has paginated; the person id in it is a POSITION, and persons.id already survives erasure as a tombstone",
	"portal_email_throttle": "a KEYED HMAC of an address plus a send counter - derived from a person's identifier, so it IS personal data, but it is not reachable from a person id or a cid and it self-prunes after 1 day (PrunePortal). Erasure cannot target it; the 1-day window is the argument that it does not need to",
}

func TestErasureInvariantSweep(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	pool := e.admin.Pool

	decisions := map[string]erasureDecision{
		"persons": {keptWhy: "tombstone by design: client-held CID references must keep resolving to 404, not to a fresh person",
			check: func(ctx context.Context, t *testing.T, q *pgxpool.Pool, pid string, _ []string) {
				var n int64
				mustScan(t, q.QueryRow(ctx, `SELECT count(*) FROM persons WHERE id=$1 AND erased_at IS NULL`, pid), &n)
				if n != 0 {
					t.Error("persons: the erased person must carry erased_at")
				}
			}},
		"cids": {keptWhy: "tombstone by design: the pseudonym row survives with the blob NULLed so references never break",
			check: func(ctx context.Context, t *testing.T, q *pgxpool.Pool, pid string, _ []string) {
				var n int64
				mustScan(t, q.QueryRow(ctx, `SELECT count(*) FROM cids WHERE person_id=$1 AND pii_encrypted IS NOT NULL`, pid), &n)
				if n != 0 {
					t.Error("cids: every blob of the erased person must be NULL")
				}
			}},
		"erasure_events": {keptWhy: "the erasure record itself: per-scope delivery queue and proof the erasure happened"},
		"erasures":       {keptWhy: "the erasure request record (id, who, when): proof the erasure was performed, minted BY erasePerson itself"},
		"erasure_cascade": {
			keptWhy: "the cascade WORK PLAN, minted by erasePerson itself in the same transaction: it is what makes an interrupted cascade describable and resumable after the parent's own erasure has deleted person_links (GDPR-ERASURE-4). Same accountability class as erasures/erasure_events - a pseudonym plus a status, no attribute data. Deleting it would recreate the defect it exists to close.",
			check: func(ctx context.Context, t *testing.T, q *pgxpool.Pool, pid string, cids []string) {
				// Whatever survives must be marked done: a row still PENDING
				// after its child was erased would send a resume at an
				// already-finished person forever.
				var stuck int
				if err := q.QueryRow(ctx,
					`SELECT count(*) FROM erasure_cascade WHERE child_person=$1 AND status<>'DONE'`,
					pid).Scan(&stuck); err != nil {
					t.Fatal(err)
				}
				if stuck != 0 {
					t.Errorf("erasure_cascade: %d row(s) for an erased child are still PENDING", stuck)
				}
			}},
		"person_tokens":      {erased: true},
		"cid_blob_versions":  {erased: true},
		"value_tokens":       {erased: true}, // cid-bound rows; NULL-cid rows are unattributed by design
		"shared_records":     {erased: true},
		"person_links":       {erased: true},
		"portal_sessions":    {erased: true},
		"portal_tokens":      {erased: true},
		"portal_outbox":      {erased: true},
		"external_envelopes": {erased: true},
		"person_record_keys": {erased: true},
		"consents":           {erased: true}, // state dies; the immutable consent.set audit trail is the accountability record
		"oti": {keptWhy: "rows are REVOKED, not deleted (anti-replay until expiry), and pruned by retention after 30 days",
			check: func(ctx context.Context, t *testing.T, q *pgxpool.Pool, _ string, cids []string) {
				var n int64
				mustScan(t, q.QueryRow(ctx, `SELECT count(*) FROM oti WHERE status='VALID' AND cid = ANY($1)`, cids), &n)
				if n != 0 {
					t.Error("oti: no VALID token may survive the person's erasure")
				}
			}},
		"files": {keptWhy: "crypto-shredded at erasure (record key deleted) and marked for GC; RunFileGC removes rows and objects without a storage round trip on the erasure path",
			check: func(ctx context.Context, t *testing.T, q *pgxpool.Pool, _ string, cids []string) {
				var n int64
				mustScan(t, q.QueryRow(ctx, `SELECT count(*) FROM files WHERE cid = ANY($1) AND gc_at IS NULL`, cids), &n)
				if n != 0 {
					t.Error("files: every file of the erased person must be marked gc_at")
				}
			}},
		"audit":              {keptWhy: "the immutable hash chain IS the tamper evidence; rows are pseudonymous (cid) and never pruned by design"},
		"audit_read_buckets": {keptWhy: "hour-bucketed read accounting sealed into the chain; pseudonymous and immutable like the chain itself"},
	}

	// --- populate one person across the features -------------------------------
	client := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions: []string{auth.ActContactsRegister, auth.ActConsentManage, auth.ActDSRErase,
			auth.ActTokensCreate, auth.ActSharesCreate, auth.ActAttributesRead, auth.ActFilesWrite},
		AllowedPurposes: []string{"support"}}
	cid, err := e.svc.Register(ctx, client, service.RegisterInput{
		Email: "sweep@example.com", Attributes: map[string]string{"iban": "HR12"}})
	if err != nil {
		t.Fatal(err)
	}
	var pid string
	mustScan(t, pool.QueryRow(ctx, `SELECT person_id FROM cids WHERE cid=$1`, cid), &pid)

	if err := e.gdpr.SetConsent(ctx, client, cid, "support", true); err != nil {
		t.Fatal(err)
	}
	vt := &service.ValueTokens{Pool: pool, Eng: e.svc.PII.Engine(), Ring: e.svc.Ring, Tok: e.svc.Tok}
	if _, err := vt.Tokenize(ctx, client, service.TokenizeInput{Value: "HR99", CID: cid}); err != nil {
		t.Fatal(err)
	}
	sh := &service.Shares{Pool: pool, Contacts: e.svc}
	if _, _, err := sh.Create(ctx, client, service.ShareInput{
		CID: cid, Fields: []string{"iban"}, PartnerLabel: "p", Purpose: "support", TTLSeconds: 3600}); err != nil {
		t.Fatal(err)
	}
	drv, err := storage.Open(storage.Config{Kind: "local", Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	files := &service.Files{Pool: pool, Eng: e.svc.PII.Engine(), Ring: e.svc.Ring,
		Store: drv, Contacts: e.svc, MaxBytes: 1 << 20}
	if _, err := files.Upload(ctx, client, cid, "doc.txt", "text/plain", strings.NewReader("x")); err != nil {
		t.Fatal(err)
	}
	// Rows the services do not mint in this flow: seed directly.
	seed := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO cid_blob_versions (cid, version_no, blob, key_id, alg, written_by) VALUES ($1,1,'\x00'::bytea,'v1','aes256gcm','t')`, []any{cid}},
		{`INSERT INTO oti (jti, cid, purpose, audience, expires_at) VALUES (gen_random_uuid(), $1, 'support', 'erp', now() + interval '5 minutes')`, []any{cid}},
		// Portal and envelope rows are not minted by this flow's services -
		// seed them directly so their erased-checks are NOT vacuous (S2 was
		// exactly a cleanup that ran and deleted nothing).
		{`INSERT INTO portal_sessions (session_hash, person_id, expires_at) VALUES ('\x01'::bytea, $1, now() + interval '1 hour')`, []any{"PID"}},
		{`INSERT INTO portal_tokens (token_hash, person_id, kind, expires_at) VALUES ('\x02'::bytea, $1, 'login', now() + interval '1 hour')`, []any{"PID"}},
		{`INSERT INTO portal_outbox (kind, payload, key_id, alg, expires_at, person_id) VALUES ('login', '\x00'::bytea, 'v1', 'aes256gcm', now() + interval '1 hour', $1)`, []any{"PID"}},
		{`INSERT INTO external_envelopes (jti, issuer_id, expires_at, cid) VALUES ('sweep-jti-0001', 'sweep-issuer', now() + interval '1 hour', $1)`, []any{cid}},
	}
	// A link needs a second person.
	cid2, err := e.svc.Register(ctx, client, service.RegisterInput{Email: "sweep-child@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	var pid2 string
	mustScan(t, pool.QueryRow(ctx, `SELECT person_id FROM cids WHERE cid=$1`, cid2), &pid2)
	seed = append(seed, struct {
		sql  string
		args []any
	}{
		`INSERT INTO person_links (parent_person, child_person, scope, link_type, created_by) VALUES ($1,$2,'crm','guardian','t')`, []any{pid, pid2}})
	for _, s := range seed {
		args := s.args
		for i := range args {
			if args[i] == "PID" {
				args[i] = pid
			}
		}
		if _, err := pool.Exec(ctx, s.sql, args...); err != nil {
			t.Fatalf("seed %q: %v", s.sql[:40], err)
		}
	}

	// Non-vacuity: the tables this flow populated must actually hold rows,
	// or the post-erasure zero-checks prove nothing.
	for _, tb := range []string{"person_tokens", "consents", "value_tokens", "shared_records",
		"cid_blob_versions", "person_links", "files", "person_record_keys", "oti",
		"portal_sessions", "portal_tokens", "portal_outbox", "external_envelopes"} {
		if n := countPersonRows(ctx, t, pool, tb, pid, []string{cid}); n == 0 {
			t.Fatalf("setup: expected rows in %s before erasure", tb)
		}
	}

	// --- erase ------------------------------------------------------------------
	if _, _, err := e.gdpr.Erase(ctx, client, cid); err != nil {
		t.Fatal(err)
	}
	var cids []string
	rows, err := pool.Query(ctx, `SELECT cid FROM cids WHERE person_id=$1`, pid)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			t.Fatal(err)
		}
		cids = append(cids, c)
	}
	rows.Close()

	// --- discover and judge every person-linked table ----------------------------
	// Two discovery modes, unioned: by COLUMN NAME (catches conventionally
	// named columns even without a foreign key) and by FOREIGN KEY into
	// cids/persons (catches any column name - a future subject_cid cannot
	// hide behind naming). A table linked only transitively (through another
	// person-linked table) is still invisible; its parent's decision must
	// account for it.
	var discoveredCols []linkedCol
	drows, err := pool.Query(ctx, `
		SELECT x.table_name, x.column_name, x.target FROM (
			SELECT c.table_name, c.column_name,
			       CASE WHEN c.column_name = 'cid' THEN 'cids' ELSE 'persons' END AS target
			  FROM information_schema.columns c
			  JOIN information_schema.tables t
			    ON t.table_schema = c.table_schema AND t.table_name = c.table_name
			 WHERE c.table_schema = 'public' AND t.table_type = 'BASE TABLE'
			   AND c.column_name IN ('person_id','parent_person','child_person','cid')
			UNION
			SELECT tc.table_name, kcu.column_name, ccu.table_name
			  FROM information_schema.table_constraints tc
			  JOIN information_schema.key_column_usage kcu
			    ON kcu.constraint_name = tc.constraint_name AND kcu.table_schema = tc.table_schema
			  JOIN information_schema.constraint_column_usage ccu
			    ON ccu.constraint_name = tc.constraint_name AND ccu.table_schema = tc.table_schema
			 WHERE tc.constraint_type = 'FOREIGN KEY' AND tc.table_schema = 'public'
			   AND ccu.table_name IN ('cids','persons')
		) x ORDER BY x.table_name, x.column_name`)
	if err != nil {
		t.Fatal(err)
	}
	for drows.Next() {
		var l linkedCol
		if err := drows.Scan(&l.table, &l.col, &l.target); err != nil {
			t.Fatal(err)
		}
		discoveredCols = append(discoveredCols, l)
	}
	drows.Close()
	type linked struct {
		table string
		cols  []linkedCol
	}
	byTable := map[string][]linkedCol{}
	for _, l := range discoveredCols {
		byTable[l.table] = append(byTable[l.table], l)
	}
	var discovered []linked
	for tb, cols := range byTable {
		discovered = append(discovered, linked{table: tb, cols: cols})
	}
	// persons is person-linked through its PK `id`, which neither filter can
	// see - include it by hand so its tombstone predicate runs.
	discovered = append(discovered, linked{table: "persons", cols: []linkedCol{{table: "persons", col: "id", target: "persons"}}})
	if len(discovered) < 15 {
		t.Fatalf("discovery looks broken: only %d person-linked tables found", len(discovered))
	}

	for _, l := range discovered {
		d, known := decisions[l.table]
		if !known {
			t.Errorf("table %q carries person-linked columns %v but has NO erasure decision: "+
				"either make erasePerson clean it (and mark it erased here) or add it to the "+
				"decision map with a written reason and a post-erasure predicate", l.table, l.cols)
			continue
		}
		if d.erased {
			if n := countLinkedRows(ctx, t, pool, l.cols, pid, cids); n != 0 {
				t.Errorf("table %q is declared erased but %d rows referencing the erased person survive", l.table, n)
			}
		} else if d.check != nil {
			d.check(ctx, t, pool, pid, cids)
		}
	}
	// EVERY base table, not only the ones a column name or a foreign key
	// betrays. Discovery by `person_id`/`cid`/FK cannot see a table keyed by
	// a DERIVED value - portal_email_throttle stores a keyed HMAC of the
	// person's e-mail address and is a live counterexample already in the
	// schema (TESTS-13). A table with no written decision at all is the
	// failure the sweep exists to prevent, so the gate is over the whole
	// schema and `notPersonal` is an explicit, reviewed category.
	trows, err := pool.Query(ctx, `
		SELECT table_name FROM information_schema.tables
		 WHERE table_schema='public' AND table_type='BASE TABLE'
		 ORDER BY table_name`)
	if err != nil {
		t.Fatal(err)
	}
	var allTables []string
	for trows.Next() {
		var tb string
		if err := trows.Scan(&tb); err != nil {
			t.Fatal(err)
		}
		allTables = append(allTables, tb)
	}
	trows.Close()
	if len(allTables) < 25 {
		t.Fatalf("schema discovery looks broken: only %d base tables", len(allTables))
	}
	for _, tb := range allTables {
		if _, known := decisions[tb]; known {
			continue
		}
		if why, ok := notPersonal[tb]; ok {
			if why == "" {
				t.Errorf("table %q is listed as not personal with no reason", tb)
			}
			continue
		}
		t.Errorf("table %q has NO erasure decision and is not listed as non-personal.\n"+
			"Every base table needs one of the two: an entry in `decisions` (erased, or kept with a "+
			"written reason and a post-erasure predicate), or an entry in `notPersonal` with a reason. "+
			"Column-name and foreign-key discovery cannot see a table keyed by a DERIVED value - a keyed "+
			"HMAC of an identifier is still that person's data (TESTS-13).", tb)
	}

	// The map must not rot either: every decision must match a live table.
	for name := range decisions {
		found := false
		for _, l := range discovered {
			if l.table == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("decision map entry %q matches no existing table - remove or rename it", name)
		}
	}
}

// countPersonRows counts rows in table referencing the person by the columns
// that table actually has (used for the pre-erasure non-vacuity check).
func countPersonRows(ctx context.Context, t *testing.T, pool *pgxpool.Pool, table, pid string, cids []string) int64 {
	cols := map[string][]linkedCol{
		"person_tokens":      {{col: "person_id", target: "persons"}},
		"consents":           {{col: "cid", target: "cids"}},
		"value_tokens":       {{col: "cid", target: "cids"}},
		"shared_records":     {{col: "cid", target: "cids"}},
		"cid_blob_versions":  {{col: "cid", target: "cids"}},
		"person_links":       {{col: "parent_person", target: "persons"}, {col: "child_person", target: "persons"}},
		"files":              {{col: "cid", target: "cids"}},
		"person_record_keys": {{col: "person_id", target: "persons"}},
		"oti":                {{col: "cid", target: "cids"}},
		"portal_sessions":    {{col: "person_id", target: "persons"}},
		"portal_tokens":      {{col: "person_id", target: "persons"}},
		"portal_outbox":      {{col: "person_id", target: "persons"}},
		"external_envelopes": {{col: "cid", target: "cids"}},
	}[table]
	for i := range cols {
		cols[i].table = table
	}
	return countLinkedRows(ctx, t, pool, cols, pid, cids)
}

// countLinkedRows counts rows referencing the person: a column targeting
// cids matches the person's pseudonyms, one targeting persons matches the id.
func countLinkedRows(ctx context.Context, t *testing.T, pool *pgxpool.Pool, cols []linkedCol, pid string, cids []string) int64 {
	t.Helper()
	var total int64
	for _, lc := range cols {
		var n int64
		if lc.target == "cids" {
			q := fmt.Sprintf(`SELECT count(*) FROM %s WHERE %s = ANY($1)`, lc.table, lc.col)
			mustScan(t, pool.QueryRow(ctx, q, cids), &n)
		} else {
			q := fmt.Sprintf(`SELECT count(*) FROM %s WHERE %s = $1`, lc.table, lc.col)
			mustScan(t, pool.QueryRow(ctx, q, pid), &n)
		}
		total += n
	}
	return total
}

func mustScan(t *testing.T, row interface{ Scan(...any) error }, dst ...any) {
	t.Helper()
	if err := row.Scan(dst...); err != nil {
		t.Fatal(err)
	}
}
