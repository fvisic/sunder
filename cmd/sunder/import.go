package main

// `sunder import` is the supported bulk ingest path (P4.4). It exists
// because there deliberately is NO bulk HTTP API: the threat model's
// bulk-deny principle keeps mass operations off API credentials, and the
// per-request cost of the API path makes a large migration a multi-hour
// job that COPY finishes in minutes (28k rows/s measured at the 1M mark of
// the 26.8M scale test). This command needs database and keystore access -
// operator level, not API level - and computes the same keyed-HMAC search
// tokens and AEAD blobs through the server's own engine, so an imported
// contact is indistinguishable from a registered one.
//
// Input is JSON Lines: {"email":"..","phone":"..","name":"..","attributes":{..}}
// per line, at least one of email/phone required. Rows whose email or
// phone already exists are SKIPPED (an email or phone identifies exactly
// one person - the dedup invariant), which also makes re-running the same
// file after an interruption safe: import is idempotent per identifier.

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/fvisic/sunder/internal/api"
	"github.com/fvisic/sunder/internal/audit"
	"github.com/fvisic/sunder/internal/config"
	"github.com/fvisic/sunder/internal/crypto"
	"github.com/fvisic/sunder/internal/service"
	"github.com/fvisic/sunder/internal/store"
)

// Mirrors service.reservedAttr: identifier slots are written by the
// importer itself, never by caller-supplied attributes.
var importReservedAttr = regexp.MustCompile(`^(email|phone|name)$|^(email|phone)_[0-9]+$`)

type importLine struct {
	Email      string            `json:"email"`
	Phone      string            `json:"phone"`
	Name       string            `json:"name"`
	Attributes map[string]string `json:"attributes"`
}

type importRow struct {
	pid, cid                    string
	emailTok, phoneTok, nameTok any // nil when the identifier is absent
	// emailMatch/phoneMatch hold the identifier token under EVERY live key
	// version (newest first), used only for the dedup EXISTS check. Writes
	// use the newest token above; matches must span the rotation window or an
	// import during a rotation fails to see a contact registered under the
	// retiring version and creates a duplicate person (H13).
	emailMatch, phoneMatch []string
	phoneticToks           []string
	suffixTok              any
	blob                   []byte
	keyID, alg             string
}

func importCmd(ctx context.Context, cfg config.Config, st *store.Store, args []string) error {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	file := fs.String("file", "", "JSON Lines file to import ('-' for stdin)")
	scope := fs.String("scope", "", "scope the contacts belong to")
	batch := fs.Int("batch", 5000, "rows per transaction")
	timing := fs.Bool("timing", false, "report wall time split between the crypto/read half and the database half")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *file == "" || *scope == "" {
		return fmt.Errorf("usage: sunder import -file contacts.jsonl -scope <scope> [-batch n]")
	}
	if *batch < 1 {
		return fmt.Errorf("-batch must be positive")
	}
	if err := st.Migrate(ctx); err != nil {
		return err
	}

	var in io.Reader = os.Stdin
	if *file != "-" {
		f, err := os.Open(*file)
		if err != nil {
			return err
		}
		defer f.Close()
		in = f
	}

	// The server's own crypto: same engine, same key ring, same tokenizer.
	eng := api.OpenEngine(cfg)
	ring := &service.KeyRing{Pool: st.Pool}
	if err := ring.EnsureAll(ctx, eng); err != nil {
		return fmt.Errorf("key bootstrap: %w", err)
	}
	emailV, err := ring.Newest(ctx, crypto.KeyHMACEmail)
	if err != nil {
		return err
	}
	phoneV, err := ring.Newest(ctx, crypto.KeyHMACPhone)
	if err != nil {
		return err
	}
	nameV, err := ring.Newest(ctx, crypto.KeyHMACName)
	if err != nil {
		return err
	}
	// All live versions of the dedup identifiers (email, phone): the match
	// check must span the rotation window (H13). Name is not a dedup key.
	emailVers, err := ring.Versions(ctx, crypto.KeyHMACEmail)
	if err != nil {
		return err
	}
	phoneVers, err := ring.Versions(ctx, crypto.KeyHMACPhone)
	if err != nil {
		return err
	}
	kekV, err := ring.Newest(ctx, crypto.KeyPIIKEK)
	if err != nil {
		return err
	}
	tok := crypto.NewTokenizer(eng)
	pii := crypto.NewPIIBox(eng)
	pii.Alg = cfg.PIIAlg

	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20) // generous line limit: attribute maps can be wide

	var (
		lineNo                   int
		rows                     []importRow
		inserted, skipped, dupes int64
		start                    = time.Now()
		// The two halves of the pipeline, timed separately when -timing is
		// set. The import strictly alternates: tokenize and encrypt a batch
		// on one core while the database sits idle, then flush it in one
		// transaction while the CPU sits idle. Which half dominates decides
		// whether pipelining (overlap the halves, ceiling 2x) or fanning the
		// crypto across cores is the lever worth building - guessing wrong
		// builds the wrong thing, which is why this flag exists.
		cryptoTime, dbTime time.Duration
		sinceFlush         = time.Now()
		tm                 = &importTimings{}
	)
	// In-batch identifier dedup, PER IDENTIFIER: two lines sharing an
	// email but differing in phone are still the same person under the
	// dedup invariant, and pair-keyed dedup would let both into the batch
	// only to die on the unique index with an opaque error.
	seenEmail, seenPhone := map[string]bool{}, map[string]bool{}

	flush := func() error {
		if len(rows) == 0 {
			return nil
		}
		cryptoTime += time.Since(sinceFlush)
		dbStart := time.Now()
		ins, skip, err := importBatch(ctx, st, *scope, emailV, phoneV, nameV, rows, tm)
		dbTime += time.Since(dbStart)
		sinceFlush = time.Now()
		if err != nil {
			return err
		}
		inserted += ins
		skipped += skip
		rows = rows[:0]
		seenEmail, seenPhone = map[string]bool{}, map[string]bool{}
		fmt.Printf("  line %d: %d imported, %d skipped as existing, %d in-file duplicates (%.0f rows/s)\n",
			lineNo, inserted, skipped, dupes, float64(inserted+skipped+dupes)/time.Since(start).Seconds())
		return nil
	}

	for sc.Scan() {
		lineNo++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" {
			continue
		}
		var l importLine
		// Fail closed on malformed input with the line number: a silently
		// skipped line in a migration is a lost customer record.
		dec := json.NewDecoder(strings.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&l); err != nil {
			return fmt.Errorf("line %d: %v", lineNo, err)
		}
		if l.Email == "" && l.Phone == "" {
			return fmt.Errorf("line %d: at least one of email or phone is required", lineNo)
		}
		for k := range l.Attributes {
			if importReservedAttr.MatchString(k) {
				return fmt.Errorf("line %d: %q is a reserved attribute name", lineNo, k)
			}
			if strings.ContainsRune(k, '@') {
				return fmt.Errorf("line %d: attribute names must not contain '@' (reserved for external claims)", lineNo)
			}
		}

		attrs := map[string]string{}
		for k, v := range l.Attributes {
			attrs[k] = v
		}
		row := importRow{keyID: kekV, alg: pii.Algorithm()}
		if l.Email != "" {
			norm, err := crypto.NormalizeEmail(l.Email)
			if err != nil {
				return fmt.Errorf("line %d: email: %v", lineNo, err)
			}
			t, err := tok.EmailToken(ctx, emailV, norm)
			if err != nil {
				return err
			}
			row.emailTok, attrs["email"] = t, norm
			for _, ver := range emailVers {
				mt, err := tok.EmailToken(ctx, ver, norm)
				if err != nil {
					return err
				}
				row.emailMatch = append(row.emailMatch, mt)
			}
		}
		if l.Phone != "" {
			norm, err := crypto.NormalizePhone(l.Phone)
			if err != nil {
				return fmt.Errorf("line %d: phone: %v", lineNo, err)
			}
			t, err := tok.PhoneToken(ctx, phoneV, norm)
			if err != nil {
				return err
			}
			row.phoneTok, attrs["phone"] = t, norm
			for _, ver := range phoneVers {
				mt, err := tok.PhoneToken(ctx, ver, norm)
				if err != nil {
					return err
				}
				row.phoneMatch = append(row.phoneMatch, mt)
			}
		}
		if l.Name != "" {
			norm, err := crypto.NormalizeName(l.Name)
			if err != nil {
				return fmt.Errorf("line %d: name: %v", lineNo, err)
			}
			t, err := tok.NameToken(ctx, nameV, norm)
			if err != nil {
				return err
			}
			row.nameTok, attrs["name"] = t, l.Name
			if cfg.SearchFuzzyName {
				for _, code := range crypto.PhoneticNameCodes(norm) {
					pt, err := tok.NamePhoneticToken(ctx, nameV, code)
					if err != nil {
						return err
					}
					row.phoneticToks = append(row.phoneticToks, pt)
				}
			}
		}
		if cfg.SearchPhoneSuffix && row.phoneTok != nil {
			st2, err := tok.PhoneSuffixToken(ctx, phoneV, crypto.PhoneSuffix(attrs["phone"]))
			if err != nil {
				return err
			}
			row.suffixTok = st2
		}

		// In-file duplicates: EITHER identifier repeating within the batch
		// marks the line a duplicate (an email or phone identifies exactly
		// one person), before the unique index would kill the whole batch.
		et, _ := row.emailTok.(string)
		pt, _ := row.phoneTok.(string)
		if (et != "" && seenEmail[et]) || (pt != "" && seenPhone[pt]) {
			dupes++
			continue
		}
		if et != "" {
			seenEmail[et] = true
		}
		if pt != "" {
			seenPhone[pt] = true
		}

		if row.pid, err = newUUIDStr(); err != nil {
			return err
		}
		if row.cid, err = crypto.NewCID(); err != nil {
			return err
		}
		if row.blob, err = pii.Encrypt(ctx, row.cid, kekV, attrs); err != nil {
			return err
		}
		rows = append(rows, row)
		if len(rows) >= *batch {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if err := flush(); err != nil {
		return err
	}
	fmt.Printf("import done: %d imported, %d skipped as existing, %d in-file duplicates, %d lines, %s\n",
		inserted, skipped, dupes, lineNo, time.Since(start).Truncate(time.Millisecond))
	if *timing {
		total := cryptoTime + dbTime
		fmt.Printf("timing: crypto+read %s (%.0f%%), database %s (%.0f%%)\n",
			cryptoTime.Truncate(time.Millisecond), 100*cryptoTime.Seconds()/total.Seconds(),
			dbTime.Truncate(time.Millisecond), 100*dbTime.Seconds()/total.Seconds())
		fmt.Printf("timing: db = copy %s + dedup-match %s + inserts %s + commit %s\n",
			tm.copy_.Truncate(time.Millisecond), tm.match.Truncate(time.Millisecond),
			tm.insert.Truncate(time.Millisecond), tm.commit.Truncate(time.Millisecond))
	}
	// L12: in-file dedup is scope-BLIND (one email = one person, globally),
	// so a single file carrying the SAME identifiers for two scopes collapses
	// them - the second scope silently gets nothing. Import is per-scope by
	// -scope; if you meant to load two scopes, run it once per scope with
	// per-scope files. Say so loudly whenever duplicates were dropped.
	if dupes > 0 {
		fmt.Printf("NOTE: %d rows were dropped as in-file duplicates (same email or phone appearing twice). "+
			"Dedup is scope-blind and this run loaded ONLY scope %q - to load another scope, run import again "+
			"with its own -scope and a file of that scope's records.\n", dupes, *scope)
	}
	return nil
}

// importBatch stages one batch and lands it with conflict-skip semantics:
// rows whose email or phone already identifies a person are dropped from
// the stage, everything else inserts, and the batch is audited as ONE
// chained record. All in one transaction - a crash imports whole batches
// or nothing, and a re-run skips what landed.
// importTimings decomposes where a batch's wall time goes. Always collected
// (four time.Now() calls per batch), printed only under -timing. The
// per-batch progress log gives cumulative rows/s and nothing else; when the
// question is "which phase is the bottleneck", cumulative throughput is
// exactly the number that cannot answer it.
type importTimings struct {
	copy_  time.Duration // temp-table creation + the three CopyFroms + ANALYZE
	match  time.Duration // the dedup DELETE against person_tokens
	insert time.Duration // the INSERTs into persons / person_tokens / cids + audit
	commit time.Duration // tx.Commit - WAL flush lives here
}

func importBatch(ctx context.Context, st *store.Store, scope, emailV, phoneV, nameV string, rows []importRow, tm *importTimings) (inserted, skipped int64, err error) {
	for attempt := 0; ; attempt++ {
		inserted, skipped, err = importBatchTx(ctx, st, scope, emailV, phoneV, nameV, rows, tm)
		if err == nil {
			return inserted, skipped, nil
		}
		// A concurrent writer (another import, or live API registrations)
		// can win the unique-index race after our EXISTS check; on retry
		// the check sees their committed row and skips ours.
		var pgErr *pgconn.PgError
		if attempt == 0 && errors.As(err, &pgErr) && pgErr.Code == "23505" {
			continue
		}
		return 0, 0, err
	}
}

func importBatchTx(ctx context.Context, st *store.Store, scope, emailV, phoneV, nameV string, rows []importRow, tm *importTimings) (int64, int64, error) {
	// stage attributes the time since the previous mark to one phase.
	mark := time.Now()
	stage := func(d *time.Duration) {
		*d += time.Since(mark)
		mark = time.Now()
	}
	tx, err := st.Pool.Begin(ctx)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `
		CREATE TEMP TABLE import_stage (
			pid uuid, cid text, email_tok text, phone_tok text, name_tok text,
			suffix_tok text, blob bytea, key_id text, alg text
		) ON COMMIT DROP`); err != nil {
		return 0, 0, err
	}
	// Phonetic word codes fan out per contact, so they stage in their own
	// table and land via a JOIN on the surviving rows - a contact dropped
	// by the dedup DELETE must not leave tokens behind.
	if _, err := tx.Exec(ctx, `
		CREATE TEMP TABLE import_stage_ph (pid uuid, tok text) ON COMMIT DROP`); err != nil {
		return 0, 0, err
	}
	// Dedup match tokens across every live key version (H13): one row per
	// (person, kind, version-token). The DELETE below joins person_tokens on
	// these, so a contact registered under a retiring version is still seen.
	if _, err := tx.Exec(ctx, `
		CREATE TEMP TABLE import_match (pid uuid, kind text, tok text) ON COMMIT DROP`); err != nil {
		return 0, 0, err
	}
	src := make([][]any, len(rows))
	var phSrc, matchSrc [][]any
	for i, r := range rows {
		src[i] = []any{r.pid, r.cid, r.emailTok, r.phoneTok, r.nameTok, r.suffixTok, r.blob, r.keyID, r.alg}
		for _, pt := range r.phoneticToks {
			phSrc = append(phSrc, []any{r.pid, pt})
		}
		for _, mt := range r.emailMatch {
			matchSrc = append(matchSrc, []any{r.pid, "email", mt})
		}
		for _, mt := range r.phoneMatch {
			matchSrc = append(matchSrc, []any{r.pid, "phone", mt})
		}
	}
	staged, err := tx.CopyFrom(ctx, pgx.Identifier{"import_stage"},
		[]string{"pid", "cid", "email_tok", "phone_tok", "name_tok", "suffix_tok", "blob", "key_id", "alg"},
		pgx.CopyFromRows(src))
	if err != nil {
		return 0, 0, err
	}
	if len(phSrc) > 0 {
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"import_stage_ph"},
			[]string{"pid", "tok"}, pgx.CopyFromRows(phSrc)); err != nil {
			return 0, 0, err
		}
	}
	if len(matchSrc) > 0 {
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"import_match"},
			[]string{"pid", "kind", "tok"}, pgx.CopyFromRows(matchSrc)); err != nil {
			return 0, 0, err
		}
		// Freshly COPYed temp tables have no statistics; without this the
		// planner may nested-loop the dedup DELETE at large batch sizes.
		if _, err := tx.Exec(ctx, `ANALYZE import_match`); err != nil {
			return 0, 0, err
		}
	}
	stage(&tm.copy_)

	// The dedup invariant: an email or phone identifies exactly one person.
	// Existing identifiers mean an existing person - skip, never merge:
	// merging attribute blobs is a per-contact decision for the API, not a
	// bulk tool's. The match spans every live key version via import_match, so
	// a contact whose stored token is under a retiring version (mid-rotation,
	// before the rekey sweep catches up) is still recognised (H13).
	tag, err := tx.Exec(ctx, `
		DELETE FROM import_stage s
		 WHERE EXISTS (
			SELECT 1 FROM import_match m
			  JOIN person_tokens pt ON pt.kind = m.kind AND pt.token = m.tok
			 WHERE m.pid = s.pid)`)
	if err != nil {
		return 0, 0, err
	}
	skipped := tag.RowsAffected()
	stage(&tm.match)

	if _, err := tx.Exec(ctx, `INSERT INTO persons (id) SELECT pid FROM import_stage`); err != nil {
		return 0, 0, err
	}
	// ORDER BY the token, not the person.
	//
	// A token is a keyed HMAC, so its value is uniformly distributed and
	// carries no relationship to the order rows arrive in. Inserting in file
	// order therefore touches a random B-tree page per row, which is exactly
	// what benchmark/README.md names as the reason COPY ingest falls from
	// 28,319 rows/s at 1M to ~2,700 past 25M: "HMAC output is uniformly
	// random and index inserts have no locality".
	//
	// Sorting the batch first makes the inserts arrive in index order, so a
	// page fetched for one row serves its neighbours. The sort itself is
	// free at this scale - the rows are already in a temp table, and the
	// batch is thousands, not millions - and the bigger -batch is, the more
	// locality it buys.
	//
	// Measured on a 10M-contact dataset whose person_tokens (12 GB) fits in
	// shared_buffers (12 GB), 200k rows, same file, same host, nothing else
	// running: file order 310 rows/s, sorted 467 rows/s - 1.51x. Just as
	// telling, file-order throughput varied 310-464 rows/s across three runs
	// (it is at the mercy of cache state) while sorted runs measured 446,
	// 447 and 467. Dropping the non-unique search index on top of this
	// bought only 478 rows/s before a 36.5s rebuild - ORDER BY had already
	// repaired the locality the drop was for.
	for _, ident := range []struct{ kind, col, ver string }{
		{"email", "email_tok", emailV}, {"phone", "phone_tok", phoneV},
		{"name", "name_tok", nameV}, {"phone_suffix", "suffix_tok", phoneV},
	} {
		if _, err := tx.Exec(ctx, fmt.Sprintf(`
			INSERT INTO person_tokens (person_id, kind, token, key_version)
			SELECT pid, '%s', %s, $1 FROM import_stage WHERE %s IS NOT NULL
			 ORDER BY %s`,
			ident.kind, ident.col, ident.col, ident.col), ident.ver); err != nil {
			return 0, 0, err
		}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO person_tokens (person_id, kind, token, key_version)
		SELECT p.pid, 'name_phonetic', p.tok, $1
		  FROM import_stage_ph p JOIN import_stage s ON s.pid = p.pid
		 ORDER BY p.tok
		ON CONFLICT DO NOTHING`, nameV); err != nil {
		return 0, 0, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO cids (cid, person_id, scope, pii_encrypted, pii_key_id, pii_alg)
		SELECT cid, pid, $1, blob, key_id, alg FROM import_stage`, scope); err != nil {
		return 0, 0, err
	}

	inserted := staged - skipped
	// One chained audit record per batch: the import is auditable without
	// producing a row per contact in a log that is never pruned.
	if err := audit.AppendTx(ctx, tx, audit.Entry{
		ClientID: "_import", Action: "contacts.import",
		Detail: map[string]any{"scope": scope, "inserted": inserted, "skipped": skipped},
	}); err != nil {
		return 0, 0, err
	}
	stage(&tm.insert)
	err = tx.Commit(ctx)
	stage(&tm.commit)
	return inserted, skipped, err
}

// newUUIDStr mirrors the server's own stdlib-only UUIDv4 generator.
func newUUIDStr() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
