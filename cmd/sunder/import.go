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
	blob                        []byte
	keyID, alg                  string
}

func importCmd(ctx context.Context, cfg config.Config, st *store.Store, args []string) error {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	file := fs.String("file", "", "JSON Lines file to import ('-' for stdin)")
	scope := fs.String("scope", "", "scope the contacts belong to")
	batch := fs.Int("batch", 5000, "rows per transaction")
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
		seenBatch                map[string]bool // in-batch identifier dedup
		start                    = time.Now()
	)
	seenBatch = map[string]bool{}

	flush := func() error {
		if len(rows) == 0 {
			return nil
		}
		ins, skip, err := importBatch(ctx, st, *scope, emailV, phoneV, nameV, rows)
		if err != nil {
			return err
		}
		inserted += ins
		skipped += skip
		rows = rows[:0]
		seenBatch = map[string]bool{}
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
		}

		// In-file duplicates (the same identifier twice in one batch would
		// break the staging inserts before the DB dedup can see it).
		dupKey := fmt.Sprint(row.emailTok) + "|" + fmt.Sprint(row.phoneTok)
		if seenBatch[dupKey] {
			dupes++
			continue
		}
		seenBatch[dupKey] = true

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
	return nil
}

// importBatch stages one batch and lands it with conflict-skip semantics:
// rows whose email or phone already identifies a person are dropped from
// the stage, everything else inserts, and the batch is audited as ONE
// chained record. All in one transaction - a crash imports whole batches
// or nothing, and a re-run skips what landed.
func importBatch(ctx context.Context, st *store.Store, scope, emailV, phoneV, nameV string, rows []importRow) (inserted, skipped int64, err error) {
	for attempt := 0; ; attempt++ {
		inserted, skipped, err = importBatchTx(ctx, st, scope, emailV, phoneV, nameV, rows)
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

func importBatchTx(ctx context.Context, st *store.Store, scope, emailV, phoneV, nameV string, rows []importRow) (int64, int64, error) {
	tx, err := st.Pool.Begin(ctx)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `
		CREATE TEMP TABLE import_stage (
			pid uuid, cid text, email_tok text, phone_tok text, name_tok text,
			blob bytea, key_id text, alg text
		) ON COMMIT DROP`); err != nil {
		return 0, 0, err
	}
	src := make([][]any, len(rows))
	for i, r := range rows {
		src[i] = []any{r.pid, r.cid, r.emailTok, r.phoneTok, r.nameTok, r.blob, r.keyID, r.alg}
	}
	staged, err := tx.CopyFrom(ctx, pgx.Identifier{"import_stage"},
		[]string{"pid", "cid", "email_tok", "phone_tok", "name_tok", "blob", "key_id", "alg"},
		pgx.CopyFromRows(src))
	if err != nil {
		return 0, 0, err
	}

	// The dedup invariant: an email or phone identifies exactly one person.
	// Existing identifiers mean an existing person - skip, never merge:
	// merging attribute blobs is a per-contact decision for the API, not a
	// bulk tool's.
	tag, err := tx.Exec(ctx, `
		DELETE FROM import_stage s
		 WHERE (s.email_tok IS NOT NULL AND EXISTS
		         (SELECT 1 FROM person_tokens pt WHERE pt.kind='email' AND pt.token = s.email_tok))
		    OR (s.phone_tok IS NOT NULL AND EXISTS
		         (SELECT 1 FROM person_tokens pt WHERE pt.kind='phone' AND pt.token = s.phone_tok))`)
	if err != nil {
		return 0, 0, err
	}
	skipped := tag.RowsAffected()

	if _, err := tx.Exec(ctx, `INSERT INTO persons (id) SELECT pid FROM import_stage`); err != nil {
		return 0, 0, err
	}
	for _, ident := range []struct{ kind, col, ver string }{
		{"email", "email_tok", emailV}, {"phone", "phone_tok", phoneV}, {"name", "name_tok", nameV},
	} {
		if _, err := tx.Exec(ctx, fmt.Sprintf(`
			INSERT INTO person_tokens (person_id, kind, token, key_version)
			SELECT pid, '%s', %s, $1 FROM import_stage WHERE %s IS NOT NULL`,
			ident.kind, ident.col, ident.col), ident.ver); err != nil {
			return 0, 0, err
		}
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
	return inserted, skipped, tx.Commit(ctx)
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
