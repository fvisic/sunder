// Command bulkload fills a Sunder database with synthetic contacts at a
// scale the HTTP API cannot reach in reasonable time: the API path is
// serialized by the audit chain (see benchmark/README.md), so loading 100M
// contacts through it would take days.
//
// It writes the REAL shapes, not placeholders: keyed-HMAC search tokens
// computed with the instance's own keys through the same tokenizer the
// server uses, and AEAD-encrypted attribute blobs bound to their CID. A
// lookup for bench-42@example.com therefore resolves exactly as it would
// for a contact registered through the API - which is the point, because
// what is being measured is index behaviour at scale, not the loader.
//
// It bypasses the audit chain deliberately. Loading is not an audited
// operation being measured; the audited paths are measured separately.
package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/fvisic/sunder/internal/api"
	"github.com/fvisic/sunder/internal/config"
	"github.com/fvisic/sunder/internal/crypto"
	"github.com/fvisic/sunder/internal/service"
)

func main() {
	total := flag.Int("n", 1_000_000, "contacts to insert")
	batch := flag.Int("batch", 20_000, "rows per COPY batch")
	workers := flag.Int("workers", 8, "parallel loaders")
	scope := flag.String("scope", "bench", "scope the CIDs belong to")
	offset := flag.Int("offset", 0, "start index, so a run can be resumed or extended")
	flag.Parse()

	ctx := context.Background()
	cfg, err := config.FromEnv()
	if err != nil {
		die(err)
	}
	pool, err := pgxpool.New(ctx, cfg.DBURL)
	if err != nil {
		die(err)
	}
	defer pool.Close()

	// The same engine, tokenizer and PII box the server uses, so the rows
	// are indistinguishable from API-created ones.
	eng := api.OpenEngine(cfg)
	ring := &service.KeyRing{Pool: pool}
	if err := ring.EnsureAll(ctx, eng); err != nil {
		die(fmt.Errorf("key bootstrap: %w", err))
	}
	emailV, err := ring.Newest(ctx, crypto.KeyHMACEmail)
	if err != nil {
		die(err)
	}
	phoneV, err := ring.Newest(ctx, crypto.KeyHMACPhone)
	if err != nil {
		die(err)
	}
	nameV, err := ring.Newest(ctx, crypto.KeyHMACName)
	if err != nil {
		die(err)
	}
	kekV, err := ring.Newest(ctx, crypto.KeyPIIKEK)
	if err != nil {
		die(err)
	}
	tok := crypto.NewTokenizer(eng)
	pii := crypto.NewPIIBox(eng)

	fmt.Printf("loading %d contacts into scope %q (offset %d, %d workers, batch %d)\n",
		*total, *scope, *offset, *workers, *batch)
	start := time.Now()
	var done int64

	// Progress on its own ticker: a load this long is unusable without one.
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				n := atomic.LoadInt64(&done)
				el := time.Since(start).Seconds()
				rate := float64(n) / el
				remain := time.Duration(float64(*total-int(n))/rate) * time.Second
				fmt.Printf("  %d/%d  %.0f rows/s  elapsed %s  eta %s\n",
					n, *total, rate, time.Since(start).Truncate(time.Second), remain.Truncate(time.Second))
			}
		}
	}()

	perWorker := *total / *workers
	var wg sync.WaitGroup
	for w := 0; w < *workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			from := *offset + w*perWorker
			to := from + perWorker
			if w == *workers-1 {
				to = *offset + *total
			}
			for lo := from; lo < to; lo += *batch {
				hi := lo + *batch
				if hi > to {
					hi = to
				}
				if err := loadBatch(ctx, pool, tok, pii, *scope,
					emailV, phoneV, nameV, kekV, cfg.SearchFuzzyName,
					cfg.SearchPhoneSuffix, lo, hi); err != nil {
					die(fmt.Errorf("worker %d batch %d: %w", w, lo, err))
				}
				atomic.AddInt64(&done, int64(hi-lo))
			}
		}(w)
	}
	wg.Wait()
	close(stop)

	el := time.Since(start)
	fmt.Printf("done: %d contacts in %s (%.0f rows/s)\n",
		*total, el.Truncate(time.Second), float64(*total)/el.Seconds())
}

// loadBatch builds one batch in memory and ships it with three COPY
// streams. COPY is the only way to reach this scale; row-at-a-time INSERT
// is an order of magnitude slower.
func loadBatch(ctx context.Context, pool *pgxpool.Pool, tok *crypto.Tokenizer,
	pii *crypto.PIIBox, scope, emailV, phoneV, nameV, kekV string,
	fuzzyName, phoneSuffix bool, lo, hi int) error {

	n := hi - lo
	persons := make([][]any, 0, n)
	cids := make([][]any, 0, n)
	tokens := make([][]any, 0, n*2)

	for i := lo; i < hi; i++ {
		pid, err := crypto.NewPersonID()
		if err != nil {
			return err
		}
		cid, err := crypto.NewCID()
		if err != nil {
			return err
		}
		// Same identity scheme as benchmark/bench.go, so a lookup run can
		// address these contacts without knowing they were bulk loaded.
		email, err := crypto.NormalizeEmail(fmt.Sprintf("%s-%d@bench.example", scope, i))
		if err != nil {
			return err
		}
		// The bench client's phone namespace is only 1e6 wide, which collides
		// on the unique index long before 100M. Loaded contacts therefore get
		// a full-width phone; nothing looks contacts up by phone here.
		phone, err := crypto.NormalizePhone(fmt.Sprintf("+385%012d", i))
		if err != nil {
			return err
		}

		et, err := tok.EmailToken(ctx, emailV, email)
		if err != nil {
			return err
		}
		pt, err := tok.PhoneToken(ctx, phoneV, phone)
		if err != nil {
			return err
		}
		// The name is tokenized, not merely stored in the blob. A contact
		// registered through the API with a name gets a `name` row, and with
		// the derived indexes on gets `name_phonetic` and `phone_suffix` too;
		// a loader that wrote only email and phone produced a person the
		// dedup path and the fuzzy path could not see, and a person_tokens
		// table roughly a third smaller than the real one - so every scale
		// measurement taken on it was measuring a lighter table than
		// production has.
		name, err := crypto.NormalizeName(fmt.Sprintf("Test Osoba %d", i))
		if err != nil {
			return err
		}
		nt, err := tok.NameToken(ctx, nameV, name)
		if err != nil {
			return err
		}
		blob, err := pii.Encrypt(ctx, cid, kekV, map[string]string{
			"email":        email,
			"phone":        phone,
			"name":         name,
			"loyalty_tier": []string{"bronze", "silver", "gold"}[i%3],
			"segment":      fmt.Sprintf("seg-%d", i%50),
		})
		if err != nil {
			return err
		}

		persons = append(persons, []any{pid})
		cids = append(cids, []any{cid, pid, scope, blob, kekV, pii.Algorithm()})
		tokens = append(tokens,
			[]any{pid, "email", et, emailV},
			[]any{pid, "phone", pt, phoneV},
			[]any{pid, "name", nt, nameV})
		if fuzzyName {
			for _, code := range crypto.PhoneticNameCodes(name) {
				pht, err := tok.NamePhoneticToken(ctx, nameV, code)
				if err != nil {
					return err
				}
				tokens = append(tokens, []any{pid, "name_phonetic", pht, nameV})
			}
		}
		if phoneSuffix {
			st, err := tok.PhoneSuffixToken(ctx, phoneV, crypto.PhoneSuffix(phone))
			if err != nil {
				return err
			}
			tokens = append(tokens, []any{pid, "phone_suffix", st, phoneV})
		}
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"persons"},
		[]string{"id"}, pgx.CopyFromRows(persons)); err != nil {
		return err
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"cids"},
		[]string{"cid", "person_id", "scope", "pii_encrypted", "pii_key_id", "pii_alg"},
		pgx.CopyFromRows(cids)); err != nil {
		return err
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"person_tokens"},
		[]string{"person_id", "kind", "token", "key_version"},
		pgx.CopyFromRows(tokens)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "bulkload:", err)
	if strings.Contains(err.Error(), "SUNDER_DB_URL") {
		fmt.Fprintln(os.Stderr, "hint: set SUNDER_DB_URL and the keystore variables the server uses")
	}
	os.Exit(1)
}

// newUUID mirrors the server's own generator rather than adding a
// dependency: the project keeps a stdlib-first policy for exactly the
// supply-chain reasons a benchmark tool should not undercut.
func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
