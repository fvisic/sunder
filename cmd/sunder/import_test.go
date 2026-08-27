package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/fvisic/sunder/internal/api"
	"github.com/fvisic/sunder/internal/audit"
	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/config"
	"github.com/fvisic/sunder/internal/crypto"
	"github.com/fvisic/sunder/internal/service"
	"github.com/fvisic/sunder/internal/testutil"
)

// TestImportCmd drives the supported bulk path end to end: import, verify
// the rows resolve through the SAME service code the API uses (the whole
// point - imported contacts must be indistinguishable from registered
// ones), prove idempotency, and check the batch audit record.
func TestImportCmd(t *testing.T) {
	st := testutil.NewDB(t)
	ctx := context.Background()
	cfg := testCfg(t)

	f := filepath.Join(t.TempDir(), "contacts.jsonl")
	if err := os.WriteFile(f, []byte(`
{"email":"ana@example.com","name":"Ana Anic","attributes":{"tier":"gold"}}
{"phone":"+385 91 111 2222","attributes":{"segment":"b2b"}}
{"email":"ivo@example.com","phone":"+385 91 333 4444"}
{"email":"ana@example.com","attributes":{"tier":"silver"}}
`), 0o600); err != nil {
		t.Fatal(err)
	}

	// First run: 3 imported (the 4th line is an in-file duplicate of ana).
	if err := importCmd(ctx, cfg, st, []string{"-file", f, "-scope", "crm", "-batch", "2"}); err != nil {
		t.Fatal(err)
	}
	var persons, tokens, cids int64
	if err := st.Pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM persons), (SELECT count(*) FROM person_tokens), (SELECT count(*) FROM cids)`,
	).Scan(&persons, &tokens, &cids); err != nil {
		t.Fatal(err)
	}
	// ana: email+name, phone-only: phone, ivo: email+phone -> 5 tokens.
	if persons != 3 || cids != 3 || tokens != 5 {
		t.Fatalf("want 3 persons / 3 cids / 5 tokens, got %d/%d/%d", persons, cids, tokens)
	}

	// Second run of the SAME file: nothing imported, everything skipped -
	// re-running after an interruption must be safe.
	if err := importCmd(ctx, cfg, st, []string{"-file", f, "-scope", "crm"}); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM persons`).Scan(&persons); err != nil {
		t.Fatal(err)
	}
	if persons != 3 {
		t.Fatalf("re-import must be idempotent, persons = %d", persons)
	}

	// The imported contact resolves through the SERVICE lookup path with
	// the same keys the importer used.
	eng := api.OpenEngine(cfg)
	ring := &service.KeyRing{Pool: st.Pool, RetireGrace: -1}
	contacts := &service.Contacts{Pool: st.Pool, Tok: crypto.NewTokenizer(eng), PII: crypto.NewPIIBox(eng), Ring: ring}
	client := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions: []string{auth.ActLookup, auth.ActAttributesRead}, AllowedPurposes: []string{"support"}}
	cid, err := contacts.Lookup(ctx, client, service.LookupInput{Email: "Ana@Example.com"})
	if err != nil || cid == "" {
		t.Fatalf("imported contact must resolve via the API path: %q %v", cid, err)
	}
	val, err := contacts.GetAttribute(ctx, client, cid, "tier", "support")
	if err != nil || val != "gold" {
		t.Fatalf("attribute of imported contact: %q %v (first line wins, in-file dup skipped)", val, err)
	}

	// Each batch left ONE chained audit record.
	if _, err := audit.Drain(ctx, st.Pool, 100); err != nil {
		t.Fatal(err)
	}
	var imports int64
	if err := st.Pool.QueryRow(ctx,
		`SELECT count(*) FROM audit WHERE action='contacts.import'`).Scan(&imports); err != nil {
		t.Fatal(err)
	}
	// Run 1 with batch=2: two batches; run 2: one batch (3 rows < 5000).
	if imports != 3 {
		t.Fatalf("want 3 contacts.import audit records, got %d", imports)
	}
	if broken, reason, _, err := audit.Verify(ctx, st.Pool); err != nil || broken != 0 {
		t.Fatalf("chain after import: broken=%d err=%v (%s)", broken, err, reason)
	}
}

func TestImportCmdFailsClosedOnBadInput(t *testing.T) {
	st := testutil.NewDB(t)
	ctx := context.Background()
	cfg := testCfg(t)
	write := func(content string) string {
		t.Helper()
		f := filepath.Join(t.TempDir(), "bad.jsonl")
		if err := os.WriteFile(f, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return f
	}

	if err := importCmd(ctx, cfg, st, []string{"-file", write(`{"email":}`), "-scope", "crm"}); err == nil {
		t.Fatal("malformed JSON must abort with the line number")
	}
	if err := importCmd(ctx, cfg, st, []string{"-file", write(`{"name":"No Identifier"}`), "-scope", "crm"}); err == nil {
		t.Fatal("a line without email or phone must abort")
	}
	if err := importCmd(ctx, cfg, st, []string{"-file", write(`{"email":"x@example.com","attributes":{"email":"forged"}}`), "-scope", "crm"}); err == nil {
		t.Fatal("reserved attribute names must abort")
	}
	if err := importCmd(ctx, cfg, st, []string{"-scope", "crm"}); err == nil {
		t.Fatal("missing -file must abort")
	}
	// Nothing may have landed from any failed run.
	var persons int64
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM persons`).Scan(&persons); err != nil {
		t.Fatal(err)
	}
	if persons != 0 {
		t.Fatalf("failed imports must import nothing, found %d persons", persons)
	}
}

func TestImportCmdFlagGuards(t *testing.T) {
	st := testutil.NewDB(t)
	ctx := context.Background()
	cfg := testCfg(t)
	if err := importCmd(ctx, cfg, st, []string{"-file", "/does/not/exist.jsonl", "-scope", "crm"}); err == nil {
		t.Fatal("missing file must error")
	}
	if err := importCmd(ctx, cfg, st, []string{"-file", "x", "-scope", "crm", "-batch", "0"}); err == nil {
		t.Fatal("non-positive batch must error")
	}
	if err := importCmd(ctx, cfg, st, []string{"-bogus"}); err == nil {
		t.Fatal("unknown flag must error")
	}
}

// TestImportBatchRetryOnUniqueRace: two rows with the SAME identifier
// token inside one batch slip past the stage-level dedup (importCmd's
// in-file dedup normally prevents this; the race with a concurrent writer
// produces the same DB state). The unique index fires, the batch retries
// once, and the persistent conflict surfaces as an error instead of a
// partial import.
func TestImportBatchRetryOnUniqueRace(t *testing.T) {
	st := testutil.NewDB(t)
	ctx := context.Background()
	rows := []importRow{
		{pid: "6f000000-0000-4000-8000-000000000001", cid: "CID-AAAAAAAAAAAAAAAAAAAAAAAAA1",
			emailTok: "tok-same", blob: []byte("b"), keyID: "v1", alg: "aes256gcm"},
		{pid: "6f000000-0000-4000-8000-000000000002", cid: "CID-AAAAAAAAAAAAAAAAAAAAAAAAA2",
			emailTok: "tok-same", blob: []byte("b"), keyID: "v1", alg: "aes256gcm"},
	}
	if _, _, err := importBatch(ctx, st, "crm", "v1", "v1", "v1", rows); err == nil {
		t.Fatal("a persistent unique conflict must surface after the retry")
	}
	// The failed batch imported nothing (whole-batch transactionality).
	var persons int64
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM persons`).Scan(&persons); err != nil {
		t.Fatal(err)
	}
	if persons != 0 {
		t.Fatalf("failed batch must land nothing, found %d", persons)
	}
}

func TestImportBatchSurfacesCopyErrors(t *testing.T) {
	st := testutil.NewDB(t)
	ctx := context.Background()
	rows := []importRow{{pid: "not-a-uuid", cid: "CID-X", emailTok: "t", blob: []byte("b"), keyID: "v1", alg: "aes256gcm"}}
	if _, _, err := importBatch(ctx, st, "crm", "v1", "v1", "v1", rows); err == nil {
		t.Fatal("a malformed staged row must surface, not vanish")
	}
}

func TestImportCmdRejectsBadIdentifiers(t *testing.T) {
	st := testutil.NewDB(t)
	ctx := context.Background()
	cfg := testCfg(t)
	write := func(content string) string {
		t.Helper()
		f := filepath.Join(t.TempDir(), "bad.jsonl")
		if err := os.WriteFile(f, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return f
	}
	if err := importCmd(ctx, cfg, st, []string{"-file", write(`{"email":"not-an-email"}`), "-scope", "crm"}); err == nil {
		t.Fatal("unnormalizable email must abort with the line number")
	}
	if err := importCmd(ctx, cfg, st, []string{"-file", write(`{"phone":"abc"}`), "-scope", "crm"}); err == nil {
		t.Fatal("unnormalizable phone must abort")
	}
	if err := importCmd(ctx, cfg, st, []string{"-file", write(`{"email":"a@b.example","attributes":{"x@y":"1"}}`), "-scope", "crm"}); err == nil {
		t.Fatal("attribute with '@' must abort")
	}
}

func TestImportCmdReadsStdin(t *testing.T) {
	st := testutil.NewDB(t)
	ctx := context.Background()
	cfg := testCfg(t)
	f := filepath.Join(t.TempDir(), "stdin.jsonl")
	if err := os.WriteFile(f, []byte(`{"email":"pipe@example.com"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fh, err := os.Open(f)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	old := os.Stdin
	os.Stdin = fh
	t.Cleanup(func() { os.Stdin = old })
	if err := importCmd(ctx, cfg, st, []string{"-file", "-", "-scope", "crm"}); err != nil {
		t.Fatal(err)
	}
	var n int64
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM persons`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("stdin import landed %d persons", n)
	}
}

// TestImportDedupsPerIdentifier is the review regression: two lines that
// share an email but differ in phone are one person under the dedup
// invariant. Pair-keyed dedup let both into the batch and the unique index
// killed the whole import with an opaque error.
func TestImportDedupsPerIdentifier(t *testing.T) {
	st := testutil.NewDB(t)
	ctx := context.Background()
	cfg := testCfg(t)
	f := filepath.Join(t.TempDir(), "dup.jsonl")
	if err := os.WriteFile(f, []byte(
		`{"email":"same@example.com","phone":"+385 91 111 1111"}
{"email":"same@example.com","phone":"+385 91 222 2222"}
{"email":"other@example.com","phone":"+385 91 222 2222"}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := importCmd(ctx, cfg, st, []string{"-file", f, "-scope", "crm"}); err != nil {
		t.Fatalf("a file with repeated identifiers must import cleanly, not die on a unique index: %v", err)
	}
	var persons int64
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM persons`).Scan(&persons); err != nil {
		t.Fatal(err)
	}
	// Line 2 repeats line 1's email, so it is skipped WHOLE - including
	// its phone, which therefore never lands. Line 3 then owns that phone
	// as a fresh person: first occurrence wins, skipped lines contribute
	// nothing. Two persons total, and no unique-index abort.
	if persons != 2 {
		t.Fatalf("want 2 persons (line 2 skipped whole by email), got %d", persons)
	}
}

// TestImportMintsDerivedTokens: with F1/F2 enabled the importer mints
// phonetic and suffix tokens, and skipped duplicate lines leave none.
func TestImportMintsDerivedTokens(t *testing.T) {
	st := testutil.NewDB(t)
	ctx := context.Background()
	cfg := testCfg(t)
	cfg.SearchFuzzyName = true
	cfg.SearchPhoneSuffix = true
	f := filepath.Join(t.TempDir(), "c.jsonl")
	if err := os.WriteFile(f, []byte(
		`{"email":"ana@example.com","phone":"+385911234567","name":"Ana Anić"}
{"email":"ana@example.com","name":"Ana Anić Duplikat"}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := importCmd(ctx, cfg, st, []string{"-file", f, "-scope", "crm"}); err != nil {
		t.Fatal(err)
	}
	var phonetic, suffix int64
	if err := st.Pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM person_tokens WHERE kind='name_phonetic'),
		(SELECT count(*) FROM person_tokens WHERE kind='phone_suffix')`).Scan(&phonetic, &suffix); err != nil {
		t.Fatal(err)
	}
	// "Ana Anić" = 2 word codes; the duplicate line's tokens must NOT land.
	if phonetic != 2 || suffix != 1 {
		t.Fatalf("want 2 phonetic + 1 suffix token, got %d/%d", phonetic, suffix)
	}

	// The imported contact is findable through the fuzzy/partial paths of
	// the same service the API uses.
	eng := api.OpenEngine(cfg)
	ring := &service.KeyRing{Pool: st.Pool, RetireGrace: -1}
	contacts := &service.Contacts{Pool: st.Pool, Tok: crypto.NewTokenizer(eng), PII: crypto.NewPIIBox(eng), Ring: ring,
		FuzzyName: true, PhoneSuffix: true}
	client := &auth.Client{ID: "crm", Scope: "crm", AllowedActions: []string{auth.ActLookup}}
	if cid, err := contacts.Lookup(ctx, client, service.LookupInput{PhoneSuffix: "0911234567", Name: "anic"}); err != nil || cid == "" {
		t.Fatalf("imported contact must resolve via suffix+fuzzy name: %q %v", cid, err)
	}
}

// TestRekeyBackfillsDerivedTokens: enabling F1/F2 on an existing dataset
// is "flip the config, run `sunder keys rekey`" - prove it.
func TestRekeyBackfillsDerivedTokens(t *testing.T) {
	st := testutil.NewDB(t)
	ctx := context.Background()
	cfg := testCfg(t) // features OFF at import time
	f := filepath.Join(t.TempDir(), "c.jsonl")
	if err := os.WriteFile(f, []byte(`{"email":"ana@example.com","phone":"+385911234567","name":"Ana Anić"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := importCmd(ctx, cfg, st, []string{"-file", f, "-scope", "crm"}); err != nil {
		t.Fatal(err)
	}
	var n int64
	if err := st.Pool.QueryRow(ctx,
		`SELECT count(*) FROM person_tokens WHERE kind IN ('name_phonetic','phone_suffix')`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("features off: no derived tokens expected, got %d", n)
	}

	// Flip the switches, run the rekey sweep: tokens appear.
	cfg.SearchFuzzyName = true
	cfg.SearchPhoneSuffix = true
	if err := keysCmd(ctx, cfg, st, []string{"rekey", "-batch", "100"}); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx,
		`SELECT count(*) FROM person_tokens WHERE kind IN ('name_phonetic','phone_suffix')`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 3 { // 2 phonetic word codes + 1 suffix
		t.Fatalf("rekey must backfill derived tokens, got %d of 3", n)
	}
}

func TestImportFailsClosedOnBrokenKeystore(t *testing.T) {
	st := testutil.NewDB(t)
	ctx := context.Background()
	// A keystore the importer cannot write to: key bootstrap must abort
	// the import before a single row is read.
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	cfg := config.Config{Keystore: "file", KeyRetireGrace: -1, KeystorePath: dir}
	f := filepath.Join(t.TempDir(), "c.jsonl")
	if err := os.WriteFile(f, []byte(`{"email":"x@example.com"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := importCmd(ctx, cfg, st, []string{"-file", f, "-scope", "crm"}); err == nil {
		t.Fatal("a broken keystore must abort the import")
	}
	var n int64
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM persons`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("nothing may land after a keystore failure, found %d", n)
	}
}

func TestImportSuffixOnlyDerived(t *testing.T) {
	st := testutil.NewDB(t)
	ctx := context.Background()
	cfg := testCfg(t)
	cfg.SearchPhoneSuffix = true // suffix only, no fuzzy name
	f := filepath.Join(t.TempDir(), "c.jsonl")
	if err := os.WriteFile(f, []byte(`{"phone":"+385911234567"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := importCmd(ctx, cfg, st, []string{"-file", f, "-scope", "crm"}); err != nil {
		t.Fatal(err)
	}
	var suffix, phonetic int64
	if err := st.Pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM person_tokens WHERE kind='phone_suffix'),
		(SELECT count(*) FROM person_tokens WHERE kind='name_phonetic')`).Scan(&suffix, &phonetic); err != nil {
		t.Fatal(err)
	}
	if suffix != 1 || phonetic != 0 {
		t.Fatalf("suffix-only: %d suffix, %d phonetic", suffix, phonetic)
	}
}

func TestImportBatchTableDenied(t *testing.T) {
	st := testutil.NewDB(t)
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	// Drop the persons table so the batch INSERT fails mid-transaction;
	// the whole batch must roll back.
	if _, err := st.Pool.Exec(ctx, `ALTER TABLE persons RENAME TO persons_hidden`); err != nil {
		t.Fatal(err)
	}
	cfg := testCfg(t)
	f := filepath.Join(t.TempDir(), "c.jsonl")
	if err := os.WriteFile(f, []byte(`{"email":"x@example.com"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := importCmd(ctx, cfg, st, []string{"-file", f, "-scope", "crm"}); err == nil {
		t.Fatal("import must fail when a target table is missing")
	}
}

func TestImportMalformedLinesAndDeniedKeys(t *testing.T) {
	st := testutil.NewDB(t)
	ctx := context.Background()
	cfg := testCfg(t)
	cfg.SearchFuzzyName = true
	cfg.SearchPhoneSuffix = true

	// A malformed phone number must fail the batch with a line error.
	bad := filepath.Join(t.TempDir(), "bad.jsonl")
	if err := os.WriteFile(bad, []byte(`{"phone":"not-a-phone!!!"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := importCmd(ctx, cfg, st, []string{"-file", bad, "-scope", "crm"}); err == nil {
		t.Fatal("a malformed phone must fail the import")
	}

	// A good line with name+phone+fuzzy exercises the token minting paths.
	good := filepath.Join(t.TempDir(), "good.jsonl")
	if err := os.WriteFile(good, []byte(`{"email":"a@example.com","phone":"+385911234567","name":"Ana Anić"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := importCmd(ctx, cfg, st, []string{"-file", good, "-scope", "crm"}); err != nil {
		t.Fatal(err)
	}

	// Denying the keys table makes the up-front Newest lookups fail.
	if _, err := st.Pool.Exec(ctx, `ALTER TABLE keys RENAME TO keys_import_gone`); err != nil {
		t.Fatal(err)
	}
	if err := importCmd(ctx, cfg, st, []string{"-file", good, "-scope", "crm"}); err == nil {
		t.Fatal("import must fail when key versions cannot be read")
	}
}

// TestImportDedupsAcrossKeyRotation: mid-rotation (ACTIVE + RETIRING key
// versions, before the rekey sweep re-tokenizes), an existing contact's
// person_tokens still carry the RETIRING version's token. The importer used
// to compute only the NEWEST version's token for its dedup check, miss the
// existing row, and mint a duplicate person for the same email - breaking the
// dedup invariant exactly when RETIRING exists to preserve it (H13).
func TestImportDedupsAcrossKeyRotation(t *testing.T) {
	st := testutil.NewDB(t)
	ctx := context.Background()
	cfg := testCfg(t)

	f := filepath.Join(t.TempDir(), "one.jsonl")
	if err := os.WriteFile(f, []byte(`{"email":"rot@example.com","phone":"+385 91 555 6666"}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := importCmd(ctx, cfg, st, []string{"-file", f, "-scope", "crm"}); err != nil {
		t.Fatal(err)
	}
	var persons int64
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM persons`).Scan(&persons); err != nil {
		t.Fatal(err)
	}
	if persons != 1 {
		t.Fatalf("setup: want 1 person, got %d", persons)
	}

	// Rotate BOTH dedup identifier keys: the stored tokens are now under
	// RETIRING versions while a fresh import tokenizes with the new ACTIVE.
	eng := api.OpenEngine(cfg)
	ring := &service.KeyRing{Pool: st.Pool, RetireGrace: -1}
	if err := ring.EnsureAll(ctx, eng); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{crypto.KeyHMACEmail, crypto.KeyHMACPhone} {
		if _, err := ring.Rotate(ctx, eng, kind); err != nil {
			t.Fatalf("rotate %s: %v", kind, err)
		}
	}

	// Re-import the same contact (and a genuinely new one, phone-only, to
	// prove the batch still inserts what IS new).
	f2 := filepath.Join(t.TempDir(), "two.jsonl")
	if err := os.WriteFile(f2, []byte(`{"email":"rot@example.com"}
{"phone":"+385 91 555 6666"}
{"phone":"+385 91 777 8888"}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := importCmd(ctx, cfg, st, []string{"-file", f2, "-scope", "crm"}); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM persons`).Scan(&persons); err != nil {
		t.Fatal(err)
	}
	if persons != 2 {
		t.Fatalf("mid-rotation re-import must dedup by RETIRING-version tokens too: want 2 persons (1 existing + 1 new), got %d", persons)
	}
}
