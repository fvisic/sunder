package service_test

// GAP-1 / CRYPTO-2 regressions.
//
// Every store sealed under pii-kek must be swept by `keys rekey
// -reencrypt-pii`, and `keys retire` must refuse a version any store still
// references. portal_outbox was sealed under pii-kek by migration 0016 -
// AFTER the sweep was written - and nothing ever re-sealed it, so a retired
// or leaked KEK kept opening the data subject's plaintext e-mail address and
// any still-undelivered portal login token.

import (
	"context"
	"sort"
	"strings"
	"testing"

	"bytes"
	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/crypto"
	"github.com/fvisic/sunder/internal/service"
	"github.com/fvisic/sunder/internal/storage"
)

func TestRekeyResealsPortalOutbox(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	e.register(t)

	adminRing := &service.KeyRing{Pool: e.admin.Pool, RetireGrace: -1}
	admin := &service.Contacts{Pool: e.admin.Pool, Tok: e.svc.Tok, PII: e.svc.PII, Ring: adminRing}
	portal := &service.Portal{GDPR: &service.GDPR{Pool: e.admin.Pool, Contacts: admin}, Contacts: admin}

	if err := portal.Start(ctx, "fault@example.com"); err != nil {
		t.Fatal(err)
	}
	var before string
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT key_id FROM portal_outbox LIMIT 1`).Scan(&before); err != nil {
		t.Fatalf("Portal.Start must queue a sealed mail: %v", err)
	}

	newest, err := adminRing.Rotate(ctx, e.oti.Eng, crypto.KeyPIIKEK)
	if err != nil {
		t.Fatal(err)
	}
	stats, err := admin.Rekey(ctx, true, 500)
	if err != nil {
		t.Fatal(err)
	}
	if stats.OutboxRewrapped == 0 {
		t.Fatal("the sweep did not re-seal any portal_outbox row")
	}
	var stale int
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM portal_outbox WHERE key_id <> $1`, newest).Scan(&stale); err != nil {
		t.Fatal(err)
	}
	if stale != 0 {
		t.Fatalf("%d portal_outbox row(s) still sealed under a superseded KEK", stale)
	}

	// The retired key must no longer open the payload.
	var payload []byte
	var alg string
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT payload, alg FROM portal_outbox LIMIT 1`).Scan(&payload, &alg); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.PII.OpenBytes(ctx, "portal-outbox", payload, before, alg); err == nil {
		t.Fatal("the superseded KEK still opens a portal_outbox payload")
	}
}

// TestRetireRefusesWhileReferenced: a pii-kek version any sealed store still
// references must not be retirable, so a table the sweep forgot becomes a
// loud CLI failure instead of a silent leak.
func TestRetireRefusesWhileReferenced(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	e.register(t)

	adminRing := &service.KeyRing{Pool: e.admin.Pool, RetireGrace: -1}
	admin := &service.Contacts{Pool: e.admin.Pool, Tok: e.svc.Tok, PII: e.svc.PII, Ring: adminRing}
	portal := &service.Portal{GDPR: &service.GDPR{Pool: e.admin.Pool, Contacts: admin}, Contacts: admin}
	if err := portal.Start(ctx, "fault@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := adminRing.Rotate(ctx, e.oti.Eng, crypto.KeyPIIKEK); err != nil {
		t.Fatal(err)
	}
	if err := adminRing.Retire(ctx, crypto.KeyPIIKEK, "v1"); err == nil {
		t.Fatal("retiring a KEK version that still seals live data must be refused")
	}
	// -force is the documented escape hatch.
	if err := adminRing.RetireWithForce(ctx, crypto.KeyPIIKEK, "v1", true); err != nil {
		t.Fatalf("-force must still retire: %v", err)
	}
}

// TestEveryKEKSealedStoreIsSwept is the structural guard: any table with a
// key-version column holding pii-kek-sealed ciphertext must be covered by
// both the rekey sweep and the retire reference check. A future migration
// that adds one without wiring it up fails here rather than leaking.
func TestEveryKEKSealedStoreIsSwept(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()

	rows, err := e.admin.Pool.Query(ctx, `
		SELECT table_name, column_name FROM information_schema.columns
		 WHERE table_schema='public' AND column_name IN ('key_id','pii_key_id')
		 ORDER BY table_name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var found []string
	for rows.Next() {
		var tbl, col string
		if err := rows.Scan(&tbl, &col); err != nil {
			t.Fatal(err)
		}
		found = append(found, tbl+"."+col)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	// keys.key_id is the key registry itself, not sealed ciphertext.
	covered := map[string]bool{
		"cids.pii_key_id":           true, // rekeyPerson
		"cid_blob_versions.key_id":  true, // rekeyVaults
		"value_tokens.key_id":       true, // rekeyVaults
		"person_record_keys.key_id": true, // rekeyVaults
		"portal_outbox.key_id":      true, // rekeyVaults (GAP-1)
		"keys.key_id":               true, // the registry, not ciphertext
	}
	sort.Strings(found)
	for _, f := range found {
		if !covered[f] {
			t.Fatalf("%s holds a key version but is not listed as covered.\n"+
				"Either add a pass to Contacts.rekeyVaults and an entry to kekSealedStores\n"+
				"(internal/service/keyring.go), or add it here with a comment saying why it\n"+
				"needs neither. A pii-kek-sealed store the sweep forgets stays decryptable\n"+
				"by a retired or leaked key while the CLI reports success (GAP-1).", f)
		}
	}
	if len(found) == 0 {
		t.Fatal("discovery found no key-version columns - the guard is vacuous")
	}
}

// CRYPTO-2: retiring an HMAC key must purge the DERIVED search tokens minted
// from it, not only the base kind. name_phonetic hangs off hmac-name and
// phone_suffix off hmac-phone, and both carry the base key's version.
func TestRetirePurgesDerivedSearchTokens(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()

	adminRing := &service.KeyRing{Pool: e.admin.Pool, RetireGrace: -1}
	admin := &service.Contacts{Pool: e.admin.Pool, Tok: e.svc.Tok, PII: e.svc.PII, Ring: adminRing,
		FuzzyName: true, PhoneSuffix: true}
	if _, err := admin.Register(ctx, e.crm, service.RegisterInput{
		Email: "derived@example.com", Phone: "+385911234567", Name: "Derived Case"}); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"name_phonetic", "phone_suffix"} {
		var n int
		if err := e.admin.Pool.QueryRow(ctx,
			`SELECT count(*) FROM person_tokens WHERE kind=$1`, kind).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			t.Fatalf("precondition: no %s tokens were minted", kind)
		}
	}
	for _, kind := range []string{crypto.KeyHMACName, crypto.KeyHMACPhone} {
		if _, err := adminRing.Rotate(ctx, e.oti.Eng, kind); err != nil {
			t.Fatal(err)
		}
		if err := adminRing.Retire(ctx, kind, "v1"); err != nil {
			t.Fatal(err)
		}
	}
	var left int
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM person_tokens WHERE kind IN ('name_phonetic','phone_suffix') AND key_version='v1'`).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Fatalf("%d derived token(s) survived the retirement of the key they were minted from", left)
	}
}

// OPS-CLI-CONFIG-1: `serve` must refuse to mint replacement material for a
// key version live data was written under. Minting there manufactures a
// vault that cannot read its own contents and reports healthy.
func TestEnsureAllRefusesToMintOverLiveData(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	e.register(t) // writes person_tokens under hmac-*/v1 and a blob under pii-kek/v1

	// A fresh, EMPTY keystore: the lost-volume shape.
	lostEng := crypto.NewLocalEngine(crypto.NewCachingKeystore(&crypto.FileKeystore{Dir: t.TempDir()}))
	ring := &service.KeyRing{Pool: e.admin.Pool, RetireGrace: -1}
	err := ring.EnsureAll(ctx, lostEng)
	if err == nil {
		t.Fatal("booting against a keystore missing material for referenced key versions must fail")
	}
	if !strings.Contains(err.Error(), "lost or wrong keystore") {
		t.Fatalf("the error must name the condition: %v", err)
	}
	// The explicit operator act still mints.
	if err := ring.EnsureAllAllowingMint(ctx, lostEng); err != nil {
		t.Fatalf("bootstrap must still be able to mint: %v", err)
	}
}

// The symmetric case: a genuinely fresh vault (keys rows seeded by migration
// 0002, no data written under them) must boot without an operator flag.
func TestEnsureAllMintsOnAFreshVault(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	eng := crypto.NewLocalEngine(crypto.NewCachingKeystore(&crypto.FileKeystore{Dir: t.TempDir()}))
	ring := &service.KeyRing{Pool: e.admin.Pool, RetireGrace: -1}
	if err := ring.EnsureAll(ctx, eng); err != nil {
		t.Fatalf("a first boot against an empty vault must succeed: %v", err)
	}
}

// CRYPTO-3 / TOKENS-LOOKUP-4: `unique:true` is the contract that tokenizing
// the same IBAN twice returns the same token instead of breeding aliases. It
// was keyed by the newest hmac-email version with no version column, no
// rekey pass and no purge, so ANY search-key rotation broke it silently and
// permanently - and leaking the e-mail SEARCH key left an offline dictionary
// oracle over every tokenized card number, IBAN and national id.
func TestUniqueDedupSurvivesSearchKeyRotation(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cid := e.register(t)

	adminRing := &service.KeyRing{Pool: e.admin.Pool, RetireGrace: -1}
	admin := &service.Contacts{Pool: e.admin.Pool, Tok: e.svc.Tok, PII: e.svc.PII, Ring: adminRing}
	vt := &service.ValueTokens{Pool: e.admin.Pool, Eng: e.oti.Eng, Ring: adminRing, Tok: e.svc.Tok}
	client := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions:  []string{auth.ActTokensCreate, auth.ActTokensRead},
		AllowedPurposes: []string{"support"}}

	const iban = "HR1210010051863000160"
	first, err := vt.Tokenize(ctx, client, service.TokenizeInput{
		Type: "string", Value: iban, CID: cid, Unique: true})
	if err != nil {
		t.Fatal(err)
	}

	// Rotate the SEARCH key. The dedup hash must not be keyed by it any
	// more, so this alone must not break matching.
	if _, err := adminRing.Rotate(ctx, e.oti.Eng, crypto.KeyHMACEmail); err != nil {
		t.Fatal(err)
	}
	again, err := vt.Tokenize(ctx, client, service.TokenizeInput{
		Type: "string", Value: iban, CID: cid, Unique: true})
	if err != nil {
		t.Fatal(err)
	}
	if again != first {
		t.Fatalf("dedup broke across an hmac-email rotation: %s vs %s", again, first)
	}

	// Rotate the VALUE key: matching must span the rotation window, and the
	// row must converge onto the new version on touch.
	if _, err := adminRing.Rotate(ctx, e.oti.Eng, crypto.KeyHMACValue); err != nil {
		t.Fatal(err)
	}
	third, err := vt.Tokenize(ctx, client, service.TokenizeInput{
		Type: "string", Value: iban, CID: cid, Unique: true})
	if err != nil {
		t.Fatal(err)
	}
	if third != first {
		t.Fatalf("dedup broke across an hmac-value rotation: %s vs %s", third, first)
	}
	var rows int
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM value_tokens WHERE scope='crm'`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("one value must have exactly one live token, got %d rows", rows)
	}
	var version string
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT COALESCE(unique_key_version,'') FROM value_tokens WHERE token=$1`, first).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != crypto.KeyHMACValue+"/v2" {
		t.Fatalf("the row must converge onto the newest value key on touch, got %q", version)
	}

	// The sweep converges rows that are never touched, and retirement of a
	// version any row still keys on is refused until it has.
	if _, err := admin.Rekey(ctx, true, 100); err != nil {
		t.Fatal(err)
	}
	if err := adminRing.Retire(ctx, crypto.KeyHMACValue, "v1"); err != nil {
		t.Fatalf("v1 keys nothing after the sweep, so retiring it must succeed: %v", err)
	}
}

// The dedup hash must no longer be derivable from the e-mail search key at
// all: that cross-attribute borrow is what made an hmac-email leak a
// dictionary attack over IBANs and card numbers.
func TestUniqueHashIsNotKeyedByTheEmailKey(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()

	adminRing := &service.KeyRing{Pool: e.admin.Pool, RetireGrace: -1}
	vt := &service.ValueTokens{Pool: e.admin.Pool, Eng: e.oti.Eng, Ring: adminRing, Tok: e.svc.Tok}
	client := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions: []string{auth.ActTokensCreate}, AllowedPurposes: []string{"support"}}

	const value = "HR1210010051863000160"
	token, err := vt.Tokenize(ctx, client, service.TokenizeInput{
		Type: "string", Value: value, Unique: true})
	if err != nil {
		t.Fatal(err)
	}
	var stored []byte
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT unique_hash FROM value_tokens WHERE token=$1`, token).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	// The legacy derivation, recomputed with the leaked e-mail key.
	legacy, err := e.oti.Eng.MAC(ctx, crypto.KeyHMACEmail+"/v1",
		[]byte("valtok\x00crm\x00string\x00"+value))
	if err != nil {
		t.Fatal(err)
	}
	if string(stored) == string(legacy) {
		t.Fatal("the dedup hash is still derivable from the e-mail search key")
	}
}

// DOCS-6: RUNBOOK-ALG-MIGRATION exists to move a fleet OFF a deprecated
// AEAD, and its verification query reads `cids` only. rekeyVaults sealed
// value_tokens and person_record_keys with a hard-coded aes256gcm, so the
// F4 value vault and the crypto-shredding pivot for every file stayed on
// the old algorithm while the runbook reported the migration complete.
func TestAlgorithmMigrationCoversEveryStore(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cid := e.register(t)

	adminRing := &service.KeyRing{Pool: e.admin.Pool, RetireGrace: -1}
	client := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions:  []string{auth.ActTokensCreate, auth.ActFilesWrite},
		AllowedPurposes: []string{"support"}}

	// Something in every store: a value token, and a record key (minted by
	// the file vault when a person first gets a file).
	vt := &service.ValueTokens{Pool: e.admin.Pool, Eng: e.oti.Eng, Ring: adminRing, Tok: e.svc.Tok}
	if _, err := vt.Tokenize(ctx, client, service.TokenizeInput{
		Type: "string", Value: "HR12", CID: cid}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.admin.Pool.Exec(ctx, `
		INSERT INTO person_record_keys (person_id, wrapped, key_id, alg)
		SELECT person_id, $2, 'v1', 'aes256gcm' FROM cids WHERE cid=$1`,
		cid, mustWrapRecordKey(t, e, cid)); err != nil {
		t.Fatal(err)
	}

	// Migrate the fleet to the other AEAD.
	migrated := crypto.NewPIIBox(e.oti.Eng)
	migrated.Alg = crypto.AlgXChaCha20
	admin := &service.Contacts{Pool: e.admin.Pool, Tok: e.svc.Tok, PII: migrated,
		Ring: adminRing, VersionsKeep: 3}
	if _, err := admin.Rekey(ctx, true, 500); err != nil {
		t.Fatal(err)
	}

	// The runbook's verification, extended to every store that holds
	// pii-kek-sealed ciphertext.
	for _, q := range []struct{ table, query string }{
		{"cids", `SELECT DISTINCT COALESCE(pii_alg,'') FROM cids WHERE pii_encrypted IS NOT NULL`},
		{"value_tokens", `SELECT DISTINCT alg FROM value_tokens`},
		{"person_record_keys", `SELECT DISTINCT alg FROM person_record_keys`},
	} {
		rows, err := e.admin.Pool.Query(ctx, q.query)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var alg string
			if err := rows.Scan(&alg); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			if alg != crypto.AlgXChaCha20 {
				rows.Close()
				t.Fatalf("%s still holds %q after the migration - the runbook's check reads `cids` only, so this is invisible",
					q.table, alg)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
	}
}

// mustWrapRecordKey builds a legitimately wrapped record key under v1.
func mustWrapRecordKey(t *testing.T, e *faultEnv, cid string) []byte {
	t.Helper()
	ctx := context.Background()
	var personID string
	if err := e.admin.Pool.QueryRow(ctx, `SELECT person_id FROM cids WHERE cid=$1`, cid).Scan(&personID); err != nil {
		t.Fatal(err)
	}
	sealed, err := e.oti.Eng.Seal(ctx, crypto.KeyPIIKEK+"/v1", crypto.AlgAES256GCM,
		[]byte("record-key\x00"+personID), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

// The sweep's SKIP branches. A row it cannot decrypt must be counted and
// stepped over, never abandon the run - a single unreadable blob would
// otherwise stop a migration the operator is running to completion.
func TestRekeySkipsUndecryptableRowsAndKeepsGoing(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cid := e.register(t)

	adminRing := &service.KeyRing{Pool: e.admin.Pool, RetireGrace: -1}
	admin := &service.Contacts{Pool: e.admin.Pool, Tok: e.svc.Tok, PII: e.svc.PII,
		Ring: adminRing, VersionsKeep: 3}
	client := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions:  []string{auth.ActTokensCreate},
		AllowedPurposes: []string{"support"}}
	vt := &service.ValueTokens{Pool: e.admin.Pool, Eng: e.oti.Eng, Ring: adminRing, Tok: e.svc.Tok}

	// One good token, one whose ciphertext is corrupt, plus a corrupt
	// version blob and a corrupt record key.
	if _, err := vt.Tokenize(ctx, client, service.TokenizeInput{Type: "string", Value: "good"}); err != nil {
		t.Fatal(err)
	}
	bad, err := vt.Tokenize(ctx, client, service.TokenizeInput{Type: "string", Value: "bad"})
	if err != nil {
		t.Fatal(err)
	}
	// XOR, never assignment: `overlay ... placing '\xff'` is a no-op when the
	// byte already holds 0xff, which leaves the ciphertext valid and the test
	// asserting nothing. Same 1-in-256 flake that took a CI leg down in
	// TestPortalMailAbandonsACorruptPayload.
	if _, err := e.admin.Pool.Exec(ctx,
		`UPDATE value_tokens SET ciphertext = set_byte(ciphertext, 19, get_byte(ciphertext, 19) # 255) WHERE token=$1`,
		bad); err != nil {
		t.Fatal(err)
	}
	// A version snapshot (created by the second register) with a corrupt blob.
	if _, err := admin.Register(ctx, e.crm, service.RegisterInput{
		Email: "fault@example.com", Attributes: map[string]string{"tier": "silver"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.admin.Pool.Exec(ctx,
		`UPDATE cid_blob_versions SET blob = set_byte(blob, 19, get_byte(blob, 19) # 255)`); err != nil {
		t.Fatal(err)
	}
	// A record key nothing can unwrap.
	var personID string
	if err := e.admin.Pool.QueryRow(ctx, `SELECT person_id FROM cids WHERE cid=$1`, cid).Scan(&personID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.admin.Pool.Exec(ctx, `
		INSERT INTO person_record_keys (person_id, wrapped, key_id, alg)
		VALUES ($1, '\xdeadbeef'::bytea, 'v1', 'aes256gcm')
		ON CONFLICT (person_id) DO UPDATE SET wrapped='\xdeadbeef'::bytea`, personID); err != nil {
		t.Fatal(err)
	}

	if _, err := adminRing.Rotate(ctx, e.oti.Eng, crypto.KeyPIIKEK); err != nil {
		t.Fatal(err)
	}
	stats, err := admin.Rekey(ctx, true, 100)
	if err != nil {
		t.Fatalf("an unreadable row must not abort the sweep: %v", err)
	}
	if stats.Skipped == 0 {
		t.Fatal("the undecryptable rows must be COUNTED, not silently ignored")
	}
	if stats.ValueTokensRewrapped == 0 {
		t.Fatal("the sweep must still convert the rows it can read")
	}
	// The good token still opens after the sweep.
	reader := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions: []string{auth.ActTokensRead}, AllowedPurposes: []string{"support"}}
	var goodToken string
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT token FROM value_tokens WHERE token <> $1`, bad).Scan(&goodToken); err != nil {
		t.Fatal(err)
	}
	if v, err := vt.Detokenize(ctx, reader, goodToken); err != nil || v != "good" {
		t.Fatalf("the readable token must survive the sweep: %q %v", v, err)
	}
}

// Retire's error branches, one per denied table: the purge, the audit
// record and the commit are one transaction, so a failure in any of them
// must leave the version RETIRING - a half-retired key is a key whose token
// rows are gone while lookups still compute under it.
func TestRetireFailsClosedPerTable(t *testing.T) {
	for _, table := range []string{"person_tokens", "audit", "keys"} {
		t.Run(table, func(t *testing.T) {
			e := newFaultEnv(t, table)
			ctx := context.Background()
			e.register(t)

			adminRing := &service.KeyRing{Pool: e.admin.Pool, RetireGrace: -1}
			if _, err := adminRing.Rotate(ctx, e.oti.Eng, crypto.KeyHMACEmail); err != nil {
				t.Fatal(err)
			}
			// Retire through the DENIED pool.
			denied := &service.KeyRing{Pool: e.svc.Pool, RetireGrace: -1}
			if err := denied.Retire(ctx, crypto.KeyHMACEmail, "v1"); err == nil {
				t.Fatalf("retire must fail closed when %s is unavailable", table)
			}
			// The version is still RETIRING: nothing was half-applied.
			var status string
			if err := e.admin.Pool.QueryRow(ctx,
				`SELECT status FROM keys WHERE key_id=$1`, crypto.KeyHMACEmail+"/v1").Scan(&status); err != nil {
				t.Fatal(err)
			}
			if status != "RETIRING" {
				t.Errorf("a failed retire must leave the version RETIRING, got %s", status)
			}
			// ...and its token rows are intact, so lookups still work.
			var tokens int
			if err := e.admin.Pool.QueryRow(ctx,
				`SELECT count(*) FROM person_tokens WHERE key_version='v1'`).Scan(&tokens); err != nil {
				t.Fatal(err)
			}
			if tokens == 0 {
				t.Error("a failed retire must not have purged the token rows")
			}
		})
	}
}

// Rotate's guards: an unknown kind, and the audited record every rotation
// leaves in the chain.
func TestRotateGuardsAndAudit(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	ring := &service.KeyRing{Pool: e.admin.Pool, RetireGrace: -1}

	if _, err := ring.Rotate(ctx, e.oti.Eng, "not-a-kind"); err == nil {
		t.Fatal("an unknown key kind must be refused")
	}
	if _, err := ring.Rotate(ctx, e.oti.Eng, crypto.KeyHMACEmail); err != nil {
		t.Fatal(err)
	}
	var audited int
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM audit WHERE action='keys.rotate'`).Scan(&audited); err != nil {
		t.Fatal(err)
	}
	if audited != 1 {
		t.Fatalf("a rotation must be on the chain exactly once, got %d", audited)
	}
	// The newest ACTIVE version cannot be retired - rotate first.
	if err := ring.Retire(ctx, crypto.KeyHMACEmail, "v2"); err == nil {
		t.Fatal("the ACTIVE version must not be retirable")
	}
}

// rekeyVaults' remaining branches: a run where every store already carries
// the newest KEK and layout (the common case - the sweep is idempotent and
// operators rerun it until it reports zero), and the wrapped-key path for a
// person who really does have a record key.
func TestRekeyIsIdempotentAcrossEveryVault(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cid := e.register(t)

	adminRing := &service.KeyRing{Pool: e.admin.Pool, RetireGrace: -1}
	admin := &service.Contacts{Pool: e.admin.Pool, Tok: e.svc.Tok, PII: e.svc.PII,
		Ring: adminRing, VersionsKeep: 3}
	client := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions:  []string{auth.ActTokensCreate, auth.ActFilesWrite},
		AllowedPurposes: []string{"support"}}

	// Populate every store the sweep walks: a value token, a version
	// snapshot, a real record key (via a file), and a portal payload.
	vt := &service.ValueTokens{Pool: e.admin.Pool, Eng: e.oti.Eng, Ring: adminRing, Tok: e.svc.Tok}
	if _, err := vt.Tokenize(ctx, client, service.TokenizeInput{Type: "string", Value: "v1", CID: cid}); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Register(ctx, e.crm, service.RegisterInput{
		Email: "fault@example.com", Attributes: map[string]string{"tier": "silver"}}); err != nil {
		t.Fatal(err)
	}
	drv, err := storage.Open(storage.Config{Kind: "local", Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	files := &service.Files{Pool: e.admin.Pool, Eng: e.oti.Eng, Ring: adminRing,
		Store: drv, Contacts: admin, MaxBytes: 1 << 20}
	if _, err := files.Upload(ctx, client, cid, "f.txt", "text/plain",
		bytes.NewReader([]byte("file content"))); err != nil {
		t.Fatal(err)
	}
	portal := &service.Portal{GDPR: &service.GDPR{Pool: e.admin.Pool, Contacts: admin}, Contacts: admin}
	if err := portal.Start(ctx, "fault@example.com"); err != nil {
		t.Fatal(err)
	}

	// First sweep after a rotation: everything converts.
	if _, err := adminRing.Rotate(ctx, e.oti.Eng, crypto.KeyPIIKEK); err != nil {
		t.Fatal(err)
	}
	first, err := admin.Rekey(ctx, true, 500)
	if err != nil {
		t.Fatal(err)
	}
	if first.ValueTokensRewrapped == 0 || first.RecordKeysRewrapped == 0 ||
		first.VersionsRewrapped == 0 || first.OutboxRewrapped == 0 {
		t.Fatalf("every pii-kek-sealed store must be swept: %+v", first)
	}

	// Second sweep: a no-op. An operator reruns until it reports zero, so
	// "zero" has to actually mean converged.
	second, err := admin.Rekey(ctx, true, 500)
	if err != nil {
		t.Fatal(err)
	}
	if second.ValueTokensRewrapped != 0 || second.RecordKeysRewrapped != 0 ||
		second.VersionsRewrapped != 0 || second.OutboxRewrapped != 0 || second.BlobsReenc != 0 {
		t.Fatalf("a converged sweep must report zero work: %+v", second)
	}
	if second.Skipped != 0 || second.Raced != 0 {
		t.Fatalf("a converged sweep must report no skips or races either: %+v", second)
	}
	// And the file still downloads: the record key was re-wrapped, not lost.
	var buf bytes.Buffer
	var fileID string
	if err := e.admin.Pool.QueryRow(ctx, `SELECT id::text FROM files LIMIT 1`).Scan(&fileID); err != nil {
		t.Fatal(err)
	}
	reader := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions: []string{auth.ActFilesRead}, AllowedPurposes: []string{"support"}}
	if _, err := files.Download(ctx, reader, fileID, "support", &buf); err != nil {
		t.Fatalf("the file must survive a KEK rotation: %v", err)
	}
	if buf.String() != "file content" {
		t.Fatalf("the file content changed across the sweep: %q", buf.String())
	}
}
