package service_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/service"
	"github.com/fvisic/sunder/internal/storage"
)

func tokenEnv(t *testing.T) (*faultEnv, *service.ValueTokens, *auth.Client) {
	t.Helper()
	e := newFaultEnv(t)
	// The same engine/ring the env's Contacts uses (PII holds the engine;
	// the ring lives on the service).
	v := &service.ValueTokens{Pool: e.admin.Pool, Eng: e.svc.PII.Engine(), Ring: e.svc.Ring, Tok: e.svc.Tok}
	client := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions: []string{auth.ActTokensCreate, auth.ActTokensRead, auth.ActTokensDelete}}
	return e, v, client
}

func TestValueTokenLifecycle(t *testing.T) {
	e, v, client := tokenEnv(t)
	ctx := context.Background()

	tok, err := v.Tokenize(ctx, client, service.TokenizeInput{Value: "HR12 2360 0001"})
	if err != nil || !strings.HasPrefix(tok, "VT-") {
		t.Fatalf("tokenize: %q %v", tok, err)
	}
	got, err := v.Detokenize(ctx, client, tok)
	if err != nil || got != "HR12 2360 0001" {
		t.Fatalf("detokenize: %q %v", got, err)
	}

	// Scope isolation: another scope's client gets a plain miss.
	foreign := &auth.Client{ID: "erp", Scope: "erp",
		AllowedActions: []string{auth.ActTokensRead}}
	if _, err := v.Detokenize(ctx, foreign, tok); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("foreign scope must miss, indistinguishably: %v", err)
	}

	// Delete, then the owner misses too - and the miss is audited.
	if err := v.Delete(ctx, client, tok); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Detokenize(ctx, client, tok); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("deleted token must miss: %v", err)
	}
	if err := v.Delete(ctx, client, tok); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("double delete must be a miss: %v", err)
	}

	// Guards.
	if _, err := v.Tokenize(ctx, client, service.TokenizeInput{}); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("empty value: %v", err)
	}
	if _, err := v.Tokenize(ctx, client, service.TokenizeInput{Value: strings.Repeat("x", 9000)}); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("oversized value: %v", err)
	}
	noPerm := &auth.Client{ID: "np", Scope: "crm"}
	if _, err := v.Tokenize(ctx, noPerm, service.TokenizeInput{Value: "x"}); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("missing action: %v", err)
	}
	_ = e
}

func TestValueTokenCardShape(t *testing.T) {
	_, v, client := tokenEnv(t)
	ctx := context.Background()

	// A real Luhn-valid PAN (the canonical test number).
	tok, err := v.Tokenize(ctx, client, service.TokenizeInput{Type: "card", Value: "4111 1111 1111 1111"})
	if err != nil {
		t.Fatal(err)
	}
	// Same digit count, valid Luhn, and NOT the original.
	if len(tok) != 16 {
		t.Fatalf("card token must preserve length, got %d (%q)", len(tok), tok)
	}
	for _, r := range tok {
		if r < '0' || r > '9' {
			t.Fatalf("card token must be digits only: %q", tok)
		}
	}
	if tok == "4111111111111111" {
		t.Fatal("token must not equal the original")
	}
	if tok[:6] == "411111" {
		t.Fatal("BIN must not be preserved")
	}
	sum, alt := 0, false
	for i := len(tok) - 1; i >= 0; i-- {
		d := int(tok[i] - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	if sum%10 != 0 {
		t.Fatalf("card token must satisfy Luhn: %q", tok)
	}
	// Round trip returns the original PAN as given.
	if got, err := v.Detokenize(ctx, client, tok); err != nil || got != "4111 1111 1111 1111" {
		t.Fatalf("card round trip: %q %v", got, err)
	}
	// A non-Luhn "card" is refused - it was never a card number.
	if _, err := v.Tokenize(ctx, client, service.TokenizeInput{Type: "card", Value: "4111111111111112"}); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("non-Luhn card must be refused: %v", err)
	}
}

func TestValueTokenUniqueDedupAndExpiry(t *testing.T) {
	e, v, client := tokenEnv(t)
	ctx := context.Background()

	a, err := v.Tokenize(ctx, client, service.TokenizeInput{Value: "HR12", Unique: true})
	if err != nil {
		t.Fatal(err)
	}
	b, err := v.Tokenize(ctx, client, service.TokenizeInput{Value: "HR12", Unique: true})
	if err != nil || b != a {
		t.Fatalf("unique dedup must return the same token: %q vs %q (%v)", a, b, err)
	}
	// Same value in ANOTHER scope must NOT dedup to the same token: the
	// hash is scope-bound or one tenant could probe another's values.
	foreign := &auth.Client{ID: "erp", Scope: "erp",
		AllowedActions: []string{auth.ActTokensCreate}}
	c, err := v.Tokenize(ctx, foreign, service.TokenizeInput{Value: "HR12", Unique: true})
	if err != nil || c == a {
		t.Fatalf("cross-scope dedup must not collide: %q vs %q (%v)", c, a, err)
	}

	// Sliding expiry: a starved window is a miss; the pruner removes it.
	s, err := v.Tokenize(ctx, client, service.TokenizeInput{Value: "short", SlidingSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.admin.Pool.Exec(ctx,
		`UPDATE value_tokens SET last_used = now() - interval '10 minutes' WHERE token=$1`, s); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Detokenize(ctx, client, s); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("starved sliding window must be a miss: %v", err)
	}
	n, err := service.PruneValueTokens(ctx, e.admin.Pool)
	if err != nil || n == 0 {
		t.Fatalf("prune must sweep the starved token: %d %v", n, err)
	}

	// Final expiry in the past: miss on arrival.
	f, err := v.Tokenize(ctx, client, service.TokenizeInput{Value: "gone", ExpiresFinal: "2020-01-01T00:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Detokenize(ctx, client, f); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("finally-expired token must miss: %v", err)
	}
}

func TestValueTokenBulk(t *testing.T) {
	_, v, client := tokenEnv(t)
	ctx := context.Background()

	items := []service.TokenizeInput{{Value: "a"}, {Value: "b"}, {Value: "c"}}
	tokens, err := v.TokenizeBulk(ctx, client, items)
	if err != nil || len(tokens) != 3 {
		t.Fatalf("bulk create: %v %v", tokens, err)
	}
	// Bulk read: order preserved, a deleted token is an empty slot.
	if err := v.Delete(ctx, client, tokens[1]); err != nil {
		t.Fatal(err)
	}
	values, err := v.DetokenizeBulk(ctx, client, tokens)
	if err != nil {
		t.Fatal(err)
	}
	if values[0] != "a" || values[1] != "" || values[2] != "c" {
		t.Fatalf("bulk read slots: %v", values)
	}
	// Caps and guards.
	if _, err := v.TokenizeBulk(ctx, client, nil); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("empty bulk: %v", err)
	}
	big := make([]service.TokenizeInput, 1001)
	for i := range big {
		big[i] = service.TokenizeInput{Value: "x"}
	}
	if _, err := v.TokenizeBulk(ctx, client, big); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("over-cap bulk: %v", err)
	}
	// A bad item fails the WHOLE batch - no silent holes in a migration.
	if _, err := v.TokenizeBulk(ctx, client, []service.TokenizeInput{{Value: "ok"}, {Value: ""}}); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("bad item must fail the batch: %v", err)
	}
}

func TestValueTokenBulkReadHTTPPath(t *testing.T) {
	_, v, client := tokenEnv(t)
	ctx := context.Background()
	a, _ := v.Tokenize(ctx, client, service.TokenizeInput{Value: "one"})
	b, _ := v.Tokenize(ctx, client, service.TokenizeInput{Value: "two"})
	vals, err := v.DetokenizeBulk(ctx, client, []string{a, "VT-NONEXISTENT", b})
	if err != nil {
		t.Fatal(err)
	}
	if vals[0] != "one" || vals[1] != "" || vals[2] != "two" {
		t.Fatalf("bulk read with a miss in the middle: %v", vals)
	}
	// Permission guard on the bulk read path.
	noPerm := &auth.Client{ID: "np", Scope: "crm"}
	if _, err := v.DetokenizeBulk(ctx, noPerm, []string{a}); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("bulk read without action: %v", err)
	}
	if _, err := v.TokenizeBulk(ctx, noPerm, []service.TokenizeInput{{Value: "x"}}); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("bulk create without action: %v", err)
	}
}

func TestValueTokenFailsClosedUnderDeniedTable(t *testing.T) {
	e := newFaultEnv(t, "value_tokens")
	v := &service.ValueTokens{Pool: e.svc.Pool, Eng: e.svc.PII.Engine(), Ring: e.svc.Ring, Tok: e.svc.Tok}
	client := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions: []string{auth.ActTokensCreate, auth.ActTokensRead}}
	ctx := context.Background()
	if _, err := v.Tokenize(ctx, client, service.TokenizeInput{Value: "x"}); err == nil {
		t.Fatal("tokenize without table rights must error")
	}
	if _, err := v.Tokenize(ctx, client, service.TokenizeInput{Value: "x", Unique: true}); err == nil {
		t.Fatal("unique tokenize without table rights must error")
	}
	if _, err := v.Detokenize(ctx, client, "VT-X"); err == nil {
		t.Fatal("detokenize without table rights must error")
	}
	if err := v.Delete(ctx, client, "VT-X"); err == nil {
		t.Fatal("delete without table rights must error")
	}
	if _, err := service.PruneValueTokens(ctx, e.svc.Pool); err == nil {
		t.Fatal("prune without table rights must error")
	}
}

func TestValueTokenCardLengthGuards(t *testing.T) {
	_, v, client := tokenEnv(t)
	ctx := context.Background()
	// Too short to be a card even if Luhn-shaped.
	if _, err := v.Tokenize(ctx, client, service.TokenizeInput{Type: "card", Value: "0"}); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("too-short card: %v", err)
	}
	// Bad type.
	if _, err := v.Tokenize(ctx, client, service.TokenizeInput{Type: "bogus", Value: "x"}); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("bad type: %v", err)
	}
	// Bad expiry format and negative sliding.
	if _, err := v.Tokenize(ctx, client, service.TokenizeInput{Value: "x", ExpiresFinal: "not-a-date"}); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("bad expiry: %v", err)
	}
	if _, err := v.Tokenize(ctx, client, service.TokenizeInput{Value: "x", SlidingSeconds: -1}); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("negative sliding: %v", err)
	}
}

func TestValueTokenUniqueRefreshesOnHit(t *testing.T) {
	e, v, client := tokenEnv(t)
	ctx := context.Background()
	a, err := v.Tokenize(ctx, client, service.TokenizeInput{Value: "HR12", Unique: true, SlidingSeconds: 3600})
	if err != nil {
		t.Fatal(err)
	}
	// Backdate last_used, then a dedup hit must refresh it.
	if _, err := e.admin.Pool.Exec(ctx,
		`UPDATE value_tokens SET last_used = now() - interval '10 minutes' WHERE token=$1`, a); err != nil {
		t.Fatal(err)
	}
	b, err := v.Tokenize(ctx, client, service.TokenizeInput{Value: "HR12", Unique: true, SlidingSeconds: 3600})
	if err != nil || b != a {
		t.Fatalf("dedup: %q %v", b, err)
	}
	var recent bool
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT last_used > now() - interval '1 minute' FROM value_tokens WHERE token=$1`, a).Scan(&recent); err != nil {
		t.Fatal(err)
	}
	if !recent {
		t.Fatal("a dedup hit must refresh the sliding window")
	}
}

func TestValueTokenDeleteAuditDenied(t *testing.T) {
	// Create a token with a privileged env, then attempt Delete/Detokenize
	// through a service whose audit table is denied.
	e := newFaultEnv(t, "audit")
	v := &service.ValueTokens{Pool: e.svc.Pool, Eng: e.svc.PII.Engine(), Ring: e.svc.Ring, Tok: e.svc.Tok}
	// Seed a row directly (Tokenize would fail on the denied audit).
	ctx := context.Background()
	if _, err := e.admin.Pool.Exec(ctx, `
		INSERT INTO value_tokens (token, scope, token_type, ciphertext, key_id, alg)
		VALUES ('VT-SEED', 'crm', 'string', '\x00'::bytea, 'v1', 'aes256gcm')`); err != nil {
		t.Fatal(err)
	}
	client := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions: []string{auth.ActTokensCreate}}
	if err := v.Delete(ctx, client, "VT-SEED"); err == nil {
		t.Fatal("delete must fail when audit is denied")
	}
}

func TestValueTokenKeysDenied(t *testing.T) {
	e := newFaultEnv(t, "keys")
	v := &service.ValueTokens{Pool: e.svc.Pool, Eng: e.svc.PII.Engine(), Ring: e.svc.Ring, Tok: e.svc.Tok}
	client := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions: []string{auth.ActTokensCreate}}
	ctx := context.Background()
	// sealKey (Ring.Newest) fails when the keys table is denied.
	if _, err := v.Tokenize(ctx, client, service.TokenizeInput{Value: "x"}); err == nil {
		t.Fatal("tokenize must fail when key versions cannot be read")
	}
	// The unique path also needs the key for the HMAC domain.
	if _, err := v.Tokenize(ctx, client, service.TokenizeInput{Value: "x", Unique: true}); err == nil {
		t.Fatal("unique tokenize must fail when keys are denied")
	}
}

func TestValueTokenSlidingRefreshOnRead(t *testing.T) {
	e, v, client := tokenEnv(t)
	ctx := context.Background()
	tok, err := v.Tokenize(ctx, client, service.TokenizeInput{Value: "keep", SlidingSeconds: 3600})
	if err != nil {
		t.Fatal(err)
	}
	// Backdate, read (which refreshes), verify last_used moved forward.
	if _, err := e.admin.Pool.Exec(ctx,
		`UPDATE value_tokens SET last_used = now() - interval '10 minutes' WHERE token=$1`, tok); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Detokenize(ctx, client, tok); err != nil {
		t.Fatal(err)
	}
	var recent bool
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT last_used > now() - interval '1 minute' FROM value_tokens WHERE token=$1`, tok).Scan(&recent); err != nil {
		t.Fatal(err)
	}
	if !recent {
		t.Fatal("a read must refresh the sliding window")
	}
}

func TestValueTokenBulkReadErrorPropagates(t *testing.T) {
	e, v, client := tokenEnv(t)
	ctx := context.Background()
	tok, err := v.Tokenize(ctx, client, service.TokenizeInput{Value: "a"})
	if err != nil {
		t.Fatal(err)
	}
	// Break value_tokens so a bulk read hits a hard error (not a miss) and
	// propagates it instead of returning an empty slot.
	if _, err := e.admin.Pool.Exec(ctx, `ALTER TABLE value_tokens RENAME TO vt_gone`); err != nil {
		t.Fatal(err)
	}
	if _, err := v.DetokenizeBulk(ctx, client, []string{tok}); err == nil {
		t.Fatal("bulk read must propagate a hard error")
	}
	if _, err := v.TokenizeBulk(ctx, client, []service.TokenizeInput{{Value: "x"}}); err == nil {
		t.Fatal("bulk create must propagate a hard error")
	}
}

// TestReviewH1_UniqueSurvivesKekRotation: the unique dedup hash must not be
// named by the pii-kek version (a rotated KEK would name a nonexistent
// hmac key). Rotate the KEK, then unique tokenization must still work and
// still dedup.
func TestReviewH1_UniqueSurvivesKekRotation(t *testing.T) {
	e, v, client := tokenEnv(t)
	ctx := context.Background()
	a, err := v.Tokenize(ctx, client, service.TokenizeInput{Value: "HR12", Unique: true})
	if err != nil {
		t.Fatal(err)
	}
	// Rotate the pii-kek (the documented operation that triggered H1).
	if _, err := e.svc.Ring.Rotate(ctx, e.svc.PII.Engine(), "pii-kek"); err != nil {
		t.Fatal(err)
	}
	b, err := v.Tokenize(ctx, client, service.TokenizeInput{Value: "HR12", Unique: true})
	if err != nil {
		t.Fatalf("unique tokenize must survive a kek rotation: %v", err)
	}
	if b != a {
		t.Fatalf("dedup must still hit after rotation: %q vs %q", b, a)
	}
}

// TestReviewM1_UniqueBindsTypeAndSkipsExpired.
func TestReviewM1_UniqueBindsTypeAndSkipsExpired(t *testing.T) {
	_, v, client := tokenEnv(t)
	ctx := context.Background()
	// A card and a string of the same digits must NOT dedup to each other.
	sTok, err := v.Tokenize(ctx, client, service.TokenizeInput{Value: "4111111111111111", Unique: true})
	if err != nil {
		t.Fatal(err)
	}
	cTok, err := v.Tokenize(ctx, client, service.TokenizeInput{Type: "card", Value: "4111111111111111", Unique: true})
	if err != nil {
		t.Fatal(err)
	}
	if sTok == cTok {
		t.Fatal("string and card unique tokens of the same value must not collide")
	}
	// An expired unique row must not be returned by a fresh unique request.
	exp, err := v.Tokenize(ctx, client, service.TokenizeInput{Value: "OLD", Unique: true, ExpiresFinal: "2020-01-01T00:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	again, err := v.Tokenize(ctx, client, service.TokenizeInput{Value: "OLD", Unique: true})
	if err != nil {
		t.Fatal(err)
	}
	if again == exp {
		t.Fatal("a fresh unique request must not return an already-expired token")
	}
}

// TestReviewM4_BulkAtomic: a bad item rolls the whole batch back - no
// orphaned rows.
func TestReviewM4_BulkAtomic(t *testing.T) {
	e, v, client := tokenEnv(t)
	ctx := context.Background()
	_, err := v.TokenizeBulk(ctx, client, []service.TokenizeInput{
		{Value: "one"}, {Value: "two"}, {Value: ""}}) // third is invalid
	if err == nil {
		t.Fatal("a bad item must fail the batch")
	}
	var n int64
	if err := e.admin.Pool.QueryRow(ctx, `SELECT count(*) FROM value_tokens`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("a failed bulk must leave no rows, got %d", n)
	}
}

func TestValueTokenBulkFaultRollsBack(t *testing.T) {
	e, v, client := tokenEnv(t)
	ctx := context.Background()
	// Break the table mid-batch: the whole transaction must roll back.
	if _, err := e.admin.Pool.Exec(ctx, `ALTER TABLE value_tokens RENAME TO vt_bulk_gone`); err != nil {
		t.Fatal(err)
	}
	if _, err := v.TokenizeBulk(ctx, client, []service.TokenizeInput{{Value: "a"}, {Value: "b"}}); err == nil {
		t.Fatal("bulk must fail when the table is broken")
	}
	if _, err := e.admin.Pool.Exec(ctx, `ALTER TABLE vt_bulk_gone RENAME TO value_tokens`); err != nil {
		t.Fatal(err)
	}
	// Keys denied breaks the seal key up front.
	e2 := newFaultEnv(t, "keys")
	v2 := &service.ValueTokens{Pool: e2.svc.Pool, Eng: e2.svc.PII.Engine(), Ring: e2.svc.Ring, Tok: e2.svc.Tok}
	if _, err := v2.TokenizeBulk(ctx, client, []service.TokenizeInput{{Value: "a"}}); err == nil {
		t.Fatal("bulk must fail when keys are denied")
	}
}

func TestValueTokenDeleteNeedsDeleteAction(t *testing.T) {
	_, v, client := tokenEnv(t)
	ctx := context.Background()
	tok, err := v.Tokenize(ctx, client, service.TokenizeInput{Value: "x"})
	if err != nil {
		t.Fatal(err)
	}
	// A create+read client without tokens.delete cannot destroy mappings.
	writer := &auth.Client{ID: "w", Scope: "crm",
		AllowedActions: []string{auth.ActTokensCreate, auth.ActTokensRead}}
	if err := v.Delete(ctx, writer, tok); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("delete without tokens.delete must be forbidden: %v", err)
	}
}

// TestReviewM5_RekeyRewrapsVaults: after a kek rotation + rekey, value
// tokens and record keys are wrapped under the newest kek, so retiring the
// old kek actually protects F4/F5 data.
func TestReviewM5_RekeyRewrapsVaults(t *testing.T) {
	e, v, client := tokenEnv(t)
	ctx := context.Background()
	// A value token and a file (record key) under the current kek.
	tok, err := v.Tokenize(ctx, client, service.TokenizeInput{Value: "iban-123"})
	if err != nil {
		t.Fatal(err)
	}
	drv, err := storage.Open(storage.Config{Kind: "local", Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	files := &service.Files{Pool: e.admin.Pool, Eng: e.svc.PII.Engine(), Ring: e.svc.Ring,
		Store: drv, Contacts: e.svc, MaxBytes: 1 << 20}
	fclient := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions:  []string{auth.ActFilesWrite, auth.ActFilesRead, auth.ActContactsRegister},
		AllowedPurposes: []string{"support"}}
	cid, err := e.svc.Register(ctx, fclient, service.RegisterInput{Email: "m5@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	fm, err := files.Upload(ctx, fclient, cid, "f.txt", "", strings.NewReader("secret"))
	if err != nil {
		t.Fatal(err)
	}

	// Note the current key ids.
	var vtKey, rkKey string
	e.admin.Pool.QueryRow(ctx, `SELECT key_id FROM value_tokens WHERE token=$1`, tok).Scan(&vtKey)
	e.admin.Pool.QueryRow(ctx, `SELECT rk.key_id FROM person_record_keys rk JOIN cids c ON c.person_id=rk.person_id WHERE c.cid=$1`, cid).Scan(&rkKey)

	// Rotate the kek and rekey with -reencrypt.
	newKEK, err := e.svc.Ring.Rotate(ctx, e.svc.PII.Engine(), "pii-kek")
	if err != nil {
		t.Fatal(err)
	}
	stats, err := e.svc.Rekey(ctx, true, 100)
	if err != nil {
		t.Fatal(err)
	}
	if stats.ValueTokensRewrapped < 1 || stats.RecordKeysRewrapped < 1 {
		t.Fatalf("rekey must re-wrap the vaults: %+v", stats)
	}
	// Both now point at the newest kek.
	var vtKey2, rkKey2 string
	e.admin.Pool.QueryRow(ctx, `SELECT key_id FROM value_tokens WHERE token=$1`, tok).Scan(&vtKey2)
	e.admin.Pool.QueryRow(ctx, `SELECT rk.key_id FROM person_record_keys rk JOIN cids c ON c.person_id=rk.person_id WHERE c.cid=$1`, cid).Scan(&rkKey2)
	if vtKey2 != newKEK || rkKey2 != newKEK {
		t.Fatalf("vaults not moved to newest kek: vt=%s rk=%s newest=%s", vtKey2, rkKey2, newKEK)
	}
	if vtKey2 == vtKey || rkKey2 == rkKey {
		t.Fatal("key ids should have changed after rekey")
	}
	// Data still reads correctly under the new wrapping.
	got, err := v.Detokenize(ctx, client, tok)
	if err != nil || got != "iban-123" {
		t.Fatalf("token still readable: %q %v", got, err)
	}
	var out bytes.Buffer
	if _, err := files.Download(ctx, fclient, fm.ID, "support", &out); err != nil || out.String() != "secret" {
		t.Fatalf("file still readable: %q %v", out.String(), err)
	}
}

func TestRekeyVaultsFaultBranches(t *testing.T) {
	e, v, client := tokenEnv(t)
	ctx := context.Background()
	if _, err := v.Tokenize(ctx, client, service.TokenizeInput{Value: "x"}); err != nil {
		t.Fatal(err)
	}
	// A corrupt ciphertext must be counted as Skipped, not abort the rekey.
	if _, err := e.admin.Pool.Exec(ctx,
		`UPDATE value_tokens SET ciphertext = $1, key_id='v0'`, []byte{0, 1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	stats, err := e.svc.Rekey(ctx, true, 100)
	if err != nil {
		t.Fatalf("a corrupt token must be skipped, not fatal: %v", err)
	}
	if stats.Skipped < 1 {
		t.Fatalf("corrupt token should be skipped: %+v", stats)
	}

	// A broken value_tokens table makes rekeyVaults' query fail.
	e2, v2, c2 := tokenEnv(t)
	if _, err := v2.Tokenize(ctx, c2, service.TokenizeInput{Value: "y"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e2.admin.Pool.Exec(ctx, `ALTER TABLE value_tokens RENAME TO vt_rekey_gone`); err != nil {
		t.Fatal(err)
	}
	if _, err := e2.svc.Rekey(ctx, true, 100); err == nil {
		t.Fatal("rekey must fail when value_tokens is broken")
	}
	if _, err := e2.admin.Pool.Exec(ctx, `ALTER TABLE vt_rekey_gone RENAME TO value_tokens`); err != nil {
		t.Fatal(err)
	}

	// A broken person_record_keys table makes the record-key pass fail.
	e3 := newFaultEnv(t)
	if _, err := e3.admin.Pool.Exec(ctx, `ALTER TABLE person_record_keys RENAME TO prk_gone`); err != nil {
		t.Fatal(err)
	}
	if _, err := e3.svc.Rekey(ctx, true, 100); err == nil {
		t.Fatal("rekey must fail when person_record_keys is broken")
	}
}

func TestRekeyFailsWhenKeysUnavailable(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	// Break the keys table: Rekey's Newest lookups must surface the error
	// up front, before touching any data.
	if _, err := e.admin.Pool.Exec(ctx, `ALTER TABLE keys RENAME TO keys_gone`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Rekey(ctx, true, 100); err == nil {
		t.Fatal("rekey must fail when key versions cannot be read")
	}
}

func TestBulkUniqueDedupHit(t *testing.T) {
	_, v, client := tokenEnv(t)
	ctx := context.Background()
	// A bulk with the SAME unique value twice: the second dedups to the
	// first within the batch transaction.
	toks, err := v.TokenizeBulk(ctx, client, []service.TokenizeInput{
		{Value: "SAME", Unique: true}, {Value: "SAME", Unique: true}})
	if err != nil {
		t.Fatal(err)
	}
	if toks[0] != toks[1] {
		t.Fatalf("bulk unique dedup must return the same token: %v", toks)
	}
}

// TestS4_ValueTokensDieWithThePerson: a token minted for a person's CID must
// not survive that person's erasure - value_tokens was the one PII table
// erasure could not reach (S4).
func TestS4_ValueTokensDieWithThePerson(t *testing.T) {
	e, v, client := tokenEnv(t)
	ctx := context.Background()
	reg := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions: []string{auth.ActContactsRegister, auth.ActDSRErase}}
	cid, err := e.svc.Register(ctx, reg, service.RegisterInput{
		Email: "s4@example.com", Attributes: map[string]string{"iban": "HR12"}})
	if err != nil {
		t.Fatal(err)
	}

	bound, err := v.Tokenize(ctx, client, service.TokenizeInput{Value: "HR99 1500 0001", CID: cid})
	if err != nil {
		t.Fatal(err)
	}
	free, err := v.Tokenize(ctx, client, service.TokenizeInput{Value: "SCOPE-WIDE-SECRET"})
	if err != nil {
		t.Fatal(err)
	}

	// A CID outside the caller's scope (or absent) is refused - one tenant's
	// erasure must never reach another tenant's token.
	erpReg := &auth.Client{ID: "erp", Scope: "erp", AllowedActions: []string{auth.ActContactsRegister}}
	erpCID, err := e.svc.Register(ctx, erpReg, service.RegisterInput{Email: "s4-erp@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Tokenize(ctx, client, service.TokenizeInput{Value: "x", CID: erpCID}); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("foreign-scope cid must be an indistinguishable miss: %v", err)
	}
	if _, err := v.Tokenize(ctx, client, service.TokenizeInput{Value: "x", CID: "CID-NOPE"}); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("unknown cid must be an indistinguishable miss: %v", err)
	}

	if _, _, err := e.gdpr.Erase(ctx, reg, cid); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Detokenize(ctx, client, bound); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("bound token must die with the person: %v", err)
	}
	var n int64
	if err := e.admin.Pool.QueryRow(ctx, `SELECT count(*) FROM value_tokens WHERE token=$1`, bound).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("erasure must DELETE the bound token row, %d left", n)
	}
	// The unattributed token belongs to no single subject and survives.
	if got, err := v.Detokenize(ctx, client, free); err != nil || got != "SCOPE-WIDE-SECRET" {
		t.Fatalf("unattributed token must survive: %q %v", got, err)
	}
}

// TestS4_UniqueDedupIsPerPerson: `unique: true` dedup keys on (scope, cid,
// unique_hash), so two people tokenizing the same value each hold their own
// erasable token, while no-cid callers keep the old scope-wide dedup.
func TestS4_UniqueDedupIsPerPerson(t *testing.T) {
	e, v, client := tokenEnv(t)
	ctx := context.Background()
	reg := &auth.Client{ID: "crm", Scope: "crm", AllowedActions: []string{auth.ActContactsRegister}}
	cidA, err := e.svc.Register(ctx, reg, service.RegisterInput{Email: "a@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	cidB, err := e.svc.Register(ctx, reg, service.RegisterInput{Email: "b@example.com"})
	if err != nil {
		t.Fatal(err)
	}

	tA, err := v.Tokenize(ctx, client, service.TokenizeInput{Value: "SAME", Unique: true, CID: cidA})
	if err != nil {
		t.Fatal(err)
	}
	tB, err := v.Tokenize(ctx, client, service.TokenizeInput{Value: "SAME", Unique: true, CID: cidB})
	if err != nil {
		t.Fatal(err)
	}
	if tA == tB {
		t.Fatal("two persons' unique tokens for the same value must differ (each erasable on its own)")
	}
	tA2, err := v.Tokenize(ctx, client, service.TokenizeInput{Value: "SAME", Unique: true, CID: cidA})
	if err != nil || tA2 != tA {
		t.Fatalf("same person + same value must dedup: %q vs %q (%v)", tA2, tA, err)
	}
	// No-cid callers keep scope-wide dedup, separate from any person's token.
	g1, err := v.Tokenize(ctx, client, service.TokenizeInput{Value: "SAME", Unique: true})
	if err != nil {
		t.Fatal(err)
	}
	g2, err := v.Tokenize(ctx, client, service.TokenizeInput{Value: "SAME", Unique: true})
	if err != nil || g1 != g2 {
		t.Fatalf("scope-wide dedup must hold: %q vs %q (%v)", g1, g2, err)
	}
	if g1 == tA || g1 == tB {
		t.Fatal("the unattributed unique token must not collide with a person's")
	}
}

// TestS4_TokenizeRefusesTombstonedCID (review F2): the cid check must go
// through the same tombstone predicate as every CID-addressed path - a token
// minted FOR an erased person after their erasure would be permanently
// outside erasure's reach (the second Erase is refused, so the delete can
// never run again).
func TestS4_TokenizeRefusesTombstonedCID(t *testing.T) {
	e, v, client := tokenEnv(t)
	ctx := context.Background()
	reg := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions: []string{auth.ActContactsRegister, auth.ActDSRErase}}
	cid, err := e.svc.Register(ctx, reg, service.RegisterInput{Email: "f2@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.gdpr.Erase(ctx, reg, cid); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Tokenize(ctx, client, service.TokenizeInput{Value: "AFTER-ERASURE", CID: cid}); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("a tombstoned cid must be refused indistinguishably: %v", err)
	}
	var n int64
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM value_tokens WHERE cid=$1`, cid).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("no token may be stored against a tombstone, found %d", n)
	}
}

// TestS4_CidTokenizeAdoptsPreUpgradeAlias (review F5): a value tokenized
// unique WITHOUT a cid before the upgrade must not become a second, never-
// erasable alias when the caller starts passing the cid - the cid-bearing
// call adopts the existing row, and erasure then reaches it.
func TestS4_CidTokenizeAdoptsPreUpgradeAlias(t *testing.T) {
	e, v, client := tokenEnv(t)
	ctx := context.Background()
	reg := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions: []string{auth.ActContactsRegister, auth.ActDSRErase}}
	cid, err := e.svc.Register(ctx, reg, service.RegisterInput{Email: "f5@example.com"})
	if err != nil {
		t.Fatal(err)
	}

	pre, err := v.Tokenize(ctx, client, service.TokenizeInput{Value: "HR-PRE-UPGRADE", Unique: true})
	if err != nil {
		t.Fatal(err)
	}
	bound, err := v.Tokenize(ctx, client, service.TokenizeInput{Value: "HR-PRE-UPGRADE", Unique: true, CID: cid})
	if err != nil {
		t.Fatal(err)
	}
	if bound != pre {
		t.Fatalf("the cid-bearing call must ADOPT the pre-upgrade row, not mint an alias: %q vs %q", bound, pre)
	}
	var total int64
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM value_tokens WHERE scope='crm'`).Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total != 1 {
		t.Fatalf("exactly one live token may exist for the value, found %d", total)
	}
	// A second person tokenizing the same value now gets their OWN token
	// (the row is already claimed).
	cid2, err := e.svc.Register(ctx, reg, service.RegisterInput{Email: "f5b@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	other, err := v.Tokenize(ctx, client, service.TokenizeInput{Value: "HR-PRE-UPGRADE", Unique: true, CID: cid2})
	if err != nil {
		t.Fatal(err)
	}
	if other == bound {
		t.Fatal("a claimed row must not be re-adopted by a different person")
	}
	// And erasure now reaches the adopted token.
	if _, _, err := e.gdpr.Erase(ctx, reg, cid); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Detokenize(ctx, client, bound); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("the adopted token must die with the person: %v", err)
	}
}

// TestS4_TokenizeRacingErasureCannotLandToken (review N2): the locking read
// must target PERSONS - EvalPlanQual re-fetches only FOR UPDATE targets, so
// locking cids alone re-evaluated erased_at against a STALE persons tuple
// and a tokenize racing an erasure landed an unerasable token. The persons
// row is the serialization point with erasePerson's opening guard; this
// replays the interleaving where the erasure holds it first.
func TestS4_TokenizeRacingErasureCannotLandToken(t *testing.T) {
	e, v, client := tokenEnv(t)
	ctx := context.Background()
	reg := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions: []string{auth.ActContactsRegister}}
	cid, err := e.svc.Register(ctx, reg, service.RegisterInput{Email: "n2@example.com"})
	if err != nil {
		t.Fatal(err)
	}

	// The "erasure": take the locks in erasePerson's order (cids first, then
	// the persons guard), then finish its statements and commit while the
	// tokenize below is parked on the persons FOR UPDATE.
	tx, err := e.admin.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT 1 FROM cids WHERE cid=$1 FOR UPDATE`, cid); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx,
		`SELECT erased_at FROM persons WHERE id=(SELECT person_id FROM cids WHERE cid=$1) FOR UPDATE`, cid); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE cids SET pii_encrypted=NULL WHERE cid=$1`, cid); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, terr := v.Tokenize(ctx, client, service.TokenizeInput{Value: "HR-RACED", CID: cid})
		done <- terr
	}()
	// Wait until the tokenize backend is genuinely parked on the row lock.
	deadline := time.Now().Add(10 * time.Second)
	for {
		var waiting int64
		if err := e.admin.Pool.QueryRow(ctx, `
			SELECT count(*) FROM pg_stat_activity
			 WHERE wait_event_type='Lock' AND query LIKE '%sunder:tokenize-lock%'`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("tokenize never blocked on the cids lock - the locking read may have lost its FOR UPDATE")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Finish the erasure: its value_tokens DELETE and the tombstone, then commit.
	if _, err := tx.Exec(ctx, `DELETE FROM value_tokens WHERE cid=$1`, cid); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE persons SET erased_at=now() WHERE id=(SELECT person_id FROM cids WHERE cid=$1)`, cid); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	if terr := <-done; !errors.Is(terr, service.ErrNotFound) {
		t.Fatalf("a tokenize racing the erasure must be refused, got: %v", terr)
	}
	var n int64
	if err := e.admin.Pool.QueryRow(ctx, `SELECT count(*) FROM value_tokens WHERE cid=$1`, cid).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("the race must not land an unerasable token, found %d", n)
	}
}

// TestS4_AdoptionSurvivesDeadRowInTargetSlot (review N3): a dead row already
// holding (scope, cid, unique_hash) used to make the adoption UPDATE violate
// the unique index - a raw 23505 surfacing as a 500, and in bulk with the
// unlock token already burned. The expired-slot cleanup now runs first.
func TestS4_AdoptionSurvivesDeadRowInTargetSlot(t *testing.T) {
	e, v, client := tokenEnv(t)
	ctx := context.Background()
	reg := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions: []string{auth.ActContactsRegister}}
	cid, err := e.svc.Register(ctx, reg, service.RegisterInput{Email: "n3@example.com"})
	if err != nil {
		t.Fatal(err)
	}

	dead, err := v.Tokenize(ctx, client, service.TokenizeInput{Value: "HR-N3", Unique: true, CID: cid, SlidingSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	// Starve its sliding window: the row is now dead but still occupies the
	// (scope, cid, unique_hash) slot in the partial unique index.
	if _, err := e.admin.Pool.Exec(ctx,
		`UPDATE value_tokens SET last_used = now() - interval '1 hour' WHERE token=$1`, dead); err != nil {
		t.Fatal(err)
	}
	// A live unattributed row for the same value (the pre-upgrade shape).
	free, err := v.Tokenize(ctx, client, service.TokenizeInput{Value: "HR-N3", Unique: true})
	if err != nil {
		t.Fatal(err)
	}
	// The cid-bearing call must clean the dead slot and adopt - not 500.
	got, err := v.Tokenize(ctx, client, service.TokenizeInput{Value: "HR-N3", Unique: true, CID: cid})
	if err != nil {
		t.Fatalf("adoption against a dead same-slot row must succeed: %v", err)
	}
	if got != free {
		t.Fatalf("must adopt the live unattributed row: got %q want %q", got, free)
	}
}

// TestConcurrentUniqueTokenizeConverges (review medium): a unique_hash
// collision from a CONCURRENT tokenize of the same value used to be retried
// by minting a fresh random token - which can never satisfy the constraint -
// and after three raw 23505s surfaced as a 500 (in bulk with the unlock
// token already burned). The retry now inspects the constraint and returns
// the winner's token.
func TestConcurrentUniqueTokenizeConverges(t *testing.T) {
	e, v, client := tokenEnv(t)
	ctx := context.Background()

	const workers = 8
	tokens := make([]string, workers)
	errs := make([]error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tokens[i], errs[i] = v.Tokenize(ctx, client, service.TokenizeInput{Value: "RACE-ME", Unique: true})
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("worker %d: concurrent unique tokenize must never error: %v", i, err)
		}
		if tokens[i] != tokens[0] {
			t.Fatalf("all workers must converge on ONE token: %q vs %q", tokens[i], tokens[0])
		}
	}
	var n int64
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM value_tokens WHERE scope='crm'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("exactly one row may exist, found %d", n)
	}
}

// TestTokenDeleteIsAttributed (review medium): tokens.delete used to audit an
// EMPTY detail - destroying the only copy of a sealed value left no trace of
// what was destroyed or who had minted it.
func TestTokenDeleteIsAttributed(t *testing.T) {
	e, v, client := tokenEnv(t)
	ctx := context.Background()
	tok, err := v.Tokenize(ctx, client, service.TokenizeInput{Value: "GONE-SOON"})
	if err != nil {
		t.Fatal(err)
	}
	var createdBy string
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT COALESCE(created_by,'') FROM value_tokens WHERE token=$1`, tok).Scan(&createdBy); err != nil {
		t.Fatal(err)
	}
	if createdBy != "crm" {
		t.Fatalf("mint must record its client: %q", createdBy)
	}
	if err := v.Delete(ctx, client, tok); err != nil {
		t.Fatal(err)
	}
	var detail string
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT detail FROM audit WHERE action='tokens.delete' ORDER BY seq DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(detail, tok) || !strings.Contains(detail, `"created_by":"crm"`) {
		t.Fatalf("the delete audit must attribute what was destroyed: %s", detail)
	}
}

// TestBulkValidateBeforeUnlock (review L9): a malformed item must be rejected
// by ValidateInputs BEFORE the unlock token is spent, so a bad batch cannot
// burn a single-use token. (The handler calls ValidateInputs first; this
// pins the pure validator it relies on.)
func TestBulkValidateBeforeUnlock(t *testing.T) {
	_, v, _ := tokenEnv(t)
	// empty batch, over-cap, and a bad item are all caught with no side effects.
	if err := v.ValidateInputs(nil); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("empty batch: %v", err)
	}
	big := make([]service.TokenizeInput, 1001)
	for i := range big {
		big[i] = service.TokenizeInput{Value: "x"}
	}
	if err := v.ValidateInputs(big); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("over-cap: %v", err)
	}
	batch := []service.TokenizeInput{{Value: "ok"}, {Type: "card", Value: "not-luhn"}}
	if err := v.ValidateInputs(batch); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("a bad item must fail the batch pre-unlock: %v", err)
	}
	// A clean batch validates.
	if err := v.ValidateInputs([]service.TokenizeInput{{Value: "a"}, {Value: "b"}}); err != nil {
		t.Fatalf("a clean batch must validate: %v", err)
	}
}

// The 23505 recovery branch: two callers tokenizing the SAME value with
// unique:true concurrently. One INSERT wins the partial unique index; the
// loser must return the winner's token (dedup semantics, decided by the
// database instead of the earlier SELECT), never a 500 - and never a second
// live alias for one value.
func TestConcurrentUniqueTokenizeConvergesOnOneToken(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cid := e.register(t)

	adminRing := &service.KeyRing{Pool: e.admin.Pool, RetireGrace: -1}
	vt := &service.ValueTokens{Pool: e.admin.Pool, Eng: e.oti.Eng, Ring: adminRing, Tok: e.svc.Tok}
	client := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions:  []string{auth.ActTokensCreate},
		AllowedPurposes: []string{"support"}}

	const writers = 8
	start := make(chan struct{})
	var wg sync.WaitGroup
	tokens := make([]string, writers)
	errs := make([]error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			tokens[i], errs[i] = vt.Tokenize(ctx, client, service.TokenizeInput{
				Type: "string", Value: "HR1210010051863000160", CID: cid, Unique: true})
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("writer %d: a concurrent unique tokenize must dedup, not fail: %v", i, err)
		}
	}
	for i, tok := range tokens {
		if tok != tokens[0] {
			t.Fatalf("writer %d got %s, writer 0 got %s - one value bred two live aliases", i, tok, tokens[0])
		}
	}
	var rows int
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT count(*) FROM value_tokens WHERE scope='crm'`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("unique:true must leave exactly one row, got %d", rows)
	}
}

// The bulk surface's input guards - the two the unlock token is spent
// against, so a rejected batch must not have cost the caller their
// single-use declaration of intent.
func TestBulkGuards(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	vt := &service.ValueTokens{Pool: e.admin.Pool, Eng: e.oti.Eng, Ring: e.svc.Ring, Tok: e.svc.Tok}
	client := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions:  []string{auth.ActTokensCreate, auth.ActTokensRead},
		AllowedPurposes: []string{"support"}}

	if _, err := vt.DetokenizeBulk(ctx, client, nil); err == nil {
		t.Error("an empty bulk read must be a validation error")
	}
	huge := make([]string, 1001)
	for i := range huge {
		huge[i] = "VT-X"
	}
	if _, err := vt.DetokenizeBulk(ctx, client, huge); err == nil {
		t.Error("a bulk read past the limit must be refused")
	}
	if _, err := vt.TokenizeBulk(ctx, client, nil); err == nil {
		t.Error("an empty bulk create must be a validation error")
	}
	// A miss inside a bulk read is an empty slot, not an error: a bulk
	// reader learns which of ITS OWN tokens are gone, nothing about why.
	out, err := vt.DetokenizeBulk(ctx, client, []string{"VT-DOESNOTEXIST"})
	if err != nil {
		t.Fatalf("a miss must not fail the batch: %v", err)
	}
	if len(out) != 1 || out[0] != "" {
		t.Fatalf("a miss must come back as an empty slot: %+v", out)
	}
}

// tokenizeInTx's remaining branches: the expiry shapes, the adopt path for a
// pre-cid row, and the dead-row cleanup that a re-tokenize after an expiry
// depends on.
func TestTokenizeExpiryShapesAndAdoption(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cid := e.register(t)

	adminRing := &service.KeyRing{Pool: e.admin.Pool, RetireGrace: -1}
	vt := &service.ValueTokens{Pool: e.admin.Pool, Eng: e.oti.Eng, Ring: adminRing, Tok: e.svc.Tok}
	client := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions:  []string{auth.ActTokensCreate, auth.ActTokensRead},
		AllowedPurposes: []string{"support"}}

	// A sliding window: reading refreshes it.
	sliding, err := vt.Tokenize(ctx, client, service.TokenizeInput{
		Type: "string", Value: "sliding", SlidingSeconds: 3600})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vt.Detokenize(ctx, client, sliding); err != nil {
		t.Fatal(err)
	}
	var lastUsed time.Time
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT last_used FROM value_tokens WHERE token=$1`, sliding).Scan(&lastUsed); err != nil {
		t.Fatal(err)
	}
	if time.Since(lastUsed) > time.Minute {
		t.Fatal("a read must refresh the sliding window")
	}

	// A hard expiry that has passed: the row is dead, so a re-tokenize of
	// the same value must mint a FRESH token rather than resurrect it or
	// collide on the unique index.
	dead, err := vt.Tokenize(ctx, client, service.TokenizeInput{
		Type: "string", Value: "expiring", CID: cid, Unique: true, ExpiresFinal: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.admin.Pool.Exec(ctx,
		`UPDATE value_tokens SET expires_final = now() - interval '1 minute' WHERE token=$1`, dead); err != nil {
		t.Fatal(err)
	}
	if _, err := vt.Detokenize(ctx, client, dead); err == nil {
		t.Fatal("an expired token must not detokenize")
	}
	fresh, err := vt.Tokenize(ctx, client, service.TokenizeInput{
		Type: "string", Value: "expiring", CID: cid, Unique: true, ExpiresFinal: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	if err != nil {
		t.Fatalf("re-tokenizing a value whose token expired must succeed: %v", err)
	}
	if fresh == dead {
		t.Fatal("an expired token must not be resurrected")
	}

	// The upgrade boundary: a live UNATTRIBUTED row for a value is ADOPTED
	// by the first caller that supplies a cid, rather than breeding an alias
	// erasure could never reach.
	orphan, err := vt.Tokenize(ctx, client, service.TokenizeInput{
		Type: "string", Value: "adopt-me", Unique: true})
	if err != nil {
		t.Fatal(err)
	}
	adopted, err := vt.Tokenize(ctx, client, service.TokenizeInput{
		Type: "string", Value: "adopt-me", CID: cid, Unique: true})
	if err != nil {
		t.Fatal(err)
	}
	if adopted != orphan {
		t.Fatalf("the pre-cid row must be adopted, not duplicated: %s vs %s", adopted, orphan)
	}
	var boundCID *string
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT cid FROM value_tokens WHERE token=$1`, orphan).Scan(&boundCID); err != nil {
		t.Fatal(err)
	}
	if boundCID == nil || *boundCID != cid {
		t.Fatal("the adopted row must now be bound to the person, so erasure reaches it")
	}
}
