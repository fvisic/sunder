package main

// The scale test rests entirely on one claim this loader makes, in its own
// package comment:
//
//	"A lookup for bench-42@example.com therefore resolves exactly as it would
//	 for a contact registered through the API - which is the point, because
//	 what is being measured is index behaviour at scale, not the loader."
//
// Nothing verified it. If loadBatch wrote a token under the wrong key
// version, or an AEAD blob without the AAD binding the server expects, every
// number ever measured against a bulk-loaded dataset would be measuring a
// different system - and the failure mode is a silent MISS, not an error.
// The 26.9M-contact numbers in benchmark/README.md all depend on this.
//
// That is the same shape as the defects Phase 7 exists for: correct-looking
// code, no assertion, and a green suite because nothing checked the thing
// that mattered.

import (
	"context"
	"fmt"
	"testing"

	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/crypto"
	"github.com/fvisic/sunder/internal/service"
	"github.com/fvisic/sunder/internal/testutil"
)

// loaderEnv is the loader's own dependencies plus the SERVER-side services a
// real request would go through - the whole point is to prove those two
// agree.
type loaderEnv struct {
	svc      *service.Contacts
	client   *auth.Client
	tok      *crypto.Tokenizer
	pii      *crypto.PIIBox
	ring     *service.KeyRing
	emailV   string
	nameV    string
	phoneV   string
	kekV     string
	scopeStr string
}

func newLoaderEnv(t *testing.T) *loaderEnv {
	t.Helper()
	st := testutil.NewDB(t)
	ctx := context.Background()

	eng := crypto.NewLocalEngine(crypto.NewCachingKeystore(&crypto.FileKeystore{Dir: t.TempDir()}))
	ring := &service.KeyRing{Pool: st.Pool, RetireGrace: -1}
	if err := ring.EnsureAll(ctx, eng); err != nil {
		t.Fatal(err)
	}
	emailV, err := ring.Newest(ctx, crypto.KeyHMACEmail)
	if err != nil {
		t.Fatal(err)
	}
	phoneV, err := ring.Newest(ctx, crypto.KeyHMACPhone)
	if err != nil {
		t.Fatal(err)
	}
	nameV, err := ring.Newest(ctx, crypto.KeyHMACName)
	if err != nil {
		t.Fatal(err)
	}
	kekV, err := ring.Newest(ctx, crypto.KeyPIIKEK)
	if err != nil {
		t.Fatal(err)
	}

	svc := &service.Contacts{
		Pool: st.Pool, Tok: crypto.NewTokenizer(eng),
		PII: crypto.NewPIIBox(eng), Ring: ring,
		// ON, so the shape comparison covers the derived kinds too. With
		// them off the test would compare three token kinds and call the
		// loader faithful, which is how the missing `name` token survived.
		FuzzyName: true, PhoneSuffix: true,
	}
	return &loaderEnv{
		svc: svc, tok: crypto.NewTokenizer(eng), pii: crypto.NewPIIBox(eng), ring: ring,
		emailV: emailV, phoneV: phoneV, nameV: nameV, kekV: kekV, scopeStr: "bench",
		client: &auth.Client{
			ID: "bench", Scope: "bench",
			AllowedActions:  []string{"contacts.register", "lookup", "attributes.read"},
			AllowedPurposes: []string{"benchmark"},
		},
	}
}

// TestBulkLoadedContactResolvesThroughTheServer is the claim itself: rows
// written by COPY must be found by the ordinary lookup path, which knows
// nothing about how they got there.
func TestBulkLoadedContactResolvesThroughTheServer(t *testing.T) {
	e := newLoaderEnv(t)
	ctx := context.Background()

	const n = 25
	if err := loadBatch(ctx, e.svc.Pool, e.tok, e.pii,
		e.scopeStr, e.emailV, e.phoneV, e.nameV, e.kekV, true, true, 0, n); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < n; i++ {
		email := fmt.Sprintf("%s-%d@bench.example", e.scopeStr, i)
		cid, err := e.svc.Lookup(ctx, e.client, service.LookupInput{Email: email})
		if err != nil {
			t.Fatalf("bulk-loaded contact %d does not resolve by e-mail (%s): %v - "+
				"every scale number measured against a loaded dataset is measuring "+
				"a different system than the one under test", i, email, err)
		}
		if cid == "" {
			t.Fatalf("contact %d resolved to an empty cid", i)
		}
	}
}

// TestBulkLoadedBlobDecryptsUnderTheServersAAD proves the AEAD binding, not
// merely that a blob exists.
//
// pii.Encrypt binds the CID into the associated data. A loader that sealed a
// blob under a different AAD - a different cid, a legacy layout - would
// still COPY successfully, still be found by e-mail (the token is a separate
// mechanism), and fail only later, at read time, on data nobody re-reads
// during a throughput benchmark.
func TestBulkLoadedBlobDecryptsUnderTheServersAAD(t *testing.T) {
	e := newLoaderEnv(t)
	ctx := context.Background()

	if err := loadBatch(ctx, e.svc.Pool, e.tok, e.pii,
		e.scopeStr, e.emailV, e.phoneV, e.nameV, e.kekV, true, true, 100, 105); err != nil {
		t.Fatal(err)
	}

	email := fmt.Sprintf("%s-100@bench.example", e.scopeStr)
	cid, err := e.svc.Lookup(ctx, e.client, service.LookupInput{Email: email})
	if err != nil {
		t.Fatal(err)
	}
	// Read through the server's own attribute path: purpose checked, blob
	// decrypted with the AAD the server derives, not the one the loader
	// happened to use.
	got, err := e.svc.GetAttribute(ctx, e.client, cid, "email", "benchmark")
	if err != nil {
		t.Fatalf("the server cannot decrypt a bulk-loaded blob: %v - the loader's "+
			"AEAD binding disagrees with the server's", err)
	}
	if got != email {
		t.Fatalf("decrypted e-mail is %q, want %q", got, email)
	}
	for _, attr := range []string{"name", "loyalty_tier", "segment"} {
		if _, err := e.svc.GetAttribute(ctx, e.client, cid, attr, "benchmark"); err != nil {
			t.Fatalf("attribute %q unreadable on a bulk-loaded contact: %v", attr, err)
		}
	}
}

// TestBulkLoadedAndRegisteredContactsAreIndistinguishable closes the loop.
// The benchmark compares operations against loaded contacts with operations
// against registered ones; if the two differ in shape, the comparison is
// meaningless.
func TestBulkLoadedAndRegisteredContactsAreIndistinguishable(t *testing.T) {
	e := newLoaderEnv(t)
	ctx := context.Background()

	if err := loadBatch(ctx, e.svc.Pool, e.tok, e.pii,
		e.scopeStr, e.emailV, e.phoneV, e.nameV, e.kekV, true, true, 200, 201); err != nil {
		t.Fatal(err)
	}
	loadedCID, err := e.svc.Lookup(ctx, e.client, service.LookupInput{
		Email: fmt.Sprintf("%s-200@bench.example", e.scopeStr)})
	if err != nil {
		t.Fatal(err)
	}
	registeredCID, err := e.svc.Register(ctx, e.client, service.RegisterInput{
		Email: "registered@bench.example",
		Phone: "+385991234567",
		Name:  "Test Osoba 200",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Same token kinds, same key versions: a loader writing a stale version
	// would produce contacts that stop resolving the moment that version is
	// retired - and a benchmark would never notice.
	type row struct{ kind, version string }
	shape := func(cid string) map[row]int {
		rows, err := e.svc.Pool.Query(ctx,
			`SELECT t.kind, t.key_version FROM person_tokens t
			   JOIN cids c ON c.person_id = t.person_id WHERE c.cid=$1`, cid)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[row]int{}
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.kind, &r.version); err != nil {
				t.Fatal(err)
			}
			out[r]++
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	loaded, registered := shape(loadedCID), shape(registeredCID)
	// BOTH directions. The first version ran only the first loop - it proved
	// the loader wrote nothing EXTRA and said nothing about what it left
	// out. It passed while the loader wrote no `name` token at all: the name
	// went into the encrypted blob and never into the index, so a loaded
	// contact could not be narrowed by name and person_tokens was about a
	// third smaller than production's. Every scale number taken on such a
	// dataset measured a lighter table than the one it claimed to describe.
	for k := range loaded {
		if _, ok := registered[k]; !ok {
			t.Fatalf("bulk-loaded contact has a %+v token the registered one does not", k)
		}
	}
	for k := range registered {
		if _, ok := loaded[k]; !ok {
			t.Fatalf("a REGISTERED contact has a %+v token the bulk-loaded one lacks - the "+
				"loader is not writing the real shapes, and a dataset built from it is "+
				"lighter than production. Fix loadBatch, not this test.", k)
		}
	}
	for _, want := range []string{"email", "phone"} {
		if loaded[row{want, map[string]string{"email": e.emailV, "phone": e.phoneV}[want]}] == 0 {
			t.Fatalf("bulk-loaded contact has no %q token under the newest key version - "+
				"it would stop resolving the moment that version is retired", want)
		}
	}

	// And the blob is stored under the same key version and algorithm.
	var lKey, lAlg, rKey, rAlg string
	q := `SELECT COALESCE(pii_key_id,''), COALESCE(pii_alg,'') FROM cids WHERE cid=$1`
	if err := e.svc.Pool.QueryRow(ctx, q, loadedCID).Scan(&lKey, &lAlg); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Pool.QueryRow(ctx, q, registeredCID).Scan(&rKey, &rAlg); err != nil {
		t.Fatal(err)
	}
	if lKey != rKey || lAlg != rAlg {
		t.Fatalf("loaded blob is (%s,%s) but a registered one is (%s,%s) - the rekey "+
			"sweep and `keys retire` treat them differently", lKey, lAlg, rKey, rAlg)
	}
}
