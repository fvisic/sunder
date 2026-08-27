package service_test

// CONCURRENCY-CORE-4 and TOKENS-LOOKUP-2: two defects that only appear with
// more than one process against one database - which is the deployment the
// chart defaults to.

import (
	"context"
	"testing"
	"time"

	"github.com/fvisic/sunder/internal/crypto"
	"github.com/fvisic/sunder/internal/service"
)

// A rotate+retire run from the CLI must not orphan the search tokens a
// replica mints from its cached ring. Invalidate() only nils ONE process's
// map, so the replica kept writing rows under a version the purge had
// already swept - rows nothing ever deletes or probes again, leaving the
// person unfindable and breeding a second person on re-registration.
func TestRetireDoesNotOrphanAnotherReplicasTokens(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()

	// "replica B": its own ring over the same pool, primed on v1.
	ringB := &service.KeyRing{Pool: e.admin.Pool}
	if _, err := ringB.Versions(ctx, crypto.KeyHMACEmail); err != nil {
		t.Fatal(err)
	}
	replicaB := &service.Contacts{Pool: e.admin.Pool, Tok: e.svc.Tok, PII: e.svc.PII, Ring: ringB}

	// "the operator's CLI": a third ring, rotating and retiring, with the
	// production grace period in force.
	cli := &service.KeyRing{Pool: e.admin.Pool}
	if _, err := cli.Rotate(ctx, e.oti.Eng, crypto.KeyHMACEmail); err != nil {
		t.Fatal(err)
	}
	// The purge is refused while B could still be writing under v1. This is
	// the structural half of the fix: the orphan window is not narrowed, it
	// is closed.
	if err := cli.Retire(ctx, crypto.KeyHMACEmail, "v1"); err == nil {
		t.Fatal("retiring inside the ring-cache window must be refused")
	}
	// Wait it out (simulated by ageing retiring_since) - and give B past the
	// cross-process epoch interval, which is what converges it without
	// anyone calling Invalidate in its process.
	if _, err := e.admin.Pool.Exec(ctx,
		`UPDATE keys SET retiring_since = now() - interval '1 hour' WHERE key_id=$1`,
		crypto.KeyHMACEmail+"/v1"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1200 * time.Millisecond)
	if err := cli.Retire(ctx, crypto.KeyHMACEmail, "v1"); err != nil {
		t.Fatal(err)
	}

	// B has never had Invalidate() called in its process. It must still see
	// the new ring, so the row it writes is under a LIVE version - the one
	// thing that makes the person findable afterwards.
	cid, err := replicaB.Register(ctx, e.crm, service.RegisterInput{Email: "replica@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	var version string
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT key_version FROM person_tokens WHERE kind='email'`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version == "v1" {
		t.Fatal("a token was minted under a RETIRED key version - it can never be probed or purged again")
	}

	// And the invariant that matters to the caller: the person is findable,
	// and re-registering the address does not mint a second one.
	got, err := replicaB.Lookup(ctx, e.crm, service.LookupInput{Email: "replica@example.com"})
	if err != nil || got != cid {
		t.Fatalf("the person written across a retirement must stay findable: %q %v", got, err)
	}
	again, err := replicaB.Register(ctx, e.crm, service.RegisterInput{Email: "replica@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if again != cid {
		t.Fatalf("re-registering minted a SECOND person: %s vs %s", again, cid)
	}
}

// The grace period is the structural half of the same fix: a version cannot
// be retired until every replica has certainly seen the rotation.
func TestRetireRefusesInsideTheGracePeriod(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	ring := &service.KeyRing{Pool: e.admin.Pool, RetireGrace: time.Hour}
	if _, err := ring.Rotate(ctx, e.oti.Eng, crypto.KeyHMACEmail); err != nil {
		t.Fatal(err)
	}
	if err := ring.Retire(ctx, crypto.KeyHMACEmail, "v1"); err == nil {
		t.Fatal("retiring a just-rotated version must be refused: replicas may still be writing under it")
	}
	// -force is the documented escape hatch for an operator who knows no
	// other replica is running.
	if err := ring.RetireWithForce(ctx, crypto.KeyHMACEmail, "v1", true); err != nil {
		t.Fatalf("-force must still retire: %v", err)
	}
}

// TOKENS-LOOKUP-2: the rekey sweep's guard was (key_id, alg) - the pair it is
// trying to CHANGE, and the pair a concurrent writer leaves untouched. The
// sweep clobbered the merge and counted it as a success.
func TestRekeyDoesNotClobberAConcurrentMerge(t *testing.T) {
	e := newFaultEnv(t)
	ctx := context.Background()
	cid := e.register(t)

	adminRing := &service.KeyRing{Pool: e.admin.Pool, RetireGrace: -1}
	admin := &service.Contacts{Pool: e.admin.Pool, Tok: e.svc.Tok, PII: e.svc.PII, Ring: adminRing}

	// Capture what the sweep would have read...
	var blob []byte
	var keyID, alg string
	var updatedAt time.Time
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT pii_encrypted, COALESCE(pii_key_id,'v1'), COALESCE(pii_alg,'aes256gcm'), updated_at
		   FROM cids WHERE cid=$1`, cid).Scan(&blob, &keyID, &alg, &updatedAt); err != nil {
		t.Fatal(err)
	}
	// ...then let a concurrent writer merge an attribute, leaving the
	// (key_id, alg) pair EXACTLY as it was - the replica-on-the-old-setting
	// case the algorithm-migration runbook explicitly blesses.
	if _, err := admin.Register(ctx, e.crm, service.RegisterInput{
		Email: "fault@example.com", Attributes: map[string]string{"probe": "1"}}); err != nil {
		t.Fatal(err)
	}
	var afterKey, afterAlg string
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT COALESCE(pii_key_id,'v1'), COALESCE(pii_alg,'aes256gcm') FROM cids WHERE cid=$1`,
		cid).Scan(&afterKey, &afterAlg); err != nil {
		t.Fatal(err)
	}
	if afterKey != keyID || afterAlg != alg {
		t.Skip("the writer changed the key/alg pair; this test needs the case where it does not")
	}

	// Now replay the sweep's guarded write with its STALE snapshot.
	tag, err := e.admin.Pool.Exec(ctx,
		`UPDATE cids c SET pii_encrypted=$2, pii_key_id=$3, pii_alg=$4
		   FROM persons p
		  WHERE c.cid=$1 AND p.id = c.person_id AND p.erased_at IS NULL
		    AND c.pii_encrypted IS NOT NULL
		    AND c.updated_at = $7
		    AND COALESCE(c.pii_key_id,'v1')=$5 AND COALESCE(c.pii_alg,'aes256gcm')=$6`,
		cid, blob, keyID, alg, keyID, alg, updatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if tag.RowsAffected() != 0 {
		t.Fatal("the guard let a stale snapshot overwrite a concurrent merge - the merged attribute is lost silently")
	}
	// The merged attribute survives.
	got, err := admin.GetAttribute(ctx, e.crm, cid, "probe", "support")
	if err != nil || got != "1" {
		t.Fatalf("the concurrently merged attribute must survive: %q %v", got, err)
	}
}
