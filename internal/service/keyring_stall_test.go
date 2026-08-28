package service_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/crypto"
	"github.com/fvisic/sunder/internal/service"
	"github.com/fvisic/sunder/internal/testutil"
)

// The write stall: a key-ring lock and a connection pool acquired in the
// wrong order.
//
// Found by execution, not by reading. On a 26.9M-contact dataset, writes ran
// at 516 rps with zero errors at c=8 and collapsed to 18 rps with 150
// client timeouts at c=32 - while the database sat at ZERO active queries
// and ZERO ungranted locks for ninety seconds. A goroutine dump named it:
//
//	goroutine 191 [select]:            <- waiting for a pool connection
//	  pgxpool.(*Pool).QueryRow
//	  service.(*KeyRing).currentEpoch
//	  service.(*KeyRing).staleLocked
//	  service.(*KeyRing).Newest        <- HOLDING the key-ring mutex
//	  service.(*Contacts).mergeIntoBlob
//	  service.(*Contacts).registerTx   <- HOLDING an open transaction
//
// with fifteen more goroutines blocked on that same mutex, each holding a
// transaction of its own, and twenty-three queued for a connection.
//
// Every connection in the pool was held by a goroutine waiting for the
// mutex, and the one goroutine holding the mutex was waiting for a
// connection that could not be freed until a client gave up. Seven review
// rounds read this code; none of them saw it, because it needs concurrency
// at or above the pool size, a write workload, and the once-a-second epoch
// check to land inside a transaction.
//
// The test reproduces it with a deliberately small pool instead of a large
// one, which is the same condition reached at scale.

// smallPoolEnv builds a service whose pool is smaller than the concurrency
// the test will apply - the condition the reference server reached with 32
// clients against a 12-connection pool.
func smallPoolEnv(t *testing.T, maxConns int32) (*service.Contacts, *service.KeyRing, *pgxpool.Pool) {
	t.Helper()
	st := testutil.NewDB(t)
	ctx := context.Background()

	cfg := st.Pool.Config().Copy()
	cfg.MaxConns = maxConns
	cfg.MinConns = 0
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	eng := crypto.NewLocalEngine(crypto.NewCachingKeystore(&crypto.FileKeystore{Dir: t.TempDir()}))
	ring := &service.KeyRing{Pool: pool, RetireGrace: -1}
	if err := ring.EnsureAll(ctx, eng); err != nil {
		t.Fatal(err)
	}
	// As `serve` does: the refresher owns freshness, so the request path
	// never queries. A test that skipped this would be measuring the CLI's
	// posture, not the server's.
	rctx, rcancel := context.WithCancel(ctx)
	t.Cleanup(rcancel)
	ring.StartRefresher(rctx, nil)

	svc := &service.Contacts{
		Pool: pool, Tok: crypto.NewTokenizer(eng), PII: crypto.NewPIIBox(eng), Ring: ring,
		// Both derived indexes ON: this is what the benchmark stack runs,
		// and it is what multiplies the pressure. One Register then resolves
		// a key version for the e-mail, the phone, the name, every phonetic
		// code, the suffix and the PII KEK.
		FuzzyName: true, PhoneSuffix: true,
	}
	return svc, ring, pool
}

// TestConcurrentWritesDoNotStallOnTheKeyRing is the regression.
//
// Against the pre-fix code it does not fail with a wrong answer - it HANGS,
// until the context deadline turns the hang into an error. That is the
// honest shape of the defect: nothing is corrupted, the service simply stops
// answering.
func TestConcurrentWritesDoNotStallOnTheKeyRing(t *testing.T) {
	const (
		maxConns    = 4
		concurrency = 16
		perWorker   = 3
	)
	svc, ring, _ := smallPoolEnv(t, maxConns)

	client := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions:  []string{auth.ActContactsRegister, auth.ActLookup, auth.ActAttributesRead},
		AllowedPurposes: []string{"support"}}

	// Warm the ring first, so the run below is about the refresh and not
	// about a cold start.
	if _, err := svc.Register(context.Background(), client, service.RegisterInput{
		Email: "warm@example.com", Phone: "+385990000001", Name: "Warm Up"}); err != nil {
		t.Fatal(err)
	}

	// The trigger, made DETERMINISTIC.
	//
	// A first version of this test simply slept past keyEpochInterval and
	// then wrote. It passed against the BROKEN code, because after the sleep
	// exactly one goroutine performed the epoch check, refreshed the
	// timestamp, and the remaining writes finished inside the same second -
	// so the check never once landed while the pool was saturated. On the
	// reference server it landed constantly, because the load ran for
	// minutes across thousands of requests.
	//
	// Invalidate() forces the same condition on demand and is not a
	// contrivance: `keys rotate` and `keys retire` call it, and an
	// unknown-kid verification miss calls InvalidateThrottled. Driving it in
	// a loop while writers are in flight is a rotation happening under load.
	invalidating := make(chan struct{})
	var invWG sync.WaitGroup
	invWG.Add(1)
	go func() {
		defer invWG.Done()
		for {
			select {
			case <-invalidating:
				return
			default:
			}
			ring.Invalidate()
			time.Sleep(2 * time.Millisecond)
		}
	}()
	defer func() { close(invalidating); invWG.Wait() }()

	// Generous relative to the work (48 registers on a small dataset take
	// well under a second) and far below the 30s the deadlock ran for.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	errs := make(chan error, concurrency*perWorker)
	start := time.Now()
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				_, err := svc.Register(ctx, client, service.RegisterInput{
					Email: fmt.Sprintf("stall-%d-%d@example.com", w, i),
					Phone: fmt.Sprintf("+3859911%05d", w*100+i),
					Name:  fmt.Sprintf("Stall Test %d %d", w, i),
				})
				if err != nil {
					errs <- err
					return
				}
			}
		}(w)
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatalf("%d concurrent writers against a %d-connection pool did not finish in %v.\n"+
			"This is the key-ring stall: Newest() takes an exclusive lock and then asks the\n"+
			"pool for a connection, while its caller already holds one inside registerTx.\n"+
			"Once concurrency reaches the pool size, the connection the lock holder needs\n"+
			"can never be freed - every other connection is held by a goroutine queued on\n"+
			"that same lock. A rotation under load is all it takes.", concurrency, maxConns, 20*time.Second)
	}
	close(errs)
	for err := range errs {
		t.Errorf("write failed: %v", err)
	}
	t.Logf("%d writers x %d registers on a %d-connection pool: %v",
		concurrency, perWorker, maxConns, time.Since(start).Round(time.Millisecond))
}

// TestKeyRingReadPathTouchesNoDatabase pins the property the fix rests on.
//
// A regression here would not stall this test - it would stall production
// under load, which is exactly what happened. So the guard is direct: close
// the pool, and prove a warm ring still answers. A read path that needs the
// database cannot.
func TestKeyRingReadPathTouchesNoDatabase(t *testing.T) {
	_, ring, pool := smallPoolEnv(t, 4)
	ctx := context.Background()

	// Warm it while the database is still reachable.
	if _, err := ring.Newest(ctx, crypto.KeyHMACEmail); err != nil {
		t.Fatal(err)
	}
	if _, err := ring.Versions(ctx, crypto.KeyHMACEmail); err != nil {
		t.Fatal(err)
	}

	pool.Close()

	for _, kind := range []string{crypto.KeyHMACEmail, crypto.KeyHMACPhone, crypto.KeyPIIKEK} {
		if _, err := ring.Newest(ctx, kind); err != nil {
			t.Errorf("Newest(%q) needs the database on a warm ring: %v - the epoch check has "+
				"moved back onto the request path, and writes will stall under load", kind, err)
		}
	}
	if _, err := ring.Versions(ctx, crypto.KeyHMACEmail); err != nil {
		t.Errorf("Versions needs the database on a warm ring: %v", err)
	}
}

// TestKeyRingRefresherPicksUpARotation proves the background refresher still
// does the job the inline epoch check was there for: a `keys rotate` run in a
// SEPARATE process must reach this replica in about a second, not in a
// keyRingTTL (CONCURRENCY-CORE-4). Moving the check off the request path
// must not turn it off.
func TestKeyRingRefresherPicksUpARotation(t *testing.T) {
	st := testutil.NewDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	eng := crypto.NewLocalEngine(crypto.NewCachingKeystore(&crypto.FileKeystore{Dir: t.TempDir()}))
	// The replica's ring, with the refresher running - as `serve` starts it.
	replica := &service.KeyRing{Pool: st.Pool, RetireGrace: -1}
	if err := replica.EnsureAll(ctx, eng); err != nil {
		t.Fatal(err)
	}
	before, err := replica.Newest(ctx, crypto.KeyHMACEmail)
	if err != nil {
		t.Fatal(err)
	}
	replica.StartRefresher(ctx, nil)

	// A different process entirely: the CLI's ring, sharing only Postgres.
	operator := &service.KeyRing{Pool: st.Pool, RetireGrace: -1}
	rotated, err := operator.Rotate(ctx, eng, crypto.KeyHMACEmail)
	if err != nil {
		t.Fatal(err)
	}
	if rotated == before {
		t.Fatalf("rotate returned the same version %q", rotated)
	}

	deadline := time.Now().Add(10 * time.Second)
	for {
		got, err := replica.Newest(ctx, crypto.KeyHMACEmail)
		if err == nil && got == rotated {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the replica still writes under %q %v after another process rotated to %q - "+
				"the background refresher is not converging the fleet, and this replica will "+
				"mint tokens under a version that can be retired and purged out from under it",
				got, 10*time.Second, rotated)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestRefresherOwnedRingRefusesToQueryFromTheRequestPath is what makes the
// pool-inversion guard's exemption for `refresh` honest.
//
// That guard permits KeyRing.refresh to sit under a transaction-holding call
// path ONLY because a refresher-owned ring can never reach it. Prove it: own
// the ring, close the pool, and ask for a kind that is not in the cache. A
// query would hang or error on a closed pool; the correct behaviour is an
// immediate, explicit refusal.
func TestRefresherOwnedRingRefusesToQueryFromTheRequestPath(t *testing.T) {
	_, ring, pool := smallPoolEnv(t, 4)
	ctx := context.Background()

	if _, err := ring.Newest(ctx, crypto.KeyHMACEmail); err != nil {
		t.Fatal(err)
	}
	pool.Close()

	_, err := ring.Newest(ctx, "no-such-kind")
	if err == nil {
		t.Fatal("a kind with no key returned a version")
	}
	if !strings.Contains(err.Error(), "no live version in the cached ring") {
		t.Fatalf("a refresher-owned ring went to the database instead of refusing: %v\n"+
			"That is the deadlock shape: a query from the request path while the caller "+
			"holds a transaction.", err)
	}
}

// TestRefresherTicksWithoutChurningOnAnUnchangedRing covers the path the
// refresher spends nearly all of its life on: the epoch is unchanged, so it
// must NOT reload. A refresher that reloaded every tick would put a query
// per second per replica on the keys table forever, and would swap the ring
// maps under readers for no reason.
func TestRefresherTicksWithoutChurningOnAnUnchangedRing(t *testing.T) {
	_, ring, _ := smallPoolEnv(t, 4)
	ctx := context.Background()

	first, err := ring.Newest(ctx, crypto.KeyHMACEmail)
	if err != nil {
		t.Fatal(err)
	}
	// Several ticks with nothing changing.
	time.Sleep(3 * service.KeyEpochIntervalForTest)

	got, err := ring.Newest(ctx, crypto.KeyHMACEmail)
	if err != nil {
		t.Fatalf("the ring stopped answering after idle ticks: %v", err)
	}
	if got != first {
		t.Fatalf("an idle refresher changed the active version from %q to %q", first, got)
	}
}

// TestRefresherSurvivesTheDatabaseGoingAway is the failure mode an operator
// actually meets: Postgres restarts under a running replica. Serving the
// cached ring beats failing every write, and the ring must still answer
// afterwards rather than wedging.
func TestRefresherSurvivesTheDatabaseGoingAway(t *testing.T) {
	_, ring, pool := smallPoolEnv(t, 4)
	ctx := context.Background()

	want, err := ring.Newest(ctx, crypto.KeyHMACEmail)
	if err != nil {
		t.Fatal(err)
	}
	pool.Close()
	// Let the refresher tick into the closed pool a few times.
	time.Sleep(3 * service.KeyEpochIntervalForTest)

	got, err := ring.Newest(ctx, crypto.KeyHMACEmail)
	if err != nil {
		t.Fatalf("the ring stopped answering once the database went away: %v - "+
			"a replica must keep serving from its cached ring", err)
	}
	if got != want {
		t.Fatalf("the cached version changed to %q while the database was unreachable", got)
	}
}
