package ratelimit

import (
	"bufio"
	"net"
	"os"
	"testing"
	"time"
)

// Runs against a real Redis when SUNDER_TEST_REDIS_ADDR is set
// (locally: docker run --rm -p 6379:6379 redis:7). Skipped otherwise.
func redisLimiter(t *testing.T) *RedisLimiter {
	t.Helper()
	addr := os.Getenv("SUNDER_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("SUNDER_TEST_REDIS_ADDR not set")
	}
	l := NewRedisLimiter(addr, "", false)
	return l
}

func TestRedisLimiterBlocksAtLimit(t *testing.T) {
	l := redisLimiter(t)
	base := time.Date(2026, 8, 22, 12, 0, 30, 0, time.UTC)
	l.now = func() time.Time { return base }
	key := "crm-" + t.Name() + time.Now().Format("150405.000000") // unique per run
	for i := 0; i < 5; i++ {
		if !l.Allow(key, 5) {
			t.Fatalf("request %d should pass", i)
		}
	}
	if l.Allow(key, 5) {
		t.Fatal("6th request in the same window must be blocked")
	}
	if !l.Allow(key+"-other", 5) {
		t.Fatal("independent client blocked")
	}
	if l.Failures() != 0 {
		t.Fatalf("unexpected redis failures: %d", l.Failures())
	}
}

func TestRedisLimiterSlidesAcrossWindows(t *testing.T) {
	l := redisLimiter(t)
	base := time.Date(2026, 8, 22, 13, 0, 0, 0, time.UTC)
	now := base
	l.now = func() time.Time { return now }
	key := "slide-" + time.Now().Format("150405.000000")
	for i := 0; i < 10; i++ {
		l.Allow(key, 10)
	}
	// Right after the boundary the previous window still weighs ~1.0.
	now = base.Add(window + time.Second)
	l.Allow(key, 10) // marginal one admitted by the approximation
	if l.Allow(key, 10) {
		t.Fatal("previous window should block near its start")
	}
	// Deep into the next window the weight decays.
	now = base.Add(window + 55*time.Second)
	if !l.Allow(key, 10) {
		t.Fatal("decayed window should admit requests")
	}
}

func TestRedisDetectorCounts(t *testing.T) {
	l := redisLimiter(t)
	base := time.Date(2026, 8, 22, 14, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return base }
	key := "det-" + time.Now().Format("150405.000000")
	for i := 1; i <= 3; i++ {
		if got := l.Miss(key); got != i {
			t.Fatalf("miss %d counted as %d", i, got)
		}
	}
}

func TestRedisFailOpenAndClosed(t *testing.T) {
	// Unreachable address: fail-open admits, fail-closed blocks; both count.
	open := NewRedisLimiter("127.0.0.1:1", "", false)
	if !open.Allow("x", 5) {
		t.Fatal("fail-open must admit when redis is unreachable")
	}
	if open.Failures() == 0 {
		t.Fatal("failure not counted")
	}
	closed := NewRedisLimiter("127.0.0.1:1", "", true)
	if closed.Allow("x", 5) {
		t.Fatal("fail-closed must block when redis is unreachable")
	}
}

func TestRedisDoWriteFailsOnClosedConn(t *testing.T) {
	c1, c2 := net.Pipe()
	c2.Close() // peer gone -> writes fail
	rc := &respConn{c: c1, rd: bufio.NewReader(c1)}
	if _, err := (&RedisClient{}).do(rc, "PING"); err == nil {
		t.Fatal("do() over a closed connection must error")
	}
	c1.Close()
}

// AUTHZ-3: SUNDER_REDIS_FAIL_CLOSED defaults to fail-OPEN, and the
// allowlist of buckets that ignore it covered only portal:/claims: - so a
// Redis outage removed the only brute-force throttle on bearer credentials
// (authfail:) and the only control on the credential-less share fetch.
func TestSecurityCriticalBucketsAlwaysFailClosed(t *testing.T) {
	// Point at a port nothing listens on: every command errors.
	l := NewRedisLimiter("127.0.0.1:1", "", false)
	for _, key := range []string{
		"authfail:203.0.113.9",
		"share-public:203.0.113.9",
		"portal:203.0.113.9",
		"claims:crm",
		"audit-verify:crm",
		"audit-chain:crm",
	} {
		if l.Allow(key, 100) {
			t.Errorf("%s must fail CLOSED when Redis is unreachable, regardless of SUNDER_REDIS_FAIL_CLOSED", key)
		}
	}
	// An ordinary authenticated bucket still degrades to fail-open, which is
	// the documented availability trade-off.
	if !l.Allow("crm", 100) {
		t.Error("an ordinary client bucket must fail open by default")
	}
	// ...and fails closed when the operator asks for it.
	strict := NewRedisLimiter("127.0.0.1:1", "", true)
	if strict.Allow("crm", 100) {
		t.Error("SUNDER_REDIS_FAIL_CLOSED=true must deny on backend failure")
	}
}
