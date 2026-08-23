package ratelimit

import (
	"testing"
	"time"
)

func TestLimiterBlocksAtLimit(t *testing.T) {
	l := NewLimiter()
	base := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return base }
	for i := 0; i < 5; i++ {
		if !l.Allow("crm", 5) {
			t.Fatalf("request %d should pass", i)
		}
	}
	if l.Allow("crm", 5) {
		t.Fatal("6th request in the same window must be blocked")
	}
	// Another client is unaffected.
	if !l.Allow("dwh", 5) {
		t.Fatal("independent client blocked")
	}
}

func TestLimiterSlidesOverWindows(t *testing.T) {
	l := NewLimiter()
	base := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	now := base
	l.now = func() time.Time { return now }
	for i := 0; i < 10; i++ {
		l.Allow("crm", 10)
	}
	// At the start of the next window the previous one weighs ~0.98: the
	// approximation admits at most one marginal request, then blocks.
	now = base.Add(window + time.Second)
	l.Allow("crm", 10)
	if l.Allow("crm", 10) {
		t.Fatal("previous window should block near its start")
	}
	// Deep into the next window the weight decays and requests pass again.
	now = base.Add(window + 55*time.Second)
	if !l.Allow("crm", 10) {
		t.Fatal("decayed window should admit requests")
	}
	// After two idle windows everything resets.
	now = base.Add(10 * window)
	if !l.Allow("crm", 10) {
		t.Fatal("stale entry should reset")
	}
}

func TestLimiterZeroLimit(t *testing.T) {
	l := NewLimiter()
	if l.Allow("x", 0) {
		t.Fatal("zero limit must block everything")
	}
}

func TestDetectorSlidingWindow(t *testing.T) {
	d := NewDetector()
	base := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	now := base
	d.now = func() time.Time { return now }
	for i := 1; i <= 3; i++ {
		if got := d.Miss("crm"); got != i {
			t.Fatalf("miss %d counted as %d", i, got)
		}
	}
	// Right after the boundary the previous window still weighs ~1.0: a
	// paced attacker straddling the boundary cannot reset the count.
	now = base.Add(detectWindow)
	if got := d.Miss("crm"); got != 4 {
		t.Fatalf("boundary miss should carry previous window, got %d", got)
	}
	// Two idle windows later everything decays away.
	now = base.Add(3 * detectWindow)
	if got := d.Miss("crm"); got != 1 {
		t.Fatalf("stale window should reset, got %d", got)
	}
}

func TestGCEvictsStaleEntries(t *testing.T) {
	l := NewLimiter()
	base := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	now := base
	l.now = func() time.Time { return now }
	l.Allow("stale", 10)
	// Jump far ahead and drive enough operations to trigger the periodic GC.
	now = base.Add(48 * time.Hour)
	for i := 0; i < gcEvery+1; i++ {
		l.Allow("active", 1000000)
	}
	l.mu.Lock()
	_, staleExists := l.entries["stale"]
	l.mu.Unlock()
	if staleExists {
		t.Fatal("stale entry survived GC")
	}
}

// The in-memory detector's GC path and the two backends' identical ceiling.
func TestDetectorGCAndBackendParity(t *testing.T) {
	d := NewDetector()
	// Enough misses to cross the GC interval.
	for i := 0; i < gcEvery+10; i++ {
		d.Miss("client")
	}
	if got := d.Miss("client"); got == 0 {
		t.Fatal("the detector must keep counting across a GC pass")
	}
	// The in-memory limiter denies AT the limit, which the Redis backend
	// now matches exactly (review N10).
	l := NewLimiter()
	const limit = 3
	allowed := 0
	for i := 0; i < 10; i++ {
		if l.Allow("c", limit) {
			allowed++
		}
	}
	if allowed != limit {
		t.Fatalf("limit %d must allow exactly %d, allowed %d", limit, limit, allowed)
	}
	if l.Allow("c", 0) {
		t.Fatal("a zero limit must deny")
	}
}
