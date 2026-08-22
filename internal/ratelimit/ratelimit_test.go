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

func TestDetectorCountsPerWindow(t *testing.T) {
	d := NewDetector()
	base := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	now := base
	d.now = func() time.Time { return now }
	for i := 1; i <= 3; i++ {
		if got := d.Miss("crm"); got != i {
			t.Fatalf("miss %d counted as %d", i, got)
		}
	}
	now = base.Add(detectWindow)
	if got := d.Miss("crm"); got != 1 {
		t.Fatalf("new window should reset count, got %d", got)
	}
}
