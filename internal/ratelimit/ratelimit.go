// Package ratelimit provides a per-client sliding-window rate limiter and an
// enumeration detector for the lookup surface.
//
// In-memory by design for v1 (single-node pilots); the types are small
// interfaces over one method each, so a Redis-backed implementation can drop
// in when multi-replica deployments need shared counters (docs/DESIGN.md, performance targets).
package ratelimit

import (
	"sync"
	"time"
)

// Allower gates requests per client; MissCounter feeds enumeration
// detection. The in-memory implementations below are single-replica by
// design; RedisLimiter (redis.go) implements both with shared counters for
// multi-replica deployments.
type Allower interface {
	Allow(key string, limit int) bool
}

type MissCounter interface {
	Miss(key string) int
}

// Limiter approximates a 60s sliding window with two adjacent fixed windows
// (the standard weighted-window scheme): cheap, O(1) memory per client, and
// accurate enough for abuse control (not billing).
type Limiter struct {
	mu      sync.Mutex
	entries map[string]*entry
	ops     int
	now     func() time.Time // injectable for tests
}

type entry struct {
	windowStart time.Time
	curr, prev  int
}

const window = time.Minute

func NewLimiter() *Limiter {
	return &Limiter{entries: map[string]*entry{}, now: time.Now}
}

// Allow reports whether one more request fits under limit-per-minute and
// counts it if so.
func (l *Limiter) Allow(key string, limit int) bool {
	if limit <= 0 {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if l.ops++; l.ops%gcEvery == 0 {
		gc(l.entries, now, window)
	}
	e := l.entries[key]
	if e == nil {
		e = &entry{windowStart: now.Truncate(window)}
		l.entries[key] = e
	}
	start := now.Truncate(window)
	switch {
	case start.Equal(e.windowStart):
	case start.Sub(e.windowStart) == window:
		e.prev, e.curr, e.windowStart = e.curr, 0, start
	default:
		e.prev, e.curr, e.windowStart = 0, 0, start
	}
	// Weight the previous window by how much of the sliding window it covers.
	frac := 1 - float64(now.Sub(start))/float64(window)
	effective := float64(e.curr) + frac*float64(e.prev)
	if effective >= float64(limit) {
		return false
	}
	e.curr++
	return true
}

// gcEvery bounds memory: every N operations, entries idle for two or more
// full windows are evicted (their weight is zero anyway).
const gcEvery = 4096

func gc(entries map[string]*entry, now time.Time, span time.Duration) {
	for k, e := range entries {
		if now.Sub(e.windowStart) >= 2*span {
			delete(entries, k)
		}
	}
}

// Detector tracks lookup misses per client with the same weighted
// sliding-window scheme as the limiter - a fixed wall-clock window would let
// a paced attacker straddle the boundary and never trigger the alert.
type Detector struct {
	mu     sync.Mutex
	misses map[string]*entry
	ops    int
	now    func() time.Time
}

const detectWindow = 10 * time.Minute

func NewDetector() *Detector {
	return &Detector{misses: map[string]*entry{}, now: time.Now}
}

// Miss records a lookup that matched nothing and returns the weighted miss
// count over the sliding 10-minute window.
func (d *Detector) Miss(key string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	if d.ops++; d.ops%gcEvery == 0 {
		gc(d.misses, now, detectWindow)
	}
	e := d.misses[key]
	start := now.Truncate(detectWindow)
	if e == nil {
		e = &entry{windowStart: start}
		d.misses[key] = e
	}
	switch {
	case start.Equal(e.windowStart):
	case start.Sub(e.windowStart) == detectWindow:
		e.prev, e.curr, e.windowStart = e.curr, 0, start
	default:
		e.prev, e.curr, e.windowStart = 0, 0, start
	}
	e.curr++
	frac := 1 - float64(now.Sub(start))/float64(detectWindow)
	return e.curr + int(frac*float64(e.prev))
}
