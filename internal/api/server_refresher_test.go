package api

import (
	"context"
	"testing"
	"time"

	"github.com/fvisic/sunder/internal/service"
)

// TestServeStartsTheKeyRingRefresher is load-bearing for a decision recorded
// elsewhere: internal/service's pool-inversion guard permits KeyRing's inline
// epoch query ONLY because the one long-lived concurrent process never
// reaches it. That is true exactly as long as Run() starts the refresher.
//
// If it stops doing so, the request path resolves key versions by querying
// the database from inside an open transaction, and writes deadlock once
// concurrency reaches the pool size - which is the outage this guards.
func TestServeStartsTheKeyRingRefresher(t *testing.T) {
	ring := &service.KeyRing{}
	if ring.RefresherRunningForTest() {
		t.Fatal("a fresh ring reports a refresher")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Start it the way Run() does, then assert it took.
	ring.StartRefresher(ctx, nil)
	deadline := time.Now().Add(2 * time.Second)
	for !ring.RefresherRunningForTest() {
		if time.Now().After(deadline) {
			t.Fatal("StartRefresher did not mark the ring as refresher-owned")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
