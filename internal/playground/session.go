package playground

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"time"
)

// Session holds one visitor's walkthrough state: the variables their steps
// captured, and the fake person they registered. Sessions are per browser
// because a public demo has concurrent visitors, and one shared variable
// map would make two of them overwrite each other's CIDs mid-scenario.
//
// One visitor can still have two requests in flight - a double-clicked Run,
// a duplicated tab - so the state behind the cookie is guarded by its own
// mutex and only ever touched through Do/Snapshot. Lock order is always
// Sessions.mu before Session.mu.
type Session struct {
	ID string
	mu sync.Mutex
	// vars are the captured values; results the last outcome per
	// "scenario/step index", so a reloaded page can redraw the walkthrough
	// instead of starting blank.
	vars    map[string]string
	results map[string]*StepResult
	Seen    time.Time
}

// Do runs fn with exclusive access to this session's variables, so a step
// that captures a CID cannot interleave with another step reading it.
func (s *Session) Do(fn func(vars map[string]string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(s.vars)
}

// Record stores a step outcome.
func (s *Session) Record(key string, res *StepResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results[key] = res
}

// Snapshot copies the state for serialization: handing the live maps to a
// JSON encoder would race with the next step.
func (s *Session) Snapshot() (map[string]string, []*StepResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	vars := make(map[string]string, len(s.vars))
	for k, v := range s.vars {
		vars[k] = v
	}
	results := make([]*StepResult, 0, len(s.results))
	for _, r := range s.results {
		results = append(results, r)
	}
	return vars, results
}

// Vars returns a copy of the captured variables.
func (s *Session) Vars() map[string]string {
	vars, _ := s.Snapshot()
	return vars
}

// replace swaps in fresh state (Sessions.Reset).
func (s *Session) replace(vars map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vars, s.results = vars, map[string]*StepResult{}
}

// builtinVarNames are the variables every session starts with. Listed
// separately from the generator so Validate can accept references to them
// without constructing a session.
func builtinVarNames() []string {
	return []string{"demo_email", "demo_phone", "demo_name", "unique", "miss_email"}
}

// newSessionVars mints the per-visitor demo identity. Unique per session on
// purpose: two visitors registering the same e-mail would dedup onto ONE
// person (that is what the dedup rule does), and then one visitor's erasure
// step would wipe the other's record out from under them.
func newSessionVars(unique string) map[string]string {
	return map[string]string{
		"unique":     unique,
		"demo_name":  "Ana Horvat",
		"demo_email": fmt.Sprintf("ana.horvat+%s@example.com", unique),
		// E.164 with a session-derived subscriber number.
		"demo_phone": "+3859" + digitsFrom(unique, 8),
		"miss_email": fmt.Sprintf("nobody-%s@example.com", unique),
	}
}

// digitsFrom maps a hex string onto n decimal digits, deterministically:
// the same session keeps the same phone number across page reloads (the
// dedup story depends on the identifier being stable within a session).
func digitsFrom(seed string, n int) string {
	out := make([]byte, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, '0'+seed[i%len(seed)]%10)
	}
	return string(out)
}

// Sessions is a TTL map of visitor state. Bounded on purpose: an unbounded
// map keyed by a client-supplied cookie is a memory-exhaustion lever on a
// publicly reachable demo.
type Sessions struct {
	mu   sync.Mutex
	byID map[string]*Session
	ttl  time.Duration
	max  int
	// now is swappable in tests; production leaves it nil for time.Now.
	now func() time.Time
}

const (
	defaultSessionTTL = 2 * time.Hour
	defaultMaxSession = 2000
)

func NewSessions(ttl time.Duration, max int) *Sessions {
	if ttl <= 0 {
		ttl = defaultSessionTTL
	}
	if max <= 0 {
		max = defaultMaxSession
	}
	return &Sessions{byID: map[string]*Session{}, ttl: ttl, max: max}
}

func (s *Sessions) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// Get returns the session for id, creating one when the cookie is absent,
// unknown or expired. The returned id is what the caller must set as the
// cookie value.
func (s *Sessions) Get(id string) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock()
	if sess, ok := s.byID[id]; ok && now.Sub(sess.Seen) < s.ttl {
		sess.Seen = now
		return sess
	}
	s.sweepLocked(now)
	fresh := &Session{ID: newID(), results: map[string]*StepResult{}, Seen: now}
	fresh.vars = newSessionVars(fresh.ID[:12])
	s.byID[fresh.ID] = fresh
	return fresh
}

// Reset clears a session's captured state and mints a FRESH demo identity.
// A new identity, not the old one: the erasure scenario ends with the
// person gone, and replaying it against an erased record would teach a
// 404 instead of the story.
func (s *Sessions) Reset(id string) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byID[id]
	if !ok {
		return nil
	}
	sess.replace(newSessionVars(newID()[:12]))
	sess.Seen = s.clock()
	return sess
}

// sweepLocked drops expired sessions, then - if the map is still at its cap
// - the least recently seen ones. Eviction over refusal: a demo that starts
// answering "come back later" is worse than one that forgets old visitors.
func (s *Sessions) sweepLocked(now time.Time) {
	for id, sess := range s.byID {
		if now.Sub(sess.Seen) >= s.ttl {
			delete(s.byID, id)
		}
	}
	if len(s.byID) < s.max {
		return
	}
	type entry struct {
		id   string
		seen time.Time
	}
	all := make([]entry, 0, len(s.byID))
	for id, sess := range s.byID {
		all = append(all, entry{id, sess.Seen})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].seen.Before(all[j].seen) })
	for i := 0; i <= len(all)-s.max; i++ {
		delete(s.byID, all[i].id)
	}
}

// Count reports how many sessions are live (used by the status endpoint and
// the tests).
func (s *Sessions) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byID)
}

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// A session id that is not random would let one visitor read
		// another's walkthrough state; there is no safe fallback.
		panic("playground: no randomness for session ids: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

// randomDigits is used by the seeder for demo values that must not collide
// across stacks.
func randomDigits(n int) string {
	out := make([]byte, n)
	for i := range out {
		d, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			panic("playground: no randomness: " + err.Error())
		}
		out[i] = '0' + byte(d.Int64())
	}
	return string(out)
}
