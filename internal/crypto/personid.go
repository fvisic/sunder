package crypto

import (
	"fmt"
	"sync/atomic"
	"time"
)

// Person-id shapes (SUNDER_PERSON_ID).
//
// persons.id is internal to the database: it appears in no JSON response,
// SDK, export or mail - the exposed pseudonym is the CID. Its SHAPE still
// decides import throughput, because the primary key of person_tokens starts
// with it: a random v4 id gives every insert a random B-tree page, and the
// measured cost is a -26%-per-decade decay in offline import (11,235 rows/s
// at 1M -> 8,347 at 10M) as that index outgrows cache. A time-ordered id
// makes those inserts append-like.
const (
	PersonIDV4 = "v4" // random (RFC 9562 version 4) - the shape every measurement before 2026-09 was taken under
	PersonIDV7 = "v7" // time-ordered (RFC 9562 version 7): 48-bit unix-ms prefix, then randomness
)

// personIDV7 is set once at process start from the validated config, the
// same way audit.SetReadsMode is: the raw environment is never consulted
// here, so a typo is refused by config.FromEnv rather than silently
// defaulting, and no request path can flip the shape mid-run.
var personIDV7 atomic.Bool

// SetPersonIDShape selects the shape NewPersonID mints. Anything other than
// PersonIDV7 selects v4; validation of the string is config's job.
func SetPersonIDShape(shape string) { personIDV7.Store(shape == PersonIDV7) }

// PersonIDShape reports the active shape.
func PersonIDShape() string {
	if personIDV7.Load() {
		return PersonIDV7
	}
	return PersonIDV4
}

// NewPersonID returns a fresh persons.id in the configured shape, formatted
// as the canonical 36-character UUID string Postgres parses into its uuid
// type either way.
func NewPersonID() (string, error) {
	var b [16]byte
	if _, err := randRead(b[:]); err != nil {
		return "", err
	}
	if personIDV7.Load() {
		ms := uint64(time.Now().UnixMilli())
		b[0] = byte(ms >> 40)
		b[1] = byte(ms >> 32)
		b[2] = byte(ms >> 24)
		b[3] = byte(ms >> 16)
		b[4] = byte(ms >> 8)
		b[5] = byte(ms)
		b[6] = (b[6] & 0x0f) | 0x70
	} else {
		b[6] = (b[6] & 0x0f) | 0x40
	}
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
