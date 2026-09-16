package crypto

// EXPERIMENT (uncommitted until measured): the person-id generator, in one
// place, selectable at process start.
//
// persons.id is internal-only (it appears in no JSON response, SDK, export
// or mail - the exposed pseudonym is the CID). Its SHAPE still matters for
// throughput: a random v4 id gives every primary-key insert a random B-tree
// page, and the measured cost of that is a -26%-per-decade decay in offline
// import (11,235 rows/s at 1M -> 8,347 at 10M) as the index outgrows cache.
// A time-ordered id makes those inserts append-like.
//
// SUNDER_PERSON_ID selects the variant: "v4" (default, the behaviour every
// existing measurement was taken under) or "v7" (RFC 9562: 48-bit unix-ms
// prefix, then randomness). Read once at first use - switching id shapes
// mid-process is not a thing that should be possible.

import (
	cryptorand "crypto/rand"
	"fmt"
	"os"
	"sync"
	"time"
)

var (
	personIDModeOnce sync.Once
	personIDV7       bool
)

// NewPersonID returns a fresh persons.id in the configured shape.
func NewPersonID() (string, error) {
	personIDModeOnce.Do(func() {
		personIDV7 = os.Getenv("SUNDER_PERSON_ID") == "v7"
	})
	var b [16]byte
	if _, err := cryptorand.Read(b[:]); err != nil {
		return "", err
	}
	if personIDV7 {
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
