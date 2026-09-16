package crypto

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func setShape(t *testing.T, s string) {
	t.Helper()
	old := PersonIDShape()
	SetPersonIDShape(s)
	t.Cleanup(func() { SetPersonIDShape(old) })
}

// rawUUID undoes the canonical formatting so the bit layout can be checked.
func rawUUID(t *testing.T, s string) []byte {
	t.Helper()
	if len(s) != 36 || strings.Count(s, "-") != 4 {
		t.Fatalf("not a canonical uuid string: %q", s)
	}
	b, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(b) != 16 {
		t.Fatalf("not hex: %q (%v)", s, err)
	}
	return b
}

func TestPersonIDDefaultIsV4(t *testing.T) {
	setShape(t, "")
	if PersonIDShape() != PersonIDV4 {
		t.Fatalf("default shape must be v4 (the one every prior measurement used), got %q", PersonIDShape())
	}
	id, err := NewPersonID()
	if err != nil {
		t.Fatal(err)
	}
	b := rawUUID(t, id)
	if b[6]>>4 != 4 {
		t.Errorf("version nibble = %x, want 4", b[6]>>4)
	}
	if b[8]>>6 != 0b10 {
		t.Errorf("variant bits = %b, want 10", b[8]>>6)
	}
}

func TestPersonIDV7IsTimeOrdered(t *testing.T) {
	setShape(t, PersonIDV7)
	before := time.Now().UnixMilli()
	var prev uint64
	for i := 0; i < 1000; i++ {
		id, err := NewPersonID()
		if err != nil {
			t.Fatal(err)
		}
		b := rawUUID(t, id)
		if b[6]>>4 != 7 {
			t.Fatalf("version nibble = %x, want 7", b[6]>>4)
		}
		if b[8]>>6 != 0b10 {
			t.Fatalf("variant bits = %b, want 10", b[8]>>6)
		}
		ms := uint64(b[0])<<40 | uint64(b[1])<<32 | uint64(b[2])<<24 |
			uint64(b[3])<<16 | uint64(b[4])<<8 | uint64(b[5])
		if int64(ms) < before || int64(ms) > time.Now().UnixMilli() {
			t.Fatalf("timestamp prefix %d is outside [%d, now]", ms, before)
		}
		// The prefix is the clock, so it never goes backwards within one
		// process - which is the whole point: inserts land at the right
		// edge of the primary key instead of on a random page.
		if ms < prev {
			t.Fatalf("timestamp prefix went backwards: %d after %d", ms, prev)
		}
		prev = ms
	}
}

func TestPersonIDsAreUnique(t *testing.T) {
	for _, shape := range []string{PersonIDV4, PersonIDV7} {
		setShape(t, shape)
		seen := make(map[string]struct{}, 10000)
		for i := 0; i < 10000; i++ {
			id, err := NewPersonID()
			if err != nil {
				t.Fatal(err)
			}
			if _, dup := seen[id]; dup {
				t.Fatalf("%s: duplicate id %s", shape, id)
			}
			seen[id] = struct{}{}
		}
	}
}

func TestPersonIDUnknownShapeFallsBackToV4(t *testing.T) {
	// config refuses anything but v4/v7 at startup; this pins what the
	// generator does if it is ever handed something else anyway.
	setShape(t, "v9")
	if PersonIDShape() != PersonIDV4 {
		t.Fatalf("got %q", PersonIDShape())
	}
}
