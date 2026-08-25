package crypto

import (
	"reflect"
	"testing"
)

// mustNorm pipes through NormalizeName first - production always does.
func mustNorm(t *testing.T, s string) string {
	t.Helper()
	n, err := NormalizeName(s)
	if err != nil {
		t.Fatalf("normalize %q: %v", s, err)
	}
	return n
}

func TestPhoneticFoldsCroatianVariants(t *testing.T) {
	same := [][]string{
		// Diacritic stripping - the single most common variance.
		{"Anić", "Anic", "ANIC", "anić"},
		{"Kovačević", "Kovacevic", "KOVAČEVIĆ"},
		// đ spelled đ, dj or plain d.
		{"Đurđević", "Djurdjevic", "Durdevic"},
		// ije/je/e reflexes.
		{"Bijelić", "Bjelić", "Belić"},
		// Vowel typos.
		{"Ivan", "Iven"},
		// Foreign-letter folds.
		{"Walter", "Valter"},
		{"Ksenija", "Xenija"},
		{"Žužul", "Zuzul"},
		{"Straße", "Strasse"},
	}
	for _, group := range same {
		first := PhoneticNameCodes(mustNorm(t, group[0]))
		for _, v := range group[1:] {
			got := PhoneticNameCodes(mustNorm(t, v))
			if !reflect.DeepEqual(first, got) {
				t.Errorf("%q -> %v but %q -> %v; variants must share a code", group[0], first, v, got)
			}
		}
	}

	different := [][2]string{
		{"Anić", "Babić"},
		{"Kovačević", "Kovačić"},
		{"Ivan", "Ivana"}, // trailing consonant difference survives
	}
	for _, pair := range different {
		a := PhoneticNameCodes(mustNorm(t, pair[0]))
		b := PhoneticNameCodes(mustNorm(t, pair[1]))
		if reflect.DeepEqual(a, b) {
			t.Errorf("%q and %q must not collide (both %v)", pair[0], pair[1], a)
		}
	}
}

func TestPhoneticPerWordAndCaps(t *testing.T) {
	// Multi-word names produce one code per word, deduplicated, so a
	// lookup by surname alone can narrow against a stored full name.
	full := PhoneticNameCodes(mustNorm(t, "Ana Marija Anić"))
	if len(full) != 3 {
		t.Fatalf("want 3 word codes, got %v", full)
	}
	surname := PhoneticNameCodes(mustNorm(t, "Anić"))
	found := false
	for _, c := range full {
		if c == surname[0] {
			found = true
		}
	}
	if !found {
		t.Fatalf("surname code %v must appear in full-name codes %v", surname, full)
	}
	// Word fan-out is capped; duplicates collapse; pure-symbol words drop.
	long := PhoneticNameCodes("a b c d e f g h")
	if len(long) > maxPhoneticWords {
		t.Fatalf("word cap breached: %v", long)
	}
	if got := PhoneticNameCodes("ana ana"); len(got) != 1 {
		t.Fatalf("duplicate words must dedupe, got %v", got)
	}
	if got := PhoneticNameCodes("--- ***"); len(got) != 0 {
		t.Fatalf("symbol-only words must vanish, got %v", got)
	}
}

func TestPhoneSuffix(t *testing.T) {
	// The property the whole feature rests on: national and international
	// spellings of the SAME number share the suffix.
	intl := PhoneSuffix("+385911234567")
	if intl != "11234567" {
		t.Fatalf("suffix of +385911234567 = %q", intl)
	}
	// Different numbers, different suffixes.
	if PhoneSuffix("+385921234567") == intl {
		t.Fatal("distinct numbers must not share this suffix")
	}
	// Short numbers: everything after '+' (deterministic, still keyed).
	if got := PhoneSuffix("+38512345"); got != "38512345" {
		t.Fatalf("short number suffix = %q", got)
	}
}
