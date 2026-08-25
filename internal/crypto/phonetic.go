package crypto

// Phonetic name codes (Phase 3 / F1). A fuzzy name lookup cannot work on
// exact HMAC tokens, so each word of a name is reduced to a deterministic
// phonetic code and the CODE is tokenized - the database still stores only
// keyed HMACs, never anything reversible, and fuzziness comes entirely
// from the reduction being many-to-one.
//
// The algorithm ("ph1") is deliberately our own, small and versioned,
// rather than Double Metaphone: the primary alphabet here is Croatian,
// where the variance that actually occurs is diacritic stripping
// (Anić/Anic), the đ/dj/d spellings (Đurđević/Djurdjevic/Durdevic),
// ije/je/e reflexes (Bijelić/Belić) and vowel typos - all of which ph1
// folds - while Double Metaphone is tuned for English and handles none of
// those. The code version is part of the HMAC input domain, so a future
// ph2 can coexist under the dual-key lookup window.
//
// ph1, per word of an already-normalized name (NormalizeName: NFKC,
// lowercase, single spaces):
//
//  1. transliterate: Croatian diacritics (č ć -> c, đ -> d, š -> s,
//     ž -> z) and common European ones (ä -> a, é -> e, ñ -> n, ç -> c,
//     ß -> ss); foreign letters fold (w -> v, q -> k, x -> ks, y -> j);
//     anything else non-alphanumeric is dropped;
//  2. digraph fold: "dj" -> "d" (the ASCII spelling of đ);
//  3. class fold: c -> k, z -> s (merges the č/ć/c and š/s/ž families
//     that diacritic stripping conflates anyway);
//  4. collapse repeated letters;
//  5. keep the first and last letters verbatim, drop vowels and the
//     semi-vowel j from the middle (folds ije/je/e and absorbs vowel
//     typos, while the kept trailing vowel preserves the gender pairs
//     Croatian names hinge on: Ivan/Ivana must not collide).
//
// Names are ONLY ever a narrowing key beside email or phone - never a
// primary lookup key and never authentication - so the false positives a
// reduction like this admits merely narrow a little less.

import "strings"

// phTranslit maps one rune to its ASCII reduction (step 1).
var phTranslit = map[rune]string{
	'č': "c", 'ć': "c", 'đ': "d", 'š': "s", 'ž': "z",
	'à': "a", 'á': "a", 'â': "a", 'ä': "a", 'å': "a", 'ã': "a",
	'è': "e", 'é': "e", 'ê': "e", 'ë': "e",
	'ì': "i", 'í': "i", 'î': "i", 'ï': "i",
	'ò': "o", 'ó': "o", 'ô': "o", 'ö': "o", 'õ': "o",
	'ù': "u", 'ú': "u", 'û': "u", 'ü': "u",
	'ñ': "n", 'ç': "c", 'ß': "ss",
	'w': "v", 'q': "k", 'x': "ks", 'y': "j",
}

// maxPhoneticWords bounds token fan-out per name: beyond four words a
// "name" is a title string, and every extra word is another index row.
const maxPhoneticWords = 4

// PhoneticNameCodes returns the deduplicated ph1 code per word of a
// normalized name. Words that reduce to nothing (all symbols) are skipped;
// at most maxPhoneticWords words are considered.
func PhoneticNameCodes(normalized string) []string {
	words := strings.Fields(normalized)
	if len(words) > maxPhoneticWords {
		words = words[:maxPhoneticWords]
	}
	var out []string
	seen := map[string]bool{}
	for _, w := range words {
		if code := phoneticWord(w); code != "" && !seen[code] {
			seen[code] = true
			out = append(out, code)
		}
	}
	return out
}

func phoneticWord(w string) string {
	// Steps 1-3: transliterate, then fold classes rune by rune.
	var b strings.Builder
	for _, r := range w {
		s, ok := phTranslit[r]
		if !ok {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
				s = string(r)
			} else {
				continue // symbols, apostrophes, hyphens: no signal
			}
		}
		for _, rr := range s {
			switch rr {
			case 'c':
				b.WriteByte('k')
			case 'z':
				b.WriteByte('s')
			default:
				b.WriteRune(rr)
			}
		}
	}
	s := strings.ReplaceAll(b.String(), "dj", "d") // step 2 (post-translit)

	// Step 4: collapse repeats.
	var folded []byte
	var last byte
	for i := 0; i < len(s); i++ {
		if s[i] == last {
			continue
		}
		last = s[i]
		folded = append(folded, s[i])
	}
	// Step 5: first and last letters verbatim, middle without vowels or j.
	var code []byte
	for i, ch := range folded {
		if i > 0 && i < len(folded)-1 {
			switch ch {
			case 'a', 'e', 'i', 'o', 'u', 'j':
				continue
			}
		}
		code = append(code, ch)
	}
	return string(code)
}

// PhoneSuffix returns the partial-lookup key of a normalized E.164 number
// (Phase 3 / F2): its last eight digits. Eight is what survives every
// national/international spelling of the same number (+385911234567 and
// 0911234567 share them) while staying long enough that collisions are
// rare - and a collision is not wrong, merely ambiguous: the suffix lookup
// answers only when it narrows to exactly one person.
func PhoneSuffix(normalizedE164 string) string {
	digits := strings.TrimPrefix(normalizedE164, "+")
	if len(digits) <= 8 {
		return digits
	}
	return digits[len(digits)-8:]
}
