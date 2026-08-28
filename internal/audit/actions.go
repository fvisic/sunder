package audit

import "strings"

// The audit action vocabulary, as a closed set.
//
// Until this file existed, an action was whatever string a call site passed
// to Append or ReadEvent. That is fine while one person holds the whole list
// in their head and stops being fine the moment a reader has to answer "what
// can `action` contain?" - which is exactly the question an auditor, a SIEM
// rule, and a retention policy all ask first. A typo produced a new action
// silently, and a downstream filter matching the old spelling went quiet
// rather than red.
//
// The set is enforced by TestEveryAuditActionIsRegistered, which reads the
// tree rather than trusting this map: an `Action: "..."` literal that is not
// registered fails the build, and a registered action that appears nowhere
// fails it too, so the list cannot rot into documentation of the past.
//
// It is deliberately NOT enforced at write time. A guard that refuses to
// append would convert a typo into a hole in the audit trail, which is the
// one outcome worse than an unfamiliar action string.

// ActionFamily is a prefix under which actions are generated rather than
// written literally - the suffix comes from runtime state.
type ActionFamily struct {
	Prefix  string
	Meaning string
	// Suffixes is the complete set of suffixes the code can produce.
	Suffixes []string
}

// Families are the generated action prefixes.
var Families = []ActionFamily{
	{
		Prefix:   "portal.mail.",
		Meaning:  "outcome of one privacy-portal mail delivery attempt",
		Suffixes: []string{"delivered", "failed", "no_mailer"},
	},
}

// Actions maps every literal audit action to what its presence means. The
// value is not decoration: it is what a reader of the trail needs in order
// to tell a routine read from a privileged one.
var Actions = map[string]string{
	// Reads. These are the high-volume ones, and the reason read events
	// are bucketed hourly by default (SUNDER_AUDIT_READS).
	"lookup":              "exact identifier resolved to a scope pseudonym (hit or miss)",
	"lookup.fuzzy":        "lookup widened by phonetic name codes - a match was possible, not necessarily found",
	"lookup.suffix":       "lookup by phone suffix - a partial identifier, single-hit only",
	"lookup.suffix.fuzzy": "phone suffix AND phonetic name together - the widest search this API offers",
	"attributes.read":     "one attribute decrypted and returned",
	"attributes.history":  "prior versions of an attribute listed",
	"files.read":          "an encrypted file was fetched",
	"files.list":          "a contact's files were listed",
	"versions.list":       "blob version metadata listed",
	"links.list":          "a contact's cross-scope links were listed",
	"tokens.read":         "a value token was detokenized",
	"tokens.bulk_read":    "a batch of value tokens was detokenized",
	"shares.fetch":        "a share link was redeemed",

	// Writes against contact data.
	"contacts.register":        "a contact entered the vault (or an existing one was matched)",
	"contacts.import":          "a bulk import batch committed",
	"scopes.issue":             "a new scope pseudonym was minted for an existing person",
	"consent.set":              "consent granted or withdrawn for a (cid, purpose)",
	"claims.external":          "an externally-issued claim was accepted",
	"claims.external.rejected": "an externally-issued claim was refused (issuer, signature or freshness)",

	// One-time identifiers.
	"oti.issue":  "a one-time identifier was minted",
	"oti.verify": "a one-time identifier was presented and consumed",

	// Value tokenization.
	"tokens.create":      "a value token was minted",
	"tokens.bulk_create": "a batch of value tokens was minted",
	"tokens.delete":      "a value token was destroyed",

	// Files and shares.
	"files.upload":  "ciphertext was stored against a contact",
	"files.delete":  "a file was marked for collection and its metadata redacted",
	"shares.create": "a share link was created",
	"shares.revoke": "a share link was revoked",

	// Cross-scope links.
	"links.link":   "two scope pseudonyms were linked to one person",
	"links.unlink": "a link was removed",

	// Data-subject rights. dsr.access and dsr.erase are org-wide and
	// linkage-capable; their presence in the trail is itself significant.
	"dsr.access":            "a full subject-access record was assembled",
	"dsr.export":            "a portability export was produced",
	"dsr.erase":             "a person was erased (crypto-shredded)",
	"dsr.erase.failed":      "an erasure notification exhausted its retries and needs a human",
	"dsr.cascade_completed": "every linked child of an erased person finished erasing",

	// The privacy portal, where the data subject acts for themselves.
	"portal.login":           "a portal magic-link was requested",
	"portal.access":          "the data subject viewed their own record",
	"portal.consent":         "the data subject changed their own consent",
	"portal.erase_requested": "the data subject requested erasure",

	// Operator and key lifecycle. Every one of these is a privileged act.
	"bootstrap":            "the vault was initialised",
	"client.grant":         "a client's actions, purposes or attributes changed",
	"client.rotate_secret": "a client credential was rotated",
	"issuer.add":           "an external claim issuer was trusted",
	"issuer.remove":        "an external claim issuer was untrusted",
	"keys.rotate":          "a new key version was minted",
	"keys.rekey":           "the re-encryption sweep ran",
	"keys.retire":          "a key version was destroyed",
	"admin.unlock":         "an unlock token was minted for a restricted operation",
	"admin.unlock.use":     "an unlock token was spent",
	"retention.run":        "the retention sweep ran",
	// These four reach the trail through a helper that takes the action as
	// a parameter (auditOperator, terminal), which is why the first version
	// of the guard - a regexp over `Action: "..."` - did not see them. Three
	// are privileged operator acts, the exact category this registry claims
	// to cover, and they were unregistered while the docs promised a closed
	// set. The AST scanner in scan_test.go is what found them.
	"client.create":       "an API client and its credential were created",
	"webhook.set":         "the erasure-notification webhook endpoint was changed",
	"retention.set":       "a retention policy was created or changed",
	"dsr.erase.delivered": "an erasure notification was accepted by the subscriber",

	// The audit trail's own record of aggregating reads.
	"audit.reads_hourly": "one hour of read buckets was sealed and chained",
}

// IsKnownAction reports whether a is in the closed set, either as a literal
// or as a member of a generated family.
func IsKnownAction(a string) bool {
	if _, ok := Actions[a]; ok {
		return true
	}
	for _, f := range Families {
		if !strings.HasPrefix(a, f.Prefix) {
			continue
		}
		suffix := strings.TrimPrefix(a, f.Prefix)
		for _, s := range f.Suffixes {
			if s == suffix {
				return true
			}
		}
	}
	return false
}

// Lookup action variants. The trail said "lookup" for an exact e-mail match,
// for a phonetic name match, and for a partial phone suffix - three searches
// with visibly different enumeration profiles recorded as one word.
//
// Under bucketed reads the per-event Detail is dropped, so `by` did not
// survive to the aggregate: an auditor reading a sealed hour could not tell a
// client that resolves exact identifiers from one probing suffixes. The
// action is the only field that survives bucketing, which is why the
// distinction belongs there and not in Detail.
// The four forms are the cross product of two independent wideners, not a
// three-way choice. The first cut of this treated suffix and fuzzy as
// mutually exclusive, on the reasoning that a suffix lookup cannot carry a
// name - but Lookup only refuses email/phone alongside a suffix, and a NAME
// narrows a suffix search perfectly happily. So `phone_suffix + name` under
// SUNDER_SEARCH_FUZZY_NAME is a real request, it is the widest search the
// API offers, and recording it as a plain `lookup.suffix` hid the fuzzy half
// from exactly the auditor the split exists to inform.
const (
	ActionLookup            = "lookup"
	ActionLookupFuzzy       = "lookup.fuzzy"
	ActionLookupSuffix      = "lookup.suffix"
	ActionLookupSuffixFuzzy = "lookup.suffix.fuzzy"
)

// LookupActions is the closed lookup.* set, for consumers that want every
// search regardless of form ("show me everything this client searched").
var LookupActions = []string{
	ActionLookup, ActionLookupFuzzy, ActionLookupSuffix, ActionLookupSuffixFuzzy,
}
