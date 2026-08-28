package service_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/fvisic/sunder/internal/audit"
	"github.com/fvisic/sunder/internal/service"
)

// splitEnv is searchEnv with the audit split on. The two switches are
// independent: the split describes HOW a search is recorded, the search
// features decide WHICH searches are possible.
func splitEnv(t *testing.T) *faultEnv {
	t.Helper()
	e := searchEnv(t)
	e.svc.SplitLookupActions = true
	return e
}

// readActions returns action -> total count across BOTH audit surfaces. A
// lookup lands in audit_read_buckets under the default bucketed mode and in
// the chained audit table otherwise; a test that reads only one of them
// passes or fails depending on a global mode it did not set.
func readActions(t *testing.T, e *faultEnv) map[string]int {
	t.Helper()
	ctx := context.Background()
	out := map[string]int{}
	rows, err := e.admin.Pool.Query(ctx,
		`SELECT action, sum(count)::bigint FROM audit_read_buckets GROUP BY action
		 UNION ALL
		 SELECT action, count(*)::bigint FROM audit GROUP BY action`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var a string
		var n int64
		if err := rows.Scan(&a, &n); err != nil {
			t.Fatal(err)
		}
		out[a] += int(n)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestSingleLookupActionIsTheDefault pins the posture an existing deployment
// keeps on upgrade. A consumer filtering `action = 'lookup'` must not go
// quiet because a new release started writing `lookup.suffix`.
func TestSingleLookupActionIsTheDefault(t *testing.T) {
	e := searchEnv(t) // split NOT enabled
	ctx := context.Background()

	if _, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
		Email: "single@example.com", Phone: "+385911234567", Name: "Ana Anić"}); err != nil {
		t.Fatal(err)
	}
	// One of each form.
	if _, err := e.svc.Lookup(ctx, e.crm, service.LookupInput{Email: "single@example.com"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Lookup(ctx, e.crm, service.LookupInput{
		Email: "single@example.com", Name: "Ana Anic"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Lookup(ctx, e.crm, service.LookupInput{
		PhoneSuffix: "911234567"}); err != nil {
		t.Fatal(err)
	}

	got := readActions(t, e)
	if got[audit.ActionLookup] != 3 {
		t.Errorf("default posture must record all three forms as %q, got %d of them (%v)",
			audit.ActionLookup, got[audit.ActionLookup], got)
	}
	for _, a := range []string{audit.ActionLookupFuzzy, audit.ActionLookupSuffix} {
		if got[a] != 0 {
			t.Errorf("%q appeared %d time(s) with the split off - an upgrade must not "+
				"silently re-label what a consumer filters on", a, got[a])
		}
	}
}

// TestSplitLookupActionsSeparatesTheThreeForms is the feature itself.
func TestSplitLookupActionsSeparatesTheThreeForms(t *testing.T) {
	e := splitEnv(t)
	ctx := context.Background()

	if _, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
		Email: "split@example.com", Phone: "+385911234567", Name: "Ana Anić"}); err != nil {
		t.Fatal(err)
	}
	// Exact identifier: the ordinary action.
	if _, err := e.svc.Lookup(ctx, e.crm, service.LookupInput{Email: "split@example.com"}); err != nil {
		t.Fatal(err)
	}
	// Phonetic narrowing participated: lookup.fuzzy. The stripped spelling
	// only resolves through the phonetic codes, so a hit here proves the
	// fuzzy path ran rather than merely being enabled.
	if _, err := e.svc.Lookup(ctx, e.crm, service.LookupInput{
		Email: "split@example.com", Name: "Ana Anic"}); err != nil {
		t.Fatal(err)
	}
	// Partial identifier: lookup.suffix.
	if _, err := e.svc.Lookup(ctx, e.crm, service.LookupInput{PhoneSuffix: "911234567"}); err != nil {
		t.Fatal(err)
	}

	got := readActions(t, e)
	for _, want := range []struct {
		action string
		n      int
	}{
		{audit.ActionLookup, 1},
		{audit.ActionLookupFuzzy, 1},
		{audit.ActionLookupSuffix, 1},
	} {
		if got[want.action] != want.n {
			t.Errorf("want %d x %q, got %d (all: %v)", want.n, want.action, got[want.action], got)
		}
	}
}

// TestNameLookupIsFuzzyOnlyWhenPhoneticsRan is the distinction that makes
// the split worth having: `lookup.fuzzy` claims a WIDER search surface than
// `lookup`, so it must mean the phonetic branch actually widened this query -
// not merely that a name was supplied, and not merely that the feature is
// switched on somewhere in the config.
//
// Two ways the fuzzy branch does not run even though the input has a name:
// the feature is off for the deployment, and the name reduces to no phonetic
// code at all. Both must record as plain `lookup`.
func TestNameLookupIsFuzzyOnlyWhenPhoneticsRan(t *testing.T) {
	t.Run("feature off", func(t *testing.T) {
		e := newFaultEnv(t) // FuzzyName stays false
		e.svc.SplitLookupActions = true
		ctx := context.Background()
		if _, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
			Email: "off@example.com", Name: "Ana Anić"}); err != nil {
			t.Fatal(err)
		}
		if _, err := e.svc.Lookup(ctx, e.crm, service.LookupInput{
			Email: "off@example.com", Name: "Ana Anić"}); err != nil {
			t.Fatal(err)
		}
		got := readActions(t, e)
		if got[audit.ActionLookupFuzzy] != 0 {
			t.Errorf("phonetic search is disabled on this deployment, yet %d lookup(s) "+
				"recorded as %q", got[audit.ActionLookupFuzzy], audit.ActionLookupFuzzy)
		}
		if got[audit.ActionLookup] == 0 {
			t.Errorf("the lookup was not recorded as %q either (all: %v)", audit.ActionLookup, got)
		}
	})

	t.Run("name reduces to no phonetic code", func(t *testing.T) {
		e := splitEnv(t) // feature ON
		ctx := context.Background()
		if _, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
			Email: "nocode@example.com", Name: "Ana Anić"}); err != nil {
			t.Fatal(err)
		}
		// ph1 drops symbols, so this name yields no codes at all and the
		// query narrows on the exact name token only. Digits DO produce a
		// code ("123" -> "123"), which is why this case needs symbols.
		if _, err := e.svc.Lookup(ctx, e.crm, service.LookupInput{
			Email: "nocode@example.com", Name: "---"}); !errors.Is(err, service.ErrNotFound) {
			t.Fatalf("a symbol-only name should narrow to nothing, got %v", err)
		}
		got := readActions(t, e)
		if got[audit.ActionLookupFuzzy] != 0 {
			t.Errorf("a lookup whose name produced no phonetic codes was recorded as %q "+
				"%d time(s) - the action would overstate the search surface",
				audit.ActionLookupFuzzy, got[audit.ActionLookupFuzzy])
		}
	})
}

// TestSplitLookupActionsAreAllRegistered ties the runtime back to the closed
// enum: whatever the split writes must be a registered action, or the
// vocabulary guard in internal/audit is describing a system that no longer
// exists.
func TestSplitLookupActionsAreAllRegistered(t *testing.T) {
	e := splitEnv(t)
	ctx := context.Background()

	if _, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
		Email: "reg@example.com", Phone: "+385915550001", Name: "Ana Anić"}); err != nil {
		t.Fatal(err)
	}
	for _, in := range []service.LookupInput{
		{Email: "reg@example.com"},
		{Email: "reg@example.com", Name: "Ana Anic"},
		{PhoneSuffix: "915550001"},
		{Email: "nobody@example.com"},
		{PhoneSuffix: "999999999"},
	} {
		_, _ = e.svc.Lookup(ctx, e.crm, in)
	}
	for action := range readActions(t, e) {
		if !audit.IsKnownAction(action) {
			t.Errorf("the trail carries %q, which is not in the closed action set", action)
		}
	}
}

// TestSplitLookupActionsBucketMultiplier is the MEASUREMENT the split was
// gated on, not a pass/fail of taste.
//
// Read events aggregate into buckets keyed
// (client_id, user_id, cid, action, hour). Splitting one action into three
// can only multiply rows where a single (client, user, cid, hour) key
// previously held searches of more than one form - and the worst case is
// exactly the miss bucket, because every miss shares cid = ”.
//
// The test builds that worst case deliberately and reports the ratio, so the
// number in docs/CONFIG.md comes from a run rather than from arithmetic on a
// whiteboard.
func TestSplitLookupActionsBucketMultiplier(t *testing.T) {
	count := func(e *faultEnv) int {
		var n int
		if err := e.admin.Pool.QueryRow(context.Background(),
			`SELECT count(*) FROM audit_read_buckets`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	// The same traffic against both postures: one client, one user, a hit
	// and a miss in each of the three forms. This is the shape that costs
	// the most - a client using every form within one hour.
	traffic := func(e *faultEnv) {
		ctx := context.Background()
		if _, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
			Email: "mult@example.com", Phone: "+385915559999", Name: "Ana Anić"}); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 5; i++ {
			// Hits: same cid, so they collapse per action.
			_, _ = e.svc.Lookup(ctx, e.crm, service.LookupInput{
				Email: "mult@example.com", UserID: "agent-1"})
			_, _ = e.svc.Lookup(ctx, e.crm, service.LookupInput{
				Email: "mult@example.com", Name: "Ana Anic", UserID: "agent-1"})
			_, _ = e.svc.Lookup(ctx, e.crm, service.LookupInput{
				PhoneSuffix: "915559999", UserID: "agent-1"})
			// Misses: cid is empty, so ALL of them share one key per action.
			_, _ = e.svc.Lookup(ctx, e.crm, service.LookupInput{
				Email: fmt.Sprintf("miss-%d@example.com", i), UserID: "agent-1"})
			_, _ = e.svc.Lookup(ctx, e.crm, service.LookupInput{
				Email: fmt.Sprintf("miss-%d@example.com", i), Name: "Ana Anic", UserID: "agent-1"})
			_, _ = e.svc.Lookup(ctx, e.crm, service.LookupInput{
				PhoneSuffix: fmt.Sprintf("91555%04d", 1000+i), UserID: "agent-1"})
		}
	}

	single := searchEnv(t)
	traffic(single)
	before := count(single)

	split := splitEnv(t)
	traffic(split)
	after := count(split)

	if before == 0 {
		t.Fatal("no read buckets were written - the measurement is vacuous " +
			"(is SUNDER_AUDIT_READS set to chained in this environment?)")
	}
	ratio := float64(after) / float64(before)
	t.Logf("read-bucket rows for identical worst-case traffic: single=%d split=%d ratio=%.2fx",
		before, after, ratio)

	// The bound is arithmetic, not aspiration: three actions cannot produce
	// more than three rows where one produced one. A ratio above it means
	// the split is generating actions outside the closed set.
	if ratio > 3.0 {
		t.Fatalf("bucket rows grew %.2fx, above the 3x ceiling the three-action split "+
			"can arithmetically cause - something is writing an unplanned action", ratio)
	}
	// And it must actually cost something on this traffic, or the test is
	// measuring a split that did not happen.
	if after <= before {
		t.Fatalf("split produced %d rows against single's %d - the worst-case traffic "+
			"should separate; the measurement is not exercising the feature", after, before)
	}
}
