package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/service"
)

func TestBlobVersioning(t *testing.T) {
	e := newFaultEnv(t)
	e.svc.VersionsKeep = 3
	ctx := context.Background()

	// First register: no prior blob, so no version yet.
	cid, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
		Email: "ana@example.com", Attributes: map[string]string{"tier": "bronze"}})
	if err != nil {
		t.Fatal(err)
	}
	// Re-register (merge) three times: each overwrite snapshots the prior.
	for _, tier := range []string{"silver", "gold", "platinum"} {
		if _, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
			Email: "ana@example.com", Attributes: map[string]string{"tier": tier}}); err != nil {
			t.Fatal(err)
		}
	}

	hist := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions:  []string{auth.ActAttributesHistory},
		AllowedPurposes: []string{"support"}}
	versions, err := e.svc.ListVersions(ctx, hist, cid)
	if err != nil {
		t.Fatal(err)
	}
	// 3 overwrites -> 3 versions, capped at VersionsKeep=3.
	if len(versions) != 3 {
		t.Fatalf("want 3 versions, got %d", len(versions))
	}
	// F6-1: the version author is the real client id, not a literal.
	if versions[0].WrittenBy != "crm" {
		t.Fatalf("version author must be the client id, got %q", versions[0].WrittenBy)
	}
	// The newest version holds the value that was live just before the
	// last write ("gold").
	newest := versions[0].VersionNo
	v, err := e.svc.GetVersionAttribute(ctx, hist, cid, newest, "tier", "support")
	if err != nil {
		t.Fatal(err)
	}
	if v != "gold" {
		t.Fatalf("newest version tier = %q, want gold", v)
	}

	// Guards: permission, purpose, allowlist, unknown version.
	noPerm := &auth.Client{ID: "np", Scope: "crm", AllowedPurposes: []string{"support"}}
	if _, err := e.svc.ListVersions(ctx, noPerm, cid); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("list without action: %v", err)
	}
	if _, err := e.svc.GetVersionAttribute(ctx, hist, cid, newest, "tier", ""); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("empty purpose: %v", err)
	}
	if _, err := e.svc.GetVersionAttribute(ctx, hist, cid, 99999, "tier", "support"); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("unknown version: %v", err)
	}
	narrowed := &auth.Client{ID: "n", Scope: "crm",
		AllowedActions: []string{auth.ActAttributesHistory}, AllowedPurposes: []string{"support"},
		AllowedAttributes: []string{"iban"}}
	if _, err := e.svc.GetVersionAttribute(ctx, narrowed, cid, newest, "tier", "support"); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("allowlist must gate history reads: %v", err)
	}
}

func TestBlobVersioningOffByDefault(t *testing.T) {
	e := newFaultEnv(t) // VersionsKeep = 0
	ctx := context.Background()
	cid, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
		Email: "off@example.com", Attributes: map[string]string{"tier": "bronze"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
		Email: "off@example.com", Attributes: map[string]string{"tier": "silver"}}); err != nil {
		t.Fatal(err)
	}
	var n int64
	if err := e.admin.Pool.QueryRow(ctx, `SELECT count(*) FROM cid_blob_versions`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("versioning off must keep no history, got %d", n)
	}
	_ = cid
}

func TestBlobVersionsErasedWithPerson(t *testing.T) {
	e := newFaultEnv(t)
	e.svc.VersionsKeep = 3
	ctx := context.Background()
	cid, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
		Email: "era@example.com", Attributes: map[string]string{"tier": "bronze"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
		Email: "era@example.com", Attributes: map[string]string{"tier": "gold"}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.gdpr.Erase(ctx, e.crm, cid); err != nil {
		t.Fatal(err)
	}
	var n int64
	if err := e.admin.Pool.QueryRow(ctx, `SELECT count(*) FROM cid_blob_versions`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("erasure must purge history, %d left", n)
	}
}

func TestBlobVersionFaultAndPrune(t *testing.T) {
	e := newFaultEnv(t)
	e.svc.VersionsKeep = 3
	ctx := context.Background()
	cid, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
		Email: "p@example.com", Attributes: map[string]string{"tier": "bronze"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
		Email: "p@example.com", Attributes: map[string]string{"tier": "gold"}}); err != nil {
		t.Fatal(err)
	}
	// TTL prune removes an old version.
	if _, err := e.admin.Pool.Exec(ctx,
		`UPDATE cid_blob_versions SET written_at = now() - interval '400 days'`); err != nil {
		t.Fatal(err)
	}
	n, err := service.PruneBlobVersions(ctx, e.admin.Pool, 24*time.Hour*365)
	if err != nil || n != 1 {
		t.Fatalf("prune: %d %v", n, err)
	}
	// Fault: break the table so ListVersions/GetVersionAttribute error.
	if _, err := e.admin.Pool.Exec(ctx, `ALTER TABLE cid_blob_versions RENAME TO cbv_gone`); err != nil {
		t.Fatal(err)
	}
	hist := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions: []string{auth.ActAttributesHistory}, AllowedPurposes: []string{"support"}}
	if _, err := e.svc.ListVersions(ctx, hist, cid); err == nil {
		t.Fatal("list must surface the query error")
	}
	if _, err := e.svc.GetVersionAttribute(ctx, hist, cid, 1, "tier", "support"); err == nil {
		t.Fatal("get version must surface the query error")
	}
	if _, err := service.PruneBlobVersions(ctx, e.admin.Pool, time.Hour); err == nil {
		t.Fatal("prune must surface the query error")
	}
}

func TestBlobVersioningConsentAndFault(t *testing.T) {
	e := newFaultEnv(t)
	e.svc.VersionsKeep = 3
	ctx := context.Background()
	cid, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
		Email: "c@example.com", Attributes: map[string]string{"tier": "bronze"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
		Email: "c@example.com", Attributes: map[string]string{"tier": "gold"}}); err != nil {
		t.Fatal(err)
	}
	hist := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions: []string{auth.ActAttributesHistory}, AllowedPurposes: []string{"support"}}
	// Withdrawn consent blocks the history read too.
	if err := e.gdpr.SetConsent(ctx, e.crm, cid, "support", false); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.GetVersionAttribute(ctx, hist, cid, 1, "tier", "support"); !errors.Is(err, service.ErrConsentDenied) {
		t.Fatalf("withdrawn consent must block history: %v", err)
	}
	// A wrong purpose is rejected.
	if _, err := e.svc.GetVersionAttribute(ctx, hist, cid, 1, "tier", "marketing"); !errors.Is(err, service.ErrPurposeNotAllowed) {
		t.Fatalf("wrong purpose: %v", err)
	}
	// Foreign scope: the cid is not resolvable, a miss.
	foreign := &auth.Client{ID: "erp", Scope: "erp",
		AllowedActions: []string{auth.ActAttributesHistory}, AllowedPurposes: []string{"support"}}
	if _, err := e.svc.ListVersions(ctx, foreign, cid); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("foreign scope list: %v", err)
	}
}

func TestAppendVersionFaultBlocksMerge(t *testing.T) {
	e := newFaultEnv(t)
	e.svc.VersionsKeep = 3
	ctx := context.Background()
	if _, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
		Email: "m@example.com", Attributes: map[string]string{"tier": "bronze"}}); err != nil {
		t.Fatal(err)
	}
	// Break the versions table so the next overwrite's appendVersion fails
	// - and the whole merge must roll back (atomic history).
	if _, err := e.admin.Pool.Exec(ctx, `ALTER TABLE cid_blob_versions RENAME TO cbv_hidden`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
		Email: "m@example.com", Attributes: map[string]string{"tier": "gold"}}); err == nil {
		t.Fatal("a merge must fail if its version snapshot cannot be written")
	}
	// The live blob still holds the original value (merge rolled back).
	if _, err := e.admin.Pool.Exec(ctx, `ALTER TABLE cbv_hidden RENAME TO cid_blob_versions`); err != nil {
		t.Fatal(err)
	}
	reader := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions: []string{auth.ActAttributesRead}, AllowedPurposes: []string{"support"}}
	cid, err := e.svc.Lookup(ctx, &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions: []string{auth.ActLookup}, AllowedPurposes: []string{"support"}},
		service.LookupInput{Email: "m@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	v, err := e.svc.GetAttribute(ctx, reader, cid, "tier", "support")
	if err != nil || v != "bronze" {
		t.Fatalf("merge rollback must preserve the original: %q %v", v, err)
	}
}

func TestVersionReadAuditDenied(t *testing.T) {
	e := newFaultEnv(t, "audit", "audit_read_buckets")
	e.svc.VersionsKeep = 3
	ctx := context.Background()
	// Seed a version row directly (Register would audit and fail).
	cid := e.register(t)
	if _, err := e.admin.Pool.Exec(ctx, `
		INSERT INTO cid_blob_versions (cid, version_no, blob, key_id, alg, written_by)
		SELECT $1, 1, pii_encrypted, COALESCE(pii_key_id,'v1'), COALESCE(pii_alg,'aes256gcm'), 'seed'
		  FROM cids WHERE cid=$1`, cid); err != nil {
		t.Fatal(err)
	}
	hist := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions: []string{auth.ActAttributesHistory}, AllowedPurposes: []string{"support"}}
	if _, err := e.svc.GetVersionAttribute(ctx, hist, cid, 1, "tier", "support"); err == nil {
		t.Fatal("history read must fail closed when audit is denied")
	}
}

// TestS5_RekeyRewrapsVersionHistory reproduces S5: keys rekey must
// re-encrypt attribute-version blobs under the newest KEK, so retiring a
// leaked KEK stops it decrypting old history too.
func TestS5_RekeyRewrapsVersionHistory(t *testing.T) {
	e := newFaultEnv(t)
	e.svc.VersionsKeep = 3
	ctx := context.Background()
	cid, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
		Email: "s5@example.com", Attributes: map[string]string{"tier": "bronze"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Register(ctx, e.crm, service.RegisterInput{
		Email: "s5@example.com", Attributes: map[string]string{"tier": "gold"}}); err != nil {
		t.Fatal(err)
	}
	// A version row exists under the current KEK.
	var vKeyBefore string
	if err := e.admin.Pool.QueryRow(ctx, `SELECT key_id FROM cid_blob_versions WHERE cid=$1 LIMIT 1`, cid).Scan(&vKeyBefore); err != nil {
		t.Fatal(err)
	}
	newKEK, err := e.svc.Ring.Rotate(ctx, e.svc.PII.Engine(), "pii-kek")
	if err != nil {
		t.Fatal(err)
	}
	stats, err := e.svc.Rekey(ctx, true, 100)
	if err != nil {
		t.Fatal(err)
	}
	if stats.VersionsRewrapped < 1 {
		t.Fatalf("rekey must re-wrap version history: %+v", stats)
	}
	var vKeyAfter string
	if err := e.admin.Pool.QueryRow(ctx, `SELECT key_id FROM cid_blob_versions WHERE cid=$1 LIMIT 1`, cid).Scan(&vKeyAfter); err != nil {
		t.Fatal(err)
	}
	if vKeyAfter != newKEK || vKeyAfter == vKeyBefore {
		t.Fatalf("version blob still under the old KEK: before=%s after=%s newest=%s", vKeyBefore, vKeyAfter, newKEK)
	}
	// And the history still reads correctly under the new wrapping.
	hist := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions: []string{auth.ActAttributesHistory}, AllowedPurposes: []string{"support"}}
	if v, err := e.svc.GetVersionAttribute(ctx, hist, cid, 1, "tier", "support"); err != nil || v != "bronze" {
		t.Fatalf("version still readable after rekey: %q %v", v, err)
	}
}
