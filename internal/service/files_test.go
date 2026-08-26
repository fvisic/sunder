package service_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/service"
	"github.com/fvisic/sunder/internal/storage"
)

func filesEnv(t *testing.T) (*faultEnv, *service.Files, *auth.Client, string) {
	t.Helper()
	e := newFaultEnv(t)
	drv, err := storage.Open(storage.Config{Kind: "local", Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	f := &service.Files{Pool: e.admin.Pool, Eng: e.svc.PII.Engine(), Ring: e.svc.Ring,
		Store: drv, Contacts: e.svc, MaxBytes: 1 << 20}
	client := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions:  []string{auth.ActFilesWrite, auth.ActFilesRead, auth.ActContactsRegister},
		AllowedPurposes: []string{"support"}}
	ctx := context.Background()
	cid, err := e.svc.Register(ctx, client, service.RegisterInput{Email: "ana@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	return e, f, client, cid
}

func TestFileVaultRoundTrip(t *testing.T) {
	_, f, client, cid := filesEnv(t)
	ctx := context.Background()
	content := strings.Repeat("dopis o podsjetnici ", 1000)

	meta, err := f.Upload(ctx, client, cid, "dopis.txt", "text/plain", strings.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	if meta.SizeBytes != int64(len(content)) || meta.SHA256 == "" {
		t.Fatalf("meta: %+v", meta)
	}

	var out bytes.Buffer
	if _, err := f.Download(ctx, client, meta.ID, "support", &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != content {
		t.Fatal("round trip must return the exact plaintext")
	}

	// Listing is metadata only.
	list, err := f.List(ctx, client, cid)
	if err != nil || len(list) != 1 || list[0].Name != "dopis.txt" {
		t.Fatalf("list: %+v %v", list, err)
	}

	// Purpose and permission guards.
	if _, err := f.Download(ctx, client, meta.ID, "", &out); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("empty purpose: %v", err)
	}
	if _, err := f.Download(ctx, client, meta.ID, "marketing", &out); !errors.Is(err, service.ErrPurposeNotAllowed) {
		t.Fatalf("wrong purpose: %v", err)
	}
	noPerm := &auth.Client{ID: "np", Scope: "crm", AllowedPurposes: []string{"support"}}
	if _, err := f.Download(ctx, noPerm, meta.ID, "support", &out); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("missing action: %v", err)
	}
	// Foreign scope: indistinguishable miss.
	foreign := &auth.Client{ID: "erp", Scope: "erp",
		AllowedActions: []string{auth.ActFilesRead}, AllowedPurposes: []string{"support"}}
	if _, err := f.Download(ctx, foreign, meta.ID, "support", &out); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("foreign scope must miss: %v", err)
	}

	// Delete, then a miss; the vault never lists it again.
	if err := f.Delete(ctx, client, meta.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Download(ctx, client, meta.ID, "support", &out); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("deleted file must miss: %v", err)
	}
}

func TestFileVaultMultiChunkAndTamper(t *testing.T) {
	e, f, client, cid := filesEnv(t)
	ctx := context.Background()
	// > 1 chunk would need > 4 MiB with the production chunk size; the
	// vault caps at MaxBytes=1 MiB in this env, so exercise multi-chunk
	// integrity by tampering the stored ciphertext instead: any bit flip
	// must fail the GCM open, never yield modified plaintext.
	meta, err := f.Upload(ctx, client, cid, "x.bin", "", strings.NewReader(strings.Repeat("A", 100_000)))
	if err != nil {
		t.Fatal(err)
	}
	var storageKey string
	if err := e.admin.Pool.QueryRow(ctx,
		`SELECT storage_key FROM files WHERE id=$1`, meta.ID).Scan(&storageKey); err != nil {
		t.Fatal(err)
	}
	// Flip one ciphertext byte through the driver.
	drv := f.Store
	rc, err := drv.Get(ctx, storageKey)
	if err != nil {
		t.Fatal(err)
	}
	blob := new(bytes.Buffer)
	if _, err := blob.ReadFrom(rc); err != nil {
		t.Fatal(err)
	}
	rc.Close()
	raw := blob.Bytes()
	raw[len(raw)/2] ^= 0x01
	if err := drv.Put(ctx, storageKey, bytes.NewReader(raw), int64(len(raw))); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := f.Download(ctx, client, meta.ID, "support", &out); err == nil {
		t.Fatal("tampered ciphertext must fail to open, not decrypt to something")
	}
}

func TestFileVaultCryptoShredding(t *testing.T) {
	e, f, client, cid := filesEnv(t)
	ctx := context.Background()
	meta, err := f.Upload(ctx, client, cid, "tajna.txt", "text/plain", strings.NewReader("sadrzaj"))
	if err != nil {
		t.Fatal(err)
	}

	// Erase the person: the record key dies in the same transaction.
	eraser := &auth.Client{ID: "dpo", Scope: "crm", AllowedActions: []string{auth.ActDSRErase}}
	if _, _, err := e.gdpr.Erase(ctx, eraser, cid); err != nil {
		t.Fatal(err)
	}
	var keys, gcQueued int64
	if err := e.admin.Pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM person_record_keys),
		(SELECT count(*) FROM files WHERE gc_at IS NOT NULL)`).Scan(&keys, &gcQueued); err != nil {
		t.Fatal(err)
	}
	if keys != 0 || gcQueued != 1 {
		t.Fatalf("erasure must shred the record key and queue the file for GC: keys=%d gc=%d", keys, gcQueued)
	}
	// The file no longer downloads (tombstoned person, GC'd row).
	var out bytes.Buffer
	if _, err := f.Download(ctx, client, meta.ID, "support", &out); err == nil {
		t.Fatal("files of an erased person must not download")
	}
	// GC reaps the ciphertext and the row.
	n, err := service.RunFileGC(ctx, e.admin.Pool, f.Store)
	if err != nil || n != 1 {
		t.Fatalf("gc: %d %v", n, err)
	}
	var left int64
	if err := e.admin.Pool.QueryRow(ctx, `SELECT count(*) FROM files`).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Fatalf("gc must remove the row, %d left", left)
	}
}

func TestFileVaultGuards(t *testing.T) {
	_, f, client, cid := filesEnv(t)
	ctx := context.Background()
	if _, err := f.Upload(ctx, client, cid, "", "", strings.NewReader("x")); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("empty name: %v", err)
	}
	if _, err := f.Upload(ctx, client, cid, "big.bin", "", strings.NewReader(strings.Repeat("x", 2<<20))); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("over-limit upload: %v", err)
	}
	if _, err := f.Upload(ctx, client, cid, "empty.bin", "", strings.NewReader("")); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("empty file: %v", err)
	}
	if _, err := f.Upload(ctx, client, "CID-NEMA", "a.txt", "", strings.NewReader("x")); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("unknown cid: %v", err)
	}
}

func TestFileVaultConsentAndFaults(t *testing.T) {
	e, f, client, cid := filesEnv(t)
	ctx := context.Background()
	meta, err := f.Upload(ctx, client, cid, "a.txt", "text/plain", strings.NewReader("data"))
	if err != nil {
		t.Fatal(err)
	}
	// Withdrawn consent blocks the download even with a valid purpose.
	if err := e.gdpr.SetConsent(ctx, e.crm, cid, "support", false); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := f.Download(ctx, client, meta.ID, "support", &out); !errors.Is(err, service.ErrConsentDenied) {
		t.Fatalf("withdrawn consent must block download: %v", err)
	}
	if _, err := f.Peek(ctx, client, meta.ID, "support"); !errors.Is(err, service.ErrConsentDenied) {
		t.Fatalf("Peek must also enforce consent before streaming: %v", err)
	}
	// Peek permission and purpose guards.
	noPerm := &auth.Client{ID: "np", Scope: "crm", AllowedPurposes: []string{"support"}}
	if _, err := f.Peek(ctx, noPerm, meta.ID, "support"); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("Peek without action: %v", err)
	}
	if _, err := f.Peek(ctx, client, meta.ID, "marketing"); !errors.Is(err, service.ErrPurposeNotAllowed) {
		t.Fatalf("Peek wrong purpose: %v", err)
	}
	// List permission guard and foreign scope.
	if _, err := f.List(ctx, noPerm, cid); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("list without action: %v", err)
	}
	// Delete permission guard and missing file.
	if err := f.Delete(ctx, noPerm, meta.ID); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("delete without action: %v", err)
	}
	if err := f.Delete(ctx, client, "00000000-0000-4000-8000-000000000000"); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("delete missing: %v", err)
	}
}

// TestFileVaultExpiryGC covers the expiry-driven GC branch.
func TestFileVaultExpiryGC(t *testing.T) {
	e, f, client, cid := filesEnv(t)
	ctx := context.Background()
	meta, err := f.Upload(ctx, client, cid, "old.txt", "text/plain", strings.NewReader("stale"))
	if err != nil {
		t.Fatal(err)
	}
	// Backdate an expiry into the past; GC must queue and reap it.
	if _, err := e.admin.Pool.Exec(ctx,
		`UPDATE files SET expires_at = now() - interval '1 day' WHERE id=$1`, meta.ID); err != nil {
		t.Fatal(err)
	}
	n, err := service.RunFileGC(ctx, e.admin.Pool, f.Store)
	if err != nil || n != 1 {
		t.Fatalf("expiry GC: %d %v", n, err)
	}
}

func TestFileVaultFailsClosedUnderDeniedTables(t *testing.T) {
	// Deny both the files table and the record-key table: every vault
	// operation must surface the failure, never half-write.
	e := newFaultEnv(t, "files", "person_record_keys")
	drv, err := storage.Open(storage.Config{Kind: "local", Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	f := &service.Files{Pool: e.svc.Pool, Eng: e.svc.PII.Engine(), Ring: e.svc.Ring,
		Store: drv, Contacts: e.svc, MaxBytes: 1 << 20}
	client := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions:  []string{auth.ActFilesWrite, auth.ActFilesRead},
		AllowedPurposes: []string{"support"}}
	ctx := context.Background()
	// Seed a person through the admin pool so the cid resolves.
	cid, err := e.svc.Register(ctx, e.crm, service.RegisterInput{Email: "x@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Upload(ctx, client, cid, "a.txt", "", bytes.NewReader([]byte("data"))); err == nil {
		t.Fatal("upload without record-key rights must error")
	}
	if _, err := f.List(ctx, client, cid); err == nil {
		t.Fatal("list without files rights must error")
	}
	var out bytes.Buffer
	if _, err := f.Download(ctx, client, "00000000-0000-4000-8000-000000000000", "support", &out); err == nil {
		t.Fatal("download without files rights must error")
	}
}

// TestFileVaultMultiChunk forces more than one 4 MiB chunk so the chunk
// loop and multi-chunk decrypt (index-ordered AAD) are exercised.
func TestFileVaultMultiChunk(t *testing.T) {
	e := newFaultEnv(t)
	drv, err := storage.Open(storage.Config{Kind: "local", Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	f := &service.Files{Pool: e.admin.Pool, Eng: e.svc.PII.Engine(), Ring: e.svc.Ring,
		Store: drv, Contacts: e.svc, MaxBytes: 16 << 20}
	client := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions:  []string{auth.ActFilesWrite, auth.ActFilesRead, auth.ActContactsRegister},
		AllowedPurposes: []string{"support"}}
	ctx := context.Background()
	cid, err := e.svc.Register(ctx, client, service.RegisterInput{Email: "big@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	// 10 MiB: three chunks (4+4+2).
	content := bytes.Repeat([]byte("0123456789abcdef"), (10<<20)/16)
	meta, err := f.Upload(ctx, client, cid, "big.bin", "application/octet-stream", bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	if meta.SizeBytes != int64(len(content)) {
		t.Fatalf("size: %d", meta.SizeBytes)
	}
	var out bytes.Buffer
	if _, err := f.Download(ctx, client, meta.ID, "support", &out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), content) {
		t.Fatal("multi-chunk round trip must be byte-exact")
	}
}

// failDriver injects storage failures to exercise the vault's error paths.
type failDriver struct {
	inner                        storage.Driver
	failPut, failGet, failDelete bool
}

func (d *failDriver) Put(ctx context.Context, k string, r io.Reader, n int64) error {
	if d.failPut {
		return errors.New("injected put failure")
	}
	return d.inner.Put(ctx, k, r, n)
}
func (d *failDriver) Get(ctx context.Context, k string) (io.ReadCloser, error) {
	if d.failGet {
		return nil, errors.New("injected get failure")
	}
	return d.inner.Get(ctx, k)
}
func (d *failDriver) Delete(ctx context.Context, k string) error {
	if d.failDelete {
		return errors.New("injected delete failure")
	}
	return d.inner.Delete(ctx, k)
}

func TestFileVaultStorageFailures(t *testing.T) {
	e := newFaultEnv(t)
	base, err := storage.Open(storage.Config{Kind: "local", Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	fd := &failDriver{inner: base}
	f := &service.Files{Pool: e.admin.Pool, Eng: e.svc.PII.Engine(), Ring: e.svc.Ring,
		Store: fd, Contacts: e.svc, MaxBytes: 1 << 20}
	client := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions:  []string{auth.ActFilesWrite, auth.ActFilesRead, auth.ActContactsRegister},
		AllowedPurposes: []string{"support"}}
	ctx := context.Background()
	cid, err := e.svc.Register(ctx, client, service.RegisterInput{Email: "s@example.com"})
	if err != nil {
		t.Fatal(err)
	}

	// Put failure: upload surfaces it, nothing is left in the DB.
	fd.failPut = true
	if _, err := f.Upload(ctx, client, cid, "a.txt", "", strings.NewReader("data")); err == nil {
		t.Fatal("storage put failure must surface")
	}
	var n int64
	if err := e.admin.Pool.QueryRow(ctx, `SELECT count(*) FROM files`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("failed put must leave no row, %d", n)
	}
	fd.failPut = false

	// A good upload, then a Get failure on download.
	meta, err := f.Upload(ctx, client, cid, "a.txt", "", strings.NewReader("data"))
	if err != nil {
		t.Fatal(err)
	}
	fd.failGet = true
	var out bytes.Buffer
	if _, err := f.Download(ctx, client, meta.ID, "support", &out); err == nil {
		t.Fatal("storage get failure must surface")
	}
	fd.failGet = false

	// Delete queues GC even when the eager storage delete fails; the row
	// stays until a later sweep succeeds.
	fd.failDelete = true
	if err := f.Delete(ctx, client, meta.ID); err != nil {
		t.Fatalf("delete must tolerate a transient storage failure: %v", err)
	}
	if err := e.admin.Pool.QueryRow(ctx, `SELECT count(*) FROM files WHERE gc_at IS NOT NULL`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("failed eager delete must leave the row queued for GC, %d", n)
	}
	// GC with the driver still failing: the row is retained (transient).
	reaped, err := service.RunFileGC(ctx, e.admin.Pool, fd)
	if err != nil {
		t.Fatal(err)
	}
	if reaped != 0 {
		t.Fatalf("GC must not delete the row while storage delete fails, reaped %d", reaped)
	}
	// Driver recovers: GC reaps.
	fd.failDelete = false
	if reaped, err = service.RunFileGC(ctx, e.admin.Pool, fd); err != nil || reaped != 1 {
		t.Fatalf("GC after recovery: %d %v", reaped, err)
	}
}

func TestFileVaultSecondUploadReusesRecordKey(t *testing.T) {
	_, f, client, cid := filesEnv(t)
	ctx := context.Background()
	// Two uploads for the same person: the second loads the existing
	// record key (reload branch) rather than minting a new one.
	a, err := f.Upload(ctx, client, cid, "one.txt", "text/plain", strings.NewReader("first"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := f.Upload(ctx, client, cid, "two.txt", "text/plain", strings.NewReader("second"))
	if err != nil {
		t.Fatal(err)
	}
	// Both decrypt (same record key wraps both DEKs).
	var out bytes.Buffer
	if _, err := f.Download(ctx, client, a.ID, "support", &out); err != nil || out.String() != "first" {
		t.Fatalf("first file: %q %v", out.String(), err)
	}
	out.Reset()
	if _, err := f.Download(ctx, client, b.ID, "support", &out); err != nil || out.String() != "second" {
		t.Fatalf("second file: %q %v", out.String(), err)
	}
}

// TestFileUploadAuditDeniedCleansUp: audit denied but everything else OK
// exercises Upload's audit-append failure branch AND its commit-fail
// storage cleanup (the object must not be orphaned).
func TestFileUploadAuditDeniedCleansUp(t *testing.T) {
	e := newFaultEnv(t, "audit")
	drv, err := storage.Open(storage.Config{Kind: "local", Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	f := &service.Files{Pool: e.svc.Pool, Eng: e.svc.PII.Engine(), Ring: e.svc.Ring,
		Store: drv, Contacts: e.svc, MaxBytes: 1 << 20}
	client := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions:  []string{auth.ActFilesWrite},
		AllowedPurposes: []string{"support"}}
	ctx := context.Background()
	cid := e.register(t) // seeded via the unrestricted admin pool
	if _, err := f.Upload(ctx, client, cid, "a.txt", "", strings.NewReader("data")); err == nil {
		t.Fatal("upload must fail when audit is denied")
	}
	// No files row survived the rollback.
	var n int64
	if err := e.admin.Pool.QueryRow(ctx, `SELECT count(*) FROM files`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("failed upload must leave no row, %d", n)
	}
}

func TestFileVaultKeysDenied(t *testing.T) {
	e := newFaultEnv(t, "keys")
	drv, err := storage.Open(storage.Config{Kind: "local", Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	f := &service.Files{Pool: e.svc.Pool, Eng: e.svc.PII.Engine(), Ring: e.svc.Ring,
		Store: drv, Contacts: e.svc, MaxBytes: 1 << 20}
	client := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions:  []string{auth.ActFilesWrite, auth.ActFilesRead},
		AllowedPurposes: []string{"support"}}
	ctx := context.Background()
	cid := e.register(t)
	// recordKey's Ring.Newest fails when keys are denied.
	if _, err := f.Upload(ctx, client, cid, "a.txt", "", strings.NewReader("data")); err == nil {
		t.Fatal("upload must fail when the KEK cannot be read")
	}
}

func TestFileVaultPeekForeignScopeMiss(t *testing.T) {
	_, f, client, cid := filesEnv(t)
	ctx := context.Background()
	meta, err := f.Upload(ctx, client, cid, "a.txt", "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	foreign := &auth.Client{ID: "erp", Scope: "erp",
		AllowedActions: []string{auth.ActFilesRead}, AllowedPurposes: []string{"support"}}
	if _, err := f.Peek(ctx, foreign, meta.ID, "support"); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("Peek across scope must miss: %v", err)
	}
}

func TestFileVaultFilesTableDenied(t *testing.T) {
	// Deny only the files table: recordKey mint and storage put succeed,
	// the files INSERT fails, and the orphaned object is cleaned up.
	e := newFaultEnv(t, "files")
	drv, err := storage.Open(storage.Config{Kind: "local", Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	f := &service.Files{Pool: e.svc.Pool, Eng: e.svc.PII.Engine(), Ring: e.svc.Ring,
		Store: drv, Contacts: e.svc, MaxBytes: 1 << 20}
	client := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions:  []string{auth.ActFilesWrite},
		AllowedPurposes: []string{"support"}}
	ctx := context.Background()
	cid := e.register(t)
	if _, err := f.Upload(ctx, client, cid, "a.txt", "", strings.NewReader("data")); err == nil {
		t.Fatal("upload must fail when the files table is denied")
	}
}

func TestFileVaultListDeleteQueryErrors(t *testing.T) {
	e, f, client, cid := filesEnv(t)
	ctx := context.Background()
	meta, err := f.Upload(ctx, client, cid, "a.txt", "", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	// Break files so List's Query and Delete's loadOwned hit hard errors.
	if _, err := e.admin.Pool.Exec(ctx, `ALTER TABLE files RENAME TO files_gone`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.List(ctx, client, cid); err == nil {
		t.Fatal("list must surface the query error")
	}
	if err := f.Delete(ctx, client, meta.ID); err == nil {
		t.Fatal("delete must surface the query error")
	}
	var out bytes.Buffer
	if _, err := f.Download(ctx, client, meta.ID, "support", &out); err == nil {
		t.Fatal("download must surface the query error")
	}
	if _, err := service.RunFileGC(ctx, e.admin.Pool, f.Store); err == nil {
		t.Fatal("gc must surface the query error")
	}
}

// TestReviewM2_ShortReadDetected: a truncated stored object must fail the
// download, not report success on partial content.
func TestReviewM2_ShortReadDetected(t *testing.T) {
	e, f, client, cid := filesEnv(t)
	ctx := context.Background()
	meta, err := f.Upload(ctx, client, cid, "a.txt", "", strings.NewReader(strings.Repeat("A", 50000)))
	if err != nil {
		t.Fatal(err)
	}
	var storageKey string
	if err := e.admin.Pool.QueryRow(ctx, `SELECT storage_key FROM files WHERE id=$1`, meta.ID).Scan(&storageKey); err != nil {
		t.Fatal(err)
	}
	// Truncate the stored ciphertext to the first chunk header + partial.
	rc, err := f.Store.Get(ctx, storageKey)
	if err != nil {
		t.Fatal(err)
	}
	blob := new(bytes.Buffer)
	blob.ReadFrom(rc)
	rc.Close()
	raw := blob.Bytes()
	if err := f.Store.Put(ctx, storageKey, bytes.NewReader(raw[:len(raw)/2]), int64(len(raw)/2)); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := f.Download(ctx, client, meta.ID, "support", &out); err == nil {
		t.Fatal("a truncated object must fail the download")
	}
}

// TestReviewM6_FileExpiry: an expired file is a miss at read time.
func TestReviewM6_FileExpiry(t *testing.T) {
	e, f, client, cid := filesEnv(t)
	ctx := context.Background()
	past := time.Now().Add(-time.Hour)
	meta, err := f.UploadWithExpiry(ctx, client, cid, "a.txt", "", &past, strings.NewReader("data"))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := f.Download(ctx, client, meta.ID, "support", &out); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("an expired file must be a miss: %v", err)
	}
	_ = e
}

// TestReviewL2_DekBoundToCid: repointing files.cid to another of the same
// person's cids must make the DEK fail to unwrap.
func TestReviewL2_DekBoundToCid(t *testing.T) {
	e, f, client, cid := filesEnv(t)
	ctx := context.Background()
	// Give the person a second scope so there is another cid to point at.
	otherCID, err := e.svc.IssueScopedCid(ctx, e.crm, cid, "erp")
	if err != nil {
		t.Fatal(err)
	}
	meta, err := f.Upload(ctx, client, cid, "a.txt", "", strings.NewReader("secret"))
	if err != nil {
		t.Fatal(err)
	}
	// Attacker repoints the row to the erp cid (same person, same record key).
	if _, err := e.admin.Pool.Exec(ctx, `UPDATE files SET cid=$1 WHERE id=$2`, otherCID, meta.ID); err != nil {
		t.Fatal(err)
	}
	erp := &auth.Client{ID: "erp", Scope: "erp",
		AllowedActions: []string{auth.ActFilesRead}, AllowedPurposes: []string{"support"}}
	// Grant erp the support purpose+consent path; the DEK AAD mismatch must
	// still fail the decrypt even though scope now matches.
	var out bytes.Buffer
	if _, err := f.Download(ctx, erp, meta.ID, "support", &out); err == nil {
		t.Fatal("a cid-repointed file must fail to decrypt (DEK bound to cid)")
	}
}

// TestReviewL3_UploadAfterErasureRejected: a person erased before the
// insert commits must not get a stranded, undecryptable file row.
func TestReviewL3_UploadAfterErasureRejected(t *testing.T) {
	e, f, client, cid := filesEnv(t)
	ctx := context.Background()
	// Erase the person first, then attempt an upload against the (retained)
	// cid: the in-transaction re-check must reject it as a miss.
	if _, _, err := e.gdpr.Erase(ctx, e.crm, cid); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Upload(ctx, client, cid, "a.txt", "", strings.NewReader("data")); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("upload for an erased person must be a miss: %v", err)
	}
	var n int64
	if err := e.admin.Pool.QueryRow(ctx, `SELECT count(*) FROM files`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("no file row must survive, got %d", n)
	}
}

func TestRekeyRecordKeyCorruptSkipped(t *testing.T) {
	e, f, client, cid := filesEnv(t)
	ctx := context.Background()
	if _, err := f.Upload(ctx, client, cid, "a.txt", "", strings.NewReader("data")); err != nil {
		t.Fatal(err)
	}
	// Corrupt the wrapped record key: rekey must skip it, not abort.
	if _, err := e.admin.Pool.Exec(ctx,
		`UPDATE person_record_keys SET wrapped = $1, key_id='v0'`, []byte{9, 9, 9}); err != nil {
		t.Fatal(err)
	}
	// Rotate + rekey.
	if _, err := e.svc.Ring.Rotate(ctx, e.svc.PII.Engine(), "pii-kek"); err != nil {
		t.Fatal(err)
	}
	stats, err := e.svc.Rekey(ctx, true, 100)
	if err != nil {
		t.Fatalf("a corrupt record key must be skipped, not fatal: %v", err)
	}
	if stats.Skipped < 1 {
		t.Fatalf("corrupt record key should be skipped: %+v", stats)
	}
}

// TestFileVaultCorruptChunkHeaderNoPanic: a stored object whose chunk-length
// header is below the nonce+tag minimum must be a clean error, not a panic.
func TestFileVaultCorruptChunkHeaderNoPanic(t *testing.T) {
	e, f, client, cid := filesEnv(t)
	ctx := context.Background()
	meta, err := f.Upload(ctx, client, cid, "a.txt", "", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	var storageKey string
	if err := e.admin.Pool.QueryRow(ctx, `SELECT storage_key FROM files WHERE id=$1`, meta.ID).Scan(&storageKey); err != nil {
		t.Fatal(err)
	}
	// Overwrite the stored object with a tiny chunk-length header (n=5) and
	// a few bytes - below the 12-byte nonce, which previously panicked.
	bad := []byte{0, 0, 0, 5, 1, 2, 3, 4, 5}
	if err := f.Store.Put(ctx, storageKey, bytes.NewReader(bad), int64(len(bad))); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := f.Download(ctx, client, meta.ID, "support", &out); err == nil {
		t.Fatal("a corrupt chunk header must be a clean error")
	}
}

// TestH9_OrphanReapedWhenInsertFails: Store.Put lands before the files row;
// if the INSERT (or the audit append, or the tombstone re-check) then fails,
// the ciphertext has no row and RunFileGC can never reap it (H9). The upload
// path now guarantees reap-on-no-commit via one defer; this drives the exact
// INSERT-failure path by denying the files table and asserts the storage dir
// ends empty.
func TestH9_OrphanReapedWhenInsertFails(t *testing.T) {
	e := newFaultEnv(t, "files")
	dir := t.TempDir()
	drv, err := storage.Open(storage.Config{Kind: "local", Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	f := &service.Files{Pool: e.svc.Pool, Eng: e.svc.PII.Engine(), Ring: e.svc.Ring,
		Store: drv, Contacts: e.svc, MaxBytes: 1 << 20}
	client := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions: []string{auth.ActFilesWrite, auth.ActContactsRegister}}
	ctx := context.Background()
	cid, err := e.svc.Register(ctx, client, service.RegisterInput{Email: "h9@example.com"})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := f.Upload(ctx, client, cid, "doc.pdf", "application/pdf",
		strings.NewReader("orphan-me")); err == nil {
		t.Fatal("upload must fail when the files INSERT is denied")
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var left []string
	for _, en := range ents {
		left = append(left, en.Name())
	}
	if len(left) != 0 {
		t.Fatalf("failed upload must reap its ciphertext, found %v", left)
	}
}

// cancelAfterPut wraps a driver and kills the request context right after
// Put succeeds - the moment a client disconnect typically lands.
type cancelAfterPut struct {
	storage.Driver
	cancel context.CancelFunc
}

func (c *cancelAfterPut) Put(ctx context.Context, key string, r io.Reader, size int64) error {
	err := c.Driver.Put(ctx, key, r, size)
	c.cancel()
	return err
}

// TestH9_OrphanReapedWhenRequestContextDies (review F3): the commonest
// late-upload failure is the REQUEST context dying between Put and Commit.
// Both drivers short-circuit on a dead context, so a reap issued under the
// request context would be a silent no-op - the defer must reap under a
// context that survives the request's cancellation.
func TestH9_OrphanReapedWhenRequestContextDies(t *testing.T) {
	e := newFaultEnv(t)
	dir := t.TempDir()
	drv, err := storage.Open(storage.Config{Kind: "local", Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := &service.Files{Pool: e.admin.Pool, Eng: e.svc.PII.Engine(), Ring: e.svc.Ring,
		Store: &cancelAfterPut{Driver: drv, cancel: cancel}, Contacts: e.svc, MaxBytes: 1 << 20}
	client := &auth.Client{ID: "crm", Scope: "crm",
		AllowedActions: []string{auth.ActFilesWrite, auth.ActContactsRegister}}
	cid, err := e.svc.Register(context.Background(), client, service.RegisterInput{Email: "f3@example.com"})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := f.Upload(ctx, client, cid, "doc.pdf", "application/pdf",
		strings.NewReader("orphan-me")); err == nil {
		t.Fatal("upload must fail once its context is canceled")
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 0 {
		var left []string
		for _, en := range ents {
			left = append(left, en.Name())
		}
		t.Fatalf("the reap must survive the request context, ciphertext left: %v", left)
	}
}
