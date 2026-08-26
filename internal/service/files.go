package service

// File vault (Phase 3 / F5). Crypto chain, outermost first:
//
//	PII KEK (engine, keystore/Vault/signer)
//	  wraps the per-person RECORD KEY (person_record_keys)
//	    which wraps the per-file DEK (files.dek_wrapped)
//	      which encrypts the content in 4 MiB AES-256-GCM chunks
//
// The record key exists for exactly one property: crypto-shredding.
// Erasure deletes one database row and every file of that person is
// unrecoverable at commit time, with no storage round trip on the erasure
// path; the retention sweep garbage-collects the dead ciphertext later.
// Chunk indexes ride in the AAD, so chunks cannot be reordered, dropped
// or transplanted between files without the decrypt failing.

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/fvisic/sunder/internal/audit"
	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/crypto"
	"github.com/fvisic/sunder/internal/storage"
)

// fileChunkSize is the AEAD chunk granularity and bounds the blast radius
// of a corrupted chunk. Per-upload memory is bounded by MaxBytes (a single-
// PUT SigV4 body is buffered whole; see the note at the encrypt loop) and
// total upload memory by MaxConcurrentUploads * MaxBytes.
const fileChunkSize = 4 << 20

// defaultUploadConcurrency bounds simultaneous uploads when the config knob
// is unset. See MaxConcurrentUploads.
const defaultUploadConcurrency = 4

// Files is the vault service.
type Files struct {
	Pool     *pgxpool.Pool
	Eng      crypto.Engine
	Ring     *KeyRing
	Store    storage.Driver
	Contacts *Contacts
	// MaxBytes caps one upload (config SUNDER_FILES_MAX_MB).
	MaxBytes int64
	// MaxConcurrentUploads bounds how many uploads may be encrypting/buffering
	// at once (config SUNDER_FILES_MAX_CONCURRENT_UPLOADS, default
	// defaultUploadConcurrency). A single-PUT SigV4 body must be buffered
	// whole (see the Upload note), so worst-case upload memory is
	// MaxConcurrentUploads * MaxBytes; without this bound a handful of
	// concurrent max-size uploads is an OOM of the whole service (H8).
	MaxConcurrentUploads int

	semOnce   sync.Once
	uploadSem chan struct{}
}

// acquireUpload blocks until an upload slot is free (or ctx is done), and
// returns a release func. Excess uploads WAIT rather than all buffer at once.
// The HTTP handler streams the multipart body (no ParseMultipartForm spool),
// so a waiting request has read only part headers off the socket - the file
// CONTENT is first read here, under the slot.
func (f *Files) acquireUpload(ctx context.Context) (func(), error) {
	f.semOnce.Do(func() {
		n := f.MaxConcurrentUploads
		if n <= 0 {
			n = defaultUploadConcurrency
		}
		f.uploadSem = make(chan struct{}, n)
	})
	select {
	case f.uploadSem <- struct{}{}:
		return func() { <-f.uploadSem }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// FileMeta is the listing/inspection shape - metadata only, never content.
type FileMeta struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	ContentType string     `json:"content_type"`
	SizeBytes   int64      `json:"size_bytes"`
	SHA256      string     `json:"sha256"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// recordKey loads (or on first use mints) the person's record key. The
// caller must already hold a legitimate path to the person - this is a
// key-management helper, not an access check.
func (f *Files) recordKey(ctx context.Context, personID string) ([]byte, error) {
	kek, err := f.Ring.Newest(ctx, crypto.KeyPIIKEK)
	if err != nil {
		return nil, err
	}
	var wrapped []byte
	var keyID, alg string
	err = f.Pool.QueryRow(ctx,
		`SELECT wrapped, key_id, alg FROM person_record_keys WHERE person_id=$1`, personID).
		Scan(&wrapped, &keyID, &alg)
	if err == nil {
		return f.Eng.Open(ctx, crypto.KeyPIIKEK+"/"+keyID, alg, recordKeyAAD(personID), wrapped)
	}
	if err != pgx.ErrNoRows {
		return nil, err
	}
	fresh := make([]byte, 32)
	mustRand(fresh)
	sealed, err := f.Eng.Seal(ctx, crypto.KeyPIIKEK+"/"+kek, "aes256gcm", recordKeyAAD(personID), fresh)
	if err != nil {
		return nil, err
	}
	// A concurrent first-upload can win the race; their key is then the
	// authoritative one and ours is discarded.
	if _, err := f.Pool.Exec(ctx, `
		INSERT INTO person_record_keys (person_id, wrapped, key_id, alg)
		VALUES ($1,$2,$3,'aes256gcm') ON CONFLICT (person_id) DO NOTHING`,
		personID, sealed, kek); err != nil {
		return nil, err
	}
	err = f.Pool.QueryRow(ctx,
		`SELECT wrapped, key_id, alg FROM person_record_keys WHERE person_id=$1`, personID).
		Scan(&wrapped, &keyID, &alg)
	if err != nil {
		return nil, err
	}
	return f.Eng.Open(ctx, crypto.KeyPIIKEK+"/"+keyID, alg, recordKeyAAD(personID), wrapped)
}

func recordKeyAAD(personID string) []byte { return []byte("record-key\x00" + personID) }

// Upload stores one file for the person behind cid, in the caller's scope.
func (f *Files) Upload(ctx context.Context, client *auth.Client, cid, name, contentType string, r io.Reader) (*FileMeta, error) {
	return f.UploadWithExpiry(ctx, client, cid, name, contentType, nil, r)
}

// UploadWithExpiry is Upload with an optional hard expiry after which the
// file is unreadable and gets garbage-collected.
func (f *Files) UploadWithExpiry(ctx context.Context, client *auth.Client, cid, name, contentType string, expiresAt *time.Time, r io.Reader) (*FileMeta, error) {
	if !client.Can(auth.ActFilesWrite) {
		return nil, ErrForbidden
	}
	if name == "" || len(name) > 255 {
		return nil, fmt.Errorf("%w: file name required (max 255 chars)", ErrValidation)
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	// Bound concurrent uploads so peak memory stays MaxConcurrentUploads *
	// MaxBytes, not unbounded (H8). Released as soon as this upload returns.
	release, err := f.acquireUpload(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	personID, err := f.Contacts.personForClientCID(ctx, client, cid)
	if err != nil {
		return nil, err
	}
	recordKey, err := f.recordKey(ctx, personID)
	if err != nil {
		return nil, err
	}

	dek := make([]byte, 32)
	mustRand(dek)
	fileID := newRandomUUID()
	storageKey := "f-" + fileID

	// Encrypt chunk by chunk (chunk index in the AAD, running sha256 over the
	// PLAINTEXT for integrity metadata). NOTE: the sealed bytes are buffered
	// whole before Put - the S3 driver's single-PUT SigV4 needs the full
	// body to sign, so true streaming would require multipart upload (a
	// follow-up). Peak memory per upload is therefore bounded by MaxBytes
	// (config, default 25 MiB; capped at 256 MiB on the s3 driver), enforced
	// by the size guard below and the handler's MaxBytesReader.
	enc := newChunkWriter(dek, fileID)
	hasher := sha256.New()
	var size int64
	var sealedBuf bytes.Buffer
	buf := make([]byte, fileChunkSize)
	for {
		n, rerr := io.ReadFull(r, buf)
		if n > 0 {
			size += int64(n)
			if f.MaxBytes > 0 && size > f.MaxBytes {
				return nil, fmt.Errorf("%w: file exceeds the %d-byte limit", ErrValidation, f.MaxBytes)
			}
			hasher.Write(buf[:n])
			if err := enc.writeChunk(&sealedBuf, buf[:n]); err != nil {
				return nil, err
			}
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break
		}
		if rerr != nil {
			return nil, rerr
		}
	}
	if size == 0 {
		return nil, fmt.Errorf("%w: empty file", ErrValidation)
	}
	if err := f.Store.Put(ctx, storageKey, &sealedBuf, int64(sealedBuf.Len())); err != nil {
		return nil, fmt.Errorf("storage put: %w", err)
	}
	// From here the ciphertext is in storage but no row references it yet.
	// Every path that does not end in a committed row must reap the object,
	// or RunFileGC (which reaps only keys it can find via a files row) can
	// never get to it (H9). One defer covers ALL such paths - the tombstone
	// re-check, the INSERT, the audit append and the commit itself. The reap
	// must NOT ride the request context: the commonest late failure IS that
	// context dying (client disconnect, deadline), and both drivers
	// short-circuit on a dead context - a reap under ctx would be a silent
	// no-op exactly when it is needed (F3).
	committed := false
	defer func() {
		if !committed {
			reapCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			_ = f.Store.Delete(reapCtx, storageKey)
		}
	}()

	// Wrap the DEK under the record key, bound to this file id.
	dekWrapped := gcmSeal(recordKey, dekAAD(fileID, cid), dek)
	sum := hex.EncodeToString(hasher.Sum(nil))

	tx, err := f.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// L3: an erasure that committed while we were encrypting would have
	// shredded the record key; a row inserted now would be undecryptable
	// and never GC'd. Re-check under the PERSONS row lock and fail closed:
	// EvalPlanQual re-fetches only FOR UPDATE targets, so locking cids alone
	// evaluated erased_at against a stale persons tuple when racing the
	// erasure itself. The persons row is the serialization point with
	// erasePerson's opening guard; the cids lock is not needed here and
	// would invert erasure's c -> p order (ABBA deadlock).
	var stillLive bool
	if err := tx.QueryRow(ctx,
		`SELECT NOT p.erased_at IS NOT NULL FROM cids c JOIN persons p ON p.id=c.person_id
		 WHERE c.cid=$1 FOR UPDATE OF p`, cid).Scan(&stillLive); err != nil {
		return nil, err
	}
	if !stillLive {
		return nil, ErrNotFound
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO files (id, cid, name, content_type, size_bytes, sha256, dek_wrapped, storage_key, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		fileID, cid, name, contentType, size, sum, dekWrapped, storageKey, expiresAt); err != nil {
		return nil, err
	}
	if err := audit.AppendTx(ctx, tx, audit.Entry{
		ClientID: client.ID, Action: "files.upload", CID: cid,
		Detail: map[string]any{"file": fileID, "bytes": size},
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	committed = true
	return &FileMeta{ID: fileID, Name: name, ContentType: contentType,
		SizeBytes: size, SHA256: sum, CreatedAt: time.Now().UTC(), ExpiresAt: expiresAt}, nil
}

// Download streams one file's plaintext to w. Purpose-checked like an
// attribute read, audited BEFORE the first byte leaves (fail closed).
func (f *Files) Download(ctx context.Context, client *auth.Client, fileID, purpose string, w io.Writer) (*FileMeta, error) {
	if !client.Can(auth.ActFilesRead) {
		return nil, ErrForbidden
	}
	if purpose == "" {
		return nil, fmt.Errorf("%w: purpose required", ErrValidation)
	}
	if !client.CanUse(purpose) {
		return nil, ErrPurposeNotAllowed
	}
	meta, cid, dekWrapped, storageKey, err := f.loadOwned(ctx, client, fileID)
	if err != nil {
		return nil, err
	}
	personID, err := f.Contacts.personForClientCID(ctx, client, cid)
	if err != nil {
		return nil, err
	}
	if denied, err := consentDenied(ctx, f.Pool, cid, purpose); err != nil {
		return nil, err
	} else if denied {
		return nil, ErrConsentDenied
	}
	recordKey, err := f.recordKey(ctx, personID)
	if err != nil {
		return nil, err
	}
	dek, err := gcmOpen(recordKey, dekAAD(fileID, cid), dekWrapped)
	if err != nil {
		return nil, err
	}
	if err := audit.ReadEvent(ctx, f.Pool, audit.Entry{
		ClientID: client.ID, Action: "files.read", CID: cid,
		Detail: map[string]any{"file": fileID, "purpose": purpose},
	}); err != nil {
		return nil, fmt.Errorf("audit append: %w", err)
	}

	rc, err := f.Store.Get(ctx, storageKey)
	if err != nil {
		return nil, fmt.Errorf("storage get: %w", err)
	}
	defer rc.Close()
	written, err := decryptChunks(dek, fileID, rc, w)
	if err != nil {
		return nil, err
	}
	// M2: a truncated object decrypts cleanly chunk by chunk and stops at a
	// boundary; compare against the size recorded at upload so a short read
	// is an error, not a silent partial success.
	if written != meta.SizeBytes {
		return meta, fmt.Errorf("file vault: short read (%d of %d bytes) - stored object truncated", written, meta.SizeBytes)
	}
	return meta, nil
}

// List returns metadata for one person's files in the caller's scope.
// Metadata only - names and sizes, never content - and only for a person
// the caller can already resolve, so it is not a bulk surface.
func (f *Files) List(ctx context.Context, client *auth.Client, cid string) ([]FileMeta, error) {
	if !client.Can(auth.ActFilesRead) {
		return nil, ErrForbidden
	}
	if _, err := f.Contacts.personForClientCID(ctx, client, cid); err != nil {
		return nil, err
	}
	rows, err := f.Pool.Query(ctx, `
		SELECT id, name, content_type, size_bytes, sha256, created_at, expires_at
		  FROM files WHERE cid=$1 AND gc_at IS NULL ORDER BY created_at`, cid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []FileMeta{}
	for rows.Next() {
		var m FileMeta
		if err := rows.Scan(&m.ID, &m.Name, &m.ContentType, &m.SizeBytes, &m.SHA256, &m.CreatedAt, &m.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// Delete removes one file: the row goes to GC state in the same chained
// transaction as the audit record, then the object is deleted eagerly.
func (f *Files) Delete(ctx context.Context, client *auth.Client, fileID string) error {
	if !client.Can(auth.ActFilesWrite) {
		return ErrForbidden
	}
	_, cid, _, storageKey, err := f.loadOwned(ctx, client, fileID)
	if err != nil {
		return err
	}
	tx, err := f.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `UPDATE files SET gc_at = now() WHERE id=$1`, fileID); err != nil {
		return err
	}
	if err := audit.AppendTx(ctx, tx, audit.Entry{
		ClientID: client.ID, Action: "files.delete", CID: cid,
		Detail: map[string]any{"file": fileID},
	}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	// Best effort now; the GC sweep retries until the driver confirms.
	if err := f.Store.Delete(ctx, storageKey); err == nil {
		_, _ = f.Pool.Exec(ctx, `DELETE FROM files WHERE id=$1 AND gc_at IS NOT NULL`, fileID)
	}
	return nil
}

// loadOwned fetches a file row IFF its cid belongs to the caller's scope.
// Foreign and absent files are the same miss.
func (f *Files) loadOwned(ctx context.Context, client *auth.Client, fileID string) (*FileMeta, string, []byte, string, error) {
	var m FileMeta
	var cid, storageKey string
	var dekWrapped []byte
	err := f.Pool.QueryRow(ctx, `
		SELECT fl.id, fl.name, fl.content_type, fl.size_bytes, fl.sha256, fl.created_at, fl.expires_at,
		       fl.cid, fl.dek_wrapped, fl.storage_key
		  FROM files fl JOIN cids c ON c.cid = fl.cid
		 WHERE fl.id=$1 AND c.scope=$2 AND fl.gc_at IS NULL
		   AND (fl.expires_at IS NULL OR fl.expires_at > now())`,
		fileID, client.Scope).
		Scan(&m.ID, &m.Name, &m.ContentType, &m.SizeBytes, &m.SHA256, &m.CreatedAt, &m.ExpiresAt,
			&cid, &dekWrapped, &storageKey)
	if err == pgx.ErrNoRows {
		return nil, "", nil, "", ErrNotFound
	}
	if err != nil {
		return nil, "", nil, "", err
	}
	return &m, cid, dekWrapped, storageKey, nil
}

// ShredRecordKey destroys a person's record key - the crypto-shredding
// half of erasure - and marks their files for garbage collection. Runs
// inside the erasure transaction.
func ShredRecordKey(ctx context.Context, tx pgx.Tx, personID string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM person_record_keys WHERE person_id=$1`, personID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `
		UPDATE files SET gc_at = now()
		 WHERE gc_at IS NULL AND cid IN (SELECT cid FROM cids WHERE person_id=$1)`, personID)
	return err
}

// RunFileGC deletes storage objects for rows in GC state and rows whose
// expiry passed, then removes the rows the driver confirmed. Wired into
// `sunder retention run`.
func RunFileGC(ctx context.Context, pool *pgxpool.Pool, store storage.Driver) (int64, error) {
	if _, err := pool.Exec(ctx, `
		UPDATE files SET gc_at = now()
		 WHERE gc_at IS NULL AND expires_at IS NOT NULL AND expires_at < now()`); err != nil {
		return 0, err
	}
	rows, err := pool.Query(ctx, `SELECT id, storage_key FROM files WHERE gc_at IS NOT NULL LIMIT 1000`)
	if err != nil {
		return 0, err
	}
	type victim struct{ id, key string }
	var victims []victim
	for rows.Next() {
		var v victim
		if err := rows.Scan(&v.id, &v.key); err != nil {
			rows.Close()
			return 0, err
		}
		victims = append(victims, v)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	var reaped int64
	for _, v := range victims {
		if err := store.Delete(ctx, v.key); err != nil && !storage.IsNotExist(err) {
			continue // transient: the next sweep retries
		}
		if _, err := pool.Exec(ctx, `DELETE FROM files WHERE id=$1`, v.id); err != nil {
			return reaped, err
		}
		reaped++
	}
	return reaped, nil
}

// --- chunked AES-256-GCM ------------------------------------------------

// Wire format per chunk: 4-byte big-endian ciphertext length, then
// nonce||ciphertext as produced by GCM Seal. The AAD binds file id and
// chunk index; index 0xFFFFFFFF is reserved for the wrapped DEK.
// dekAAD binds the wrapped DEK to BOTH the file id and its cid (L2): a
// DB attacker who repoints files.cid to another of the same person's cids
// keeps the record key but not this AAD, so the DEK no longer unwraps.
func dekAAD(fileID, cid string) []byte {
	return []byte("file-dek\x00" + fileID + "\x00" + cid)
}

func fileAAD(fileID string, idx uint32) []byte {
	aad := make([]byte, 0, len(fileID)+6)
	aad = append(aad, []byte("file\x00"+fileID+"\x00")...)
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], idx)
	return append(aad, n[:]...)
}

// mustGCM builds AES-256-GCM over a key. A 32-byte key can only fail these
// constructors if the crypto library is broken - an unrecoverable state,
// like the CSPRNG failing in newUUID - so it panics rather than returning
// an error no caller could handle.
func mustGCM(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return gcm
}

type chunkWriter struct {
	gcm    cipher.AEAD
	fileID string
	idx    uint32
}

func newChunkWriter(dek []byte, fileID string) *chunkWriter {
	return &chunkWriter{gcm: mustGCM(dek), fileID: fileID}
}

func (c *chunkWriter) writeChunk(w io.Writer, plain []byte) error {
	nonce := make([]byte, c.gcm.NonceSize())
	mustRand(nonce)
	sealed := c.gcm.Seal(nonce, nonce, plain, fileAAD(c.fileID, c.idx))
	c.idx++
	var lenHdr [4]byte
	binary.BigEndian.PutUint32(lenHdr[:], uint32(len(sealed)))
	if _, err := w.Write(lenHdr[:]); err != nil {
		return err
	}
	_, err := w.Write(sealed)
	return err
}

func decryptChunks(dek []byte, fileID string, r io.Reader, w io.Writer) (int64, error) {
	gcm := mustGCM(dek)
	var idx uint32
	var written int64
	var lenHdr [4]byte
	for {
		if _, err := io.ReadFull(r, lenHdr[:]); err == io.EOF {
			return written, nil
		} else if err != nil {
			return written, err
		}
		n := binary.BigEndian.Uint32(lenHdr[:])
		// A sealed chunk is at least a nonce plus a GCM tag; a header below
		// that (from a truncated or corrupt object) must be a clean error,
		// never a slice past the nonce size that panics.
		minChunk := uint32(gcm.NonceSize() + gcm.Overhead())
		if n < minChunk || n > fileChunkSize+64 {
			return written, fmt.Errorf("file vault: corrupt chunk header")
		}
		sealed := make([]byte, n)
		if _, err := io.ReadFull(r, sealed); err != nil {
			return written, err
		}
		nonce, ct := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
		plain, err := gcm.Open(nil, nonce, ct, fileAAD(fileID, idx))
		if err != nil {
			return written, fmt.Errorf("file vault: chunk %d failed to open (reordered, truncated or shredded): %w", idx, err)
		}
		idx++
		if _, err := w.Write(plain); err != nil {
			return written, err
		}
		written += int64(len(plain))
	}
}

func gcmSeal(key, aad, plain []byte) []byte {
	gcm := mustGCM(key)
	nonce := make([]byte, gcm.NonceSize())
	mustRand(nonce)
	return gcm.Seal(nonce, nonce, plain, aad)
}

func gcmOpen(key, aad, sealed []byte) ([]byte, error) {
	gcm := mustGCM(key)
	if len(sealed) < gcm.NonceSize() {
		return nil, fmt.Errorf("file vault: sealed blob too short")
	}
	return gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], aad)
}

// newRandomUUID mirrors the stdlib-only UUIDv4 generator used elsewhere.
func newRandomUUID() string {
	var b [16]byte
	mustRand(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// Peek runs the FULL download pre-flight (permission, purpose, ownership,
// consent) and returns the metadata, so the HTTP handler can validate
// before writing a single response byte - once headers are out, a later
// failure can only truncate the stream, never restate the status.
func (f *Files) Peek(ctx context.Context, client *auth.Client, fileID, purpose string) (*FileMeta, error) {
	if !client.Can(auth.ActFilesRead) {
		return nil, ErrForbidden
	}
	if purpose == "" {
		return nil, fmt.Errorf("%w: purpose required", ErrValidation)
	}
	if !client.CanUse(purpose) {
		return nil, ErrPurposeNotAllowed
	}
	meta, cid, _, _, err := f.loadOwned(ctx, client, fileID)
	if err != nil {
		return nil, err
	}
	if _, err := f.Contacts.personForClientCID(ctx, client, cid); err != nil {
		return nil, err
	}
	if denied, err := consentDenied(ctx, f.Pool, cid, purpose); err != nil {
		return nil, err
	} else if denied {
		return nil, ErrConsentDenied
	}
	return meta, nil
}
