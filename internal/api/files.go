package api

// File vault endpoints (F5). Mounted only when SUNDER_FILES_STORAGE is
// configured - files are a new data class, and an upgrade must not start
// accepting them silently.

import (
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strconv"
	"time"

	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/service"
)

// truncGuard distinguishes a TRUNCATED multipart body from a clean end of
// the file part (N1). multipart.Part returns io.ErrUnexpectedEOF when the
// closing boundary never arrives (client disconnected mid-upload); the
// service's chunked io.ReadFull loop would treat that exactly like its own
// short-final-chunk ErrUnexpectedEOF and store the partial content as a
// complete file, digest and all. Converting the part's error into a
// validation error makes the truncation a clean 400 with nothing stored
// (the upload's reap defer removes anything already in storage).
type truncGuard struct{ r io.Reader }

func (t truncGuard) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if err == io.ErrUnexpectedEOF {
		return n, fmt.Errorf("%w: multipart body truncated mid-file", service.ErrValidation)
	}
	return n, err
}

func (s *Server) handleFileUpload(w http.ResponseWriter, r *http.Request) {
	client := auth.FromContext(r.Context())
	// Authorize BEFORE reading a byte of the body: an unauthorized client
	// must never make the server spool a multipart body to disk (H2).
	if !client.Can(auth.ActFilesWrite) {
		writeErr(w, service.ErrForbidden)
		return
	}
	if !s.allow(w, client) {
		return
	}
	// Cap the whole request body at the per-file limit plus a small
	// multipart overhead allowance (H2), and STREAM the multipart body
	// instead of ParseMultipartForm: parsing would read and spool the whole
	// (plaintext) body to os.TempDir() BEFORE the service's upload slot is
	// taken, so queued uploads would each pin a MaxBytes-sized temp file
	// (F4). MultipartReader reads only boundaries and part headers here;
	// the file CONTENT is first read inside Upload, under the concurrency
	// slot, straight off the socket.
	limit := s.Files.MaxBytes
	if limit <= 0 {
		limit = 25 << 20
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit+(1<<20))
	mr, err := r.MultipartReader()
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "validation", "detail": "multipart form with a \"file\" part required"})
		return
	}
	var file *multipart.Part
	for {
		p, perr := mr.NextPart()
		if perr != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "validation", "detail": "multipart part \"file\" required (or body too large)"})
			return
		}
		if p.FormName() == "file" {
			file = p
			break
		}
		_ = p.Close() // drain and discard non-file fields (bounded by MaxBytesReader)
	}
	defer file.Close()
	var expiresAt *time.Time
	if hv := r.Header.Get("X-Sunder-File-Expiry"); hv != "" {
		t, perr := time.Parse(time.RFC3339, hv)
		if perr != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "validation", "detail": "X-Sunder-File-Expiry must be RFC3339"})
			return
		}
		expiresAt = &t
	}
	meta, err := s.Files.UploadWithExpiry(r.Context(), client, r.PathValue("cid"),
		file.FileName(), file.Header.Get("Content-Type"), expiresAt, truncGuard{file})
	if err != nil {
		s.logErr(r, err)
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, meta)
}

func (s *Server) handleFileDownload(w http.ResponseWriter, r *http.Request) {
	client := auth.FromContext(r.Context())
	if !s.allow(w, client) {
		return
	}
	purpose := r.URL.Query().Get("purpose")
	// Validate everything that can fail BEFORE writing any header - once
	// the 200 and Content-Length are out, a later error can only truncate
	// the body, never change the status. Peek performs the same
	// permission, purpose, ownership and consent checks Download will, so
	// a bad request is a clean JSON error here, not a 200 with a short
	// body.
	meta, err := s.Files.Peek(r.Context(), client, r.PathValue("id"), purpose)
	if err != nil {
		s.logErr(r, err)
		writeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", meta.ContentType)
	w.Header().Set("Content-Length", itoa64(meta.SizeBytes))
	w.Header().Set("Content-Disposition", `attachment; filename="`+sanitizeFilename(meta.Name)+`"`)
	if _, err := s.Files.Download(r.Context(), client, r.PathValue("id"), purpose, w); err != nil {
		// Headers may already be gone; the truncated body plus the log
		// line is the best honest signal left.
		s.logErr(r, err)
		return
	}
}

func (s *Server) handleFileList(w http.ResponseWriter, r *http.Request) {
	client := auth.FromContext(r.Context())
	if !s.allow(w, client) {
		return
	}
	out, err := s.Files.List(r.Context(), client, r.PathValue("cid"), r.URL.Query().Get("purpose"))
	if err != nil {
		s.logErr(r, err)
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"files": out})
}

func (s *Server) handleFileDelete(w http.ResponseWriter, r *http.Request) {
	client := auth.FromContext(r.Context())
	if !s.allow(w, client) {
		return
	}
	if err := s.Files.Delete(r.Context(), client, r.PathValue("id")); err != nil {
		s.logErr(r, err)
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// sanitizeFilename keeps header injection out of Content-Disposition.
func sanitizeFilename(name string) string {
	out := make([]rune, 0, len(name))
	for _, r := range name {
		if r == '"' || r == '\\' || r == '\r' || r == '\n' || r < 0x20 {
			continue
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		return "file"
	}
	return string(out)
}

func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// fmtSscan parses a base-10 int64 from a path segment.
func fmtSscan(str string, out *int64) (int, error) {
	v, err := strconv.ParseInt(str, 10, 64)
	if err != nil {
		return 0, err
	}
	*out = v
	return 1, nil
}

func (s *Server) handleVersionList(w http.ResponseWriter, r *http.Request) {
	client := auth.FromContext(r.Context())
	if !s.allow(w, client) {
		return
	}
	out, err := s.Contacts.ListVersions(r.Context(), client, r.PathValue("cid"))
	if err != nil {
		s.logErr(r, err)
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"versions": out})
}

func (s *Server) handleVersionAttribute(w http.ResponseWriter, r *http.Request) {
	client := auth.FromContext(r.Context())
	if !s.allow(w, client) {
		return
	}
	var versionNo int64
	if _, err := fmtSscan(r.PathValue("version"), &versionNo); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "validation", "detail": "version must be a number"})
		return
	}
	val, err := s.Contacts.GetVersionAttribute(r.Context(), client,
		r.PathValue("cid"), versionNo, r.PathValue("name"), r.URL.Query().Get("purpose"))
	if err != nil {
		s.logErr(r, err)
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"value": val})
}
