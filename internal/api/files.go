package api

// File vault endpoints (F5). Mounted only when SUNDER_FILES_STORAGE is
// configured - files are a new data class, and an upgrade must not start
// accepting them silently.

import (
	"net/http"

	"github.com/fvisic/sunder/internal/auth"
)

func (s *Server) handleFileUpload(w http.ResponseWriter, r *http.Request) {
	client := auth.FromContext(r.Context())
	// Multipart with one "file" part; the part name and filename are the
	// metadata, the body streams into the vault.
	if err := r.ParseMultipartForm(1 << 20); err != nil { // headers in memory; the file part streams
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "validation", "detail": "multipart form with a \"file\" part required"})
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "validation", "detail": "multipart part \"file\" required"})
		return
	}
	defer file.Close()
	meta, err := s.Files.Upload(r.Context(), client, r.PathValue("cid"),
		header.Filename, header.Header.Get("Content-Type"), file)
	if err != nil {
		s.logErr(r, err)
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, meta)
}

func (s *Server) handleFileDownload(w http.ResponseWriter, r *http.Request) {
	client := auth.FromContext(r.Context())
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
	out, err := s.Files.List(r.Context(), client, r.PathValue("cid"))
	if err != nil {
		s.logErr(r, err)
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"files": out})
}

func (s *Server) handleFileDelete(w http.ResponseWriter, r *http.Request) {
	client := auth.FromContext(r.Context())
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
