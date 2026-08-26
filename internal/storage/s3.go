package storage

// S3-compatible driver (AWS S3, MinIO, Cloudflare R2) over net/http, with
// AWS Signature Version 4 implemented from the specification. Stdlib-first:
// three object operations - PUT, GET, DELETE - do not justify the AWS SDK
// and its dependency tree, the same reasoning that produced the hand-rolled
// RESP client in internal/ratelimit.
//
// The signing primitives below (canonicalRequest, stringToSign, signingKey,
// signature) are deliberately pure functions over strings: SigV4 is
// unforgiving about byte-exact canonicalization, and the only way to be
// confident in a hand-rolled implementation is to pin it against the
// official AWS test vector - see sigv4_test.go.
//
// Payload hashing. SigV4 puts the body hash inside the signature, and the
// header carrying it must be sent before the body goes on the wire. That
// leaves three options:
//
//   - UNSIGNED-PAYLOAD: cheap, but drops the body out of the signature
//     entirely, so anyone on the path can substitute a different ciphertext
//     under our credentials. Not acceptable for the vault.
//   - STREAMING-AWS4-HMAC-SHA256-PAYLOAD: chunked signing, correct but a
//     separate wire protocol that several S3-compatible gateways do not
//     implement.
//   - Buffer the body, hash it, then send it.
//
// We buffer. The vault hands us a finished ciphertext blob whose length it
// already knows, so Put REQUIRES an explicit size and caps it at 256 MiB -
// a bound chosen to keep a single upload's memory cost survivable on a small
// instance while comfortably exceeding any document the vault stores. Larger
// objects need multipart upload, which is a different feature, not a bigger
// buffer.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	sigV4Algorithm = "AWS4-HMAC-SHA256"
	// amzDateFormat is ISO8601 basic, the only format SigV4 accepts.
	amzDateFormat = "20060102T150405Z"
	dateFormat    = "20060102"
	s3Service     = "s3"

	// emptyPayloadHash is sha256 of the empty string, used for GET/DELETE.
	emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	// maxPutSize bounds the in-memory buffer a single Put may allocate.
	maxPutSize = 256 << 20 // 256 MiB
)

// bucketPattern whitelists bucket names. The name is interpolated into a URL
// host (virtual-host style) or path (path-style), so a permissive check here
// would let a misconfiguration redirect every object write to another host.
var bucketPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{1,62}$`)

// -------------------------------------------------------------------------
// SigV4 primitives
// -------------------------------------------------------------------------

// uriEncodePath encodes a path per RFC 3986, preserving the "/" separators.
// S3 - unlike every other SigV4 service - does NOT double-encode the path,
// so the canonical URI is the request path encoded exactly once.
func uriEncodePath(p string) string {
	if p == "" {
		return "/"
	}
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			b.WriteByte(c)
		case c == '-' || c == '.' || c == '_' || c == '~' || c == '/':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// trimHeaderValue applies the canonicalization SigV4 mandates for header
// values: trim the ends, collapse internal runs of spaces to one.
func trimHeaderValue(v string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(v)), " ")
}

// canonicalRequest builds the canonical request document and the matching
// SignedHeaders list. headers are matched case-insensitively; every header
// passed in is signed, so callers control the signed set by what they pass.
func canonicalRequest(method, uri, query string, headers map[string]string, payloadHash string) (canonical, signedHeaders string) {
	if uri == "" {
		uri = "/"
	}
	names := make([]string, 0, len(headers))
	lowered := make(map[string]string, len(headers))
	for k, v := range headers {
		lk := strings.ToLower(strings.TrimSpace(k))
		names = append(names, lk)
		lowered[lk] = trimHeaderValue(v)
	}
	sort.Strings(names)

	var b strings.Builder
	b.WriteString(method)
	b.WriteByte('\n')
	b.WriteString(uri)
	b.WriteByte('\n')
	b.WriteString(query)
	b.WriteByte('\n')
	for _, n := range names {
		b.WriteString(n)
		b.WriteByte(':')
		b.WriteString(lowered[n])
		b.WriteByte('\n')
	}
	// A blank line separates the canonical headers from the signed list.
	b.WriteByte('\n')
	signedHeaders = strings.Join(names, ";")
	b.WriteString(signedHeaders)
	b.WriteByte('\n')
	b.WriteString(payloadHash)
	return b.String(), signedHeaders
}

// credentialScope is the date/region/service/aws4_request tuple that binds a
// signature to one day, one region and one service.
func credentialScope(t time.Time, region, service string) string {
	return t.UTC().Format(dateFormat) + "/" + region + "/" + service + "/aws4_request"
}

// stringToSign is the document actually run through HMAC.
func stringToSign(t time.Time, region, service, canonical string) string {
	sum := sha256.Sum256([]byte(canonical))
	return strings.Join([]string{
		sigV4Algorithm,
		t.UTC().Format(amzDateFormat),
		credentialScope(t, region, service),
		hex.EncodeToString(sum[:]),
	}, "\n")
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

// signingKey derives the per-day, per-region, per-service key. The chain is
// what keeps a leaked signing key useless outside its scope - the long-lived
// secret itself never touches the wire and never signs a request directly.
func signingKey(secret string, t time.Time, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), t.UTC().Format(dateFormat))
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	return hmacSHA256(kService, "aws4_request")
}

// signature is the final hex-encoded HMAC over the string-to-sign.
func signature(key []byte, sts string) string {
	return hex.EncodeToString(hmacSHA256(key, sts))
}

// -------------------------------------------------------------------------
// Errors
// -------------------------------------------------------------------------

// s3Error carries an unsuccessful HTTP status plus the S3 error code from
// the response body, when the body carries one. Ops need the code (AccessDenied
// vs NoSuchBucket vs SignatureDoesNotMatch) to tell a misconfiguration from
// an outage, and the raw status alone does not distinguish them.
type s3Error struct {
	Op      string
	Key     string
	Status  int
	Code    string
	Message string
}

func (e *s3Error) Error() string {
	msg := fmt.Sprintf("storage: s3 %s %q: http %d", e.Op, e.Key, e.Status)
	if e.Code != "" {
		msg += " (" + e.Code + ")"
	}
	if e.Message != "" {
		msg += ": " + e.Message
	}
	return msg
}

// Unwrap maps a missing key onto os.ErrNotExist so IsNotExist gives one
// answer across both drivers. Both signals are honoured: the status, and the
// NoSuchKey/NoSuchBucket code, because some S3-compatible gateways answer
// 403 for a missing object to avoid leaking existence to unauthorized
// callers but still name the code in the body.
func (e *s3Error) Unwrap() error {
	if e.Status == http.StatusNotFound || e.Code == "NoSuchKey" || e.Code == "NoSuchBucket" {
		return os.ErrNotExist
	}
	return nil
}

// maxErrBody bounds how much of an error response we read. A hostile or
// broken endpoint must not be able to make us allocate without limit on the
// error path.
const maxErrBody = 64 << 10

// newS3Error parses the minimal S3 error document:
//
//	<Error><Code>NoSuchKey</Code><Message>...</Message></Error>
//
// A body that is missing, truncated or not XML at all is not itself an
// error - the status code is the fact we must not lose, and the code element
// is a bonus. The response body is consumed and closed here, so callers must
// not touch it afterwards.
func newS3Error(op, key string, resp *http.Response) error {
	e := &s3Error{Op: op, Key: key, Status: resp.StatusCode}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrBody))
	_ = resp.Body.Close()
	var doc struct {
		XMLName xml.Name `xml:"Error"`
		Code    string   `xml:"Code"`
		Message string   `xml:"Message"`
	}
	if err := xml.Unmarshal(body, &doc); err == nil {
		e.Code = doc.Code
		e.Message = doc.Message
	}
	return e
}

// -------------------------------------------------------------------------
// Driver
// -------------------------------------------------------------------------

type s3Driver struct {
	client    *http.Client
	endpoint  *url.URL
	bucket    string
	region    string
	accessKey string
	secretKey string
	pathStyle bool

	// now is swappable so tests can pin the clock; production uses time.Now.
	now func() time.Time
}

func newS3(cfg Config) (Driver, error) {
	missing := ""
	switch {
	case cfg.S3Endpoint == "":
		missing = "endpoint"
	case cfg.S3Bucket == "":
		missing = "bucket"
	case cfg.S3Region == "":
		missing = "region"
	case cfg.S3AccessKey == "":
		missing = "access key"
	case cfg.S3SecretKey == "":
		missing = "secret key"
	}
	if missing != "" {
		return nil, fmt.Errorf("storage: s3 driver requires an %s", missing)
	}
	u, err := url.Parse(strings.TrimRight(cfg.S3Endpoint, "/"))
	if err != nil {
		return nil, fmt.Errorf("storage: parse s3 endpoint %q: %w", cfg.S3Endpoint, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("storage: s3 endpoint %q must be http or https", cfg.S3Endpoint)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("storage: s3 endpoint %q has no host", cfg.S3Endpoint)
	}
	// The bucket name lands in a URL host or path, so it gets the same
	// whitelist treatment as a key.
	if !bucketPattern.MatchString(cfg.S3Bucket) {
		return nil, fmt.Errorf("storage: invalid s3 bucket name %q", cfg.S3Bucket)
	}
	return &s3Driver{
		client:    &http.Client{Timeout: 60 * time.Second},
		endpoint:  u,
		bucket:    cfg.S3Bucket,
		region:    cfg.S3Region,
		accessKey: cfg.S3AccessKey,
		secretKey: cfg.S3SecretKey,
		pathStyle: cfg.S3PathStyle,
		now:       time.Now,
	}, nil
}

// objectURL renders the request URL for a key in whichever addressing style
// is configured. Virtual-host style puts the bucket in the Host header,
// which is what AWS prefers; path-style keeps it in the path, which is what
// MinIO and most on-prem gateways require.
func (d *s3Driver) objectURL(key string) (*url.URL, error) {
	if !keyPattern.MatchString(key) || key == "." || key == ".." {
		return nil, fmt.Errorf("%w: %q", ErrBadKey, key)
	}
	u := *d.endpoint
	base := strings.TrimRight(d.endpoint.Path, "/")
	if d.pathStyle {
		u.Path = base + "/" + d.bucket + "/" + key
	} else {
		u.Host = d.bucket + "." + d.endpoint.Host
		u.Path = base + "/" + key
	}
	return &u, nil
}

// newRequest builds and signs one request. Every attempt re-signs: the
// signature covers x-amz-date, and a retry that reused a stale timestamp
// would be rejected as skewed rather than served.
func (d *s3Driver) newRequest(ctx context.Context, method, key string, body io.Reader, size int64, payloadHash string) (*http.Request, error) {
	u, err := d.objectURL(key)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, fmt.Errorf("storage: s3 build request: %w", err)
	}
	if size >= 0 {
		req.ContentLength = size
	}

	t := d.now().UTC()
	amzDate := t.Format(amzDateFormat)
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	// Exactly these three headers are signed. Keeping the set minimal and
	// explicit means an intermediary adding a header (proxies love to) does
	// not invalidate a signature we computed correctly.
	headers := map[string]string{
		"host":                 u.Host,
		"x-amz-date":           amzDate,
		"x-amz-content-sha256": payloadHash,
	}
	canonical, signed := canonicalRequest(req.Method, uriEncodePath(u.Path), u.RawQuery, headers, payloadHash)
	sts := stringToSign(t, d.region, s3Service, canonical)
	sig := signature(signingKey(d.secretKey, t, d.region, s3Service), sts)
	req.Header.Set("Authorization", fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		sigV4Algorithm, d.accessKey, credentialScope(t, d.region, s3Service), signed, sig))
	return req, nil
}

// drain closes a response body we are not going to read, reading a bounded
// amount first so the connection can go back to the keep-alive pool.
func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrBody))
	_ = resp.Body.Close()
}

// Put stores a key. size is REQUIRED (see the payload hashing note at the
// top of this file): SigV4 must know sha256(body) before the body is sent,
// so the body is buffered, and an unbounded buffer is a memory-exhaustion
// bug waiting to happen.
//
// Put is never retried. It is not idempotent from our side - the reader has
// been consumed, and a retry after an ambiguous failure could race a
// concurrent overwrite - so a failed Put is reported to the vault, which
// owns the decision to try again with a fresh reader.
func (d *s3Driver) Put(ctx context.Context, key string, r io.Reader, size int64) error {
	if size < 0 {
		return fmt.Errorf("storage: s3 put %q: size is required", key)
	}
	if size > maxPutSize {
		return fmt.Errorf("storage: s3 put %q: %d bytes exceeds the %d byte limit", key, size, int64(maxPutSize))
	}

	// Read one byte past the declared size so an over-long reader is caught
	// rather than silently truncated.
	buf := bytes.NewBuffer(make([]byte, 0, size))
	n, err := io.Copy(buf, io.LimitReader(r, size+1))
	if err != nil {
		return fmt.Errorf("storage: s3 put %q: read body: %w", key, err)
	}
	if n != size {
		return fmt.Errorf("storage: s3 put %q: got %d bytes, want %d", key, n, size)
	}
	sum := sha256.Sum256(buf.Bytes())
	payloadHash := hex.EncodeToString(sum[:])

	req, err := d.newRequest(ctx, http.MethodPut, key, bytes.NewReader(buf.Bytes()), size, payloadHash)
	if err != nil {
		return err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("storage: s3 put %q: %w", key, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return newS3Error("put", key, resp)
	}
	drain(resp)
	return nil
}

// Get fetches a key. The caller owns the returned body and must close it.
func (d *s3Driver) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	var out io.ReadCloser
	err := d.retryable(ctx, "get", key, func(resp *http.Response) error {
		out = resp.Body
		return nil
	}, http.MethodGet)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Delete removes a key. Like the local driver, a missing key is an error
// (wrapping os.ErrNotExist via s3Error.Unwrap) rather than a silent success,
// so the vault can notice index drift instead of inheriting it.
//
// Note that S3 itself answers 204 for a delete of a key that was never
// there; only endpoints that report 404 will surface as ErrNotExist. The
// mapping exists so the two drivers agree wherever the backend gives us the
// information, not because S3 can be made to behave like a filesystem.
func (d *s3Driver) Delete(ctx context.Context, key string) error {
	return d.retryable(ctx, "delete", key, func(resp *http.Response) error {
		drain(resp)
		return nil
	}, http.MethodDelete)
}

// retryable runs an idempotent request with exactly one retry on a transport
// error or a 5xx. One retry, not a backoff loop: GET and DELETE are safe to
// repeat, but the vault sits behind a request-scoped context and turning a
// dead endpoint into a long stall is worse for the caller than a fast error.
// 4xx is never retried - it will not change.
func (d *s3Driver) retryable(ctx context.Context, op, key string, onOK func(*http.Response) error, method string) error {
	const attempts = 2
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		req, err := d.newRequest(ctx, method, key, nil, 0, emptyPayloadHash)
		if err != nil {
			// A bad key or endpoint will not fix itself on a second try.
			return err
		}
		resp, err := d.client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("storage: s3 %s %q: %w", op, key, err)
			continue
		}
		if resp.StatusCode >= 500 {
			lastErr = newS3Error(op, key, resp)
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return newS3Error(op, key, resp)
		}
		return onOK(resp)
	}
	return lastErr
}
