package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testAccessKey = "AKIATESTTESTTESTTEST"
	testSecretKey = "c3VuZGVyLXRlc3Qtc2VjcmV0LWtleS12YWx1ZS0xMjM0NQ"
	testBucket    = "sunder-vault"
	testRegion    = "eu-central-1"
)

// authPattern is the exact Authorization header shape SigV4 mandates. A
// server that cannot parse this rejects every request, so the structure is
// asserted here rather than inferred from a 200.
var authPattern = regexp.MustCompile(
	`^AWS4-HMAC-SHA256 Credential=([A-Z0-9]+)/(\d{8})/([a-z0-9-]+)/s3/aws4_request, ` +
		`SignedHeaders=([a-z0-9;-]+), Signature=([0-9a-f]{64})$`)

// newTestS3 wires a driver to an httptest server in path-style, which is the
// only style that can address a 127.0.0.1 test server.
func newTestS3(t *testing.T, h http.Handler) (Driver, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	d, err := Open(Config{
		Kind:        "s3",
		S3Endpoint:  srv.URL,
		S3Bucket:    testBucket,
		S3Region:    testRegion,
		S3AccessKey: testAccessKey,
		S3SecretKey: testSecretKey,
		S3PathStyle: true,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return d, srv
}

// checkSignedRequest asserts everything the wire format must get right, and
// recomputes the signature from what actually arrived. The primitives are
// pinned to the AWS vector in sigv4_test.go, so re-deriving here catches the
// other half of the problem: a request whose canonical form does not match
// the bytes that were sent (wrong host, wrong path, unsigned header).
func checkSignedRequest(t *testing.T, r *http.Request, wantMethod, wantKey, wantPayloadHash string) {
	t.Helper()

	if r.Method != wantMethod {
		t.Errorf("method = %q, want %q", r.Method, wantMethod)
	}
	// Path-style addressing: /{bucket}/{key}, bucket NOT in the host.
	if want := "/" + testBucket + "/" + wantKey; r.URL.Path != want {
		t.Errorf("path = %q, want %q", r.URL.Path, want)
	}
	if strings.HasPrefix(r.Host, testBucket+".") {
		t.Errorf("path-style request put the bucket in the host: %q", r.Host)
	}

	gotHash := r.Header.Get("X-Amz-Content-Sha256")
	if gotHash != wantPayloadHash {
		t.Errorf("x-amz-content-sha256 = %q, want %q", gotHash, wantPayloadHash)
	}
	if gotHash == "UNSIGNED-PAYLOAD" {
		t.Error("driver sent an unsigned payload")
	}

	amzDate := r.Header.Get("X-Amz-Date")
	ts, err := time.Parse(amzDateFormat, amzDate)
	if err != nil {
		t.Fatalf("x-amz-date %q is not ISO8601 basic: %v", amzDate, err)
	}
	if skew := time.Since(ts); skew > 5*time.Minute || skew < -5*time.Minute {
		t.Errorf("x-amz-date %q is skewed by %v", amzDate, skew)
	}

	auth := r.Header.Get("Authorization")
	m := authPattern.FindStringSubmatch(auth)
	if m == nil {
		t.Fatalf("Authorization header does not match the SigV4 structure: %q", auth)
	}
	if m[1] != testAccessKey {
		t.Errorf("credential access key = %q, want %q", m[1], testAccessKey)
	}
	if m[2] != amzDate[:8] {
		t.Errorf("credential scope date = %q, want %q (from x-amz-date)", m[2], amzDate[:8])
	}
	if m[3] != testRegion {
		t.Errorf("credential scope region = %q, want %q", m[3], testRegion)
	}
	if want := "host;x-amz-content-sha256;x-amz-date"; m[4] != want {
		t.Errorf("SignedHeaders = %q, want %q", m[4], want)
	}

	// Re-derive the signature from the request as received.
	canonical, signed := canonicalRequest(r.Method, uriEncodePath(r.URL.Path), r.URL.RawQuery,
		map[string]string{
			"host":                 r.Host,
			"x-amz-date":           amzDate,
			"x-amz-content-sha256": gotHash,
		}, gotHash)
	if signed != m[4] {
		t.Errorf("recomputed SignedHeaders = %q, header says %q", signed, m[4])
	}
	sts := stringToSign(ts, testRegion, s3Service, canonical)
	want := signature(signingKey(testSecretKey, ts, testRegion, s3Service), sts)
	if m[5] != want {
		t.Errorf("signature does not verify against the received request\n got: %s\nwant: %s\ncanonical request:\n%s",
			m[5], want, canonical)
	}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestS3RoundTrip(t *testing.T) {
	payload := []byte("encrypted-blob-payload")
	stored := map[string][]byte{}

	d, _ := newTestS3(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.URL.Path, "/"+testBucket+"/")
		switch r.Method {
		case http.MethodPut:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("read body: %v", err)
			}
			checkSignedRequest(t, r, http.MethodPut, key, sha256Hex(body))
			if r.ContentLength != int64(len(payload)) {
				t.Errorf("Content-Length = %d, want %d", r.ContentLength, len(payload))
			}
			stored[key] = body
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			checkSignedRequest(t, r, http.MethodGet, key, emptyPayloadHash)
			b, ok := stored[key]
			if !ok {
				writeS3Error(w, http.StatusNotFound, "NoSuchKey", "The specified key does not exist.")
				return
			}
			_, _ = w.Write(b)
		case http.MethodDelete:
			checkSignedRequest(t, r, http.MethodDelete, key, emptyPayloadHash)
			delete(stored, key)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected method %q", r.Method)
		}
	}))

	ctx := context.Background()
	if err := d.Put(ctx, "obj-1", bytes.NewReader(payload), int64(len(payload))); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if !bytes.Equal(stored["obj-1"], payload) {
		t.Errorf("server stored %q, want %q", stored["obj-1"], payload)
	}

	rc, err := d.Get(ctx, "obj-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	_ = rc.Close()
	if !bytes.Equal(got, payload) {
		t.Errorf("Get returned %q, want %q", got, payload)
	}

	if err := d.Delete(ctx, "obj-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := d.Get(ctx, "obj-1"); !IsNotExist(err) {
		t.Errorf("Get after Delete = %v, want a not-exist error", err)
	}
}

func writeS3Error(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?>`+
		`<Error><Code>`+code+`</Code><Message>`+msg+`</Message>`+
		`<RequestId>TEST123</RequestId></Error>`)
}

// TestS3NotFoundMapping checks a 404 with a NoSuchKey document becomes an
// error that carries both the status and the S3 code, and that IsNotExist
// recognises it.
func TestS3NotFoundMapping(t *testing.T) {
	d, _ := newTestS3(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeS3Error(w, http.StatusNotFound, "NoSuchKey", "The specified key does not exist.")
	}))

	_, err := d.Get(context.Background(), "missing")
	if err == nil {
		t.Fatal("Get of a missing key returned no error")
	}
	if !IsNotExist(err) || !errors.Is(err, os.ErrNotExist) {
		t.Errorf("error %v does not map to os.ErrNotExist", err)
	}

	var se *s3Error
	if !errors.As(err, &se) {
		t.Fatalf("error %v is not an *s3Error", err)
	}
	if se.Status != http.StatusNotFound {
		t.Errorf("Status = %d, want 404", se.Status)
	}
	if se.Code != "NoSuchKey" {
		t.Errorf("Code = %q, want NoSuchKey", se.Code)
	}
	for _, want := range []string{"404", "NoSuchKey", "missing"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error message %q does not mention %q", err.Error(), want)
		}
	}
}

// TestS3AccessDeniedIsNotNotExist guards the mapping in the other direction:
// a permissions failure must not be swallowed by the vault's GC as "already
// gone".
func TestS3AccessDeniedIsNotNotExist(t *testing.T) {
	d, _ := newTestS3(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeS3Error(w, http.StatusForbidden, "AccessDenied", "Access Denied")
	}))

	err := d.Delete(context.Background(), "obj-1")
	if err == nil {
		t.Fatal("Delete returned no error on 403")
	}
	if IsNotExist(err) {
		t.Errorf("403 AccessDenied was mistaken for a missing key: %v", err)
	}
	if !strings.Contains(err.Error(), "AccessDenied") {
		t.Errorf("error %q does not carry the S3 code", err.Error())
	}
}

// TestS3ErrorWithoutXMLBody: the status must survive a body that is empty or
// not XML at all.
func TestS3ErrorWithoutXMLBody(t *testing.T) {
	d, _ := newTestS3(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, "<html>nginx</html>")
	}))

	_, err := d.Get(context.Background(), "obj-1")
	if err == nil {
		t.Fatal("Get returned no error on 502")
	}
	if !strings.Contains(err.Error(), "502") {
		t.Errorf("error %q does not carry the status", err.Error())
	}
}

// TestS3RetriesGetOnce is the retry contract: one retry on 5xx for the
// idempotent verbs, and the retry must be a freshly signed request.
func TestS3RetriesGetOnce(t *testing.T) {
	var calls int32
	var dates []string

	d, _ := newTestS3(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		dates = append(dates, r.Header.Get("X-Amz-Date"))
		checkSignedRequest(t, r, http.MethodGet, "obj-1", emptyPayloadHash)
		if n == 1 {
			writeS3Error(w, http.StatusInternalServerError, "InternalError", "We encountered an internal error.")
			return
		}
		_, _ = io.WriteString(w, "second-time-lucky")
	}))

	rc, err := d.Get(context.Background(), "obj-1")
	if err != nil {
		t.Fatalf("Get did not retry past the 500: %v", err)
	}
	defer rc.Close()
	got, _ := io.ReadAll(rc)
	if string(got) != "second-time-lucky" {
		t.Errorf("body = %q, want %q", got, "second-time-lucky")
	}
	if n := atomic.LoadInt32(&calls); n != 2 {
		t.Errorf("server saw %d calls, want 2", n)
	}
	if len(dates) == 2 && dates[0] == "" {
		t.Error("retry was sent without a signature date")
	}
}

// TestS3GivesUpAfterOneRetry: two 500s is a failure, not an unbounded loop.
func TestS3GivesUpAfterOneRetry(t *testing.T) {
	var calls int32
	d, _ := newTestS3(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		writeS3Error(w, http.StatusServiceUnavailable, "SlowDown", "Please reduce your request rate.")
	}))

	if _, err := d.Get(context.Background(), "obj-1"); err == nil {
		t.Fatal("Get returned no error after two 503s")
	}
	if n := atomic.LoadInt32(&calls); n != 2 {
		t.Errorf("server saw %d calls, want exactly 2", n)
	}
}

// TestS3DeleteRetries mirrors the GET case for the other idempotent verb.
func TestS3DeleteRetries(t *testing.T) {
	var calls int32
	d, _ := newTestS3(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		checkSignedRequest(t, r, http.MethodDelete, "obj-1", emptyPayloadHash)
		w.WriteHeader(http.StatusNoContent)
	}))

	if err := d.Delete(context.Background(), "obj-1"); err != nil {
		t.Fatalf("Delete did not retry past the 500: %v", err)
	}
	if n := atomic.LoadInt32(&calls); n != 2 {
		t.Errorf("server saw %d calls, want 2", n)
	}
}

// TestS3DoesNotRetryPut: the reader is consumed and a blind retry could race
// a concurrent overwrite, so the vault owns that decision.
func TestS3DoesNotRetryPut(t *testing.T) {
	var calls int32
	d, _ := newTestS3(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		_, _ = io.Copy(io.Discard, r.Body)
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "boom")
	}))

	err := d.Put(context.Background(), "obj-1", strings.NewReader("x"), 1)
	if err == nil {
		t.Fatal("Put returned no error on 500")
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Errorf("server saw %d calls, want exactly 1 (PUT must not be retried)", n)
	}
}

// TestS3PutRequiresSize covers the payload-hashing contract and its bound.
func TestS3PutRequiresSize(t *testing.T) {
	d, _ := newTestS3(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request should never have been sent")
	}))
	ctx := context.Background()

	if err := d.Put(ctx, "obj-1", strings.NewReader("x"), -1); err == nil {
		t.Error("Put accepted an unknown size")
	}
	if err := d.Put(ctx, "obj-1", strings.NewReader("x"), maxPutSize+1); err == nil {
		t.Error("Put accepted a size above the buffer cap")
	}
}

// TestS3PutSizeMismatch: a body that does not match the declared size is
// refused before anything is signed, in both directions.
func TestS3PutSizeMismatch(t *testing.T) {
	var calls int32
	d, _ := newTestS3(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusOK)
	}))
	ctx := context.Background()

	if err := d.Put(ctx, "obj-1", strings.NewReader("short"), 100); err == nil {
		t.Error("Put accepted a body shorter than the declared size")
	}
	if err := d.Put(ctx, "obj-1", strings.NewReader("much-longer-than-two"), 2); err == nil {
		t.Error("Put accepted a body longer than the declared size")
	}
	if n := atomic.LoadInt32(&calls); n != 0 {
		t.Errorf("server saw %d calls, want 0", n)
	}
}

func TestS3KeySanitization(t *testing.T) {
	d, _ := newTestS3(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("request should never have been sent for path %q", r.URL.Path)
	}))
	ctx := context.Background()

	for _, key := range []string{"", "..", "../../secrets", "sub/dir", "has space", "?query"} {
		if err := d.Put(ctx, key, strings.NewReader("x"), 1); !errors.Is(err, ErrBadKey) {
			t.Errorf("Put(%q) = %v, want ErrBadKey", key, err)
		}
		if _, err := d.Get(ctx, key); !errors.Is(err, ErrBadKey) {
			t.Errorf("Get(%q) = %v, want ErrBadKey", key, err)
		}
		if err := d.Delete(ctx, key); !errors.Is(err, ErrBadKey) {
			t.Errorf("Delete(%q) = %v, want ErrBadKey", key, err)
		}
	}
}

// TestS3URLShapes pins both addressing styles. Virtual-host cannot be
// exercised against httptest (the bucket would have to resolve in DNS), so
// the URL construction is asserted directly.
func TestS3URLShapes(t *testing.T) {
	base := Config{
		Kind:        "s3",
		S3Endpoint:  "https://s3.eu-central-1.amazonaws.com",
		S3Bucket:    testBucket,
		S3Region:    testRegion,
		S3AccessKey: testAccessKey,
		S3SecretKey: testSecretKey,
	}

	virtual, err := Open(base)
	if err != nil {
		t.Fatalf("Open virtual-host: %v", err)
	}
	u, err := virtual.(*s3Driver).objectURL("obj-1")
	if err != nil {
		t.Fatalf("objectURL: %v", err)
	}
	if want := "https://sunder-vault.s3.eu-central-1.amazonaws.com/obj-1"; u.String() != want {
		t.Errorf("virtual-host URL = %q, want %q", u.String(), want)
	}

	base.S3PathStyle = true
	path, err := Open(base)
	if err != nil {
		t.Fatalf("Open path-style: %v", err)
	}
	u, err = path.(*s3Driver).objectURL("obj-1")
	if err != nil {
		t.Fatalf("objectURL: %v", err)
	}
	if want := "https://s3.eu-central-1.amazonaws.com/sunder-vault/obj-1"; u.String() != want {
		t.Errorf("path-style URL = %q, want %q", u.String(), want)
	}

	// An endpoint with a path prefix (a gateway mounted under a subpath)
	// must keep that prefix.
	base.S3Endpoint = "http://gateway.internal:9000/s3"
	prefixed, err := Open(base)
	if err != nil {
		t.Fatalf("Open prefixed: %v", err)
	}
	u, err = prefixed.(*s3Driver).objectURL("obj-1")
	if err != nil {
		t.Fatalf("objectURL: %v", err)
	}
	if want := "http://gateway.internal:9000/s3/sunder-vault/obj-1"; u.String() != want {
		t.Errorf("prefixed URL = %q, want %q", u.String(), want)
	}
}

func TestS3OpenValidation(t *testing.T) {
	full := Config{
		Kind:        "s3",
		S3Endpoint:  "https://s3.amazonaws.com",
		S3Bucket:    testBucket,
		S3Region:    testRegion,
		S3AccessKey: testAccessKey,
		S3SecretKey: testSecretKey,
	}
	if _, err := Open(full); err != nil {
		t.Fatalf("complete config rejected: %v", err)
	}

	cases := map[string]func(*Config){
		"no endpoint":    func(c *Config) { c.S3Endpoint = "" },
		"no bucket":      func(c *Config) { c.S3Bucket = "" },
		"no region":      func(c *Config) { c.S3Region = "" },
		"no access key":  func(c *Config) { c.S3AccessKey = "" },
		"no secret key":  func(c *Config) { c.S3SecretKey = "" },
		"bad scheme":     func(c *Config) { c.S3Endpoint = "ftp://example.com" },
		"no scheme":      func(c *Config) { c.S3Endpoint = "s3.amazonaws.com" },
		"bad bucket":     func(c *Config) { c.S3Bucket = "bucket/../other" },
		"bucket with at": func(c *Config) { c.S3Bucket = "evil@attacker.example" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := full
			mutate(&cfg)
			if _, err := Open(cfg); err == nil {
				t.Errorf("config with %s was accepted", name)
			}
		})
	}
}

// TestS3ContextCancellation: a cancelled context must abort rather than burn
// the retry budget.
func TestS3ContextCancellation(t *testing.T) {
	var calls int32
	d, _ := newTestS3(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusOK)
	}))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := d.Get(ctx, "obj-1"); !errors.Is(err, context.Canceled) {
		t.Errorf("Get with a cancelled context = %v, want context.Canceled", err)
	}
	if err := d.Put(ctx, "obj-1", strings.NewReader("x"), 1); err == nil {
		t.Error("Put with a cancelled context returned no error")
	}
	if n := atomic.LoadInt32(&calls); n != 0 {
		t.Errorf("server saw %d calls with a cancelled context, want 0", n)
	}
}

// TestS3EmptyPayloadHashConstant guards the hard-coded constant against a
// typo - it is the hash the signature of every GET and DELETE depends on.
func TestS3EmptyPayloadHashConstant(t *testing.T) {
	if got := sha256Hex(nil); got != emptyPayloadHash {
		t.Errorf("emptyPayloadHash = %q, want %q", emptyPayloadHash, got)
	}
}

// TestS3EndpointTrailingSlash: a trailing slash in configuration must not
// produce a double slash in the signed path, which would be a signature
// mismatch against a real endpoint.
func TestS3EndpointTrailingSlash(t *testing.T) {
	d, err := Open(Config{
		Kind:        "s3",
		S3Endpoint:  "https://s3.amazonaws.com/",
		S3Bucket:    testBucket,
		S3Region:    testRegion,
		S3AccessKey: testAccessKey,
		S3SecretKey: testSecretKey,
		S3PathStyle: true,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	u, err := d.(*s3Driver).objectURL("obj-1")
	if err != nil {
		t.Fatalf("objectURL: %v", err)
	}
	if strings.Contains(u.Path, "//") {
		t.Errorf("path contains a double slash: %q", u.Path)
	}
	if _, err := url.Parse(u.String()); err != nil {
		t.Errorf("unparseable URL %q: %v", u.String(), err)
	}
}

// FILES-STORAGE-2: the driver re-buffered an already-buffered body, so real
// peak upload memory was ~4x the payload rather than the 1x the semaphore's
// documented bound assumes.
func TestPutDoesNotReBufferAnAlreadyMaterialisedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(200)
	}))
	defer srv.Close()
	d, err := Open(Config{Kind: "s3", S3Endpoint: srv.URL, S3Bucket: "test-bucket",
		S3AccessKey: "k", S3SecretKey: "s", S3Region: "us-east-1", S3PathStyle: true})
	if err != nil {
		t.Fatal(err)
	}

	const size = 8 << 20
	payload := bytes.NewBuffer(make([]byte, size))

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	if err := d.Put(context.Background(), "k1", payload, size); err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)

	delta := after.TotalAlloc - before.TotalAlloc
	// The body is already in hand, so the PUT must not allocate another
	// copy of it. A generous ceiling: request/SigV4 scratch only.
	if delta > size/2 {
		t.Fatalf("Put allocated %d bytes for an already-buffered %d-byte body - it is copying it again", delta, size)
	}
}

// An over-long reader must still be refused - that guard is what the
// LimitReader used to provide.
func TestPutRefusesAnOverLongReader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(200)
	}))
	defer srv.Close()
	d, err := Open(Config{Kind: "s3", S3Endpoint: srv.URL, S3Bucket: "test-bucket",
		S3AccessKey: "k", S3SecretKey: "s", S3Region: "us-east-1", S3PathStyle: true})
	if err != nil {
		t.Fatal(err)
	}
	// A plain reader (not *bytes.Buffer/*bytes.Reader) carrying more than
	// the declared size.
	long := io.NopCloser(bytes.NewReader(make([]byte, 100)))
	if err := d.Put(context.Background(), "k2", long, 50); err == nil {
		t.Fatal("a reader longer than the declared size must be refused")
	}
	// ...and a short one too.
	short := io.NopCloser(bytes.NewReader(make([]byte, 10)))
	if err := d.Put(context.Background(), "k3", short, 50); err == nil {
		t.Fatal("a reader shorter than the declared size must be refused")
	}
}
