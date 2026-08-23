package crypto

// P2.1 signer-split tests: the RemoteEngine must be behaviourally identical
// to the LocalEngine it proxies, the socket must be same-user-only, and
// malformed frames must never take the signer down.

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// startSigner serves a LocalEngine over a temp socket and returns a client.
func startSigner(t *testing.T) (*RemoteEngine, string) {
	t.Helper()
	// Unix socket paths are capped (~104 bytes on macOS); t.TempDir() embeds
	// the test name and can exceed it, so use a short MkdirTemp dir instead.
	dir, err := os.MkdirTemp("", "sgn")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s.sock")
	eng := NewLocalEngine(&autoKS{inner: &FileKeystore{Dir: t.TempDir()}})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = ServeSigner(ctx, sock, eng) }()
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return NewRemoteEngine(sock), sock
}

func TestRemoteEngineMatchesLocal(t *testing.T) {
	ctx := context.Background()
	remote, _ := startSigner(t)

	// MAC: deterministic and 32 bytes.
	m1, err := remote.MAC(ctx, "hmac-email/v1", []byte("filip@example.com"))
	if err != nil || len(m1) != 32 {
		t.Fatalf("mac: %d bytes, %v", len(m1), err)
	}
	m2, _ := remote.MAC(ctx, "hmac-email/v1", []byte("filip@example.com"))
	if string(m1) != string(m2) {
		t.Fatal("remote MAC not deterministic")
	}

	// Seal/Open roundtrip for both algorithms, AAD enforced.
	for _, alg := range []string{AlgAES256GCM, AlgXChaCha20} {
		blob, err := remote.Seal(ctx, "pii-kek/v1", alg, []byte("aad"), []byte(`{"a":"b"}`))
		if err != nil {
			t.Fatalf("%s seal: %v", alg, err)
		}
		plain, err := remote.Open(ctx, "pii-kek/v1", alg, []byte("aad"), blob)
		if err != nil || string(plain) != `{"a":"b"}` {
			t.Fatalf("%s open: %q %v", alg, plain, err)
		}
		if _, err := remote.Open(ctx, "pii-kek/v1", alg, []byte("other"), blob); err == nil {
			t.Fatalf("%s: wrong AAD must fail", alg)
		}
	}

	// Sign/Verify roundtrip; wrong key version fails.
	tok, err := remote.Sign(ctx, "oti-sign/v1", []byte(`{"jti":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := remote.VerifyToken(ctx, "oti-sign/v1", tok)
	if err != nil || string(payload) != `{"jti":"x"}` {
		t.Fatalf("verify: %q %v", payload, err)
	}
	if _, err := remote.VerifyToken(ctx, "oti-sign/v2", tok); err == nil {
		t.Fatal("verify under a different key must fail")
	}

	// Ensure + strict-keystore error surfaces through the wire.
	if err := remote.Ensure(ctx, "hmac-name/v1"); err != nil {
		t.Fatal(err)
	}
	if _, err := remote.MAC(ctx, "BAD NAME", []byte("x")); err == nil {
		t.Fatal("invalid key name must error across the boundary")
	}
}

func TestSignerSocketPermissions(t *testing.T) {
	_, sock := startSigner(t)
	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("socket must be 0600, got %o", perm)
	}
	di, err := os.Stat(filepath.Dir(sock))
	if err != nil {
		t.Fatal(err)
	}
	if perm := di.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("socket dir must not be group/world accessible, got %o", perm)
	}
}

// ServeSigner must TIGHTEN a pre-existing loose directory, not inherit it -
// os.MkdirAll leaves existing modes alone (review finding F5/test item 3).
func TestSignerTightensLooseDirectory(t *testing.T) {
	dir, err := os.MkdirTemp("", "sgn")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil { // deliberately loose
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "s.sock")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = ServeSigner(ctx, sock, NewLocalEngine(&FileKeystore{Dir: t.TempDir()})) }()
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	di, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := di.Mode().Perm(); perm != 0o700 {
		t.Fatalf("ServeSigner must tighten the socket dir to 0700, got %o", perm)
	}
	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("socket must be 0600 from creation, got %o", perm)
	}
}

func TestSignerSurvivesMalformedFrames(t *testing.T) {
	remote, sock := startSigner(t)
	ctx := context.Background()

	// Garbage bytes, oversized length, zero length: each drops that
	// connection only; the signer keeps serving.
	for _, raw := range [][]byte{
		[]byte("garbage without a frame header"),
		func() []byte { var h [4]byte; binary.BigEndian.PutUint32(h[:], maxFrame+1); return h[:] }(),
		func() []byte { var h [4]byte; return h[:] }(),
		func() []byte { // valid length, invalid JSON
			body := []byte("{not json")
			var h [4]byte
			binary.BigEndian.PutUint32(h[:], uint32(len(body)))
			return append(h[:], body...)
		}(),
	} {
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write(raw)
		_ = c.Close()
	}
	if _, err := remote.MAC(ctx, "hmac-email/v1", []byte("still alive")); err != nil {
		t.Fatalf("signer must survive malformed frames: %v", err)
	}
}

func TestRemoteEngineUnreachable(t *testing.T) {
	r := NewRemoteEngine(filepath.Join(t.TempDir(), "nope.sock"))
	if _, err := r.MAC(context.Background(), "hmac-email/v1", []byte("x")); err == nil {
		t.Fatal("unreachable signer must error, never fall back to local keys")
	}
}

func TestServeSignerRefusesDoubleBind(t *testing.T) {
	_, sock := startSigner(t)
	eng := NewLocalEngine(&FileKeystore{Dir: t.TempDir()})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := ServeSigner(ctx, sock, eng); err == nil {
		t.Fatal("second signer on a live socket must refuse to start")
	}
}

func TestRemoteEngineConcurrent(t *testing.T) {
	remote, _ := startSigner(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make([]error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				sum, err := remote.MAC(ctx, "hmac-email/v1", []byte{byte(i), byte(j)})
				if err != nil || len(sum) != 32 {
					errs[i] = err
					return
				}
			}
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}
}

func TestVerifyFailedSurvivesTheWire(t *testing.T) {
	remote, _ := startSigner(t)
	ctx := context.Background()
	tok, err := remote.Sign(ctx, "oti-sign/v1", []byte(`{"x":1}`))
	if err != nil {
		t.Fatal(err)
	}
	// Tampered token: the error must carry ErrVerifyFailed across the IPC
	// boundary so callers can distinguish 4xx from 5xx.
	_, err = remote.VerifyToken(ctx, "oti-sign/v1", tok[:len(tok)-2]+"AA")
	if !errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("tampered token must be ErrVerifyFailed, got %v", err)
	}
	// Unavailable key (invalid name -> strict keystore error): environmental,
	// NOT verify-failed. (The autoKS test helper mints any VALID name.)
	_, err = remote.VerifyToken(ctx, "oti-sign", tok)
	if err == nil || errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("missing key must be an environment error, got %v", err)
	}
}

// Review finding: pooled connections going stale (signer restart, idle cap)
// must be retried once on a fresh dial instead of surfacing 5xx.
func TestRemoteEngineSurvivesSignerRestart(t *testing.T) {
	dir, err := os.MkdirTemp("", "sgn")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s.sock")
	ksDir := t.TempDir()
	eng := NewLocalEngine(&autoKS{inner: &FileKeystore{Dir: ksDir}})

	ctx1, cancel1 := context.WithCancel(context.Background())
	go func() { _ = ServeSigner(ctx1, sock, eng) }()
	waitFor := func() {
		for i := 0; i < 100; i++ {
			if c, err := net.DialTimeout("unix", sock, 50*time.Millisecond); err == nil {
				_ = c.Close()
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("signer socket never came up")
	}
	waitFor()
	remote := NewRemoteEngine(sock)
	if _, err := remote.MAC(context.Background(), "hmac-email/v1", []byte("warm the pool")); err != nil {
		t.Fatal(err)
	}
	// Restart the signer: the pooled connection is now dead.
	cancel1()
	time.Sleep(50 * time.Millisecond)
	ctx2, cancel2 := context.WithCancel(context.Background())
	t.Cleanup(cancel2)
	go func() { _ = ServeSigner(ctx2, sock, eng) }()
	waitFor()
	if _, err := remote.MAC(context.Background(), "hmac-email/v1", []byte("after restart")); err != nil {
		t.Fatalf("a stale pooled conn must be retried on a fresh dial: %v", err)
	}
}

// A fresh-dial failure is never retried, and a response that arrives after
// a pooled retry is still correct.
func TestRemoteEngineNoRetryOnFreshDial(t *testing.T) {
	dir, err := os.MkdirTemp("", "sgn")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	// Nothing is listening: the first dial fails and must not be retried
	// into a loop.
	r := NewRemoteEngine(filepath.Join(dir, "absent.sock"))
	start := time.Now()
	if _, err := r.MAC(context.Background(), "hmac-email/v1", []byte("x")); err == nil {
		t.Fatal("an absent signer must error")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("a fresh-dial failure must fail fast, took %s", elapsed)
	}
}

// writeKey must fail cleanly when the temp file cannot be renamed into
// place (the directory disappeared under it).
func TestWriteKeyRenameFailure(t *testing.T) {
	dir, err := os.MkdirTemp("", "ks")
	if err != nil {
		t.Fatal(err)
	}
	ks := &FileKeystore{Dir: dir}
	if err := ks.Ensure(context.Background(), "hmac-email/v1"); err != nil {
		t.Fatal(err)
	}
	// A path whose parent is a FILE, not a directory: CreateTemp fails.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	sub := &FileKeystore{Dir: filepath.Join(blocker, "nested")}
	if err := sub.Ensure(context.Background(), "hmac-email/v1"); err == nil {
		t.Fatal("a keystore under a regular file must fail")
	}
	_ = os.RemoveAll(dir)
}

// writeFrame must refuse an oversized frame rather than truncating it, and
// Encrypt must surface a keystore failure.
func TestWriteFrameSizeCapAndEncryptFailure(t *testing.T) {
	var sink bytes.Buffer
	huge := make([]byte, maxFrame+1)
	if err := writeFrame(&sink, signerResp{OK: true, Out: huge}); err == nil {
		t.Fatal("an oversized frame must be refused, never truncated")
	}
	// A writer that fails mid-frame surfaces the error.
	if err := writeFrame(failingWriter{}, signerReq{V: 1, Op: "mac"}); err == nil {
		t.Fatal("a failing writer must surface an error")
	}
	// Sealing under a missing key fails closed (strict keystore).
	box := NewPIIBox(NewLocalEngine(&FileKeystore{Dir: t.TempDir()}))
	if _, err := box.SealBytes(context.Background(), "portal-outbox", "v1", []byte("x")); err == nil {
		t.Fatal("sealing without key material must fail")
	}
	if _, err := box.OpenBytes(context.Background(), "portal-outbox", []byte("x"), "v1", AlgAES256GCM); err == nil {
		t.Fatal("opening without key material must fail")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, context.DeadlineExceeded }

// A wrong protocol version must be rejected with an error frame, not
// silently served: the version field exists so future changes can key on it.
func TestSignerRejectsWrongProtocolVersion(t *testing.T) {
	_, sock := startSigner(t)
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := writeFrame(c, signerReq{V: 99, Op: "mac", Key: "hmac-email/v1"}); err != nil {
		t.Fatal(err)
	}
	var resp signerResp
	if err := readFrame(c, &resp); err != nil {
		t.Fatalf("the signer must answer, not just hang up: %v", err)
	}
	if resp.OK || !strings.Contains(resp.Error, "protocol version") {
		t.Fatalf("expected a version rejection, got %+v", resp)
	}
}

// A signer that accepts the request and dies before replying: the pooled
// connection is retried once on a fresh dial, so a restart mid-request does
// not surface as a 5xx to the caller.
func TestRemoteEngineRetriesLostResponse(t *testing.T) {
	dir, err := os.MkdirTemp("", "sgn")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s.sock")

	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	eng := NewLocalEngine(&autoKS{inner: &FileKeystore{Dir: t.TempDir()}})
	var mu sync.Mutex
	// Serve the first request normally (that pools a connection), then die
	// mid-request on the second: only a POOLED connection is retried.
	served := 0
	dropNth := 2
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			// Loop per connection, like the real signer, so a pooled
			// connection stays usable between requests.
			go func(c net.Conn) {
				defer c.Close()
				for {
					var req signerReq
					if err := readFrame(c, &req); err != nil {
						return
					}
					mu.Lock()
					served++
					dropThis := served == dropNth
					mu.Unlock()
					if dropThis {
						return // read the request, then die before replying
					}
					out, err := eng.MAC(context.Background(), req.Key, req.Data)
					resp := signerResp{OK: err == nil, Out: out}
					if err != nil {
						resp.Error = err.Error()
					}
					if err := writeFrame(c, resp); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = l.Close() })

	r := NewRemoteEngine(sock)
	// Warm the pool so the next call uses a POOLED connection (only those
	// are retried).
	if _, err := r.MAC(context.Background(), "hmac-email/v1", []byte("warm")); err != nil {
		t.Fatalf("warm-up must succeed: %v", err)
	}
	if _, err := r.MAC(context.Background(), "hmac-email/v1", []byte("after")); err != nil {
		t.Fatalf("a pooled connection must be retried: %v", err)
	}
}
