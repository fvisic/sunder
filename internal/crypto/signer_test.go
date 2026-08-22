package crypto

// P2.1 signer-split tests: the RemoteEngine must be behaviourally identical
// to the LocalEngine it proxies, the socket must be same-user-only, and
// malformed frames must never take the signer down.

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
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
