package crypto

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// autoKS wraps FileKeystore to create keys on demand - ONLY for tests; the
// production keystore is strict and keys are created at bootstrap.
type autoKS struct{ inner *FileKeystore }

func (a *autoKS) Key(ctx context.Context, name string) ([]byte, error) {
	if err := a.inner.Ensure(ctx, name); err != nil {
		return nil, err
	}
	return a.inner.Key(ctx, name)
}
func (a *autoKS) Ensure(ctx context.Context, name string) error { return a.inner.Ensure(ctx, name) }

func fileKS(t *testing.T) Engine {
	return NewLocalEngine(&autoKS{inner: &FileKeystore{Dir: t.TempDir()}})
}

func TestNormalizeEmail(t *testing.T) {
	for in, want := range map[string]string{
		"  Filip@Example.COM ": "filip@example.com",
		"a@b":                  "a@b",
	} {
		got, err := NormalizeEmail(in)
		if err != nil || got != want {
			t.Errorf("NormalizeEmail(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "nope", "@x", "x@", "a@@b"} {
		if _, err := NormalizeEmail(bad); err == nil {
			t.Errorf("NormalizeEmail(%q): expected error", bad)
		}
	}
}

func TestNormalizePhone(t *testing.T) {
	for in, want := range map[string]string{
		"+385 91 123-4567":  "+385911234567",
		"00385911234567":    "+385911234567",
		"+1 (212) 555.0123": "+12125550123",
	} {
		got, err := NormalizePhone(in)
		if err != nil || got != want {
			t.Errorf("NormalizePhone(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "0911234567", "+0123456789", "abc", "+385x91"} {
		if _, err := NormalizePhone(bad); err == nil {
			t.Errorf("NormalizePhone(%q): expected error", bad)
		}
	}
}

func TestNormalizeName(t *testing.T) {
	got, err := NormalizeName("  Ivan   HORVAT ")
	if err != nil || got != "ivan horvat" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := NormalizeName("   "); err == nil {
		t.Fatal("expected error for blank name")
	}
}

func TestTokenizerDeterministicAndKeySeparated(t *testing.T) {
	ctx := context.Background()
	tk := NewTokenizer(fileKS(t))
	a, err := tk.EmailToken(ctx, "v1", "filip@example.com")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := tk.EmailToken(ctx, "v1", "filip@example.com")
	if a != b {
		t.Fatal("token not deterministic")
	}
	if len(a) != 64 {
		t.Fatalf("want 64 hex chars, got %d", len(a))
	}
	// Same input under a different attribute key must differ (per-attribute keys).
	c, _ := tk.NameToken(ctx, "v1", "filip@example.com")
	if a == c {
		t.Fatal("email and name keys produce identical tokens - keys not separated")
	}
	// Different key versions must differ (rotation window).
	d, _ := tk.EmailToken(ctx, "v2", "filip@example.com")
	if a == d {
		t.Fatal("v1 and v2 produce identical tokens")
	}
}

func TestFileKeystoreStableAcrossInstances(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if err := (&FileKeystore{Dir: dir}).Ensure(ctx, "hmac-email/v1"); err != nil {
		t.Fatal(err)
	}
	k1, err := (&FileKeystore{Dir: dir}).Key(ctx, "hmac-email/v1")
	if err != nil {
		t.Fatal(err)
	}
	k2, err := (&FileKeystore{Dir: dir}).Key(ctx, "hmac-email/v1")
	if err != nil {
		t.Fatal(err)
	}
	if string(k1) != string(k2) {
		t.Fatal("keystore returned different keys for same name")
	}
}

func TestFileKeystoreStrictOnMissingKey(t *testing.T) {
	ks := &FileKeystore{Dir: t.TempDir()}
	if _, err := ks.Key(context.Background(), "hmac-email/v9"); err == nil {
		t.Fatal("strict keystore must error on a missing key, never mint one")
	}
}

func TestKeyNameValidation(t *testing.T) {
	ks := &FileKeystore{Dir: t.TempDir()}
	for _, bad := range []string{"", "hmac-email", "hmac_email/v1", "a/b/v1", "HMAC/v1", "../../etc/x/v1"} {
		if err := ks.Ensure(context.Background(), bad); err == nil {
			t.Errorf("Ensure(%q): expected name validation error", bad)
		}
	}
}

func TestPIIRoundtripTamperAndTransplant(t *testing.T) {
	ctx := context.Background()
	box := NewPIIBox(fileKS(t))
	attrs := map[string]string{"email": "filip@example.com", "name": "Filip"}
	const keyID = "v1"
	blob, err := box.Encrypt(ctx, "CID-A", keyID, attrs)
	if err != nil {
		t.Fatal(err)
	}
	got, err := box.Decrypt(ctx, "CID-A", blob, keyID, AlgAES256GCM)
	if err != nil || got["email"] != attrs["email"] {
		t.Fatalf("roundtrip failed: %v %v", got, err)
	}
	// Transplant: the same ciphertext moved under another CID must fail
	// authentication (AAD binding).
	if _, err := box.Decrypt(ctx, "CID-B", blob, keyID, AlgAES256GCM); err == nil {
		t.Fatal("blob transplanted to another CID decrypted without error")
	}
	blob[len(blob)-1] ^= 0xFF
	if _, err := box.Decrypt(ctx, "CID-A", blob, keyID, AlgAES256GCM); err == nil {
		t.Fatal("tampered blob decrypted without error")
	}
}

func TestNewCIDShape(t *testing.T) {
	cid, err := NewCID()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(cid, "CID-") || len(cid) != 4+26 {
		t.Fatalf("unexpected CID shape: %q", cid)
	}
	cid2, _ := NewCID()
	if cid == cid2 {
		t.Fatal("two CIDs identical")
	}
}

func TestPKCS11Stub(t *testing.T) {
	if _, err := (&PKCS11Keystore{}).Key(context.Background(), "x"); err == nil {
		t.Fatal("pkcs11 stub Key must error")
	}
	if err := (&PKCS11Keystore{}).Ensure(context.Background(), "x"); err == nil {
		t.Fatal("pkcs11 stub Ensure must error")
	}
}

func TestNormalizeCleanRejectsControlChars(t *testing.T) {
	if _, err := NormalizeEmail("a\x00b@example.com"); err == nil {
		t.Fatal("NUL in email must be rejected")
	}
	if _, err := NormalizeName("Ana\x1bAnic"); err == nil {
		t.Fatal("escape char in name must be rejected")
	}
	if _, err := NormalizeEmail("has space@example.com"); err == nil {
		t.Fatal("inner whitespace must be rejected")
	}
	long := strings.Repeat("a", 330) + "@example.com"
	if _, err := NormalizeEmail(long); err == nil {
		t.Fatal("overlong email must be rejected")
	}
}

func TestCSPRNGFailureSurfaces(t *testing.T) {
	old := randRead
	randRead = func([]byte) (int, error) { return 0, context.DeadlineExceeded }
	defer func() { randRead = old }()

	if _, err := NewCID(); err == nil {
		t.Fatal("NewCID must surface CSPRNG failure")
	}
	if _, err := NewClientSecret(); err == nil {
		t.Fatal("NewClientSecret must surface CSPRNG failure")
	}
	// Encrypt: create the key FIRST (with a working CSPRNG) so the failure
	// exercised here is the nonce draw inside Seal, not key generation
	// (review finding, test item 2).
	randRead = old
	ksDir := t.TempDir()
	warm := &FileKeystore{Dir: ksDir}
	if err := warm.Ensure(context.Background(), "pii-kek/v1"); err != nil {
		t.Fatal(err)
	}
	box := NewPIIBox(NewLocalEngine(warm))
	randRead = func([]byte) (int, error) { return 0, context.DeadlineExceeded }
	if _, err := box.Encrypt(context.Background(), "CID-X", "v1", map[string]string{"a": "b"}); err == nil {
		t.Fatal("Encrypt must surface a nonce CSPRNG failure")
	}
	ks := &FileKeystore{Dir: t.TempDir()}
	if err := ks.Ensure(context.Background(), "hmac-email/v1"); err == nil {
		t.Fatal("Ensure must surface CSPRNG failure")
	}
}

func TestWriteKeyFailure(t *testing.T) {
	ks := &FileKeystore{}
	if err := ks.writeKey("/definitely/not/a/dir/x.key"); err == nil {
		t.Fatal("writeKey into a nonexistent dir must error")
	}
}

// shortKS returns key material of an invalid length for AES.
type shortKS struct{}

func (shortKS) Key(context.Context, string) ([]byte, error) { return []byte("tiny"), nil }
func (shortKS) Ensure(context.Context, string) error        { return nil }

func TestPIIBoxRejectsBadKeyMaterial(t *testing.T) {
	ctx := context.Background()
	box := NewPIIBox(NewLocalEngine(shortKS{}))
	if _, err := box.Encrypt(ctx, "CID-A", "v1", map[string]string{"a": "b"}); err == nil {
		t.Fatal("encrypt with a 4-byte KEK must error")
	}
	if _, err := box.Decrypt(ctx, "CID-A", []byte("blob"), "v1", AlgAES256GCM); err == nil {
		t.Fatal("decrypt with a 4-byte KEK must error")
	}
	good := NewPIIBox(fileKS(t))
	if _, err := good.Decrypt(ctx, "CID-A", []byte("x"), "v1", AlgAES256GCM); err == nil {
		t.Fatal("blob shorter than the nonce must error")
	}
}

func TestEnsureLockedDirect(t *testing.T) {
	dir := t.TempDir()
	ks := &FileKeystore{Dir: dir}
	if err := ks.Ensure(context.Background(), "hmac-email/v1"); err != nil {
		t.Fatal(err)
	}
	// Existing valid key: early return.
	if err := ks.ensureLocked(context.Background(), "hmac-email/v1"); err != nil {
		t.Fatal(err)
	}
	// Corrupt (short) key on disk: regenerated.
	p := dir + "/hmac-email_v1.key"
	if err := os.WriteFile(p, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ks.ensureLocked(context.Background(), "hmac-email/v1"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil || len(b) != 32 {
		t.Fatalf("regenerated key: %d bytes, %v", len(b), err)
	}
}

func TestVaultErrorBranches(t *testing.T) {
	ctx := context.Background()
	// Server erroring 500 on writes: Ensure must surface the status.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.WriteHeader(404)
			return
		}
		w.WriteHeader(500)
	}))
	defer srv.Close()
	v := &VaultKeystore{Addr: srv.URL, Token: "t", HTTP: srv.Client()}
	if err := v.Ensure(ctx, "hmac-email/v1"); err == nil {
		t.Fatal("500 on vault write must error")
	}
	if err := v.Ensure(ctx, "BAD NAME"); err == nil {
		t.Fatal("invalid name must be rejected before any request")
	}
	if _, err := v.Key(ctx, "BAD NAME"); err == nil {
		t.Fatal("invalid name must be rejected on read too")
	}
	// Write accepted but the re-read still 404s: fail loudly.
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.WriteHeader(404)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv2.Close()
	v2 := &VaultKeystore{Addr: srv2.URL, Token: "t", HTTP: srv2.Client()}
	if err := v2.Ensure(ctx, "hmac-email/v1"); err == nil {
		t.Fatal("write-then-vanish must error")
	}
	// Unreachable vault.
	v3 := &VaultKeystore{Addr: "http://127.0.0.1:1", Token: "t"}
	if _, err := v3.Key(ctx, "hmac-email/v1"); err == nil {
		t.Fatal("unreachable vault must error on read")
	}
	if err := v3.Ensure(ctx, "hmac-email/v1"); err == nil {
		t.Fatal("unreachable vault must error on ensure")
	}
}
