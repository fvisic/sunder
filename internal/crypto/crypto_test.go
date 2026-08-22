package crypto

import (
	"context"
	"strings"
	"testing"
)

// autoKS wraps FileKeystore to create keys on demand — ONLY for tests; the
// production keystore is strict and keys are created at bootstrap.
type autoKS struct{ inner *FileKeystore }

func (a *autoKS) Key(ctx context.Context, name string) ([]byte, error) {
	if err := a.inner.Ensure(ctx, name); err != nil {
		return nil, err
	}
	return a.inner.Key(ctx, name)
}
func (a *autoKS) Ensure(ctx context.Context, name string) error { return a.inner.Ensure(ctx, name) }

func fileKS(t *testing.T) Keystore { return &autoKS{inner: &FileKeystore{Dir: t.TempDir()}} }

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
		t.Fatal("email and name keys produce identical tokens — keys not separated")
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
	blob, keyID, err := box.Encrypt(ctx, "CID-A", attrs)
	if err != nil {
		t.Fatal(err)
	}
	got, err := box.Decrypt(ctx, "CID-A", blob, keyID)
	if err != nil || got["email"] != attrs["email"] {
		t.Fatalf("roundtrip failed: %v %v", got, err)
	}
	// Transplant: the same ciphertext moved under another CID must fail
	// authentication (AAD binding).
	if _, err := box.Decrypt(ctx, "CID-B", blob, keyID); err == nil {
		t.Fatal("blob transplanted to another CID decrypted without error")
	}
	blob[len(blob)-1] ^= 0xFF
	if _, err := box.Decrypt(ctx, "CID-A", blob, keyID); err == nil {
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
