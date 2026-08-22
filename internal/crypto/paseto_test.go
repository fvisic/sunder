package crypto

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

// Official PASETO test vector 4-S-1 (github.com/paseto-standard/test-vectors):
// proves the PAE encoding and signing layout match the standard exactly.
func TestPasetoOfficialVector4S1(t *testing.T) {
	seed, _ := hex.DecodeString("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a3774")
	sk := ed25519.NewKeyFromSeed(seed)
	payload := []byte(`{"data":"this is a signed message","exp":"2022-01-01T00:00:00+00:00"}`)
	want := "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9bg_XBBzds8lTZShVlwwKSgeKpLT3yukTw6JUz3W4h_ExsQV-P0V54zemZDcAxFaSeef1QlXEFtkqxT1ciiQEDA"

	if got := PasetoSign(sk, payload); got != want {
		t.Fatalf("sign mismatch with official vector:\n got %s\nwant %s", got, want)
	}
	pk := sk.Public().(ed25519.PublicKey)
	out, err := PasetoVerify(pk, want)
	if err != nil || string(out) != string(payload) {
		t.Fatalf("verify of official vector failed: %v %q", err, out)
	}
}

func TestPasetoTamperAndWrongKey(t *testing.T) {
	seed := make([]byte, 32)
	sk := ed25519.NewKeyFromSeed(seed)
	pk := sk.Public().(ed25519.PublicKey)
	token := PasetoSign(sk, []byte(`{"cid":"CID-X"}`))

	// Flip one character of the body.
	broken := token[:len(token)-2] + "AA"
	if _, err := PasetoVerify(pk, broken); err == nil {
		t.Fatal("tampered token verified")
	}
	// Wrong key.
	other := ed25519.NewKeyFromSeed(append(make([]byte, 31), 1)).Public().(ed25519.PublicKey)
	if _, err := PasetoVerify(other, token); err == nil {
		t.Fatal("token verified under wrong key")
	}
	// Wrong header / garbage.
	for _, bad := range []string{"v2.public.abc", "v4.public.!!!!", "v4.public.", "v4.public.abc.Zm9vdGVy"} {
		if _, err := PasetoVerify(pk, bad); err == nil {
			t.Fatalf("malformed token %q verified", bad)
		}
	}
}

func TestEd25519FromSeedValidation(t *testing.T) {
	if _, _, err := Ed25519FromSeed(make([]byte, 16)); err == nil {
		t.Fatal("short seed accepted")
	}
	sk, pk, err := Ed25519FromSeed(make([]byte, 32))
	if err != nil || sk == nil || pk == nil {
		t.Fatal(err)
	}
}
