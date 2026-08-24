package api

// P2.1 e2e: the full API stack running with SUNDER_SIGNER_SOCKET set, so
// every crypto operation crosses the process boundary to a signer serving
// the keystore. The main-process side holds no key material.

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fvisic/sunder/internal/auth"
	"github.com/fvisic/sunder/internal/config"
	"github.com/fvisic/sunder/internal/crypto"
	"github.com/fvisic/sunder/internal/testutil"
)

func TestFullStackOverSignerSocket(t *testing.T) {
	// Short socket path (macOS caps sun_path at ~104 bytes).
	dir, err := os.MkdirTemp("", "sgn")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s.sock")

	// The signer side: sole keystore holder.
	signerEng := crypto.NewLocalEngine(crypto.NewCachingKeystore(&crypto.FileKeystore{Dir: t.TempDir()}))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = crypto.ServeSigner(ctx, sock, signerEng) }()
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// The main process side: engine over the socket, no keystore configured.
	st := testutil.NewDB(t)
	srv, err := New(config.Config{Listen: ":0", SignerSocket: sock}, st)
	if err != nil {
		t.Fatal(err)
	}

	cred, err := auth.Create(ctx, st.Pool, auth.Client{
		ID: "crm", Name: "CRM", Scope: "crm",
		AllowedActions:  []string{auth.ActContactsRegister, auth.ActLookup, auth.ActAttributesRead, auth.ActOTIIssue},
		AllowedPurposes: []string{"support"}, RateLimit: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	verifierCred, err := auth.Create(ctx, st.Pool, auth.Client{
		ID: "erp", Name: "ERP", Scope: "erp",
		AllowedActions:  []string{auth.ActOTIVerify, auth.ActAttributesRead},
		AllowedPurposes: []string{"support"}, RateLimit: 100,
	})
	if err != nil {
		t.Fatal(err)
	}

	do := func(method, path, cr, body string) (int, string) {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+cr)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	field := func(body, key string) string {
		var m map[string]any
		if err := json.Unmarshal([]byte(body), &m); err != nil {
			t.Fatalf("bad JSON %q: %v", body, err)
		}
		v, _ := m[key].(string)
		if v == "" {
			t.Fatalf("field %q missing in %q", key, body)
		}
		return v
	}

	// Register -> lookup -> attribute read: MAC + Seal + Open remote.
	code, body := do("POST", "/v1/contacts", cred,
		`{"email":"remote@example.com","name":"Remote Case","attributes":{"tier":"gold"}}`)
	if code != 201 || !strings.Contains(body, "CID-") {
		t.Fatalf("register over signer socket: %d %s", code, body)
	}
	cid := field(body, "cid")
	if code, body = do("POST", "/v1/lookup", cred, `{"email":"remote@example.com"}`); code != 200 || !strings.Contains(body, cid) {
		t.Fatalf("lookup over signer socket: %d %s", code, body)
	}
	if code, body = do("GET", "/v1/contacts/"+cid+"/attributes/tier?purpose=support", cred, ""); code != 200 || !strings.Contains(body, "gold") {
		t.Fatalf("attribute read over signer socket: %d %s", code, body)
	}

	// OTI issue + verify: Sign + VerifyToken remote, end to end.
	code, body = do("POST", "/v1/oti", cred, `{"cid":"`+cid+`","purpose":"support","audience":"erp"}`)
	if code != 201 {
		t.Fatalf("oti issue over signer socket: %d %s", code, body)
	}
	tok := field(body, "token")
	code, body = do("POST", "/v1/oti/verify", verifierCred, `{"token":"`+tok+`","purpose":"support","audience":"erp"}`)
	if code != 200 || !strings.Contains(body, "CID-") {
		t.Fatalf("oti verify over signer socket: %d %s", code, body)
	}

	// Kill the signer: everything must fail closed, nothing falls back to
	// local key material.
	cancel()
	// Poll: a pooled connection may still serve one request after the
	// listener closes.
	failed := false
	for i := 0; i < 100; i++ {
		if code, _ = do("POST", "/v1/lookup", cred, `{"email":"remote@example.com"}`); code != 200 {
			failed = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !failed {
		t.Fatal("lookup must fail closed when the signer is gone")
	}
}
