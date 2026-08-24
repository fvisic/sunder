package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fvisic/sunder/internal/config"
	"github.com/fvisic/sunder/internal/testutil"
)

// selfSigned writes a throwaway cert/key pair for 127.0.0.1.
func selfSigned(t *testing.T, dir string) (certPath, keyPath string, pool *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sunder-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		t.Fatal(err)
	}
	pool = x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	return certPath, keyPath, pool
}

// freeAddr reserves a loopback port for the server under test.
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func TestRunServesTLS13(t *testing.T) {
	cert, key, pool := selfSigned(t, t.TempDir())
	addr := freeAddr(t)
	s := mustNew(t, config.Config{Listen: addr, TLSCert: cert, TLSKey: key})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}, Timeout: 5 * time.Second}
	var lastErr error
	for i := 0; i < 50; i++ {
		resp, err := client.Get(fmt.Sprintf("https://%s/healthz", addr))
		if err == nil {
			if resp.TLS.Version < tls.VersionTLS13 {
				t.Fatalf("negotiated TLS %x, want 1.3+", resp.TLS.Version)
			}
			_ = resp.Body.Close()
			lastErr = nil
			break
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("TLS request never succeeded: %v", lastErr)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("graceful TLS shutdown: %v", err)
	}
}

func TestRunMTLSRefusesClientsWithoutCert(t *testing.T) {
	dir := t.TempDir()
	cert, key, pool := selfSigned(t, dir)
	addr := freeAddr(t)
	// The server cert doubles as the client CA: any valid client cert would
	// need to chain to it; presenting none must be refused at the handshake.
	s := mustNew(t, config.Config{Listen: addr, TLSCert: cert, TLSKey: key, MTLSCA: cert})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}, Timeout: 5 * time.Second}
	reached := false
	// The port must actually be listening, or "every request failed" would
	// pass vacuously.
	var bound bool
	for i := 0; i < 50; i++ {
		if c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond); err == nil {
			_ = c.Close()
			bound = true
			break
		}
		select {
		case err := <-done:
			t.Fatalf("server exited instead of listening: %v", err)
		default:
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !bound {
		t.Fatal("mTLS server never bound its port")
	}

	var lastErr error
	for i := 0; i < 50; i++ {
		_, err := client.Get(fmt.Sprintf("https://%s/healthz", addr))
		if err == nil {
			reached = true
			break
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	if reached {
		t.Fatal("request without a client certificate must be refused under mTLS")
	}
	if lastErr == nil {
		t.Fatal("expected handshake errors")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("graceful shutdown after mTLS refusals: %v", err)
	}
}

// The portal on its own listener: the API can keep mTLS while citizens
// reach the portal without a client certificate.
func TestRunPortalOnSeparateListener(t *testing.T) {
	st := testutil.NewDB(t)
	apiAddr := freeAddr(t)
	portalAddr := freeAddr(t)
	// The portal is only constructed when the server has a store.
	s, err := New(config.Config{
		Listen: apiAddr, Keystore: "file", KeystorePath: t.TempDir(),
		PortalEnabled: true, PortalListen: portalAddr,
	}, st)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	deadline := time.Now().Add(10 * time.Second)
	for {
		if c, err := net.DialTimeout("tcp", portalAddr, 100*time.Millisecond); err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the portal listener never came up")
		}
		select {
		case err := <-done:
			t.Fatalf("server exited: %v", err)
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	// The portal answers on its own port...
	res, err := http.Get("http://" + portalAddr + "/portal/")
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("portal on its own listener: %d", res.StatusCode)
	}
	// ...and NOT on the API one.
	res, err = http.Get("http://" + apiAddr + "/portal/")
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != 404 {
		t.Fatalf("the portal must not double-mount on the API listener: %d", res.StatusCode)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("both listeners must shut down cleanly: %v", err)
	}
}
