package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/fvisic/sunder/internal/crypto"
)

// fakeKS is a recoveryKeystore that can inject a failure at any step.
type fakeKS struct {
	keys        []crypto.KeyEntry
	bundle      []byte
	failAll     bool
	failWrite   bool
	failRead    bool
	failRestore bool
}

func (f *fakeKS) AllKeys() ([]crypto.KeyEntry, error) {
	if f.failAll {
		return nil, errors.New("allkeys boom")
	}
	return f.keys, nil
}
func (f *fakeKS) WriteRecoveryBundle(b []byte) error {
	if f.failWrite {
		return errors.New("write boom")
	}
	f.bundle = append([]byte(nil), b...)
	return nil
}
func (f *fakeKS) ReadRecoveryBundle() ([]byte, error) {
	if f.failRead {
		return nil, errors.New("read boom")
	}
	return f.bundle, nil
}
func (f *fakeKS) RestoreKeys([]crypto.KeyEntry) error {
	if f.failRestore {
		return errors.New("restore boom")
	}
	return nil
}

func goodKeys() []crypto.KeyEntry {
	return []crypto.KeyEntry{{Name: "pii-kek_v1", Key: bytes.Repeat([]byte{1}, 32)}}
}

func TestShamirInitBranches(t *testing.T) {
	// Happy path: prints n shares.
	f := &fakeKS{keys: goodKeys()}
	var buf bytes.Buffer
	if err := shamirInit(f, 5, 3, &buf); err != nil {
		t.Fatal(err)
	}
	if strings.Count(buf.String(), "share ") != 5 {
		t.Fatalf("want 5 shares printed:\n%s", buf.String())
	}
	if f.bundle == nil {
		t.Fatal("init must write a bundle")
	}

	// AllKeys failure.
	if err := shamirInit(&fakeKS{failAll: true}, 5, 3, &buf); err == nil {
		t.Fatal("AllKeys error must surface")
	}
	// Bad n/k -> SplitWithChecksum error.
	if err := shamirInit(&fakeKS{keys: goodKeys()}, 2, 5, &buf); err == nil {
		t.Fatal("k>n must error")
	}
	// WriteRecoveryBundle failure.
	if err := shamirInit(&fakeKS{keys: goodKeys(), failWrite: true}, 5, 3, &buf); err == nil {
		t.Fatal("write failure must surface")
	}
	// CSPRNG failure via the randRead seam.
	old := randRead
	randRead = func(b []byte) (int, error) { return 0, errors.New("csprng boom") }
	defer func() { randRead = old }()
	if err := shamirInit(&fakeKS{keys: goodKeys()}, 5, 3, &buf); err == nil {
		t.Fatal("CSPRNG failure must surface")
	}
}

func TestShamirRecoverBranches(t *testing.T) {
	// Build a real bundle + shares to drive the happy path.
	f := &fakeKS{keys: goodKeys()}
	var buf bytes.Buffer
	if err := shamirInit(f, 5, 3, &buf); err != nil {
		t.Fatal(err)
	}
	shares := parseSharesFromOutput(buf.String())
	dec := func(ss []string) [][]byte {
		var out [][]byte
		for _, s := range ss {
			b, _ := hex.DecodeString(s)
			out = append(out, b)
		}
		return out
	}
	// Happy path.
	buf.Reset()
	if err := shamirRecover(f, dec([]string{shares[0], shares[1], shares[2]}), &buf); err != nil {
		t.Fatal(err)
	}
	// Too few shares -> CombineWithChecksum error.
	if err := shamirRecover(f, dec([]string{shares[0], shares[1]}), &buf); err == nil {
		t.Fatal("too few shares must error")
	}
	// ReadRecoveryBundle failure.
	if err := shamirRecover(&fakeKS{failRead: true, bundle: f.bundle}, dec([]string{shares[0], shares[1], shares[2]}), &buf); err == nil {
		t.Fatal("read failure must surface")
	}
	// A garbage bundle -> OpenRecoveryBundle error.
	if err := shamirRecover(&fakeKS{bundle: []byte("not-a-bundle")}, dec([]string{shares[0], shares[1], shares[2]}), &buf); err == nil {
		t.Fatal("corrupt bundle must error")
	}
	// RestoreKeys failure.
	if err := shamirRecover(&fakeKS{bundle: f.bundle, failRestore: true}, dec([]string{shares[0], shares[1], shares[2]}), &buf); err == nil {
		t.Fatal("restore failure must surface")
	}
}

func TestShamirRotateBranches(t *testing.T) {
	f := &fakeKS{keys: goodKeys()}
	var buf bytes.Buffer
	if err := shamirInit(f, 5, 3, &buf); err != nil {
		t.Fatal(err)
	}
	shares := parseSharesFromOutput(buf.String())
	var sb [][]byte
	for _, s := range shares[:3] {
		b, _ := hex.DecodeString(s)
		sb = append(sb, b)
	}
	// Happy path.
	if err := shamirRotate(f, sb, &buf); err != nil {
		t.Fatal(err)
	}
	// Bad shares -> reassembly error.
	if err := shamirRotate(f, [][]byte{{1, 2}, {3, 4}}, &buf); err == nil {
		t.Fatal("bad shares must error")
	}
	// AllKeys failure.
	if err := shamirRotate(&fakeKS{failAll: true}, sb, &buf); err == nil {
		t.Fatal("AllKeys failure must surface")
	}
	// WriteRecoveryBundle failure.
	if err := shamirRotate(&fakeKS{keys: goodKeys(), failWrite: true}, sb, &buf); err == nil {
		t.Fatal("write failure must surface")
	}
}
