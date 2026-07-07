package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"testing"
	"time"
)

type mockExecutor struct {
	commands map[string]struct {
		stdout string
		stderr string
		err    error
	}
	files       map[string][]byte
	dirs        map[string][]os.DirEntry
	existsFiles map[string]bool
}

func newMockExecutor() *mockExecutor {
	return &mockExecutor{
		commands: make(map[string]struct {
			stdout string
			stderr string
			err    error
		}),
		files:       make(map[string][]byte),
		dirs:        make(map[string][]os.DirEntry),
		existsFiles: make(map[string]bool),
	}
}

func (m *mockExecutor) ExecCommand(name string, args ...string) (string, string, error) {
	key := name
	for _, a := range args {
		key += " " + a
	}
	if r, ok := m.commands[key]; ok {
		return r.stdout, r.stderr, r.err
	}
	return "", "", fmt.Errorf("command not found: %s", key)
}

func (m *mockExecutor) ReadFile(path string) ([]byte, error) {
	if data, ok := m.files[path]; ok {
		return data, nil
	}
	return nil, os.ErrNotExist
}

func (m *mockExecutor) WriteFile(path string, data []byte) error {
	m.files[path] = data
	return nil
}

func (m *mockExecutor) ReadDir(path string) ([]os.DirEntry, error) {
	if entries, ok := m.dirs[path]; ok {
		return entries, nil
	}
	return nil, os.ErrNotExist
}

func (m *mockExecutor) FileExists(path string) bool {
	return m.existsFiles[path]
}

// mockDirEntry implements os.DirEntry for testing.
type mockDirEntry struct {
	name  string
	isDir bool
}

func (e mockDirEntry) Name() string               { return e.name }
func (e mockDirEntry) IsDir() bool                { return e.isDir }
func (e mockDirEntry) Type() fs.FileMode          { return 0 }
func (e mockDirEntry) Info() (fs.FileInfo, error) { return nil, nil }

// makeTestCertPEM builds a self-signed certificate PEM with the given common
// name and expiry, for exercising the in-process x509 parsing.
func makeTestCertPEM(t *testing.T, cn string, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    notAfter.Add(-24 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestScanCerts(t *testing.T) {
	exe := newMockExecutor()

	exp1 := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)
	exp2 := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)
	exe.files["/etc/ssl/certs/example.com.pem"] = makeTestCertPEM(t, "example.com", exp1)
	exe.files["/etc/nginx/ssl/test.org.crt"] = makeTestCertPEM(t, "test.org", exp2)

	certPaths := []string{
		"/etc/ssl/certs/example.com.pem",
		"/etc/nginx/ssl/test.org.crt",
	}

	certs := ScanCerts(exe, certPaths)

	if len(certs) != 2 {
		t.Fatalf("expected 2 certs, got %d", len(certs))
	}

	if certs[0].Domain != "example.com" {
		t.Errorf("expected domain 'example.com', got '%s'", certs[0].Domain)
	}
	if certs[0].Expires != exp1.Format(time.RFC3339) {
		t.Errorf("unexpected expires: '%s' (want %s)", certs[0].Expires, exp1.Format(time.RFC3339))
	}
	if certs[0].Path != "/etc/ssl/certs/example.com.pem" {
		t.Errorf("unexpected path: '%s'", certs[0].Path)
	}

	if certs[1].Domain != "test.org" {
		t.Errorf("expected domain 'test.org', got '%s'", certs[1].Domain)
	}
	if certs[1].Expires != exp2.Format(time.RFC3339) {
		t.Errorf("unexpected expires: '%s' (want %s)", certs[1].Expires, exp2.Format(time.RFC3339))
	}
}

// A fullchain file (leaf + intermediate) should report the leaf's details.
func TestScanCerts_Fullchain(t *testing.T) {
	exe := newMockExecutor()

	leafExp := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)
	interExp := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	fullchain := append(makeTestCertPEM(t, "leaf.example.com", leafExp), makeTestCertPEM(t, "Intermediate CA", interExp)...)
	exe.files["/etc/letsencrypt/live/leaf.example.com/fullchain.pem"] = fullchain

	certs := ScanCerts(exe, []string{"/etc/letsencrypt/live/leaf.example.com/fullchain.pem"})
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(certs))
	}
	if certs[0].Domain != "leaf.example.com" {
		t.Errorf("expected leaf CN 'leaf.example.com', got '%s'", certs[0].Domain)
	}
	if certs[0].Expires != leafExp.Format(time.RFC3339) {
		t.Errorf("expected leaf expiry, got '%s'", certs[0].Expires)
	}
}

func TestScanCerts_EmptyPaths(t *testing.T) {
	exe := newMockExecutor()
	certs := ScanCerts(exe, nil)

	if len(certs) != 0 {
		t.Errorf("expected 0 certs, got %d", len(certs))
	}
}

func TestScanCerts_Deduplication(t *testing.T) {
	exe := newMockExecutor()
	exe.files["/etc/ssl/certs/example.com.pem"] = makeTestCertPEM(t, "example.com", time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC))

	certPaths := []string{
		"/etc/ssl/certs/example.com.pem",
		"/etc/ssl/certs/example.com.pem",
	}

	certs := ScanCerts(exe, certPaths)

	if len(certs) != 1 {
		t.Fatalf("expected 1 cert (deduplicated), got %d", len(certs))
	}
}

// An unreadable or non-PEM file yields an entry with empty fields rather than
// erroring, so callers can still see the path was inspected.
func TestScanCerts_UnreadableFile(t *testing.T) {
	exe := newMockExecutor()

	certPaths := []string{"/etc/ssl/certs/missing.pem"}
	certs := ScanCerts(exe, certPaths)

	if len(certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(certs))
	}
	if certs[0].Expires != "" {
		t.Errorf("expected empty expires for unreadable file, got '%s'", certs[0].Expires)
	}
	if certs[0].Domain != "" {
		t.Errorf("expected empty domain for unreadable file, got '%s'", certs[0].Domain)
	}
}
