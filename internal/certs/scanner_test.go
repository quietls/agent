package certs

import (
	"fmt"
	"io/fs"
	"os"
	"testing"
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

func TestScanCerts(t *testing.T) {
	exe := newMockExecutor()

	exe.commands["openssl x509 -enddate -noout -in /etc/ssl/certs/example.com.pem"] = struct {
		stdout string
		stderr string
		err    error
	}{"notAfter=Jun 25 12:00:00 2026 GMT\n", "", nil}
	exe.commands["openssl x509 -subject -noout -in /etc/ssl/certs/example.com.pem"] = struct {
		stdout string
		stderr string
		err    error
	}{"subject=CN = example.com\n", "", nil}

	exe.commands["openssl x509 -enddate -noout -in /etc/nginx/ssl/test.org.crt"] = struct {
		stdout string
		stderr string
		err    error
	}{"notAfter=Sep 15 00:00:00 2026 GMT\n", "", nil}
	exe.commands["openssl x509 -subject -noout -in /etc/nginx/ssl/test.org.crt"] = struct {
		stdout string
		stderr string
		err    error
	}{"subject=CN = test.org\n", "", nil}

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
	if certs[0].Expires != "Jun 25 12:00:00 2026 GMT" {
		t.Errorf("unexpected expires: '%s'", certs[0].Expires)
	}
	if certs[0].Path != "/etc/ssl/certs/example.com.pem" {
		t.Errorf("unexpected path: '%s'", certs[0].Path)
	}

	if certs[1].Domain != "test.org" {
		t.Errorf("expected domain 'test.org', got '%s'", certs[1].Domain)
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

	exe.commands["openssl x509 -enddate -noout -in /etc/ssl/certs/example.com.pem"] = struct {
		stdout string
		stderr string
		err    error
	}{"notAfter=Jun 25 12:00:00 2026 GMT\n", "", nil}
	exe.commands["openssl x509 -subject -noout -in /etc/ssl/certs/example.com.pem"] = struct {
		stdout string
		stderr string
		err    error
	}{"subject=CN = example.com\n", "", nil}

	certPaths := []string{
		"/etc/ssl/certs/example.com.pem",
		"/etc/ssl/certs/example.com.pem",
	}

	certs := ScanCerts(exe, certPaths)

	if len(certs) != 1 {
		t.Fatalf("expected 1 cert (deduplicated), got %d", len(certs))
	}
}

func TestScanCerts_OpensslFailure(t *testing.T) {
	exe := newMockExecutor()
	// No openssl commands configured — both will fail

	certPaths := []string{"/etc/ssl/certs/example.com.pem"}
	certs := ScanCerts(exe, certPaths)

	if len(certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(certs))
	}
	if certs[0].Expires != "" {
		t.Errorf("expected empty expires on openssl failure, got '%s'", certs[0].Expires)
	}
	if certs[0].Domain != "" {
		t.Errorf("expected empty domain on openssl failure, got '%s'", certs[0].Domain)
	}
}

func TestParseNotAfter(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"notAfter=Jun 25 12:00:00 2026 GMT", "Jun 25 12:00:00 2026 GMT"},
		{"notAfter=Sep  1 00:00:00 2025 GMT\n", "Sep  1 00:00:00 2025 GMT"},
		{"no match", ""},
	}

	for _, tt := range tests {
		got := parseNotAfter(tt.input)
		if got != tt.expected {
			t.Errorf("parseNotAfter(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestParseSubjectCN(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"subject=CN = example.com", "example.com"},
		{"subject= /CN=test.org/O=Test", "test.org"},
		{"subject=CN=wildcard.example.com", "wildcard.example.com"},
		{"subject=O=Test Org", ""},
		{"", ""},
	}

	for _, tt := range tests {
		got := parseSubjectCN(tt.input)
		if got != tt.expected {
			t.Errorf("parseSubjectCN(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}
