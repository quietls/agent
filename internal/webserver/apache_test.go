package webserver

import (
	"io/fs"
	"os"
	"testing"
)

// mockDirEntry implements os.DirEntry for testing.
type mockDirEntry struct {
	name  string
	isDir bool
}

func (e mockDirEntry) Name() string               { return e.name }
func (e mockDirEntry) IsDir() bool                { return e.isDir }
func (e mockDirEntry) Type() fs.FileMode          { return 0 }
func (e mockDirEntry) Info() (fs.FileInfo, error) { return nil, nil }

func TestDetectApache(t *testing.T) {
	exe := newMockExecutor()
	exe.commands["apache2 -v"] = struct {
		stdout string
		stderr string
		err    error
	}{"Server version: Apache/2.4.52 (Ubuntu)\n", "", nil}

	info := DetectApache(exe)

	if info == nil {
		t.Fatal("expected apache to be detected")
	}
	if info.Type != "apache2" {
		t.Errorf("expected type 'apache2', got '%s'", info.Type)
	}
	if info.Version != "2.4.52" {
		t.Errorf("expected version '2.4.52', got '%s'", info.Version)
	}
}

func TestDetectApache_Httpd(t *testing.T) {
	exe := newMockExecutor()
	exe.commands["httpd -v"] = struct {
		stdout string
		stderr string
		err    error
	}{"Server version: Apache/2.4.57 (CentOS)\n", "", nil}

	info := DetectApache(exe)

	if info == nil {
		t.Fatal("expected apache to be detected via httpd")
	}
	if info.Version != "2.4.57" {
		t.Errorf("expected version '2.4.57', got '%s'", info.Version)
	}
}

func TestDetectApache_NotInstalled(t *testing.T) {
	exe := newMockExecutor()
	info := DetectApache(exe)
	if info != nil {
		t.Error("expected nil when apache is not installed")
	}
}

func TestDetectApache_WithVhosts(t *testing.T) {
	exe := newMockExecutor()
	exe.commands["apache2 -v"] = struct {
		stdout string
		stderr string
		err    error
	}{"Server version: Apache/2.4.52 (Ubuntu)\n", "", nil}

	exe.dirs["/etc/apache2/sites-enabled"] = []os.DirEntry{
		mockDirEntry{name: "example.com.conf"},
	}

	exe.files["/etc/apache2/sites-enabled/example.com.conf"] = []byte(`<VirtualHost *:443>
    ServerName example.com
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/example.com.pem
</VirtualHost>
`)

	info := DetectApache(exe)

	if info == nil {
		t.Fatal("expected apache to be detected")
	}
	if len(info.Vhosts) != 1 {
		t.Fatalf("expected 1 vhost, got %d", len(info.Vhosts))
	}
	if info.Vhosts[0].ServerName != "example.com" {
		t.Errorf("expected server_name 'example.com', got '%s'", info.Vhosts[0].ServerName)
	}
	if !info.Vhosts[0].SSLEnabled {
		t.Error("expected SSL to be enabled")
	}
	if info.Vhosts[0].CertPath != "/etc/ssl/certs/example.com.pem" {
		t.Errorf("expected cert path '/etc/ssl/certs/example.com.pem', got '%s'", info.Vhosts[0].CertPath)
	}
}

func TestDetectWebServer_PrefersNginx(t *testing.T) {
	exe := newMockExecutor()
	exe.commands["nginx -v"] = struct {
		stdout string
		stderr string
		err    error
	}{"", "nginx version: nginx/1.24.0\n", nil}
	exe.commands["apache2 -v"] = struct {
		stdout string
		stderr string
		err    error
	}{"Server version: Apache/2.4.52\n", "", nil}

	info := DetectWebServer(exe)

	if info == nil {
		t.Fatal("expected web server to be detected")
	}
	if info.Type != "nginx" {
		t.Errorf("expected nginx to be preferred, got '%s'", info.Type)
	}
}

func TestDetectWebServer_FallsBackToApache(t *testing.T) {
	exe := newMockExecutor()
	exe.commands["apache2 -v"] = struct {
		stdout string
		stderr string
		err    error
	}{"Server version: Apache/2.4.52\n", "", nil}

	info := DetectWebServer(exe)

	if info == nil {
		t.Fatal("expected apache to be detected as fallback")
	}
	if info.Type != "apache2" {
		t.Errorf("expected apache2, got '%s'", info.Type)
	}
}
