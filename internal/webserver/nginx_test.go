package webserver

import (
	"fmt"
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

// setupNginxMock creates a mock executor with nginx binary detection and
// a nginx.conf that includes vhost files via sites-enabled/conf.d.
func setupNginxMock() *mockExecutor {
	exe := newMockExecutor()
	exe.commands["nginx -v"] = struct {
		stdout string
		stderr string
		err    error
	}{"", "nginx version: nginx/1.24.0\n", nil}
	exe.commands["nginx -V"] = struct {
		stdout string
		stderr string
		err    error
	}{"", "configure arguments: --conf-path=/etc/nginx/nginx.conf\n", nil}

	// Main nginx.conf that includes sites-enabled and conf.d
	exe.files["/etc/nginx/nginx.conf"] = []byte(`
worker_processes 1;
http {
    include /etc/nginx/mime.types;
    include /etc/nginx/sites-enabled/*;
    include /etc/nginx/conf.d/*.conf;
}
`)

	// mime.types needed by crossplane include resolution
	exe.files["/etc/nginx/mime.types"] = []byte(`types { text/html html; }`)

	return exe
}

// ── Basic detection tests ──────────────────────────────────────────

func TestDetectNginx(t *testing.T) {
	exe := setupNginxMock()

	info := DetectNginx(exe)

	if info == nil {
		t.Fatal("expected nginx to be detected")
	}
	if info.Type != "nginx" {
		t.Errorf("expected type 'nginx', got '%s'", info.Type)
	}
	if info.Version != "1.24.0" {
		t.Errorf("expected version '1.24.0', got '%s'", info.Version)
	}
}

func TestDetectNginx_ConfigPathFromOverride(t *testing.T) {
	exe := newMockExecutor()
	exe.commands["nginx -v"] = struct {
		stdout string
		stderr string
		err    error
	}{"", "nginx version: nginx/1.24.0\n", nil}
	exe.commands["nginx -V"] = struct {
		stdout string
		stderr string
		err    error
	}{"", "nginx version: nginx/1.24.0 --conf-path=/etc/nginx/nginx.conf", nil}
	exe.files["/custom/nginx.conf"] = []byte(`http { server { listen 80; } }`)

	info := DetectNginxWithOptions(exe, DetectOptions{
		ConfigPathOverride: "/custom/nginx.conf",
	})
	if info == nil {
		t.Fatal("expected nginx to be detected")
	}
	if info.ConfigPath != "/custom/nginx.conf" {
		t.Fatalf("expected config path from override, got %q", info.ConfigPath)
	}
	if info.ConfigSource != "config_override" {
		t.Fatalf("expected config source config_override, got %q", info.ConfigSource)
	}
}

func TestDetectNginx_ConfigPathFromNginxV(t *testing.T) {
	exe := newMockExecutor()
	exe.commands["nginx -v"] = struct {
		stdout string
		stderr string
		err    error
	}{"", "nginx version: nginx/1.24.0\n", nil}
	exe.commands["nginx -V"] = struct {
		stdout string
		stderr string
		err    error
	}{"", "configure arguments: --conf-path=/usr/local/openresty/nginx/conf/nginx.conf", nil}
	exe.files["/usr/local/openresty/nginx/conf/nginx.conf"] = []byte(`http { }`)

	info := DetectNginx(exe)
	if info == nil {
		t.Fatal("expected nginx to be detected")
	}
	if info.ConfigPath != "/usr/local/openresty/nginx/conf/nginx.conf" {
		t.Fatalf("expected config path from nginx -V, got %q", info.ConfigPath)
	}
	if info.ConfigSource != "nginx_v" {
		t.Fatalf("expected config source nginx_v, got %q", info.ConfigSource)
	}
}

func TestDetectNginx_ConfigPathFromFallbackPaths(t *testing.T) {
	exe := newMockExecutor()
	exe.commands["nginx -v"] = struct {
		stdout string
		stderr string
		err    error
	}{"", "nginx version: nginx/1.24.0\n", nil}
	exe.existsFiles["/etc/tengine/nginx.conf"] = true
	exe.files["/etc/tengine/nginx.conf"] = []byte(`http { }`)

	info := DetectNginx(exe)
	if info == nil {
		t.Fatal("expected nginx to be detected")
	}
	if info.ConfigPath != "/etc/tengine/nginx.conf" {
		t.Fatalf("expected fallback config path, got %q", info.ConfigPath)
	}
	if info.ConfigSource != "standard_paths" {
		t.Fatalf("expected config source standard_paths, got %q", info.ConfigSource)
	}
}

func TestDetectNginx_NotInstalled(t *testing.T) {
	exe := newMockExecutor()
	info := DetectNginx(exe)
	if info != nil {
		t.Error("expected nil when nginx is not installed")
	}
}

// ── Crossplane-based vhost detection tests ──────────────────────────

func TestDetectNginx_WithVhosts(t *testing.T) {
	exe := setupNginxMock()

	exe.dirs["/etc/nginx/sites-enabled"] = []os.DirEntry{
		mockDirEntry{name: "example.com"},
	}
	exe.dirs["/etc/nginx/conf.d"] = []os.DirEntry{}

	exe.files["/etc/nginx/sites-enabled/example.com"] = []byte(`server {
    listen 443 ssl;
    server_name example.com www.example.com;
    ssl_certificate /etc/ssl/certs/example.com.pem;
    ssl_certificate_key /etc/ssl/private/example.com.key;
}
`)

	info := DetectNginx(exe)

	if info == nil {
		t.Fatal("expected nginx to be detected")
	}
	if len(info.Vhosts) != 1 {
		t.Fatalf("expected 1 vhost, got %d", len(info.Vhosts))
	}
	vhost := info.Vhosts[0]
	if vhost.ServerName != "example.com" {
		t.Errorf("expected server_name 'example.com', got '%s'", vhost.ServerName)
	}
	if len(vhost.ServerNames) != 2 {
		t.Errorf("expected 2 server_names, got %d", len(vhost.ServerNames))
	}
	if !vhost.SSLEnabled {
		t.Error("expected SSL to be enabled")
	}
	if vhost.CertPath != "/etc/ssl/certs/example.com.pem" {
		t.Errorf("expected cert path '/etc/ssl/certs/example.com.pem', got '%s'", vhost.CertPath)
	}
	if vhost.CertKeyPath != "/etc/ssl/private/example.com.key" {
		t.Errorf("expected cert key path '/etc/ssl/private/example.com.key', got '%s'", vhost.CertKeyPath)
	}
}

func TestDetectNginx_SkipsUnderscore(t *testing.T) {
	exe := setupNginxMock()

	exe.dirs["/etc/nginx/sites-enabled"] = []os.DirEntry{
		mockDirEntry{name: "default"},
	}

	exe.files["/etc/nginx/sites-enabled/default"] = []byte(`server {
    listen 80 default_server;
    server_name _;
}
`)

	info := DetectNginx(exe)

	if len(info.Vhosts) != 0 {
		t.Errorf("expected 0 vhosts (underscore skipped), got %d", len(info.Vhosts))
	}
}

func TestDetectNginx_MultiNameServerName(t *testing.T) {
	exe := setupNginxMock()

	exe.dirs["/etc/nginx/sites-enabled"] = []os.DirEntry{
		mockDirEntry{name: "multi.conf"},
	}

	exe.files["/etc/nginx/sites-enabled/multi.conf"] = []byte(`server {
    listen 443 ssl;
    server_name a.com b.com c.com;
    ssl_certificate /etc/ssl/a.com.pem;
}
`)

	info := DetectNginx(exe)

	if len(info.Vhosts) != 1 {
		t.Fatalf("expected 1 vhost, got %d", len(info.Vhosts))
	}
	vhost := info.Vhosts[0]
	if len(vhost.ServerNames) != 3 {
		t.Errorf("expected 3 server_names, got %d: %v", len(vhost.ServerNames), vhost.ServerNames)
	}
	if vhost.ServerName != "a.com" {
		t.Errorf("expected primary name 'a.com', got '%s'", vhost.ServerName)
	}
}

func TestDetectNginx_SSLDetectedFromCertPresence(t *testing.T) {
	exe := setupNginxMock()

	exe.dirs["/etc/nginx/conf.d"] = []os.DirEntry{
		mockDirEntry{name: "app.conf"},
	}

	exe.files["/etc/nginx/conf.d/app.conf"] = []byte(`server {
    listen 80;
    server_name app.example.com;
    ssl_certificate /etc/ssl/app.pem;
}
`)

	info := DetectNginx(exe)

	if len(info.Vhosts) != 1 {
		t.Fatalf("expected 1 vhost, got %d", len(info.Vhosts))
	}
	if !info.Vhosts[0].SSLEnabled {
		t.Error("expected SSL to be enabled from ssl_certificate presence alone")
	}
}

func TestDetectNginx_NonStandardSSLPort(t *testing.T) {
	exe := setupNginxMock()

	exe.dirs["/etc/nginx/conf.d"] = []os.DirEntry{
		mockDirEntry{name: "custom.conf"},
	}

	exe.files["/etc/nginx/conf.d/custom.conf"] = []byte(`server {
    listen 8443 ssl;
    server_name custom.example.com;
    ssl_certificate /etc/ssl/custom.pem;
}
`)

	info := DetectNginx(exe)

	if len(info.Vhosts) != 1 {
		t.Fatalf("expected 1 vhost, got %d", len(info.Vhosts))
	}
	if !info.Vhosts[0].SSLEnabled {
		t.Error("expected SSL to be enabled on non-standard port")
	}
}

func TestDetectNginx_HTTPSToHTTPSRedirect(t *testing.T) {
	exe := setupNginxMock()

	exe.dirs["/etc/nginx/conf.d"] = []os.DirEntry{
		mockDirEntry{name: "redirect.conf"},
	}

	exe.files["/etc/nginx/conf.d/redirect.conf"] = []byte(`server {
    listen 80;
    server_name redirect.example.com;
    return 301 https://redirect.example.com$request_uri;
}
`)

	info := DetectNginx(exe)

	if len(info.Vhosts) != 1 {
		t.Fatalf("expected 1 vhost, got %d", len(info.Vhosts))
	}
	if !info.Vhosts[0].RedirectToHTTPS {
		t.Error("expected RedirectToHTTPS to be true")
	}
}

func TestDetectNginx_CommentedServerBlock(t *testing.T) {
	exe := setupNginxMock()

	exe.dirs["/etc/nginx/conf.d"] = []os.DirEntry{
		mockDirEntry{name: "commented.conf"},
	}

	// Crossplane properly ignores commented-out server blocks
	exe.files["/etc/nginx/conf.d/commented.conf"] = []byte(`# server {
#     listen 443 ssl;
#     server_name commented.com;
#     ssl_certificate /etc/ssl/commented.pem;
# }
server {
    listen 80;
    server_name active.com;
}
`)

	info := DetectNginx(exe)

	if len(info.Vhosts) != 1 {
		t.Fatalf("expected 1 vhost (commented block ignored), got %d", len(info.Vhosts))
	}
	if info.Vhosts[0].ServerName != "active.com" {
		t.Errorf("expected 'active.com', got '%s'", info.Vhosts[0].ServerName)
	}
}

func TestDetectNginx_DefaultServer(t *testing.T) {
	exe := setupNginxMock()

	exe.dirs["/etc/nginx/conf.d"] = []os.DirEntry{
		mockDirEntry{name: "default.conf"},
	}

	exe.files["/etc/nginx/conf.d/default.conf"] = []byte(`server {
    listen 80 default_server;
    server_name default.example.com;
}
`)

	info := DetectNginx(exe)

	if len(info.Vhosts) != 1 {
		t.Fatalf("expected 1 vhost, got %d", len(info.Vhosts))
	}
	if !info.Vhosts[0].IsDefault {
		t.Error("expected IsDefault to be true")
	}
}

func TestDetectNginx_ServerBlockInMainConf(t *testing.T) {
	exe := newMockExecutor()
	exe.commands["nginx -v"] = struct {
		stdout string
		stderr string
		err    error
	}{"", "nginx version: nginx/1.24.0\n", nil}
	exe.commands["nginx -V"] = struct {
		stdout string
		stderr string
		err    error
	}{"", "configure arguments: --conf-path=/etc/nginx/nginx.conf\n", nil}

	// Server block directly in nginx.conf (not via include)
	exe.files["/etc/nginx/nginx.conf"] = []byte(`
worker_processes 1;
http {
    server {
        listen 443 ssl;
        server_name inline.example.com;
        ssl_certificate /etc/ssl/inline.pem;
    }
}
`)

	info := DetectNginx(exe)

	if len(info.Vhosts) != 1 {
		t.Fatalf("expected 1 vhost from inline server block, got %d", len(info.Vhosts))
	}
	if info.Vhosts[0].ServerName != "inline.example.com" {
		t.Errorf("expected 'inline.example.com', got '%s'", info.Vhosts[0].ServerName)
	}
}

func TestDetectNginx_IncludeDirectiveExpansion(t *testing.T) {
	exe := newMockExecutor()
	exe.commands["nginx -v"] = struct {
		stdout string
		stderr string
		err    error
	}{"", "nginx version: nginx/1.24.0\n", nil}
	exe.commands["nginx -V"] = struct {
		stdout string
		stderr string
		err    error
	}{"", "configure arguments: --conf-path=/etc/nginx/nginx.conf\n", nil}

	// nginx.conf includes a custom vhost directory
	exe.files["/etc/nginx/nginx.conf"] = []byte(`
http {
    include /etc/nginx/vhosts.d/*.conf;
}
`)

	exe.dirs["/etc/nginx/vhosts.d"] = []os.DirEntry{
		mockDirEntry{name: "custom-vhost.conf"},
	}

	exe.files["/etc/nginx/vhosts.d/custom-vhost.conf"] = []byte(`server {
    listen 443 ssl;
    server_name custom-vhost.example.com;
    ssl_certificate /etc/ssl/custom-vhost.pem;
}
`)

	info := DetectNginx(exe)

	if len(info.Vhosts) != 1 {
		t.Fatalf("expected 1 vhost from custom include path, got %d", len(info.Vhosts))
	}
	if info.Vhosts[0].ServerName != "custom-vhost.example.com" {
		t.Errorf("expected 'custom-vhost.example.com', got '%s'", info.Vhosts[0].ServerName)
	}
}

func TestDetectNginx_ListenPorts(t *testing.T) {
	exe := setupNginxMock()

	exe.dirs["/etc/nginx/conf.d"] = []os.DirEntry{
		mockDirEntry{name: "multiport.conf"},
	}

	exe.files["/etc/nginx/conf.d/multiport.conf"] = []byte(`server {
    listen 80;
    listen 443 ssl;
    server_name multiport.example.com;
    ssl_certificate /etc/ssl/multiport.pem;
}
`)

	info := DetectNginx(exe)

	if len(info.Vhosts) != 1 {
		t.Fatalf("expected 1 vhost, got %d", len(info.Vhosts))
	}
	vhost := info.Vhosts[0]
	if len(vhost.ListenPorts) != 2 {
		t.Errorf("expected 2 listen ports, got %d: %v", len(vhost.ListenPorts), vhost.ListenPorts)
	}
	found80, found443 := false, false
	for _, p := range vhost.ListenPorts {
		if p == 80 {
			found80 = true
		}
		if p == 443 {
			found443 = true
		}
	}
	if !found80 || !found443 {
		t.Errorf("expected ports 80 and 443, got %v", vhost.ListenPorts)
	}
}

// ── Legacy regex tests (fallback path) ──────────────────────────────

func TestExtractServerBlocks(t *testing.T) {
	config := `
http {
    server {
        listen 80;
        server_name a.com;
    }
    server {
        listen 443 ssl;
        server_name b.com;
    }
}
`
	blocks := extractServerBlocks(config)
	if len(blocks) != 2 {
		t.Errorf("expected 2 server blocks, got %d", len(blocks))
	}
}
