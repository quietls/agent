package commands

import (
	"strings"
	"testing"
)

func TestHandleMetricTlsDrift_MissingDomain(t *testing.T) {
	handler := GetHandler("metric.tls-drift")
	result := handler(HandlerContext{
		Parameters: map[string]any{},
		Executor:   newMockExecutor(),
	})
	if result.Status != "failure" {
		t.Errorf("expected failure, got %s", result.Status)
	}
	if result.Error != "domain parameter is required" {
		t.Errorf("expected domain required error, got %s", result.Error)
	}
}

func TestHandleMetricTlsDrift_NoWebServer(t *testing.T) {
	exe := newMockExecutor()
	// No nginx or apache commands set up — DetectWebServer returns nil

	handler := GetHandler("metric.tls-drift")
	result := handler(HandlerContext{
		Parameters: map[string]any{"domain": "example.com"},
		Executor:   exe,
	})
	if result.Status != "failure" {
		t.Errorf("expected failure, got %s", result.Status)
	}
	if result.Error != "no web server detected" {
		t.Errorf("expected 'no web server detected', got %s", result.Error)
	}
}

func TestComputeConfigHash(t *testing.T) {
	nginxConfig := `server {
		server_name example.com;
		listen 443 ssl;
		ssl_certificate /etc/ssl/cert.pem;
	}`

	// Same content should produce same hash
	hash1 := computeConfigHash(nginxConfig, "example.com", "nginx")
	hash2 := computeConfigHash(nginxConfig, "example.com", "nginx")
	if hash1 != hash2 {
		t.Error("same config should produce same hash")
	}

	// Different content should produce different hash
	differentConfig := `server {
		server_name example.com;
		listen 443 ssl;
		ssl_certificate /etc/ssl/new-cert.pem;
	}`
	hash3 := computeConfigHash(differentConfig, "example.com", "nginx")
	if hash1 == hash3 {
		t.Error("different configs should produce different hashes")
	}

	// Hash should start with sha256:
	if !strings.HasPrefix(hash1, "sha256:") {
		t.Errorf("hash should start with 'sha256:', got %s", hash1)
	}
}

func TestExtractNginxServerBlock(t *testing.T) {
	config := `http {
		server {
			server_name other.com;
			listen 80;
		}
		server {
			server_name example.com;
			listen 443 ssl;
			ssl_certificate /etc/ssl/cert.pem;
		}
	}`

	block := extractNginxServerBlock(config, "example.com")
	if !strings.Contains(block, "example.com") {
		t.Error("expected block to contain 'example.com'")
	}
	if !strings.Contains(block, "ssl_certificate") {
		t.Error("expected block to contain ssl_certificate directive")
	}
	if strings.Contains(block, "other.com") {
		t.Error("expected block to NOT contain other.com")
	}
}

func TestExtractNginxServerBlock_NotFound(t *testing.T) {
	config := `server {
		server_name other.com;
		listen 80;
	}`

	block := extractNginxServerBlock(config, "missing.com")
	if block != "" {
		t.Errorf("expected empty block for missing domain, got %s", block)
	}
}

// Regression: querying "example.com" must not match a block whose server_name
// is "foo.example.com" (substring containment used to false-match).
func TestExtractNginxServerBlock_NoSubstringFalseMatch(t *testing.T) {
	config := `http {
		server {
			server_name foo.example.com;
			listen 443 ssl;
			ssl_certificate /etc/ssl/foo.pem;
		}
		server {
			server_name example.com www.example.com;
			listen 443 ssl;
			ssl_certificate /etc/ssl/root.pem;
		}
	}`

	block := extractNginxServerBlock(config, "example.com")
	if !strings.Contains(block, "/etc/ssl/root.pem") {
		t.Errorf("expected root block; got %q", block)
	}
	if strings.Contains(block, "/etc/ssl/foo.pem") {
		t.Error("should not have matched the foo.example.com block")
	}
}

func TestExtractNginxServerBlock_ServerAliasOnMultipleNames(t *testing.T) {
	config := `server {
		server_name alpha.com beta.com gamma.com;
		listen 443 ssl;
	}`

	for _, domain := range []string{"alpha.com", "beta.com", "gamma.com"} {
		if block := extractNginxServerBlock(config, domain); block == "" {
			t.Errorf("expected to match %s in multi-name server_name", domain)
		}
	}

	if block := extractNginxServerBlock(config, "delta.com"); block != "" {
		t.Errorf("expected no match for delta.com, got %s", block)
	}
}

func TestExtractApacheVhostBlock(t *testing.T) {
	config := `<VirtualHost *:443>
		ServerName example.com
		DocumentRoot /var/www/html
		SSLEngine on
	</VirtualHost>
	<VirtualHost *:80>
		ServerName other.com
		DocumentRoot /var/www/html
	</VirtualHost>`

	block := extractApacheVhostBlock(config, "example.com")
	if !strings.Contains(block, "example.com") {
		t.Error("expected block to contain 'example.com'")
	}
	if strings.Contains(block, "other.com") {
		t.Error("expected block to NOT contain other.com")
	}
}

func TestNormalizeBlock(t *testing.T) {
	input := `  server {
	    listen 443;

	    server_name example.com;
	}`
	normalized := normalizeBlock(input)

	// Should have no leading/trailing whitespace on lines
	if strings.Contains(normalized, "  ") {
		t.Error("normalized block should not contain double spaces")
	}
	// Should have no blank lines
	if strings.Contains(normalized, "\n\n") {
		t.Error("normalized block should not contain blank lines")
	}
	// Whitespace variations should produce same output
	input2 := "server {\n  listen 443;\n\n  server_name example.com;\n}\n"
	normalized2 := normalizeBlock(input2)
	if normalized != normalized2 {
		t.Errorf("whitespace variations should produce same normalized output:\n%s\nvs\n%s", normalized, normalized2)
	}
}