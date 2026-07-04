package commands

import (
	"fmt"
	"strings"
	"testing"
)

func TestHandleCertInstall_Nginx(t *testing.T) {
	exe := newMockExecutor()
	exe.commands["mkdir -p /etc/nginx/ssl"] = struct {
		stdout string
		stderr string
		err    error
	}{"", "", nil}
	exe.commands["nginx -t"] = struct {
		stdout string
		stderr string
		err    error
	}{"syntax is ok\n", "", nil}
	exe.commands["nginx -s reload"] = struct {
		stdout string
		stderr string
		err    error
	}{"", "", nil}
	exe.existsFiles["/etc/nginx"] = true

	ctx := HandlerContext{
		Parameters: map[string]any{
			"domain":           "example.com",
			"certificate_pem":  "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAJHGTVDEsZ3tMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnVudXNlZDAe\n-----END CERTIFICATE-----",
			"private_key_pem":  "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJT\n-----END PRIVATE KEY-----",
			"ca_bundle_pem":    "",
			"web_server_type":  "nginx",
		},
		Executor: exe,
	}

	result := handleCertInstall(ctx)

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Error)
	}

	if result.Output["domain"] != "example.com" {
		t.Errorf("expected domain example.com, got %v", result.Output["domain"])
	}

	certPath := result.Output["cert_path"].(string)
	keyPath := result.Output["key_path"].(string)

	if !strings.HasSuffix(certPath, "/etc/nginx/ssl/example.com.crt") {
		t.Errorf("unexpected cert path: %s", certPath)
	}
	if !strings.HasSuffix(keyPath, "/etc/nginx/ssl/example.com.key") {
		t.Errorf("unexpected key path: %s", keyPath)
	}

	if string(exe.files[certPath]) != ctx.Parameters["certificate_pem"] {
		t.Error("certificate PEM not written correctly")
	}
	if string(exe.files[keyPath]) != ctx.Parameters["private_key_pem"] {
		t.Error("private key PEM not written correctly")
	}
}

func TestHandleCertInstall_Apache(t *testing.T) {
	exe := newMockExecutor()
	exe.commands["mkdir -p /etc/apache2/ssl"] = struct {
		stdout string
		stderr string
		err    error
	}{"", "", nil}
	exe.commands["apachectl configtest"] = struct {
		stdout string
		stderr string
		err    error
	}{"Syntax OK\n", "", nil}
	exe.commands["systemctl reload apache2"] = struct {
		stdout string
		stderr string
		err    error
	}{"", "", nil}
	exe.existsFiles["/etc/apache2"] = true

	ctx := HandlerContext{
		Parameters: map[string]any{
			"domain":           "example.com",
			"certificate_pem":  "-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----",
			"private_key_pem":  "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----",
			"ca_bundle_pem":    "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----",
			"web_server_type":  "apache2",
		},
		Executor: exe,
	}

	result := handleCertInstall(ctx)

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Error)
	}

	caPath := result.Output["ca_path"].(string)
	if !strings.HasSuffix(caPath, "/etc/apache2/ssl/example.com.ca-bundle") {
		t.Errorf("unexpected CA path: %s", caPath)
	}

	certContent := string(exe.files[result.Output["cert_path"].(string)])
	if !strings.Contains(certContent, "CERT") || !strings.Contains(certContent, "CA") {
		t.Error("certificate + CA bundle not combined correctly")
	}
}

func TestHandleCertInstall_InvalidDomain(t *testing.T) {
	exe := newMockExecutor()
	ctx := HandlerContext{
		Parameters: map[string]any{
			"domain":          "../etc/passwd",
			"certificate_pem": "-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----",
			"private_key_pem": "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----",
		},
		Executor: exe,
	}

	result := handleCertInstall(ctx)
	if result.Status != "failure" {
		t.Fatalf("expected failure, got %s", result.Status)
	}
	if !strings.Contains(result.Error, "invalid domain") && !strings.Contains(result.Error, "invalid certificate path") {
		t.Errorf("expected domain/path validation error, got: %s", result.Error)
	}
}

func TestHandleCertInstall_PathTraversalBlocked(t *testing.T) {
	exe := newMockExecutor()
	exe.commands["mkdir -p /etc/nginx/ssl"] = struct {
		stdout string
		stderr string
		err    error
	}{"", "", nil}
	exe.existsFiles["/etc/nginx"] = true

	ctx := HandlerContext{
		Parameters: map[string]any{
			"domain":          "evil.com/../../../../../etc/passwd",
			"certificate_pem": "-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----",
			"private_key_pem": "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----",
			"web_server_type": "nginx",
		},
		Executor: exe,
	}

	result := handleCertInstall(ctx)
	if result.Status != "failure" {
		t.Fatalf("expected failure, got %s", result.Status)
	}
	if !strings.Contains(result.Error, "invalid domain name") {
		t.Errorf("expected invalid domain error, got: %s", result.Error)
	}
}

func TestHandleCertInstall_MissingParams(t *testing.T) {
	exe := newMockExecutor()
	ctx := HandlerContext{
		Parameters: map[string]any{
			"domain": "example.com",
		},
		Executor: exe,
	}

	result := handleCertInstall(ctx)

	if result.Status != "failure" {
		t.Fatalf("expected failure, got %s", result.Status)
	}
	if !strings.Contains(result.Error, "missing required parameters") {
		t.Errorf("unexpected error: %s", result.Error)
	}
}

func TestHandleCertInstall_ConfigValidationFails(t *testing.T) {
	exe := newMockExecutor()
	exe.commands["mkdir -p /etc/nginx/ssl"] = struct {
		stdout string
		stderr string
		err    error
	}{"", "", nil}
	exe.commands["nginx -t"] = struct {
		stdout string
		stderr string
		err    error
	}{"", "syntax error", fmtError("test")}
	exe.commands["apachectl configtest"] = struct {
		stdout string
		stderr string
		err    error
	}{"", "syntax error", fmtError("test")}
	exe.existsFiles["/etc/nginx"] = true

	ctx := HandlerContext{
		Parameters: map[string]any{
			"domain":           "example.com",
			"certificate_pem":  "-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----",
			"private_key_pem":  "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----",
			"web_server_type":  "nginx",
		},
		Executor: exe,
	}

	result := handleCertInstall(ctx)

	if result.Status != "failure" {
		t.Fatalf("expected failure, got %s", result.Status)
	}
	if !strings.Contains(result.Error, "config validation failed") {
		t.Errorf("unexpected error: %s", result.Error)
	}
}

func fmtError(msg string) error {
	return fmt.Errorf("%s", msg)
}
