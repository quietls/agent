package commands

import (
	"strings"
	"testing"
)

func TestHandleMetricCertLocal_DisallowedPath(t *testing.T) {
	exe := newMockExecutor()
	handler := GetHandler("metric.cert-local")
	result := handler(HandlerContext{
		Parameters: map[string]any{
			"domain":    "example.com",
			"cert_path": "/etc/passwd",
		},
		Executor: exe,
	})
	if result.Status != "failure" {
		t.Errorf("expected failure, got %s", result.Status)
	}
	if !strings.Contains(result.Error, "outside allowed SSL directories") {
		t.Errorf("expected disallowed path error, got: %s", result.Error)
	}
}

func TestHandleMetricCertLocal_MissingDomain(t *testing.T) {
	handler := GetHandler("metric.cert-local")
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

func TestHandleMetricCertLocal_NoCertPathFound(t *testing.T) {
	exe := newMockExecutor()
	// No web server detection set up — cert_path won't be auto-detected

	handler := GetHandler("metric.cert-local")
	result := handler(HandlerContext{
		Parameters: map[string]any{"domain": "example.com"},
		Executor:   exe,
	})

	if result.Status != "failure" {
		t.Errorf("expected failure, got %s", result.Status)
	}
	if !strings.Contains(result.Error, "no certificate path found") {
		t.Errorf("expected 'no certificate path found' error, got %s", result.Error)
	}
}

func TestHandleMetricCertLocal_CertPathProvided_OpensslFails(t *testing.T) {
	exe := newMockExecutor()
	// openssl commands will fail since they're not in the mock
	// ScanCerts returns 1 entry with empty fields, so handler returns success

	handler := GetHandler("metric.cert-local")
	result := handler(HandlerContext{
		Parameters: map[string]any{
			"domain":    "example.com",
			"cert_path": "/etc/ssl/cert.pem",
		},
		Executor: exe,
	})

	if result.Status != "success" {
		t.Errorf("expected success (ScanCerts returns entry even on openssl failure), got %s", result.Status)
	}
	// The cert entry has empty subject/expires since openssl failed
	if result.Output["subject"] != "" {
		t.Errorf("expected empty subject on openssl failure, got %v", result.Output["subject"])
	}
}

func TestHandleMetricCertLocal_CertPathProvided_Success(t *testing.T) {
	exe := newMockExecutor()
	exe.commands["openssl x509 -enddate -noout -in /etc/ssl/cert.pem"] = struct {
		stdout string
		stderr string
		err    error
	}{"notAfter=Jun 25 12:00:00 2026 GMT\n", "", nil}
	exe.commands["openssl x509 -subject -noout -in /etc/ssl/cert.pem"] = struct {
		stdout string
		stderr string
		err    error
	}{"subject=CN = example.com\n", "", nil}

	handler := GetHandler("metric.cert-local")
	result := handler(HandlerContext{
		Parameters: map[string]any{
			"domain":    "example.com",
			"cert_path": "/etc/ssl/cert.pem",
		},
		Executor: exe,
	})

	if result.Status != "success" {
		t.Errorf("expected success, got %s", result.Status)
	}
	if result.Output["expires"] != "Jun 25 12:00:00 2026 GMT" {
		t.Errorf("expected expires, got %v", result.Output["expires"])
	}
	if result.Output["subject"] != "example.com" {
		t.Errorf("expected subject example.com, got %v", result.Output["subject"])
	}
}

