package commands

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// makeCertPEM builds a self-signed certificate PEM for testing cert parsing.
func makeCertPEM(t *testing.T, cn string, notAfter time.Time) []byte {
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

func TestHandleMetricCertLocal_CertPathProvided_UnparseableCert(t *testing.T) {
	exe := newMockExecutor()
	// No file content at the path — ScanCerts returns 1 entry with empty fields,
	// so the handler still returns success (the path was inspected).

	handler := GetHandler("metric.cert-local")
	result := handler(HandlerContext{
		Parameters: map[string]any{
			"domain":    "example.com",
			"cert_path": "/etc/ssl/cert.pem",
		},
		Executor: exe,
	})

	if result.Status != "success" {
		t.Errorf("expected success (ScanCerts returns entry even when unparseable), got %s", result.Status)
	}
	if result.Output["subject"] != "" {
		t.Errorf("expected empty subject for unparseable cert, got %v", result.Output["subject"])
	}
}

func TestHandleMetricCertLocal_CertPathProvided_Success(t *testing.T) {
	exe := newMockExecutor()
	exp := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)
	exe.files["/etc/ssl/cert.pem"] = makeCertPEM(t, "example.com", exp)

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
	if result.Output["expires"] != exp.Format(time.RFC3339) {
		t.Errorf("expected expires %s, got %v", exp.Format(time.RFC3339), result.Output["expires"])
	}
	if result.Output["subject"] != "example.com" {
		t.Errorf("expected subject example.com, got %v", result.Output["subject"])
	}
}

