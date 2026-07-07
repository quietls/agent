package certs

import (
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"strings"
	"time"

	"github.com/quietls/agent/internal/platform"
)

// CertInfo holds information about a detected SSL certificate.
type CertInfo struct {
	Domain  string `json:"domain"`
	Expires string `json:"expires"`
	Path    string `json:"path"`
}

// ScanCerts inspects the given certificate file paths and returns info for each.
// Paths are typically extracted from web server vhost configs (ssl_certificate / SSLCertificateFile).
//
// Certificates are parsed in-process with crypto/x509 (rather than shelling out
// to `openssl`), so this works in minimal/sidecar containers that don't ship an
// openssl binary. Expiry is reported as an RFC3339 UTC timestamp.
func ScanCerts(exe platform.Executor, certPaths []string) []CertInfo {
	seen := make(map[string]struct{})
	var certs []CertInfo

	for _, p := range certPaths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}

		// Deduplicate
		abs, _ := filepath.Abs(p)
		if _, ok := seen[abs]; ok {
			continue
		}
		seen[abs] = struct{}{}

		cert := CertInfo{Path: p}

		if leaf := parseLeafCertificate(exe, p); leaf != nil {
			cert.Expires = leaf.NotAfter.UTC().Format(time.RFC3339)
			cert.Domain = certCommonName(leaf)
		}

		certs = append(certs, cert)
	}

	return certs
}

// parseLeafCertificate reads a PEM file (which may be a fullchain) and returns
// the first CERTIFICATE block parsed as an x509 certificate (the leaf).
func parseLeafCertificate(exe platform.Executor, path string) *x509.Certificate {
	data, err := exe.ReadFile(path)
	if err != nil {
		return nil
	}

	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil
		}
		return leaf
	}

	return nil
}

// certCommonName returns the certificate's subject CN, falling back to the
// first Subject Alternative Name when the CN is empty (common for modern certs).
func certCommonName(cert *x509.Certificate) string {
	if cn := strings.TrimSpace(cert.Subject.CommonName); cn != "" {
		return cn
	}
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0]
	}
	return ""
}
