package certs

import (
	"path/filepath"
	"regexp"
	"strings"

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

		// Get expiry date
		stdout, _, err := exe.ExecCommand("openssl", "x509", "-enddate", "-noout", "-in", p)
		if err == nil {
			cert.Expires = parseNotAfter(stdout)
		}

		// Get domain from certificate subject
		stdout, _, err = exe.ExecCommand("openssl", "x509", "-subject", "-noout", "-in", p)
		if err == nil {
			cert.Domain = parseSubjectCN(stdout)
		}

		certs = append(certs, cert)
	}

	return certs
}

var notAfterRe = regexp.MustCompile(`notAfter=(.+)`)

func parseNotAfter(output string) string {
	matches := notAfterRe.FindStringSubmatch(strings.TrimSpace(output))
	if len(matches) >= 2 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

var subjectCNRe = regexp.MustCompile(`CN\s*=\s*([^\s/,]+)`)

func parseSubjectCN(output string) string {
	matches := subjectCNRe.FindStringSubmatch(output)
	if len(matches) >= 2 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}
