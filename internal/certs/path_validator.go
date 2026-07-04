package certs

import (
	"fmt"
	"path/filepath"
	"strings"
)

// defaultAllowedRoots lists the well-known SSL certificate directories that
// local certificate metrics are permitted to read from. Paths outside these
// roots (or outside an explicitly allowlisted path) are rejected to limit the
// impact of a compromised backend.
var defaultAllowedRoots = []string{
	"/etc/ssl",
	"/etc/nginx/ssl",
	"/etc/apache2/ssl",
	"/etc/httpd/conf.d",
	"/etc/pki/tls",
	"/etc/letsencrypt",
}

// ValidateCertPath ensures certPath is absolute, contains no directory
// traversal, and resides under one of the default SSL roots or matches an
// entry in allowedPaths.
func ValidateCertPath(certPath string, allowedPaths []string) error {
	certPath = strings.TrimSpace(certPath)
	if certPath == "" {
		return fmt.Errorf("cert_path is empty")
	}
	if !filepath.IsAbs(certPath) {
		return fmt.Errorf("cert_path must be absolute: %s", certPath)
	}
	if strings.Contains(certPath, "..") {
		return fmt.Errorf("cert_path contains directory traversal: %s", certPath)
	}

	clean := filepath.Clean(certPath)

	for _, allowed := range allowedPaths {
		if strings.EqualFold(clean, filepath.Clean(allowed)) {
			return nil
		}
	}

	for _, root := range defaultAllowedRoots {
		root = filepath.Clean(root)
		if root == "" {
			continue
		}
		if clean == root {
			return nil
		}
		if strings.HasPrefix(clean, root+string(filepath.Separator)) {
			return nil
		}
	}

	return fmt.Errorf("cert_path outside allowed SSL directories: %s", certPath)
}
