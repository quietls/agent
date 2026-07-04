package commands

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/quietls/agent/internal/platform"
	"github.com/quietls/agent/internal/webserver"
)

// domainRe validates a simple hostname: dot-separated labels of 1-63
// alphanumeric/hyphen characters; the hyphen may not lead or trail a label.
// Max total length is enforced separately.
var domainRe = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func isValidDomain(domain string) bool {
	if domain == "" || len(domain) > 253 {
		return false
	}
	if strings.Contains(domain, "..") || strings.ContainsAny(domain, "/\\") {
		return false
	}
	return domainRe.MatchString(domain)
}

// secureCertPath builds an absolute path under sslDir for the given domain and
// file suffix, then verifies the result does not escape sslDir via ".." or an
// absolute injected component.
func secureCertPath(sslDir, domain, suffix string) (string, error) {
	if !isValidDomain(domain) {
		return "", fmt.Errorf("invalid domain name")
	}
	baseName := domain + suffix
	if strings.ContainsAny(baseName, "/\\") {
		return "", fmt.Errorf("invalid filename")
	}

	fullPath := filepath.Join(sslDir, baseName)
	absPath, err := filepath.Abs(fullPath)
	if err != nil {
		return "", err
	}
	absDir, err := filepath.Abs(sslDir)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(absDir, absPath)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("path escapes SSL directory")
	}
	return absPath, nil
}

func handleCertInstall(ctx HandlerContext) CommandResult {
	domain, _ := ctx.Parameters["domain"].(string)
	certPem, _ := ctx.Parameters["certificate_pem"].(string)
	keyPem, _ := ctx.Parameters["private_key_pem"].(string)
	caBundlePem, _ := ctx.Parameters["ca_bundle_pem"].(string)
	webServerType, _ := ctx.Parameters["web_server_type"].(string)

	if domain == "" || certPem == "" || keyPem == "" {
		return CommandResult{
			Status: "failure",
			Output: map[string]any{},
			Error:  "missing required parameters: domain, certificate_pem, private_key_pem",
		}
	}

	if !isValidDomain(domain) {
		return CommandResult{
			Status: "failure",
			Output: map[string]any{},
			Error:  "invalid domain name",
		}
	}

	// Detect web server if not provided
	if webServerType == "" {
		ws := webserver.DetectWebServer(ctx.Executor)
		if ws != nil {
			webServerType = ws.Type
		}
	}

	// Determine SSL directory based on web server
	var sslDir string
	switch webServerType {
	case "nginx":
		sslDir = "/etc/nginx/ssl"
	case "apache2":
		sslDir = "/etc/apache2/ssl"
	default:
		// Fallback to nginx path, then apache
		if ctx.Executor.FileExists("/etc/nginx") {
			sslDir = "/etc/nginx/ssl"
		} else if ctx.Executor.FileExists("/etc/apache2") {
			sslDir = "/etc/apache2/ssl"
		} else {
			sslDir = "/etc/ssl"
		}
	}

	// Ensure SSL directory exists
	if err := ensureDir(ctx.Executor, sslDir); err != nil {
		return CommandResult{
			Status: "failure",
			Output: map[string]any{},
			Error:  fmt.Sprintf("failed to create SSL directory %s: %v", sslDir, err),
		}
	}

	// Build contained file paths under sslDir.
	certPath, err := secureCertPath(sslDir, domain, ".crt")
	if err != nil {
		return CommandResult{
			Status: "failure",
			Output: map[string]any{},
			Error:  fmt.Sprintf("invalid certificate path: %v", err),
		}
	}
	keyPath, err := secureCertPath(sslDir, domain, ".key")
	if err != nil {
		return CommandResult{
			Status: "failure",
			Output: map[string]any{},
			Error:  fmt.Sprintf("invalid key path: %v", err),
		}
	}
	caPath, err := secureCertPath(sslDir, domain, ".ca-bundle")
	if err != nil {
		return CommandResult{
			Status: "failure",
			Output: map[string]any{},
			Error:  fmt.Sprintf("invalid CA bundle path: %v", err),
		}
	}

	certContent := certPem
	if caBundlePem != "" {
		certContent = certPem + "\n" + caBundlePem
	}

	if err := ctx.Executor.WriteFile(certPath, []byte(certContent)); err != nil {
		return CommandResult{
			Status: "failure",
			Output: map[string]any{},
			Error:  fmt.Sprintf("failed to write certificate: %v", err),
		}
	}

	if err := ctx.Executor.WriteFile(keyPath, []byte(keyPem)); err != nil {
		return CommandResult{
			Status: "failure",
			Output: map[string]any{},
			Error:  fmt.Sprintf("failed to write private key: %v", err),
		}
	}

	if caBundlePem != "" {
		if err := ctx.Executor.WriteFile(caPath, []byte(caBundlePem)); err != nil {
			return CommandResult{
				Status: "failure",
				Output: map[string]any{},
				Error:  fmt.Sprintf("failed to write CA bundle: %v", err),
			}
		}
	}

	// Validate web server config
	var validateOutput, validateError string
	var validateErr error

	switch webServerType {
	case "nginx":
		validateOutput, validateError, validateErr = ctx.Executor.ExecCommand("nginx", "-t")
	case "apache2":
		validateOutput, validateError, validateErr = ctx.Executor.ExecCommand("apachectl", "configtest")
	default:
		// Try both
		validateOutput, validateError, validateErr = ctx.Executor.ExecCommand("nginx", "-t")
		if validateErr != nil {
			validateOutput, validateError, validateErr = ctx.Executor.ExecCommand("apachectl", "configtest")
		}
	}

	if validateErr != nil {
		return CommandResult{
			Status: "failure",
			Output: map[string]any{
				"cert_path":   certPath,
				"key_path":    keyPath,
				"validation":  false,
				"valid_output": validateOutput + validateError,
			},
			Error: fmt.Sprintf("web server config validation failed: %v", validateErr),
		}
	}

	// Reload web server
	var reloadErr error
	switch webServerType {
	case "nginx":
		_, _, reloadErr = ctx.Executor.ExecCommand("nginx", "-s", "reload")
	case "apache2":
		_, _, reloadErr = ctx.Executor.ExecCommand("systemctl", "reload", "apache2")
	default:
		_, _, reloadErr = ctx.Executor.ExecCommand("nginx", "-s", "reload")
		if reloadErr != nil {
			_, _, reloadErr = ctx.Executor.ExecCommand("systemctl", "reload", "apache2")
		}
	}

	if reloadErr != nil {
		return CommandResult{
			Status: "failure",
			Output: map[string]any{
				"cert_path":   certPath,
				"key_path":    keyPath,
				"validation":  true,
				"valid_output": validateOutput + validateError,
			},
			Error: fmt.Sprintf("web server reload failed: %v", reloadErr),
		}
	}

	return CommandResult{
		Status: "success",
		Output: map[string]any{
			"domain":       domain,
			"cert_path":    certPath,
			"key_path":     keyPath,
			"ca_path":      caPath,
			"ssl_dir":      sslDir,
			"web_server":   webServerType,
			"validation":   true,
			"reloaded":     true,
		},
	}
}

func ensureDir(exe platform.Executor, path string) error {
	if exe.FileExists(path) {
		return nil
	}
	// Use mkdir -p via exec; no shell fallback to avoid injection risk.
	_, _, err := exe.ExecCommand("mkdir", "-p", path)
	return err
}
