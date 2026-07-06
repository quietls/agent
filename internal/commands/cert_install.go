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

	// Detect the web server. This also surfaces the cert paths referenced by
	// the parsed config, which lets us install where the server actually reads
	// (essential for sidecar/Docker deployments).
	ws := ctx.detectWebServer()
	if webServerType == "" && ws != nil {
		webServerType = ws.Type
	}

	// nginx's ssl_certificate expects the leaf followed by the intermediate
	// chain (fullchain); apache's SSLCertificateFile accepts the same.
	fullchain := certPem
	if caBundlePem != "" {
		fullchain = certPem + "\n" + caBundlePem
	}

	var certPath, keyPath, caPath, sslDir string
	writeMode := "default"

	if vc, vk, ok := resolveVhostCertPaths(ws, domain); ok {
		// Preferred: write to the exact paths the web server config references.
		writeMode = "configured"
		certPath, keyPath = vc, vk

		if err := ensureDir(ctx.Executor, filepath.Dir(certPath)); err != nil {
			return failInstall(fmt.Sprintf("failed to create certificate directory %s: %v", filepath.Dir(certPath), err))
		}
		if err := ensureDir(ctx.Executor, filepath.Dir(keyPath)); err != nil {
			return failInstall(fmt.Sprintf("failed to create key directory %s: %v", filepath.Dir(keyPath), err))
		}
		if err := ctx.Executor.WriteFile(certPath, []byte(fullchain)); err != nil {
			return failInstall(fmt.Sprintf("failed to write certificate: %v", err))
		}
		if err := ctx.Executor.WriteFile(keyPath, []byte(keyPem)); err != nil {
			return failInstall(fmt.Sprintf("failed to write private key: %v", err))
		}
	} else {
		// Fallback: fixed per-server SSL directory with <domain>.crt/.key/.ca-bundle.
		sslDir = defaultSSLDir(ctx.Executor, webServerType)
		if err := ensureDir(ctx.Executor, sslDir); err != nil {
			return failInstall(fmt.Sprintf("failed to create SSL directory %s: %v", sslDir, err))
		}

		var err error
		if certPath, err = secureCertPath(sslDir, domain, ".crt"); err != nil {
			return failInstall(fmt.Sprintf("invalid certificate path: %v", err))
		}
		if keyPath, err = secureCertPath(sslDir, domain, ".key"); err != nil {
			return failInstall(fmt.Sprintf("invalid key path: %v", err))
		}
		if caPath, err = secureCertPath(sslDir, domain, ".ca-bundle"); err != nil {
			return failInstall(fmt.Sprintf("invalid CA bundle path: %v", err))
		}

		if err := ctx.Executor.WriteFile(certPath, []byte(fullchain)); err != nil {
			return failInstall(fmt.Sprintf("failed to write certificate: %v", err))
		}
		if err := ctx.Executor.WriteFile(keyPath, []byte(keyPem)); err != nil {
			return failInstall(fmt.Sprintf("failed to write private key: %v", err))
		}
		if caBundlePem != "" {
			if err := ctx.Executor.WriteFile(caPath, []byte(caBundlePem)); err != nil {
				return failInstall(fmt.Sprintf("failed to write CA bundle: %v", err))
			}
		}
	}

	baseOutput := map[string]any{
		"domain":     domain,
		"cert_path":  certPath,
		"key_path":   keyPath,
		"web_server": webServerType,
		"write_mode": writeMode,
	}
	if caPath != "" {
		baseOutput["ca_path"] = caPath
	}
	if sslDir != "" {
		baseOutput["ssl_dir"] = sslDir
	}

	// Reload the web server. When an operator-provided reload command is set
	// (sidecar deployments where nginx runs in a separate container and the
	// agent has no local nginx binary), use it and skip in-container validation.
	if ctx.ReloadCommand != "" {
		stdout, stderr, err := ctx.Executor.ExecCommand("sh", "-c", ctx.ReloadCommand)
		if err != nil {
			baseOutput["reload_output"] = stdout + stderr
			return CommandResult{
				Status: "failure",
				Output: baseOutput,
				Error:  fmt.Sprintf("reload command failed: %v", err),
			}
		}
		baseOutput["reloaded"] = true
		baseOutput["reload_via"] = "reload_command"
		return CommandResult{Status: "success", Output: baseOutput}
	}

	// In-container validate + reload (single-host deployments).
	var validateOutput, validateError string
	var validateErr error
	switch webServerType {
	case "nginx":
		validateOutput, validateError, validateErr = ctx.Executor.ExecCommand("nginx", "-t")
	case "apache2":
		validateOutput, validateError, validateErr = ctx.Executor.ExecCommand("apachectl", "configtest")
	default:
		validateOutput, validateError, validateErr = ctx.Executor.ExecCommand("nginx", "-t")
		if validateErr != nil {
			validateOutput, validateError, validateErr = ctx.Executor.ExecCommand("apachectl", "configtest")
		}
	}

	if validateErr != nil {
		baseOutput["validation"] = false
		baseOutput["valid_output"] = validateOutput + validateError
		return CommandResult{
			Status: "failure",
			Output: baseOutput,
			Error:  fmt.Sprintf("web server config validation failed: %v", validateErr),
		}
	}

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
		baseOutput["validation"] = true
		baseOutput["valid_output"] = validateOutput + validateError
		return CommandResult{
			Status: "failure",
			Output: baseOutput,
			Error:  fmt.Sprintf("web server reload failed: %v", reloadErr),
		}
	}

	baseOutput["validation"] = true
	baseOutput["reloaded"] = true
	baseOutput["reload_via"] = "builtin"
	return CommandResult{Status: "success", Output: baseOutput}
}

func failInstall(errMsg string) CommandResult {
	return CommandResult{Status: "failure", Output: map[string]any{}, Error: errMsg}
}

// defaultSSLDir returns the conventional SSL directory for a web server type.
func defaultSSLDir(exe platform.Executor, webServerType string) string {
	switch webServerType {
	case "nginx":
		return "/etc/nginx/ssl"
	case "apache2":
		return "/etc/apache2/ssl"
	default:
		if exe.FileExists("/etc/nginx") {
			return "/etc/nginx/ssl"
		}
		if exe.FileExists("/etc/apache2") {
			return "/etc/apache2/ssl"
		}
		return "/etc/ssl"
	}
}

// resolveVhostCertPaths finds the certificate/key paths that the web server
// config already references for the given domain. Returns ok=false when no
// matching vhost with absolute cert paths is found, in which case the caller
// falls back to the default SSL directory convention.
func resolveVhostCertPaths(ws *webserver.WebServerInfo, domain string) (certPath, keyPath string, ok bool) {
	if ws == nil {
		return "", "", false
	}
	for _, v := range ws.Vhosts {
		if !vhostMatchesDomain(v, domain) {
			continue
		}
		cp := strings.TrimSpace(v.CertPath)
		kp := strings.TrimSpace(v.CertKeyPath)
		// Only use absolute paths; a relative/empty path is unusable and unsafe.
		if strings.HasPrefix(cp, "/") && strings.HasPrefix(kp, "/") {
			return cp, kp, true
		}
	}
	return "", "", false
}

func vhostMatchesDomain(v webserver.VhostInfo, domain string) bool {
	if strings.EqualFold(strings.TrimSpace(v.ServerName), domain) {
		return true
	}
	for _, sn := range v.ServerNames {
		if strings.EqualFold(strings.TrimSpace(sn), domain) {
			return true
		}
	}
	return false
}

func ensureDir(exe platform.Executor, path string) error {
	if exe.FileExists(path) {
		return nil
	}
	// Use mkdir -p via exec; no shell fallback to avoid injection risk.
	_, _, err := exe.ExecCommand("mkdir", "-p", path)
	return err
}
