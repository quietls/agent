package webserver

import (
	"regexp"
	"strings"

	"github.com/quietls/agent/internal/platform"
)

// DetectOptions controls web server detection behavior.
type DetectOptions struct {
	ConfigPathOverride string
}

// WebServerInfo holds detected web server information.
type WebServerInfo struct {
	Type         string      `json:"type"`
	Version      string      `json:"version"`
	ConfigPath   string      `json:"config_path,omitempty"`
	ConfigSource string      `json:"config_source,omitempty"`
	Vhosts       []VhostInfo `json:"vhosts"`
}

// VhostInfo holds information about a virtual host.
type VhostInfo struct {
	ServerNames     []string `json:"server_names"`
	ServerName      string   `json:"server_name"`
	ConfigPath      string   `json:"config_path"`
	SSLEnabled      bool     `json:"ssl_enabled"`
	CertPath        string   `json:"cert_path,omitempty"`
	CertKeyPath     string   `json:"cert_key_path,omitempty"`
	ListenPorts     []int    `json:"listen_ports,omitempty"`
	IsDefault       bool     `json:"is_default,omitempty"`
	RedirectToHTTPS bool     `json:"redirect_to_https,omitempty"`
}

var nginxVersionRe = regexp.MustCompile(`nginx/(\d+\.\d+\.\d+)`)

// DetectNginx detects nginx and parses its vhost configuration.
func DetectNginx(exe platform.Executor) *WebServerInfo {
	return DetectNginxWithOptions(exe, DetectOptions{})
}

// DetectNginxWithOptions detects nginx and parses its vhost configuration.
func DetectNginxWithOptions(exe platform.Executor, opts DetectOptions) *WebServerInfo {
	version := ""

	// When an explicit config path override is provided, the nginx binary may
	// not be present (e.g. the agent runs in a sidecar container that only
	// mounts the nginx config). Skip the binary probe and parse the config
	// file directly. Version is left empty since we cannot determine it.
	if strings.TrimSpace(opts.ConfigPathOverride) == "" {
		// Try nginx -v (outputs to stderr)
		_, stderr, err := exe.ExecCommand("nginx", "-v")
		if err != nil {
			return nil
		}

		matches := nginxVersionRe.FindStringSubmatch(stderr)
		if len(matches) >= 2 {
			version = matches[1]
		}
	}

	info := &WebServerInfo{
		Type:    "nginx",
		Version: version,
		Vhosts:  []VhostInfo{},
	}

	configPath, source := resolveNginxConfigPath(exe, opts.ConfigPathOverride)

	// When using a config override without the nginx binary, bail out if the
	// override file doesn't exist or can't be read — otherwise we'd return a
	// nginx "detection" with no vhosts, masking a misconfiguration.
	if strings.TrimSpace(opts.ConfigPathOverride) != "" {
		if !exe.FileExists(configPath) {
			return nil
		}
	}

	info.ConfigPath = configPath
	info.ConfigSource = source

	// Parse vhosts using crossplane with regex fallback
	if configPath != "" {
		info.Vhosts = detectNginxVhostsWithFallback(configPath, exe)
	}

	return info
}

var confPathFlagRe = regexp.MustCompile(`--conf-path=([^\s]+)`)

func resolveNginxConfigPath(exe platform.Executor, override string) (string, string) {
	if strings.TrimSpace(override) != "" {
		return strings.TrimSpace(override), "config_override"
	}

	stdout, stderr, err := exe.ExecCommand("nginx", "-V")
	if err == nil {
		combined := stdout + " " + stderr
		if m := confPathFlagRe.FindStringSubmatch(combined); len(m) >= 2 {
			confPath := strings.TrimSpace(m[1])
			if confPath != "" {
				return confPath, "nginx_v"
			}
		}
	}

	for _, path := range []string{
		"/etc/nginx/nginx.conf",
		"/usr/local/nginx/conf/nginx.conf",
		"/usr/local/openresty/nginx/conf/nginx.conf",
		"/etc/tengine/nginx.conf",
		"/opt/nginx/conf/nginx.conf",
	} {
		if exe.FileExists(path) {
			return path, "standard_paths"
		}
	}

	return "", ""
}

var (
	serverNameRe     = regexp.MustCompile(`server_name\s+([^;]+);`)
	listenSSLRe      = regexp.MustCompile(`listen\s+.*443.*ssl`)
	sslOnRe          = regexp.MustCompile(`ssl\s+on\s*;`)
	sslCertPathRe    = regexp.MustCompile(`ssl_certificate\s+([^;]+);`)
	sslCertKeyPathRe = regexp.MustCompile(`ssl_certificate_key\s+([^;]+);`)
)

func parseNginxConfig(path string, exe platform.Executor) []VhostInfo {
	data, err := exe.ReadFile(path)
	if err != nil {
		return nil
	}

	content := string(data)
	var vhosts []VhostInfo

	// Extract server blocks using brace counting
	blocks := extractServerBlocks(content)
	for _, block := range blocks {
		vhost := VhostInfo{ConfigPath: path}

		// Extract server_name
		if m := serverNameRe.FindStringSubmatch(block); len(m) >= 2 {
			names := strings.Fields(m[1])
			filtered := filterServerNames(names)
			if len(filtered) == 0 {
				continue
			}
			vhost.ServerNames = filtered
			vhost.ServerName = filtered[0]
		}

		if vhost.ServerName == "" {
			continue
		}

		// Check for SSL
		vhost.SSLEnabled = listenSSLRe.MatchString(block) || sslOnRe.MatchString(block) || sslCertPathRe.MatchString(block)

		// Extract cert path (ssl_certificate, not ssl_certificate_key)
		if vhost.SSLEnabled {
			if m := sslCertPathRe.FindStringSubmatch(block); len(m) >= 2 {
				vhost.CertPath = strings.TrimSpace(m[1])
			}
			if m := sslCertKeyPathRe.FindStringSubmatch(block); len(m) >= 2 {
				vhost.CertKeyPath = strings.TrimSpace(m[1])
			}
		}

		vhosts = append(vhosts, vhost)
	}

	return vhosts
}

func extractServerBlocks(content string) []string {
	var blocks []string
	lines := strings.Split(content, "\n")
	depth := 0
	inServer := false
	var current strings.Builder

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if !inServer && strings.HasPrefix(trimmed, "server") && strings.Contains(trimmed, "{") {
			inServer = true
			depth = 1
			current.Reset()
			current.WriteString(line + "\n")
			continue
		}

		if !inServer && strings.HasPrefix(trimmed, "server") {
			inServer = true
			depth = 0
			current.Reset()
			current.WriteString(line + "\n")
			continue
		}

		if inServer {
			current.WriteString(line + "\n")
			depth += strings.Count(line, "{") - strings.Count(line, "}")

			if depth <= 0 {
				blocks = append(blocks, current.String())
				inServer = false
			}
		}
	}

	return blocks
}
