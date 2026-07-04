package webserver

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"strings"

	crossplane "github.com/nginxinc/nginx-go-crossplane"

	"github.com/quietls/agent/internal/platform"
)

// parseNginxWithCrossplane parses nginx config using the crossplane AST parser.
// It returns extracted vhost information, or an error if parsing fails.
func parseNginxWithCrossplane(configPath string, exe platform.Executor) ([]VhostInfo, error) {
	opts := &crossplane.ParseOptions{
		CombineConfigs: true,
		Open: func(path string) (io.ReadCloser, error) {
			data, err := exe.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("crossplane open %s: %w", path, err)
			}
			return io.NopCloser(bytes.NewReader(data)), nil
		},
		Glob: func(pattern string) ([]string, error) {
			return executorGlob(exe, pattern)
		},
	}

	payload, err := crossplane.Parse(configPath, opts)
	if err != nil {
		return nil, fmt.Errorf("crossplane parse %s: %w", configPath, err)
	}

	if len(payload.Config) == 0 {
		return nil, fmt.Errorf("crossplane: no config parsed from %s", configPath)
	}

	var vhosts []VhostInfo

	for _, cfg := range payload.Config {
		vhosts = append(vhosts, extractVhostsFromDirectives(cfg.Parsed, cfg.File)...)
	}

	return vhosts, nil
}

// extractVhostsFromDirectives walks the directive tree and extracts server blocks.
func extractVhostsFromDirectives(directives crossplane.Directives, configFile string) []VhostInfo {
	var vhosts []VhostInfo

	for _, dir := range directives {
		// Look for http {} and stream {} blocks containing server {} blocks
		if (dir.Directive == "http" || dir.Directive == "stream") && dir.Block != nil {
			for _, child := range dir.Block {
				if child.Directive == "server" && child.Block != nil {
					if vhost := extractVhostFromServerBlock(child, configFile); vhost != nil {
						vhosts = append(vhosts, *vhost)
					}
				}
			}
		}

		// Handle top-level server blocks (uncommon but possible)
		if dir.Directive == "server" && dir.Block != nil {
			if vhost := extractVhostFromServerBlock(dir, configFile); vhost != nil {
				vhosts = append(vhosts, *vhost)
			}
		}
	}

	return vhosts
}

// extractVhostFromServerBlock extracts vhost info from a server {} directive block.
func extractVhostFromServerBlock(serverDir *crossplane.Directive, configFile string) *VhostInfo {
	vhost := &VhostInfo{
		ConfigPath: serverDir.File,
	}

	// If the directive has no File (combined configs), fall back to the config file
	if vhost.ConfigPath == "" {
		vhost.ConfigPath = configFile
	}

	var listenPorts []int
	var hasSSL bool
	var hasCert bool
	var certPath, certKeyPath string
	var serverNames []string

	for _, dir := range serverDir.Block {
		switch dir.Directive {
		case "server_name":
			for _, arg := range dir.Args {
				name := strings.TrimSpace(arg)
				if name == "" {
					continue
				}
				serverNames = append(serverNames, name)
			}

		case "listen":
			port, ssl, isDefault := parseListenArgs(dir.Args)
			if ssl {
				hasSSL = true
			}
			if isDefault {
				vhost.IsDefault = true
			}
			if port > 0 {
				listenPorts = append(listenPorts, port)
			}

		case "ssl":
			if len(dir.Args) > 0 && dir.Args[0] == "on" {
				hasSSL = true
			}

		case "ssl_certificate":
			if len(dir.Args) > 0 {
				certPath = dir.Args[0]
				hasCert = true
			}

		case "ssl_certificate_key":
			if len(dir.Args) > 0 {
				certKeyPath = dir.Args[0]
			}

		case "return":
			if isHTTPSRedirect(dir.Args) {
				vhost.RedirectToHTTPS = true
			}
		}
	}

	// Skip catch-all and localhost vhosts
	filteredNames := filterServerNames(serverNames)
	if len(filteredNames) == 0 {
		return nil
	}

	vhost.ServerNames = filteredNames
	vhost.ServerName = filteredNames[0]
	vhost.ListenPorts = listenPorts

	// SSL detection (certbot-style): SSL if listen has ssl, ssl on, OR ssl_certificate is present
	vhost.SSLEnabled = hasSSL || hasCert

	if vhost.SSLEnabled {
		vhost.CertPath = certPath
		vhost.CertKeyPath = certKeyPath
	}

	return vhost
}

// parseListenArgs extracts port number, ssl flag, and default_server flag from listen directive args.
// Examples: "443 ssl", "80 default_server", "*:8443 ssl", "127.0.0.1:443 ssl"
func parseListenArgs(args []string) (port int, ssl bool, isDefault bool) {
	for _, arg := range args {
		arg = strings.TrimSpace(arg)

		if arg == "ssl" {
			ssl = true
			continue
		}
		if arg == "default_server" {
			isDefault = true
			continue
		}

		// Extract port from address like "127.0.0.1:443", "*:8443", "443"
		port = extractPortFromAddress(arg)
	}
	return
}

// extractPortFromAddress parses a port number from a listen address.
// Handles: "443", "*:8443", "127.0.0.1:443", "[::]:443"
func extractPortFromAddress(addr string) int {
	// Remove interface part: "127.0.0.1:443" → "443", "[::]:443" → "443"
	if idx := strings.LastIndex(addr, ":"); idx >= 0 {
		portStr := addr[idx+1:]
		var port int
		if _, err := fmt.Sscanf(portStr, "%d", &port); err == nil && port > 0 {
			return port
		}
	}

	// Plain port number
	var port int
	if _, err := fmt.Sscanf(addr, "%d", &port); err == nil && port > 0 {
		return port
	}

	return 0
}

// isHTTPSRedirect checks if a return directive is an HTTP-to-HTTPS redirect.
func isHTTPSRedirect(args []string) bool {
	if len(args) < 2 {
		return false
	}

	// return 301 https://... or return 302 https://...
	code := args[0]
	if code != "301" && code != "302" && code != "303" && code != "307" && code != "308" {
		return false
	}

	for _, arg := range args[1:] {
		if strings.HasPrefix(arg, "https://") || strings.Contains(arg, "https://$host") {
			return true
		}
	}

	return false
}

// filterServerNames removes catch-all names ("_", "localhost") from server_name list.
func filterServerNames(names []string) []string {
	var filtered []string
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "_" || name == "localhost" || name == "" {
			continue
		}
		filtered = append(filtered, name)
	}
	return filtered
}

// executorGlob resolves glob patterns using the Executor's ReadDir.
// Supports simple patterns like /etc/nginx/conf.d/*.conf
func executorGlob(exe platform.Executor, pattern string) ([]string, error) {
	dir := filepath.Dir(pattern)
	base := filepath.Base(pattern)

	entries, err := exe.ReadDir(dir)
	if err != nil {
		// Directory doesn't exist — no matches, not an error
		return nil, nil
	}

	var matches []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		matched, _ := filepath.Match(base, entry.Name())
		if matched {
			matches = append(matches, dir+"/"+entry.Name())
		}
	}

	return matches, nil
}

// detectNginxVhostsWithFallback tries crossplane first, falls back to regex.
func detectNginxVhostsWithFallback(configPath string, exe platform.Executor) []VhostInfo {
	vhosts, err := parseNginxWithCrossplane(configPath, exe)
	if err != nil {
		log.Printf("crossplane parsing failed (%v), falling back to regex scanner", err)
		return detectNginxVhostsRegex(exe)
	}
	return vhosts
}

// detectNginxVhostsRegex is the legacy regex-based vhost scanner (fallback).
func detectNginxVhostsRegex(exe platform.Executor) []VhostInfo {
	var vhosts []VhostInfo

	for _, dir := range []string{"/etc/nginx/sites-enabled", "/etc/nginx/conf.d"} {
		entries, err := exe.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if !strings.HasSuffix(name, ".conf") && dir == "/etc/nginx/conf.d" {
				continue
			}
			configPath := dir + "/" + name
			fileVhosts := parseNginxConfig(configPath, exe)
			vhosts = append(vhosts, fileVhosts...)
		}
	}

	return vhosts
}
