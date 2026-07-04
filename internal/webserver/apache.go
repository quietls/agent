package webserver

import (
	"regexp"
	"strings"

	"github.com/quietls/agent/internal/platform"
)

var apacheVersionRe = regexp.MustCompile(`Apache/(\d+\.\d+\.\d+)`)

// DetectApache detects Apache and parses its vhost configuration.
func DetectApache(exe platform.Executor) *WebServerInfo {
	var version string

	// Try multiple apache binaries
	for _, bin := range []string{"apache2", "apachectl", "httpd"} {
		stdout, stderr, err := exe.ExecCommand(bin, "-v")
		if err != nil {
			continue
		}
		combined := stdout + stderr
		if m := apacheVersionRe.FindStringSubmatch(combined); len(m) >= 2 {
			version = m[1]
			break
		}
	}

	if version == "" {
		return nil
	}

	info := &WebServerInfo{
		Type:    "apache2",
		Version: version,
		Vhosts:  []VhostInfo{},
	}

	// Parse vhosts from sites-enabled (Debian/Ubuntu) and conf.d (CentOS/RHEL)
	for _, dir := range []string{"/etc/apache2/sites-enabled", "/etc/httpd/conf.d"} {
		entries, err := exe.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if !strings.HasSuffix(name, ".conf") {
				continue
			}
			configPath := dir + "/" + name
			vhosts := parseApacheConfig(configPath, exe)
			info.Vhosts = append(info.Vhosts, vhosts...)
		}
	}

	return info
}

var (
	serverNameApacheRe  = regexp.MustCompile(`(?i)ServerName\s+(\S+)`)
	sslEngineOnRe       = regexp.MustCompile(`(?i)SSLEngine\s+on`)
	sslCertFileApacheRe = regexp.MustCompile(`(?i)SSLCertificateFile\s+(\S+)`)
	vhostBlockRe        = regexp.MustCompile(`(?i)<VirtualHost[^>]*>`)
	vhostEndRe          = regexp.MustCompile(`(?i)</VirtualHost>`)
)

func parseApacheConfig(path string, exe platform.Executor) []VhostInfo {
	data, err := exe.ReadFile(path)
	if err != nil {
		return nil
	}

	content := string(data)
	var vhosts []VhostInfo

	// Split into VirtualHost blocks
	lines := strings.Split(content, "\n")
	inBlock := false
	var block strings.Builder

	for _, line := range lines {
		if vhostBlockRe.MatchString(line) {
			inBlock = true
			block.Reset()
		}

		if inBlock {
			block.WriteString(line + "\n")
		}

		if inBlock && vhostEndRe.MatchString(line) {
			inBlock = false
			blockStr := block.String()

			vhost := VhostInfo{ConfigPath: path}

			if m := serverNameApacheRe.FindStringSubmatch(blockStr); len(m) >= 2 {
				vhost.ServerName = m[1]
			}

			if vhost.ServerName == "" {
				continue
			}

			vhost.SSLEnabled = sslEngineOnRe.MatchString(blockStr)

			if vhost.SSLEnabled {
				if m := sslCertFileApacheRe.FindStringSubmatch(blockStr); len(m) >= 2 {
					vhost.CertPath = strings.TrimSpace(m[1])
				}
			}

			vhosts = append(vhosts, vhost)
		}
	}

	return vhosts
}

// DetectWebServer tries nginx first, then apache.
func DetectWebServer(exe platform.Executor) *WebServerInfo {
	return DetectWebServerWithOptions(exe, DetectOptions{})
}

// DetectWebServerWithOptions tries nginx first, then apache.
func DetectWebServerWithOptions(exe platform.Executor, opts DetectOptions) *WebServerInfo {
	if info := DetectNginxWithOptions(exe, opts); info != nil {
		return info
	}
	return DetectApache(exe)
}
