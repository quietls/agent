package platform

import "strings"

// DetectProfile maps detected OS, web server type, and runtime to one of the
// platform profile identifiers understood by the backend. Returns "" when no
// known profile matches, leaving the field unset.
func DetectProfile(osInfo OSInfo, webServerType string, runtime string) string {
	osName := strings.ToLower(osInfo.Distro)
	wsType := strings.ToLower(webServerType)

	// Docker-based profiles take precedence over the host distro since the
	// container's OS is irrelevant when the workload runs in Docker.
	if runtime == "docker" {
		switch wsType {
		case "nginx":
			return "docker-nginx"
		case "traefik":
			return "docker-traefik"
		}
		// Unknown docker combo — fall through to host-based detection below.
	}

	isUbuntu := strings.Contains(osName, "ubuntu") || strings.Contains(osName, "debian")
	isCentOS := strings.Contains(osName, "centos") ||
		strings.Contains(osName, "rhel") ||
		strings.Contains(osName, "rocky") ||
		strings.Contains(osName, "almalinux")

	switch {
	case isUbuntu && wsType == "nginx":
		return "ubuntu-nginx"
	case isUbuntu && wsType == "apache2":
		return "ubuntu-apache"
	case isCentOS && wsType == "nginx":
		return "centos-nginx"
	}

	return ""
}