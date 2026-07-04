package platform

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// ── Types ───────────────────────────────────────────────────────

// OSInfo holds detected operating system information.
type OSInfo struct {
	Distro  string `json:"distro"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
}

// PortStatus reports whether ports 80 and 443 are listening.
type PortStatus struct {
	Port80  bool `json:"port_80"`
	Port443 bool `json:"port_443"`
}

// ServerContext holds the complete detected server context.
type ServerContext struct {
	OS      OSInfo     `json:"os"`
	Runtime string     `json:"runtime"`
	Ports   PortStatus `json:"ports"`
}

// ── Executor interface (DI for testability) ─────────────────────

// Executor abstracts OS-level operations for dependency injection.
type Executor interface {
	ExecCommand(name string, args ...string) (stdout, stderr string, err error)
	ReadFile(path string) ([]byte, error)
	WriteFile(path string, data []byte) error
	ReadDir(path string) ([]os.DirEntry, error)
	FileExists(path string) bool
}

// OSExecutor implements Executor using real OS operations.
type OSExecutor struct{}

func (OSExecutor) ExecCommand(name string, args ...string) (string, string, error) {
	var cmd *exec.Cmd

	switch name {
	case "lsb_release":
		if !matchesArgs(args, "-a") {
			return "", "", fmt.Errorf("invalid args for lsb_release: %v", args)
		}
		cmd = exec.Command("lsb_release", "-a")
	case "uname":
		if !matchesArgs(args, "-m") {
			return "", "", fmt.Errorf("invalid args for uname: %v", args)
		}
		cmd = exec.Command("uname", "-m")
	case "ss":
		if !matchesArgs(args, "-tlnp") {
			return "", "", fmt.Errorf("invalid args for ss: %v", args)
		}
		cmd = exec.Command("ss", "-tlnp")
	case "nginx":
		if len(args) == 0 {
			return "", "", fmt.Errorf("invalid args for nginx: %v", args)
		}
		switch args[0] {
		case "-v", "-V", "-t":
			cmd = exec.Command("nginx", args...)
		case "-s":
			if len(args) == 2 && args[1] == "reload" {
				cmd = exec.Command("nginx", "-s", "reload")
			} else {
				return "", "", fmt.Errorf("invalid args for nginx -s: %v", args)
			}
		default:
			return "", "", fmt.Errorf("invalid args for nginx: %v", args)
		}
	case "apache2":
		if !matchesArgs(args, "-v") {
			return "", "", fmt.Errorf("invalid args for apache2: %v", args)
		}
		cmd = exec.Command("apache2", "-v")
	case "apachectl":
		if len(args) == 0 {
			return "", "", fmt.Errorf("invalid args for apachectl: %v", args)
		}
		switch args[0] {
		case "-v":
			cmd = exec.Command("apachectl", "-v")
		case "configtest":
			cmd = exec.Command("apachectl", "configtest")
		default:
			return "", "", fmt.Errorf("invalid args for apachectl: %v", args)
		}
	case "httpd":
		if !matchesArgs(args, "-v") {
			return "", "", fmt.Errorf("invalid args for httpd: %v", args)
		}
		cmd = exec.Command("httpd", "-v")
	case "openssl":
		if len(args) != 5 {
			return "", "", fmt.Errorf("invalid args for openssl: %v", args)
		}
		if args[0] != "x509" || args[2] != "-noout" || args[3] != "-in" {
			return "", "", fmt.Errorf("unsupported openssl subcommand: %v", args)
		}
		if args[1] != "-enddate" && args[1] != "-subject" {
			return "", "", fmt.Errorf("unsupported openssl flag: %v", args)
		}
		cmd = exec.Command("openssl", args...)
	case "mkdir":
		if len(args) != 2 || args[0] != "-p" {
			return "", "", fmt.Errorf("invalid args for mkdir: %v", args)
		}
		cmd = exec.Command("mkdir", "-p", args[1])
	case "systemctl":
		if len(args) != 2 || args[0] != "reload" || args[1] != "apache2" {
			return "", "", fmt.Errorf("invalid args for systemctl: %v", args)
		}
		cmd = exec.Command("systemctl", "reload", "apache2")
	default:
		return "", "", fmt.Errorf("unsupported command: %s", name)
	}

	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	return outBuf.String(), errBuf.String(), err
}

func (OSExecutor) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (OSExecutor) WriteFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0600)
}

func (OSExecutor) ReadDir(path string) ([]os.DirEntry, error) {
	return os.ReadDir(path)
}

func (OSExecutor) FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ── OS Detection ────────────────────────────────────────────────

// DetectOS detects the operating system info.
func DetectOS(exe Executor) OSInfo {
	info := OSInfo{}

	// Try /etc/os-release first
	data, err := exe.ReadFile("/etc/os-release")
	if err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "NAME=") {
				info.Distro = unquote(strings.TrimPrefix(line, "NAME="))
			} else if strings.HasPrefix(line, "VERSION_ID=") {
				info.Version = unquote(strings.TrimPrefix(line, "VERSION_ID="))
			}
		}
	}

	// Fallback to lsb_release
	if info.Distro == "" {
		stdout, _, err := exe.ExecCommand("lsb_release", "-a")
		if err == nil {
			for _, line := range strings.Split(stdout, "\n") {
				if strings.HasPrefix(line, "Distributor ID:") {
					info.Distro = strings.TrimSpace(strings.TrimPrefix(line, "Distributor ID:"))
				} else if strings.HasPrefix(line, "Release:") {
					info.Version = strings.TrimSpace(strings.TrimPrefix(line, "Release:"))
				}
			}
		}
	}

	// Architecture via uname
	stdout, _, err := exe.ExecCommand("uname", "-m")
	if err == nil {
		info.Arch = strings.TrimSpace(stdout)
	}

	return info
}

// ── Port Detection ──────────────────────────────────────────────

// DetectPorts checks if ports 80 and 443 are listening.
func DetectPorts(exe Executor) PortStatus {
	status := PortStatus{}

	stdout, _, err := exe.ExecCommand("ss", "-tlnp")
	if err != nil {
		return status
	}

	for _, line := range strings.Split(stdout, "\n") {
		if !strings.Contains(line, "LISTEN") {
			continue
		}
		if strings.Contains(line, ":80 ") || strings.HasSuffix(line, ":80") {
			status.Port80 = true
		}
		if strings.Contains(line, ":443 ") || strings.HasSuffix(line, ":443") {
			status.Port443 = true
		}
	}

	return status
}

// ── Runtime Detection ───────────────────────────────────────────

// DetectRuntime returns "docker" if running inside a container, "host" otherwise.
func DetectRuntime(exe Executor) string {
	if exe.FileExists("/.dockerenv") {
		return "docker"
	}
	return "host"
}

// ── Context Collection ──────────────────────────────────────────

// CollectContext gathers the full server context.
func CollectContext(exe Executor) ServerContext {
	return ServerContext{
		OS:      DetectOS(exe),
		Runtime: DetectRuntime(exe),
		Ports:   DetectPorts(exe),
	}
}

// ── Helpers ─────────────────────────────────────────────────────

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	return s
}

func matchesArgs(got []string, expected ...string) bool {
	if len(got) != len(expected) {
		return false
	}
	for i := range got {
		if got[i] != expected[i] {
			return false
		}
	}
	return true
}

// FormatContext returns a human-readable string of the server context.
func FormatContext(ctx ServerContext) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "OS: %s %s (%s)\n", ctx.OS.Distro, ctx.OS.Version, ctx.OS.Arch)
	fmt.Fprintf(&sb, "Runtime: %s\n", ctx.Runtime)
	fmt.Fprintf(&sb, "Port 80: %v | Port 443: %v\n", ctx.Ports.Port80, ctx.Ports.Port443)
	return sb.String()
}
