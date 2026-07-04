package platform

import (
	"fmt"
	"os"
	"testing"
)

// mockExecutor simulates OS operations for testing.
type mockExecutor struct {
	commands map[string]struct {
		stdout string
		stderr string
		err    error
	}
	files       map[string][]byte
	dirs        map[string][]os.DirEntry
	existsFiles map[string]bool
}

func newMockExecutor() *mockExecutor {
	return &mockExecutor{
		commands: make(map[string]struct {
			stdout string
			stderr string
			err    error
		}),
		files:       make(map[string][]byte),
		dirs:        make(map[string][]os.DirEntry),
		existsFiles: make(map[string]bool),
	}
}

func (m *mockExecutor) ExecCommand(name string, args ...string) (string, string, error) {
	key := name
	for _, a := range args {
		key += " " + a
	}
	if r, ok := m.commands[key]; ok {
		return r.stdout, r.stderr, r.err
	}
	return "", "", fmt.Errorf("command not found: %s", key)
}

func (m *mockExecutor) ReadFile(path string) ([]byte, error) {
	if data, ok := m.files[path]; ok {
		return data, nil
	}
	return nil, os.ErrNotExist
}

func (m *mockExecutor) WriteFile(path string, data []byte) error {
	m.files[path] = data
	return nil
}

func (m *mockExecutor) ReadDir(path string) ([]os.DirEntry, error) {
	if entries, ok := m.dirs[path]; ok {
		return entries, nil
	}
	return nil, os.ErrNotExist
}

func (m *mockExecutor) FileExists(path string) bool {
	return m.existsFiles[path]
}

func TestDetectOS_Ubuntu(t *testing.T) {
	exe := newMockExecutor()
	exe.files["/etc/os-release"] = []byte(`NAME="Ubuntu"
VERSION_ID="22.04"
ID=ubuntu
`)
	exe.commands["uname -m"] = struct {
		stdout string
		stderr string
		err    error
	}{"x86_64\n", "", nil}

	info := DetectOS(exe)

	if info.Distro != "Ubuntu" {
		t.Errorf("expected distro 'Ubuntu', got '%s'", info.Distro)
	}
	if info.Version != "22.04" {
		t.Errorf("expected version '22.04', got '%s'", info.Version)
	}
	if info.Arch != "x86_64" {
		t.Errorf("expected arch 'x86_64', got '%s'", info.Arch)
	}
}

func TestDetectOS_CentOS(t *testing.T) {
	exe := newMockExecutor()
	exe.files["/etc/os-release"] = []byte(`NAME="CentOS Linux"
VERSION_ID="8"
`)
	exe.commands["uname -m"] = struct {
		stdout string
		stderr string
		err    error
	}{"x86_64\n", "", nil}

	info := DetectOS(exe)

	if info.Distro != "CentOS Linux" {
		t.Errorf("expected distro 'CentOS Linux', got '%s'", info.Distro)
	}
	if info.Version != "8" {
		t.Errorf("expected version '8', got '%s'", info.Version)
	}
}

func TestDetectOS_Debian(t *testing.T) {
	exe := newMockExecutor()
	exe.files["/etc/os-release"] = []byte(`NAME="Debian GNU/Linux"
VERSION_ID="12"
`)
	exe.commands["uname -m"] = struct {
		stdout string
		stderr string
		err    error
	}{"aarch64\n", "", nil}

	info := DetectOS(exe)

	if info.Distro != "Debian GNU/Linux" {
		t.Errorf("expected distro 'Debian GNU/Linux', got '%s'", info.Distro)
	}
	if info.Arch != "aarch64" {
		t.Errorf("expected arch 'aarch64', got '%s'", info.Arch)
	}
}

func TestDetectOS_FallbackToLsbRelease(t *testing.T) {
	exe := newMockExecutor()
	// No /etc/os-release
	exe.commands["lsb_release -a"] = struct {
		stdout string
		stderr string
		err    error
	}{"Distributor ID:\tUbuntu\nRelease:\t20.04\n", "", nil}
	exe.commands["uname -m"] = struct {
		stdout string
		stderr string
		err    error
	}{"x86_64\n", "", nil}

	info := DetectOS(exe)

	if info.Distro != "Ubuntu" {
		t.Errorf("expected distro 'Ubuntu', got '%s'", info.Distro)
	}
	if info.Version != "20.04" {
		t.Errorf("expected version '20.04', got '%s'", info.Version)
	}
}

func TestDetectPorts(t *testing.T) {
	exe := newMockExecutor()
	exe.commands["ss -tlnp"] = struct {
		stdout string
		stderr string
		err    error
	}{`State    Recv-Q   Send-Q     Local Address:Port     Peer Address:Port
LISTEN   0        511              0.0.0.0:80            0.0.0.0:*
LISTEN   0        511              0.0.0.0:443           0.0.0.0:*
`, "", nil}

	ports := DetectPorts(exe)

	if !ports.Port80 {
		t.Error("expected port 80 to be listening")
	}
	if !ports.Port443 {
		t.Error("expected port 443 to be listening")
	}
}

func TestDetectPorts_NoneListening(t *testing.T) {
	exe := newMockExecutor()
	exe.commands["ss -tlnp"] = struct {
		stdout string
		stderr string
		err    error
	}{`State    Recv-Q   Send-Q     Local Address:Port     Peer Address:Port
LISTEN   0        128              0.0.0.0:22            0.0.0.0:*
`, "", nil}

	ports := DetectPorts(exe)

	if ports.Port80 {
		t.Error("port 80 should not be listening")
	}
	if ports.Port443 {
		t.Error("port 443 should not be listening")
	}
}

func TestDetectRuntime_Host(t *testing.T) {
	exe := newMockExecutor()
	runtime := DetectRuntime(exe)
	if runtime != "host" {
		t.Errorf("expected 'host', got '%s'", runtime)
	}
}

func TestDetectRuntime_Docker(t *testing.T) {
	exe := newMockExecutor()
	exe.existsFiles["/.dockerenv"] = true
	runtime := DetectRuntime(exe)
	if runtime != "docker" {
		t.Errorf("expected 'docker', got '%s'", runtime)
	}
}

func TestCollectContext(t *testing.T) {
	exe := newMockExecutor()
	exe.files["/etc/os-release"] = []byte(`NAME="Ubuntu"
VERSION_ID="22.04"
`)
	exe.commands["uname -m"] = struct {
		stdout string
		stderr string
		err    error
	}{"x86_64\n", "", nil}
	exe.commands["ss -tlnp"] = struct {
		stdout string
		stderr string
		err    error
	}{"LISTEN 0 511 0.0.0.0:80 0.0.0.0:*\n", "", nil}

	ctx := CollectContext(exe)

	if ctx.OS.Distro != "Ubuntu" {
		t.Errorf("expected distro 'Ubuntu', got '%s'", ctx.OS.Distro)
	}
	if ctx.Runtime != "host" {
		t.Errorf("expected runtime 'host', got '%s'", ctx.Runtime)
	}
	if !ctx.Ports.Port80 {
		t.Error("expected port 80 to be listening")
	}
}
