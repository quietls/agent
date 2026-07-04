package commands

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/quietls/agent/internal/httpclient"
)

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

func TestGetHandler(t *testing.T) {
	tests := []struct {
		id    string
		found bool
	}{
		{"cert.scan", true},
		{"webserver.detect", true},
		{"agent.status", true},
		{"diag.connectivity", true},
		{"webserver.reload", true},
		{"webserver.config.validate", true},
		{"cert.request", false},
		{"unknown.cmd", false},
	}

	for _, tt := range tests {
		h := GetHandler(tt.id)
		if (h != nil) != tt.found {
			t.Errorf("GetHandler(%q): expected found=%v", tt.id, tt.found)
		}
	}
}

func TestGetSupportedCommands(t *testing.T) {
	cmds := GetSupportedCommands()
	if len(cmds) < 5 {
		t.Errorf("expected at least 6 commands, got %d", len(cmds))
	}

	expected := map[string]bool{
		"cert.scan":                 true,
		"cert.install":              true,
		"webserver.detect":          true,
		"agent.status":              true,
		"diag.connectivity":         true,
		"webserver.reload":          true,
		"webserver.config.validate": true,
		"metric.tls-drift":          true,
		"metric.cert-local":         true,
	}

	for _, cmd := range cmds {
		if !expected[cmd] {
			t.Errorf("unexpected command: %s", cmd)
		}
	}
}

func TestCertScanHandler(t *testing.T) {
	exe := newMockExecutor()
	handler := GetHandler("cert.scan")

	result := handler(HandlerContext{
		Parameters: map[string]any{},
		Executor:   exe,
	})

	if result.Status != "success" {
		t.Errorf("expected success, got %s", result.Status)
	}
	if _, ok := result.Output["certs"]; !ok {
		t.Error("expected 'certs' in output")
	}
}

func TestWebserverDetectHandler(t *testing.T) {
	exe := newMockExecutor()
	handler := GetHandler("webserver.detect")

	result := handler(HandlerContext{
		Parameters: map[string]any{},
		Executor:   exe,
	})

	if result.Status != "success" {
		t.Errorf("expected success, got %s", result.Status)
	}
	if _, ok := result.Output["web_server"]; !ok {
		t.Error("expected 'web_server' in output")
	}
}

func TestDiagConnectivity_Reachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(httpclient.AgentConfigResponse{
			PollIntervalSeconds: 30,
		})
	}))
	defer srv.Close()

	client := httpclient.New(srv.URL, "ag_123", "tok_abc", nil)
	handler := GetHandler("diag.connectivity")

	result := handler(HandlerContext{
		Parameters: map[string]any{},
		Executor:   newMockExecutor(),
		HTTPClient: client,
	})

	if result.Status != "success" {
		t.Errorf("expected success, got %s", result.Status)
	}
	if result.Output["backend_reachable"] != true {
		t.Error("expected backend_reachable=true")
	}
}

func TestDiagConnectivity_Unreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	client := httpclient.New(srv.URL, "ag_123", "tok_abc", nil)
	handler := GetHandler("diag.connectivity")

	result := handler(HandlerContext{
		Parameters: map[string]any{},
		Executor:   newMockExecutor(),
		HTTPClient: client,
	})

	if result.Status != "failure" {
		t.Errorf("expected failure, got %s", result.Status)
	}
	if result.Output["backend_reachable"] != false {
		t.Error("expected backend_reachable=false")
	}
}
