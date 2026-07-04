package agent

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/quietls/agent/internal/httpclient"
)

func TestSetup_Success(t *testing.T) {
	t.Setenv("SSL_AGENT_INSECURE_DEV", "1")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/agents/register" {
			t.Errorf("expected /agents/register, got %s", r.URL.Path)
		}

		var req httpclient.RegisterRequest
		json.NewDecoder(r.Body).Decode(&req)

		if req.Token != "test_token" {
			t.Errorf("expected token 'test_token', got '%s'", req.Token)
		}

		w.WriteHeader(201)
		json.NewEncoder(w).Encode(httpclient.RegisterResponse{
			AgentID:     "ag_setup_123",
			AgentToken:  "tok_generated",
			AgentSecret: "sec_generated",
		})
	}))
	defer srv.Close()

	fs := newMockFileIO()

	err := Setup(SetupOptions{
		Token:      "test_token",
		BaseURL:    srv.URL,
		ConfigPath: "/tmp/test-agent.json",
	}, SetupDeps{
		Executor: &mockRegExecutor{},
		FileIO:   fs,
		Logger:   slog.New(slog.NewTextHandler(&strings.Builder{}, nil)),
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check config was saved
	data, ok := fs.files["/tmp/test-agent.json"]
	if !ok {
		t.Fatal("config file was not saved")
	}

	var cfg Config
	json.Unmarshal(data, &cfg)
	if cfg.AgentID != "ag_setup_123" {
		t.Errorf("expected agent_id 'ag_setup_123', got '%s'", cfg.AgentID)
	}
}

func TestSetup_MissingToken(t *testing.T) {
	err := Setup(SetupOptions{}, SetupDeps{
		Executor: &mockRegExecutor{},
		FileIO:   newMockFileIO(),
		Logger:   slog.New(slog.NewTextHandler(&strings.Builder{}, nil)),
	})

	if err == nil {
		t.Error("expected error for missing token")
	}
	if !strings.Contains(err.Error(), "token is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSetup_RegistrationFailure(t *testing.T) {
	t.Setenv("SSL_AGENT_INSECURE_DEV", "1")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte("Unauthorized"))
	}))
	defer srv.Close()

	err := Setup(SetupOptions{
		Token:      "bad_token",
		BaseURL:    srv.URL,
		ConfigPath: "/tmp/test-agent.json",
	}, SetupDeps{
		Executor: &mockRegExecutor{},
		FileIO:   newMockFileIO(),
		Logger:   slog.New(slog.NewTextHandler(&strings.Builder{}, nil)),
	})

	if err == nil {
		t.Error("expected error for failed registration")
	}
	if !strings.Contains(err.Error(), "registration failed") {
		t.Errorf("unexpected error: %v", err)
	}
}

// mockRegExecutor is a minimal executor for registration tests.
type mockRegExecutor struct{}

func (m *mockRegExecutor) ExecCommand(name string, args ...string) (string, string, error) {
	if name == "uname" {
		return "x86_64\n", "", nil
	}
	return "", "", nil
}

func (m *mockRegExecutor) ReadFile(path string) ([]byte, error) {
	if path == "/etc/os-release" {
		return []byte("NAME=\"Ubuntu\"\nVERSION_ID=\"22.04\"\n"), nil
	}
	return nil, nil
}

func (m *mockRegExecutor) WriteFile(path string, data []byte) error {
	return nil
}

func (m *mockRegExecutor) ReadDir(path string) ([]os.DirEntry, error) {
	return nil, nil
}

func (m *mockRegExecutor) FileExists(path string) bool {
	return false
}
