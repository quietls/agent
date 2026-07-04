package agent

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDaemon_StartAndStop(t *testing.T) {
	// Create a mock backend
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/commands") {
			json.NewEncoder(w).Encode(map[string]any{"commands": []any{}})
			return
		}
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(map[string]any{"ack": true})
	}))
	defer srv.Close()

	// Create config
	cfg := &Config{
		AgentID:      "ag_test",
		AgentToken:   "tok_test",
		AgentSecret:  "sec_test",
		BaseURL:      srv.URL,
		PollInterval: 30,
	}
	cfgData, _ := json.Marshal(cfg)

	fs := newMockFileIO()
	fs.files["/tmp/test-config.json"] = cfgData

	var logBuf strings.Builder
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	daemon := NewDaemon("/tmp/test-config.json", "0.0.1", DaemonDeps{
		Executor: &mockOSExecutor{},
		FileIO:   fs,
		Logger:   logger,
		Now:      time.Now,
	})

	// Start in background, stop after a short delay
	done := make(chan error, 1)
	go func() {
		done <- daemon.Start()
	}()

	time.Sleep(100 * time.Millisecond)
	daemon.Stop()

	err := <-done
	if err != nil {
		t.Fatalf("daemon.Start() returned error: %v", err)
	}

	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "ag_test") {
		t.Error("expected log to contain agent_id")
	}
	if !strings.Contains(logOutput, "shutting down") {
		t.Error("expected shutdown log message")
	}
}

func TestDaemon_LoadsConfig(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"commands": []any{}})
	}))
	defer srv.Close()

	cfg := &Config{
		AgentID:      "ag_cfg_test",
		AgentToken:   "tok_test",
		AgentSecret:  "sec_test",
		BaseURL:      srv.URL,
		PollInterval: 30,
	}
	cfgData, _ := json.Marshal(cfg)

	fs := newMockFileIO()
	fs.files["/tmp/cfg-test.json"] = cfgData

	daemon := NewDaemon("/tmp/cfg-test.json", "0.0.1", DaemonDeps{
		Executor: &mockOSExecutor{},
		FileIO:   fs,
		Logger:   slog.New(slog.NewTextHandler(&strings.Builder{}, nil)),
		Now:      time.Now,
	})

	done := make(chan error, 1)
	go func() { done <- daemon.Start() }()

	time.Sleep(50 * time.Millisecond)
	daemon.Stop()
	<-done

	if daemon.config == nil {
		t.Fatal("config should be loaded")
	}
	if daemon.config.AgentID != "ag_cfg_test" {
		t.Errorf("expected agent_id 'ag_cfg_test', got '%s'", daemon.config.AgentID)
	}
}

func TestDaemon_ConfigNotFound(t *testing.T) {
	fs := newMockFileIO()

	daemon := NewDaemon("/nonexistent.json", "0.0.1", DaemonDeps{
		Executor: &mockOSExecutor{},
		FileIO:   fs,
		Logger:   slog.New(slog.NewTextHandler(&strings.Builder{}, nil)),
		Now:      time.Now,
	})

	err := daemon.Start()
	if err == nil {
		t.Error("expected error for missing config")
	}
}

func TestDaemon_PollError(t *testing.T) {
	// Server returns errors
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte("internal error"))
	}))
	defer srv.Close()

	cfg := &Config{
		AgentID:      "ag_err_test",
		AgentToken:   "tok_test",
		AgentSecret:  "sec_test",
		BaseURL:      srv.URL,
		PollInterval: 30,
	}
	cfgData, _ := json.Marshal(cfg)

	fs := newMockFileIO()
	fs.files["/tmp/err-test.json"] = cfgData

	var logBuf strings.Builder
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	daemon := NewDaemon("/tmp/err-test.json", "0.0.1", DaemonDeps{
		Executor: &mockOSExecutor{},
		FileIO:   fs,
		Logger:   logger,
		Now:      time.Now,
	})

	done := make(chan error, 1)
	go func() { done <- daemon.Start() }()

	time.Sleep(50 * time.Millisecond)
	daemon.Stop()
	<-done

	if !strings.Contains(logBuf.String(), "Poll error") {
		t.Error("expected poll error in logs")
	}
}

func TestDaemon_SendsContextUpdateOnStart(t *testing.T) {
	contextCh := make(chan map[string]any, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/context"):
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			contextCh <- body
			w.WriteHeader(200)
			return
		case strings.HasSuffix(r.URL.Path, "/commands"):
			json.NewEncoder(w).Encode(map[string]any{"commands": []any{}})
			return
		case strings.HasSuffix(r.URL.Path, "/heartbeat"):
			json.NewEncoder(w).Encode(map[string]any{"ack": true, "server_time": "2026-01-01T00:00:00Z"})
			return
		default:
			w.WriteHeader(200)
		}
	}))
	defer srv.Close()

	cfg := &Config{
		AgentID:      "ag_ctx_test",
		AgentToken:   "tok_test",
		AgentSecret:  "sec_test",
		BaseURL:      srv.URL,
		ConfigPath:   "/custom/nginx.conf",
		PollInterval: 30,
	}
	cfgData, _ := json.Marshal(cfg)

	fs := newMockFileIO()
	fs.files["/tmp/ctx-test.json"] = cfgData

	daemon := NewDaemon("/tmp/ctx-test.json", "0.0.1", DaemonDeps{
		Executor: &mockOSExecutor{},
		FileIO:   fs,
		Logger:   slog.New(slog.NewTextHandler(&strings.Builder{}, nil)),
		Now:      time.Now,
	})

	done := make(chan error, 1)
	go func() { done <- daemon.Start() }()

	var payload map[string]any
	select {
	case payload = <-contextCh:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected context update request")
	}

	daemon.Stop()
	<-done

	// Verify web_server only contains type and version (no private paths)
	webServerRaw, ok := payload["web_server"]
	if !ok || webServerRaw == nil {
		t.Fatal("expected web_server in context payload")
	}
	webServer, ok := webServerRaw.(map[string]any)
	if !ok {
		t.Fatal("expected web_server object")
	}
	if _, hasConfigPath := webServer["config_path"]; hasConfigPath {
		t.Fatal("config_path should not be sent to backend")
	}
	if _, hasConfigSource := webServer["config_source"]; hasConfigSource {
		t.Fatal("config_source should not be sent to backend")
	}

	// Verify domains field is present
	if _, hasDomains := payload["domains"]; !hasDomains {
		t.Fatal("expected domains in context payload")
	}
}

// mockOSExecutor is a no-op executor for daemon tests.
type mockOSExecutor struct{}

func (m *mockOSExecutor) ExecCommand(name string, args ...string) (string, string, error) {
	return "", "", nil
}

func (m *mockOSExecutor) ReadFile(path string) ([]byte, error) {
	return nil, os.ErrNotExist
}

func (m *mockOSExecutor) WriteFile(path string, data []byte) error {
	return nil
}

func (m *mockOSExecutor) ReadDir(path string) ([]os.DirEntry, error) {
	return nil, os.ErrNotExist
}

func (m *mockOSExecutor) FileExists(path string) bool {
	return false
}
