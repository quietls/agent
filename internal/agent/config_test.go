package agent

import (
	"encoding/json"
	"os"
	"testing"
)

// mockFileIO simulates file system operations in memory.
type mockFileIO struct {
	files   map[string][]byte
	perms   map[string]os.FileMode
	dirs    map[string]os.FileMode
	readErr error
}

func newMockFileIO() *mockFileIO {
	return &mockFileIO{
		files: make(map[string][]byte),
		perms: make(map[string]os.FileMode),
		dirs:  make(map[string]os.FileMode),
	}
}

func (m *mockFileIO) ReadFile(path string) ([]byte, error) {
	if m.readErr != nil {
		return nil, m.readErr
	}
	data, ok := m.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return data, nil
}

func (m *mockFileIO) WriteFile(path string, data []byte, perm os.FileMode) error {
	m.files[path] = data
	m.perms[path] = perm
	return nil
}

func (m *mockFileIO) MkdirAll(path string, perm os.FileMode) error {
	m.dirs[path] = perm
	return nil
}

func sampleConfig() *Config {
	profile := "ubuntu-nginx"
	return &Config{
		AgentID:         "ag_test",
		AgentToken:      "tok_test",
		AgentSecret:     "sec_test",
		BaseURL:         "http://localhost:3000",
		PlatformProfile: &profile,
		PollInterval:    30,
	}
}

func TestLoadConfig(t *testing.T) {
	fs := newMockFileIO()
	data, _ := json.Marshal(sampleConfig())
	fs.files["/etc/ssl-agent/config.json"] = data

	cfg, err := LoadConfig("/etc/ssl-agent/config.json", fs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.AgentID != "ag_test" {
		t.Errorf("expected agent_id 'ag_test', got '%s'", cfg.AgentID)
	}
	if cfg.BaseURL != "http://localhost:3000" {
		t.Errorf("expected base_url 'http://localhost:3000', got '%s'", cfg.BaseURL)
	}
}

func TestLoadConfig_DefaultPath(t *testing.T) {
	fs := newMockFileIO()
	data, _ := json.Marshal(sampleConfig())
	fs.files[DefaultConfigPath] = data

	cfg, err := LoadConfig("", fs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.AgentID != "ag_test" {
		t.Errorf("expected agent_id 'ag_test', got '%s'", cfg.AgentID)
	}
}

func TestLoadConfig_FileNotFound(t *testing.T) {
	fs := newMockFileIO()

	_, err := LoadConfig("/nonexistent/config.json", fs)
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestSaveConfig(t *testing.T) {
	fs := newMockFileIO()
	cfg := sampleConfig()

	err := SaveConfig(cfg, "/etc/ssl-agent/config.json", fs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check file was written
	data, ok := fs.files["/etc/ssl-agent/config.json"]
	if !ok {
		t.Fatal("config file was not written")
	}

	// Check permissions
	if fs.perms["/etc/ssl-agent/config.json"] != 0600 {
		t.Errorf("expected permissions 0600, got %o", fs.perms["/etc/ssl-agent/config.json"])
	}

	// Check directory was created
	if fs.dirs["/etc/ssl-agent"] != 0700 {
		t.Errorf("expected dir permissions 0700, got %o", fs.dirs["/etc/ssl-agent"])
	}

	// Check content is valid JSON
	var loaded Config
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("saved config is not valid JSON: %v", err)
	}
	if loaded.AgentID != "ag_test" {
		t.Errorf("expected agent_id 'ag_test', got '%s'", loaded.AgentID)
	}
}
