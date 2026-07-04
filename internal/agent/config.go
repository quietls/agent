package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// DefaultConfigPath is the default location for the agent config file.
const DefaultConfigPath = "/etc/ssl-agent/config.json"

// Config holds the agent's persistent configuration.
type Config struct {
	AgentID         string  `json:"agent_id"`
	AgentToken      string  `json:"agent_token"`
	AgentSecret     string  `json:"agent_secret"`
	BaseURL         string  `json:"base_url"`
	Version         string  `json:"version,omitempty"`
	ProxyType       string  `json:"proxy_type,omitempty"`
	ConfigPath      string  `json:"config_path,omitempty"`
	ReloadCommand   string  `json:"reload_command,omitempty"`
	PlatformProfile *string `json:"platform_profile"`
	PollInterval    int     `json:"poll_interval"`
}

// FileIO abstracts file system operations for testability.
type FileIO interface {
	ReadFile(path string) ([]byte, error)
	WriteFile(path string, data []byte, perm os.FileMode) error
	MkdirAll(path string, perm os.FileMode) error
}

// OSFileIO implements FileIO using the real OS file system.
type OSFileIO struct{}

func (OSFileIO) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (OSFileIO) WriteFile(path string, data []byte, perm os.FileMode) error {
	return os.WriteFile(path, data, perm)
}

func (OSFileIO) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

// LoadConfig reads and parses the agent config file.
func LoadConfig(path string, fs FileIO) (*Config, error) {
	if path == "" {
		path = DefaultConfigPath
	}

	data, err := fs.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// SaveConfig writes the agent config to disk with restricted permissions.
func SaveConfig(cfg *Config, path string, fs FileIO) error {
	if path == "" {
		path = DefaultConfigPath
	}

	dir := filepath.Dir(path)
	if err := fs.MkdirAll(dir, 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return fs.WriteFile(path, data, 0600)
}
