package httpclient

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const defaultRequestTimeout = 30 * time.Second

// defaultHTTPClient returns an HTTP client with a reasonable timeout and a
// minimum TLS version of 1.2.
func defaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout: defaultRequestTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
}

// IsSecureBaseURL reports whether baseURL uses the HTTPS scheme.
func IsSecureBaseURL(baseURL string) bool {
	u, err := url.Parse(baseURL)
	return err == nil && strings.EqualFold(u.Scheme, "https")
}

// ── Request/Response types ──────────────────────────────────────

type OSContext struct {
	Distro  string `json:"distro"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
}

type WebServerContext struct {
	Type    string `json:"type"`
	Version string `json:"version"`
}

type RegisterContext struct {
	OS              OSContext         `json:"os"`
	WebServer       *WebServerContext `json:"web_server"`
	Runtime         string            `json:"runtime"`
	AgentVersion    string            `json:"agent_version"`
	PlatformProfile string            `json:"platform_profile,omitempty"`
}

type RegisterRequest struct {
	Token    string          `json:"token"`
	Hostname string          `json:"hostname"`
	Context  RegisterContext `json:"context"`
}

type RegisterResponse struct {
	AgentID     string `json:"agent_id"`
	AgentToken  string `json:"agent_token"`
	AgentSecret string `json:"agent_secret"`
}

type CommandMessage struct {
	CommandID   string         `json:"command_id"`
	ExecutionID string         `json:"execution_id"`
	Parameters  map[string]any `json:"parameters"`
	Priority    string         `json:"priority"`
	Timestamp   int64          `json:"timestamp"`
	Nonce       string         `json:"nonce"`
	Signature   string         `json:"signature"`
}

type PollCommandsResponse struct {
	Commands []CommandMessage `json:"commands"`
}

type CommandResultRequest struct {
	ExecutionID string         `json:"execution_id"`
	CommandID   string         `json:"command_id"`
	Status      string         `json:"status"`
	StartedAt   string         `json:"started_at"`
	CompletedAt string         `json:"completed_at"`
	DurationMs  int64          `json:"duration_ms"`
	Output      map[string]any `json:"output"`
	Error       *string        `json:"error"`
}

type SystemMetrics struct {
	CPUPercent float64 `json:"cpu_percent"`
	MemoryMB   int     `json:"memory_mb"`
	DiskFreeGB float64 `json:"disk_free_gb"`
}

type HeartbeatRequest struct {
	AgentVersion    string        `json:"agent_version"`
	UptimeSeconds   int           `json:"uptime_seconds"`
	PlatformProfile *string       `json:"platform_profile"`
	CertsManaged    int           `json:"certs_managed"`
	LastCommandAt   *string       `json:"last_command_at"`
	SystemMetrics   SystemMetrics `json:"system_metrics"`
}

type HeartbeatResponse struct {
	Ack        bool   `json:"ack"`
	ServerTime string `json:"server_time"`
}

type WebServerUpdateContext struct {
	Type    string `json:"type"`
	Version string `json:"version"`
}

type PortsContext struct {
	Port80  bool `json:"port_80"`
	Port443 bool `json:"port_443"`
}

type ContextUpdateRequest struct {
	OS              OSContext               `json:"os"`
	WebServer       *WebServerUpdateContext `json:"web_server"`
	Runtime         string                  `json:"runtime"`
	Ports           PortsContext            `json:"ports"`
	Domains         []string                `json:"domains"`
	PlatformProfile string                  `json:"platform_profile,omitempty"`
}

type AgentConfigResponse struct {
	PollIntervalSeconds      int      `json:"poll_interval_seconds"`
	HeartbeatIntervalSeconds int      `json:"heartbeat_interval_seconds"`
	LogLevel                 string   `json:"log_level"`
	CommandsWhitelist        []string `json:"commands_whitelist"`
}

// ── Client ──────────────────────────────────────────────────────

// Client communicates with the QuietLS backend API.
type Client struct {
	baseURL    string
	agentID    string
	agentToken string
	httpClient *http.Client
}

// New creates a new API client. For unauthenticated calls (Register),
// agentID and agentToken can be empty.
func New(baseURL string, agentID, agentToken string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = defaultHTTPClient()
	}
	return &Client{
		baseURL:    baseURL,
		agentID:    agentID,
		agentToken: agentToken,
		httpClient: httpClient,
	}
}

// SetCredentials updates the client's auth credentials after registration.
func (c *Client) SetCredentials(agentID, agentToken string) {
	c.agentID = agentID
	c.agentToken = agentToken
}

// Register registers a new agent with the backend.
func (c *Client) Register(req RegisterRequest) (*RegisterResponse, error) {
	var resp RegisterResponse
	if err := c.doJSON("POST", "/agents/register", req, &resp, false); err != nil {
		return nil, err
	}
	return &resp, nil
}

// PollCommands polls for pending commands.
func (c *Client) PollCommands() (*PollCommandsResponse, error) {
	var resp PollCommandsResponse
	url := fmt.Sprintf("/agents/%s/commands", c.agentID)
	if err := c.doJSON("GET", url, nil, &resp, true); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ReportResult reports a command execution result.
func (c *Client) ReportResult(req CommandResultRequest) error {
	var resp struct {
		Ack bool `json:"ack"`
	}
	url := fmt.Sprintf("/agents/%s/results", c.agentID)
	return c.doJSON("POST", url, req, &resp, true)
}

// SendHeartbeat sends a heartbeat to the backend.
func (c *Client) SendHeartbeat(req HeartbeatRequest) (*HeartbeatResponse, error) {
	var resp HeartbeatResponse
	url := fmt.Sprintf("/agents/%s/heartbeat", c.agentID)
	if err := c.doJSON("POST", url, req, &resp, true); err != nil {
		return nil, err
	}
	return &resp, nil
}

// UpdateContext sends updated server context to the backend.
func (c *Client) UpdateContext(req ContextUpdateRequest) error {
	url := fmt.Sprintf("/agents/%s/context", c.agentID)
	return c.doJSON("POST", url, req, nil, true)
}

// GetConfig fetches the agent's configuration from the backend.
func (c *Client) GetConfig() (*AgentConfigResponse, error) {
	var resp AgentConfigResponse
	url := fmt.Sprintf("/agents/%s/config", c.agentID)
	if err := c.doJSON("GET", url, nil, &resp, true); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) doJSON(method, path string, body any, result any, auth bool) error {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, c.baseURL+path, bodyReader)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	if auth {
		req.Header.Set("Authorization", "Bearer "+c.agentToken)
		req.Header.Set("X-Agent-ID", c.agentID)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	if result != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("unmarshal response: %w", err)
		}
	}

	return nil
}
