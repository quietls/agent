package httpclient

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegister(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/agents/register" {
			t.Errorf("expected /agents/register, got %s", r.URL.Path)
		}

		// Should NOT have auth headers
		if r.Header.Get("Authorization") != "" {
			t.Error("register should not send auth headers")
		}

		var req RegisterRequest
		json.NewDecoder(r.Body).Decode(&req)

		if req.Hostname != "test-server" {
			t.Errorf("expected hostname 'test-server', got '%s'", req.Hostname)
		}

		w.WriteHeader(201)
		json.NewEncoder(w).Encode(RegisterResponse{
			AgentID:     "ag_123",
			AgentToken:  "tok_abc",
			AgentSecret: "sec_xyz",
		})
	}))
	defer srv.Close()

	client := New(srv.URL, "", "", nil)
	resp, err := client.Register(RegisterRequest{
		Token:    "user_token",
		Hostname: "test-server",
		Context: RegisterContext{
			OS:           OSContext{Distro: "Ubuntu", Version: "22.04", Arch: "x86_64"},
			Runtime:      "host",
			AgentVersion: "0.0.1",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.AgentID != "ag_123" {
		t.Errorf("expected agent_id 'ag_123', got '%s'", resp.AgentID)
	}
}

func TestPollCommands(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/agents/ag_123/commands" {
			t.Errorf("expected /agents/ag_123/commands, got %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer tok_abc" {
			t.Error("missing or wrong Authorization header")
		}
		if r.Header.Get("X-Agent-ID") != "ag_123" {
			t.Error("missing or wrong X-Agent-ID header")
		}

		json.NewEncoder(w).Encode(PollCommandsResponse{
			Commands: []CommandMessage{
				{
					CommandID:   "cert.scan",
					ExecutionID: "exec_1",
					Parameters:  map[string]any{},
					Priority:    "normal",
					Timestamp:   1711382400,
					Nonce:       "n_1",
					Signature:   "sig_1",
				},
			},
		})
	}))
	defer srv.Close()

	client := New(srv.URL, "ag_123", "tok_abc", nil)
	resp, err := client.PollCommands()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(resp.Commands) != 1 {
		t.Fatalf("expected 1 command, got %d", len(resp.Commands))
	}
	if resp.Commands[0].CommandID != "cert.scan" {
		t.Errorf("expected command_id 'cert.scan', got '%s'", resp.Commands[0].CommandID)
	}
}

func TestReportResult(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/agents/ag_123/results" {
			t.Errorf("expected /agents/ag_123/results, got %s", r.URL.Path)
		}

		json.NewEncoder(w).Encode(map[string]bool{"ack": true})
	}))
	defer srv.Close()

	client := New(srv.URL, "ag_123", "tok_abc", nil)
	err := client.ReportResult(CommandResultRequest{
		ExecutionID: "exec_1",
		CommandID:   "cert.scan",
		Status:      "success",
		StartedAt:   "2026-03-25T10:00:00Z",
		CompletedAt: "2026-03-25T10:00:01Z",
		DurationMs:  1000,
		Output:      map[string]any{"certs": []any{}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSendHeartbeat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}

		json.NewEncoder(w).Encode(HeartbeatResponse{
			Ack:        true,
			ServerTime: "2026-03-25T10:00:00Z",
		})
	}))
	defer srv.Close()

	client := New(srv.URL, "ag_123", "tok_abc", nil)
	resp, err := client.SendHeartbeat(HeartbeatRequest{
		AgentVersion:  "0.0.1",
		UptimeSeconds: 3600,
		CertsManaged:  0,
		SystemMetrics: SystemMetrics{CPUPercent: 1.0, MemoryMB: 24, DiskFreeGB: 50.0},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Ack {
		t.Error("expected ack=true")
	}
}

func TestGetConfig(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}

		json.NewEncoder(w).Encode(AgentConfigResponse{
			PollIntervalSeconds:      30,
			HeartbeatIntervalSeconds: 60,
			LogLevel:                 "info",
			CommandsWhitelist:        []string{"cert.scan", "agent.status"},
		})
	}))
	defer srv.Close()

	client := New(srv.URL, "ag_123", "tok_abc", nil)
	resp, err := client.GetConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.PollIntervalSeconds != 30 {
		t.Errorf("expected poll_interval 30, got %d", resp.PollIntervalSeconds)
	}
}

func TestUpdateContext(t *testing.T) {
	var payload map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	client := New(srv.URL, "ag_123", "tok_abc", nil)
	err := client.UpdateContext(ContextUpdateRequest{
		OS: OSContext{Distro: "Ubuntu", Version: "22.04", Arch: "x86_64"},
		WebServer: &WebServerUpdateContext{
			Type:    "nginx",
			Version: "1.24.0",
		},
		Runtime: "host",
		Ports:   PortsContext{Port80: true, Port443: true},
		Domains: []string{"example.com", "api.example.com"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	webServerRaw, ok := payload["web_server"]
	if !ok || webServerRaw == nil {
		t.Fatal("expected web_server payload")
	}
	webServer := webServerRaw.(map[string]any)
	if webServer["type"] != "nginx" {
		t.Fatalf("expected type nginx, got %v", webServer["type"])
	}
	if webServer["version"] != "1.24.0" {
		t.Fatalf("expected version 1.24.0, got %v", webServer["version"])
	}

	domainsRaw, ok := payload["domains"]
	if !ok {
		t.Fatal("expected domains in payload")
	}
	domains := domainsRaw.([]any)
	if len(domains) != 2 {
		t.Fatalf("expected 2 domains, got %d", len(domains))
	}
	if domains[0] != "example.com" {
		t.Fatalf("expected first domain example.com, got %v", domains[0])
	}
}

func TestHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte("Unauthorized"))
	}))
	defer srv.Close()

	client := New(srv.URL, "ag_123", "bad_token", nil)
	_, err := client.PollCommands()
	if err == nil {
		t.Error("expected error for 401 response")
	}
}
