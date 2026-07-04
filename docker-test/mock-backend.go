package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Replicate the agent's canonicalPayload to ensure identical HMAC signatures
type canonicalPayload struct {
	CommandID   string         `json:"command_id"`
	ExecutionID string         `json:"execution_id"`
	Parameters  map[string]any `json:"parameters"`
	Timestamp   int64          `json:"timestamp"`
	Nonce       string         `json:"nonce"`
}

var (
	agents      = make(map[string]*Agent)
	agentsMu    sync.RWMutex
	commandQueues = make(map[string][]CommandMessage)
	results = make(map[string][]CommandResultRequest)
	resultsMu sync.RWMutex
)

type Agent struct {
	ID      string `json:"agent_id"`
	Token   string `json:"agent_token"`
	Secret  string `json:"agent_secret"`
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

type RegisterRequest struct {
	Token     string          `json:"token"`
	Hostname  string          `json:"hostname"`
	Context   json.RawMessage `json:"context"`
}

type RegisterResponse struct {
	AgentID     string `json:"agent_id"`
	AgentToken  string `json:"agent_token"`
	AgentSecret string `json:"agent_secret"`
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

type HeartbeatResponse struct {
	Ack        bool   `json:"ack"`
	ServerTime string `json:"server_time"`
}

type AgentConfigResponse struct {
	PollIntervalSeconds      int      `json:"poll_interval_seconds"`
	HeartbeatIntervalSeconds int      `json:"heartbeat_interval_seconds"`
	LogLevel                 string   `json:"log_level"`
	CommandsWhitelist        []string `json:"commands_whitelist"`
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)

	// Support both /v1 and root paths for the API
	mux.HandleFunc("/agents/register", handleRegister)
	mux.HandleFunc("/v1/agents/register", handleRegister)
	mux.HandleFunc("/agents/checksums", handleChecksums)
	mux.HandleFunc("/v1/agents/checksums", handleChecksums)
	mux.HandleFunc("/agents/download/", handleDownload)
	mux.HandleFunc("/v1/agents/download/", handleDownload)
	mux.HandleFunc("/agents/", handleAgentRoutes)
	mux.HandleFunc("/v1/agents/", handleAgentRoutes)

	addr := ":8080"
	log.Printf("Mock backend listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "ok")
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid request: %v", err), http.StatusBadRequest)
		return
	}

	agentID := fmt.Sprintf("agent-%06d", rand.Intn(1000000))
	agentToken := fmt.Sprintf("token-%s", randString(16))
	agentSecret := fmt.Sprintf("secret-%s", randString(32))

	agent := &Agent{
		ID:     agentID,
		Token:  agentToken,
		Secret: agentSecret,
	}

	agentsMu.Lock()
	agents[agentID] = agent
	commandQueues[agentID] = []CommandMessage{}
	agentsMu.Unlock()

	resp := RegisterResponse{
		AgentID:     agentID,
		AgentToken:  agentToken,
		AgentSecret: agentSecret,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleChecksums(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"ssl-agent":{"sha256":"fakesha256value"}}`)
}

func handleDownload(w http.ResponseWriter, r *http.Request) {
	// Serve the actual agent binary from the mounted repo
	binaryPath := "/app/apps/agent/bin/ssl-agent"
	data, err := os.ReadFile(binaryPath)
	if err != nil {
		// Fallback to a tiny static response if binary not found
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write([]byte("FAKE_BINARY_CONTENTS"))
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Write(data)
}

func handleAgentRoutes(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1")
	path = strings.TrimPrefix(path, "/agents/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) < 1 || parts[0] == "" {
		http.Error(w, "bad path", http.StatusBadRequest)
		return
	}
	agentID := parts[0]

	if len(parts) == 1 {
		// No sub-route
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	subRoute := parts[1]

	agentsMu.RLock()
	agent, exists := agents[agentID]
	agentsMu.RUnlock()
	if !exists {
		http.Error(w, "agent not found", http.StatusNotFound)
		return
	}

	switch subRoute {
	case "commands":
		handleCommands(w, r, agent)
	case "results":
		handleResults(w, r, agent)
	case "heartbeat":
		handleHeartbeat(w, r, agent)
	case "context":
		handleContext(w, r, agent)
	case "config":
		handleConfig(w, r, agent)
	default:
		if strings.HasPrefix(subRoute, "queue/") {
			cmdID := strings.TrimPrefix(subRoute, "queue/")
			handleQueueCommand(w, r, agent, cmdID)
		} else {
			http.Error(w, "not found", http.StatusNotFound)
		}
	}
}

func handleCommands(w http.ResponseWriter, r *http.Request, agent *Agent) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	agentsMu.Lock()
	queue := commandQueues[agent.ID]
	// Drain the queue
	commandQueues[agent.ID] = []CommandMessage{}
	agentsMu.Unlock()

	resp := PollCommandsResponse{Commands: queue}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleResults(w http.ResponseWriter, r *http.Request, agent *Agent) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req CommandResultRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid body: %v", err), http.StatusBadRequest)
		return
	}

	resultsMu.Lock()
	results[agent.ID] = append(results[agent.ID], req)
	resultsMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ack": true})
}

func handleHeartbeat(w http.ResponseWriter, r *http.Request, agent *Agent) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	resp := HeartbeatResponse{
		Ack:        true,
		ServerTime: time.Now().UTC().Format(time.RFC3339),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleContext(w http.ResponseWriter, r *http.Request, agent *Agent) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ack": true})
}

func handleConfig(w http.ResponseWriter, r *http.Request, agent *Agent) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	resp := AgentConfigResponse{
		PollIntervalSeconds:      30,
		HeartbeatIntervalSeconds: 60,
		LogLevel:                 "info",
		CommandsWhitelist:        []string{},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleQueueCommand(w http.ResponseWriter, r *http.Request, agent *Agent, commandID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var params map[string]any
	if r.Body != nil && r.ContentLength > 0 {
		_ = json.NewDecoder(r.Body).Decode(&params)
	}

	executionID := fmt.Sprintf("exec-%s", randString(12))
	ts := time.Now().Unix()
	nonce := randString(16)

	payload := canonicalPayload{
		CommandID:   commandID,
		ExecutionID: executionID,
		Parameters:  params,
		Timestamp:   ts,
		Nonce:       nonce,
	}

	sig := computeSignature(payload, agent.Secret)

	msg := CommandMessage{
		CommandID:   commandID,
		ExecutionID: executionID,
		Parameters:  params,
		Priority:    "normal",
		Timestamp:   ts,
		Nonce:       nonce,
		Signature:   sig,
	}

	agentsMu.Lock()
	commandQueues[agent.ID] = append(commandQueues[agent.ID], msg)
	agentsMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "queued", "execution_id": executionID})
}

func computeSignature(payload canonicalPayload, secret string) string {
	if payload.Parameters == nil {
		payload.Parameters = map[string]any{}
	}
	data, _ := json.Marshal(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

func randString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
