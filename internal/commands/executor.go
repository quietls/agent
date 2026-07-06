package commands

import (
	"context"
	"time"

	"github.com/quietls/agent/internal/httpclient"
	"github.com/quietls/agent/internal/platform"
	"github.com/quietls/agent/internal/security"
)

const defaultTimeoutMs = 5 * 60 * 1000 // 5 minutes

// ExecutionResult holds the full result of executing a command.
type ExecutionResult struct {
	ExecutionID string         `json:"execution_id"`
	CommandID   string         `json:"command_id"`
	Status      string         `json:"status"`
	StartedAt   string         `json:"started_at"`
	CompletedAt string         `json:"completed_at"`
	DurationMs  int64          `json:"duration_ms"`
	Output      map[string]any `json:"output"`
	Error       string         `json:"error,omitempty"`
}

// ExecutorDeps holds dependencies for command execution.
type ExecutorDeps struct {
	AgentSecret   string
	HTTPClient    *httpclient.Client
	Executor      platform.Executor
	NonceStore    *security.NonceStore
	TimeoutMs     int
	ConfigPath    string
	ReloadCommand string
}

// ExecuteCommand validates and executes a command message.
func ExecuteCommand(cmd httpclient.CommandMessage, deps ExecutorDeps) ExecutionResult {
	startedAt := time.Now()

	result := ExecutionResult{
		ExecutionID: cmd.ExecutionID,
		CommandID:   cmd.CommandID,
	}

	// 1. Verify HMAC signature
	fields := security.CommandFields{
		CommandID:   cmd.CommandID,
		ExecutionID: cmd.ExecutionID,
		Parameters:  cmd.Parameters,
		Timestamp:   cmd.Timestamp,
		Nonce:       cmd.Nonce,
		Signature:   cmd.Signature,
	}

	if !security.VerifySignature(fields, deps.AgentSecret) {
		return finishResult(result, startedAt, "failure", nil, "invalid_signature")
	}

	// 2. Check timestamp freshness (60s window)
	if !security.IsTimestampValid(cmd.Timestamp, 60) {
		return finishResult(result, startedAt, "failure", nil, "expired_command")
	}

	// 3. Check nonce uniqueness
	if !deps.NonceStore.Check(cmd.Nonce) {
		return finishResult(result, startedAt, "failure", nil, "already_executed")
	}

	// 4. Resolve handler
	handler := GetHandler(cmd.CommandID)
	if handler == nil {
		return finishResult(result, startedAt, "failure", nil, "unknown_command")
	}

	// 5. Execute with timeout
	timeout := deps.TimeoutMs
	if timeout <= 0 {
		timeout = defaultTimeoutMs
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Millisecond)
	defer cancel()

	type handlerResult struct {
		result CommandResult
	}

	ch := make(chan handlerResult, 1)
	go func() {
		hCtx := HandlerContext{
			Parameters:    cmd.Parameters,
			Executor:      deps.Executor,
			HTTPClient:    deps.HTTPClient,
			ConfigPath:    deps.ConfigPath,
			ReloadCommand: deps.ReloadCommand,
		}
		r := handler(hCtx)
		ch <- handlerResult{result: r}
	}()

	select {
	case <-ctx.Done():
		return finishResult(result, startedAt, "failure", nil, "timeout")
	case hr := <-ch:
		return finishResult(result, startedAt, hr.result.Status, hr.result.Output, hr.result.Error)
	}
}

func finishResult(result ExecutionResult, startedAt time.Time, status string, output map[string]any, errStr string) ExecutionResult {
	completedAt := time.Now()
	result.Status = status
	result.Output = output
	result.Error = errStr
	result.StartedAt = startedAt.UTC().Format(time.RFC3339)
	result.CompletedAt = completedAt.UTC().Format(time.RFC3339)
	result.DurationMs = completedAt.Sub(startedAt).Milliseconds()
	return result
}
