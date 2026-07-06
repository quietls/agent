package agent

import (
	"fmt"
	"log/slog"
	"math"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/quietls/agent/internal/commands"
	"github.com/quietls/agent/internal/httpclient"
	"github.com/quietls/agent/internal/platform"
	"github.com/quietls/agent/internal/security"
	"github.com/quietls/agent/internal/webserver"
)

// ── Polling intervals ────────────────────────────────────────

const (
	NormalPollMs      = 30_000
	PostCommandPollMs = 5_000
	HeartbeatMs       = 60_000
	BackoffBaseMs     = 30_000
	BackoffMaxMs      = 300_000
)

// ── Daemon ───────────────────────────────────────────────────

// DaemonDeps holds injectable dependencies for the daemon.
type DaemonDeps struct {
	Executor platform.Executor
	FileIO   FileIO
	Logger   *slog.Logger
	Now      func() time.Time
	Version  string
}

// DefaultDaemonDeps returns production dependencies.
func DefaultDaemonDeps() DaemonDeps {
	return DaemonDeps{
		Executor: platform.OSExecutor{},
		FileIO:   OSFileIO{},
		Logger:   slog.Default(),
		Now:      time.Now,
	}
}

// Daemon is the main agent polling loop.
type Daemon struct {
	configPath      string
	deps            DaemonDeps
	running         atomic.Bool
	consecutiveErrs int
	nonceStore      *security.NonceStore
	client          *httpclient.Client
	config          *Config
	startTime       time.Time
	stopOnce        sync.Once
	stopCh          chan struct{}
}

// NewDaemon creates a new daemon instance.
func NewDaemon(configPath string, version string, deps DaemonDeps) *Daemon {
	deps.Version = version
	return &Daemon{
		configPath: configPath,
		deps:       deps,
		nonceStore: security.NewNonceStore(10000),
		stopCh:     make(chan struct{}),
	}
}

// Start loads config and begins the polling loop. It blocks until Stop is called.
func (d *Daemon) Start() error {
	cfg, err := LoadConfig(d.configPath, d.deps.FileIO)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Env override: SSL_AGENT_CONFIG_PATH lets operators point the agent at the
	// web server config without editing the persisted config.json. This is
	// essential for sidecar deployments where the nginx/apache config is mounted
	// into the container but the config.json is on a named volume that may be
	// reset on redeploy. Env wins over the file value so the compose file is the
	// single source of truth.
	if envPath := os.Getenv("SSL_AGENT_CONFIG_PATH"); envPath != "" {
		cfg.ConfigPath = envPath
	}

	// Env override: SSL_AGENT_RELOAD_COMMAND provides the command used to reload
	// the web server. Essential for sidecar deployments where nginx/apache runs
	// in a separate container (e.g. "docker exec nginx nginx -s reload"). Env
	// wins over config.json so the compose file is the single source of truth.
	if reloadCmd := os.Getenv("SSL_AGENT_RELOAD_COMMAND"); reloadCmd != "" {
		cfg.ReloadCommand = reloadCmd
	}

	d.config = cfg
	d.client = httpclient.New(cfg.BaseURL, cfg.AgentID, cfg.AgentToken, nil)
	d.running.Store(true)
	d.startTime = d.deps.Now()

	d.deps.Logger.Info("Agent daemon started", "agent_id", cfg.AgentID)

	d.sendContextUpdate()

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		select {
		case <-sigCh:
			d.Stop()
		case <-d.stopCh:
		}
	}()

	// Start heartbeat goroutine
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		ticker := time.NewTicker(time.Duration(HeartbeatMs) * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				d.sendHeartbeat()
			case <-d.stopCh:
				return
			}
		}
	}()

	// Immediate first poll, then loop
	d.poll()

	for d.running.Load() {
		nextInterval := d.computeNextInterval()
		select {
		case <-time.After(time.Duration(nextInterval) * time.Millisecond):
			d.poll()
		case <-d.stopCh:
		}
	}

	<-heartbeatDone
	d.deps.Logger.Info("Agent daemon shut down")
	return nil
}

// Stop signals the daemon to stop.
func (d *Daemon) Stop() {
	d.stopOnce.Do(func() {
		d.deps.Logger.Info("Agent daemon shutting down...")
		d.running.Store(false)
		close(d.stopCh)
	})
}

func (d *Daemon) poll() {
	if !d.running.Load() || d.client == nil || d.config == nil {
		return
	}

	resp, err := d.client.PollCommands()
	if err != nil {
		d.consecutiveErrs++
		nextMs := d.computeBackoff()
		d.deps.Logger.Warn("Poll error",
			"retry_seconds", nextMs/1000,
			"error", err.Error(),
		)
		return
	}

	d.consecutiveErrs = 0

	if len(resp.Commands) > 0 {
		d.processCommands(resp.Commands)
	}
}

func (d *Daemon) processCommands(cmds []httpclient.CommandMessage) {
	for _, cmd := range cmds {
		d.deps.Logger.Info("Executing command",
			"command_id", cmd.CommandID,
			"execution_id", cmd.ExecutionID,
		)

		result := commands.ExecuteCommand(cmd, commands.ExecutorDeps{
			AgentSecret:   d.config.AgentSecret,
			HTTPClient:    d.client,
			Executor:      d.deps.Executor,
			NonceStore:    d.nonceStore,
			ConfigPath:    d.config.ConfigPath,
			ReloadCommand: d.config.ReloadCommand,
		})

		d.deps.Logger.Info("Command completed",
			"execution_id", cmd.ExecutionID,
			"status", result.Status,
		)

		var errPtr *string
		if result.Error != "" {
			errPtr = &result.Error
		}

		err := d.client.ReportResult(httpclient.CommandResultRequest{
			ExecutionID: result.ExecutionID,
			CommandID:   result.CommandID,
			Status:      result.Status,
			StartedAt:   result.StartedAt,
			CompletedAt: result.CompletedAt,
			DurationMs:  result.DurationMs,
			Output:      result.Output,
			Error:       errPtr,
		})
		if err != nil {
			d.deps.Logger.Error("Failed to report result",
				"execution_id", result.ExecutionID,
				"error", err.Error(),
			)
		}
	}
}

func (d *Daemon) sendHeartbeat() {
	if d.client == nil || d.config == nil {
		return
	}

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	_, err := d.client.SendHeartbeat(httpclient.HeartbeatRequest{
		AgentVersion:    d.deps.Version,
		UptimeSeconds:   int(d.deps.Now().Sub(d.startTime).Seconds()),
		PlatformProfile: d.config.PlatformProfile,
		CertsManaged:    0,
		SystemMetrics: httpclient.SystemMetrics{
			CPUPercent: 0,
			MemoryMB:   int(memStats.Sys / 1024 / 1024),
			DiskFreeGB: 0,
		},
	})
	if err != nil {
		d.deps.Logger.Warn("Heartbeat failed", "error", err.Error())
	}
}

func (d *Daemon) sendContextUpdate() {
	if d.client == nil || d.config == nil {
		return
	}

	osInfo := platform.DetectOS(d.deps.Executor)
	runtimeName := platform.DetectRuntime(d.deps.Executor)
	ports := platform.DetectPorts(d.deps.Executor)

	ws := webserver.DetectWebServerWithOptions(d.deps.Executor, webserver.DetectOptions{
		ConfigPathOverride: d.config.ConfigPath,
	})

	var wsCtx *httpclient.WebServerUpdateContext
	domains := []string{}
	if ws != nil {
		wsCtx = &httpclient.WebServerUpdateContext{
			Type:    ws.Type,
			Version: ws.Version,
		}
		for _, v := range ws.Vhosts {
			domains = append(domains, v.ServerName)
		}
	}

	err := d.client.UpdateContext(httpclient.ContextUpdateRequest{
		OS: httpclient.OSContext{
			Distro:  osInfo.Distro,
			Version: osInfo.Version,
			Arch:    osInfo.Arch,
		},
		WebServer: wsCtx,
		Runtime:   runtimeName,
		Ports: httpclient.PortsContext{
			Port80:  ports.Port80,
			Port443: ports.Port443,
		},
		Domains: domains,
	})
	if err != nil {
		d.deps.Logger.Warn("Context update failed", "error", err.Error())
		return
	}

	d.deps.Logger.Info("Context updated")
}

func (d *Daemon) computeNextInterval() int {
	if d.consecutiveErrs > 0 {
		return d.computeBackoff()
	}
	return NormalPollMs
}

func (d *Daemon) computeBackoff() int {
	ms := float64(BackoffBaseMs) * math.Pow(2, float64(d.consecutiveErrs-1))
	if ms > BackoffMaxMs {
		ms = BackoffMaxMs
	}
	return int(ms)
}
